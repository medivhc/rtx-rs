//! Real-UDP pump for the sans-IO DTLS 1.2 handshake (R2-3).
//!
//! This is the only test in the crate that touches a socket. Two
//! [`HandshakeMachine`]s are bound to `127.0.0.1:0` `UdpSocket`s and exchange
//! their records as datagrams over the loopback interface. The sockets are
//! non-blocking and the clock is the injected [`Timestamp`] advanced by the
//! pump itself, so the tests never read a wall clock and never sleep. The
//! drive loop is bounded; a stalled or over-budget run fails the test.
//!
//! Scope: the peer is always this crate's server machine. These tests prove
//! transport behaviour (real datagrams, loss, duplication, garbage), not
//! interoperability with a third-party DTLS stack; see `HANDSHAKE.md` §8.

mod common;

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr as StdSocketAddr, UdpSocket};

use common::Lcg;
use common::handshake::{HandshakeCrypto, SERVER_SIGNING_KEY, server_signing_public};
use rtx_dtls::{
    DatagramMeta, HandshakeConfig, HandshakeError, HandshakeEvent, HandshakeMachine,
    HandshakeState, Input, IpAddr, MAX_HANDSHAKE_RECORD_LEN, ProtocolMachine, SocketAddr,
    Timestamp,
};

type Machine = HandshakeMachine<HandshakeCrypto>;

/// Profile plus the four RFC 5764 byte strings, compared byte for byte.
type KeyingMaterial = (u16, [u8; 16], [u8; 16], [u8; 14], [u8; 14]);

const CLIENT_SEED: u64 = 0x00C0_FFEE_1234_5678;
const SERVER_SEED: u64 = 0x0BAD_CAFE_8765_4321;
const START_MICROS: u64 = 1_000_000;
/// Hard upper bound on pump iterations. A healthy handshake needs a handful.
const MAX_STEPS: usize = 4_096;
/// Largest flight in the profile is three records; this bound is defensive.
const MAX_FLIGHT_RECORDS: usize = 8;
const MAX_RECV_BATCH: usize = 64;
const MAX_SEND_ATTEMPTS: u8 = 8;
const MAX_DATAGRAM_LEN: usize = 2_048;
const SETTLE_ROUNDS: usize = 8;
/// Datagrams a lossless run puts on the wire: `ClientHello` + CKE + CCS +
/// Finished for the client, `ServerHello` + SKE + `ServerHelloDone` + CCS +
/// Finished for the server.
const BASELINE_CLIENT_DATAGRAMS: usize = 4;
const BASELINE_SERVER_DATAGRAMS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Client,
    Server,
}

impl Side {
    const fn peer(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

/// Datagram-level impairment applied to whole flights, counted per sender
/// from zero. A dropped flight is lost in full: partial loss would let the
/// peer reject the out-of-order records instead of exercising retransmission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Impairment {
    drop: Option<(Side, usize)>,
    duplicate: Option<(Side, usize)>,
}

impl Impairment {
    #[must_use]
    const fn drop_client(flight: usize) -> Self {
        Self {
            drop: Some((Side::Client, flight)),
            duplicate: None,
        }
    }

    #[must_use]
    const fn drop_server(flight: usize) -> Self {
        Self {
            drop: Some((Side::Server, flight)),
            duplicate: None,
        }
    }

    #[must_use]
    const fn duplicate_client(flight: usize) -> Self {
        Self {
            drop: None,
            duplicate: Some((Side::Client, flight)),
        }
    }

    #[must_use]
    const fn duplicate_server(flight: usize) -> Self {
        Self {
            drop: None,
            duplicate: Some((Side::Server, flight)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PumpFailure {
    /// A machine rejected input or failed internally; the error is in the
    /// corresponding slot.
    Machine,
    /// Neither endpoint can transmit, receive or arm a timer.
    Stalled,
    /// The bounded drive loop ran out of steps.
    StepBudget,
}

/// Two sans-IO machines plus the real sockets that carry their records.
struct Pump {
    client: Machine,
    server: Machine,
    client_socket: UdpSocket,
    server_socket: UdpSocket,
    client_addr: StdSocketAddr,
    server_addr: StdSocketAddr,
    now: Timestamp,
    impairment: Impairment,
    client_flights: usize,
    server_flights: usize,
    client_datagrams: usize,
    server_datagrams: usize,
    timeouts: usize,
    client_error: Option<HandshakeError>,
    server_error: Option<HandshakeError>,
}

impl Pump {
    fn new(impairment: Impairment) -> Self {
        let (client_socket, client_addr) = bind_loopback();
        let (server_socket, server_addr) = bind_loopback();
        let client = HandshakeMachine::new(
            HandshakeCrypto::new(CLIENT_SEED),
            HandshakeConfig::client(server_signing_public()),
            None,
        )
        .expect("client machine");
        let server = HandshakeMachine::new(
            HandshakeCrypto::new(SERVER_SEED),
            HandshakeConfig::server(),
            Some(&SERVER_SIGNING_KEY),
        )
        .expect("server machine");
        Self {
            client,
            server,
            client_socket,
            server_socket,
            client_addr,
            server_addr,
            now: Timestamp::from_micros(START_MICROS),
            impairment,
            client_flights: 0,
            server_flights: 0,
            client_datagrams: 0,
            server_datagrams: 0,
            timeouts: 0,
            client_error: None,
            server_error: None,
        }
    }

    /// Drives both machines until established, the step budget is exhausted,
    /// or no endpoint can make progress.
    fn run(&mut self) -> Result<(), PumpFailure> {
        for _ in 0..MAX_STEPS {
            if self.client.is_established() && self.server.is_established() {
                return Ok(());
            }
            if self.client_error.is_some() || self.server_error.is_some() {
                return Err(PumpFailure::Machine);
            }
            if self.pump_once() {
                continue;
            }
            self.advance_timer()?;
        }
        Err(PumpFailure::StepBudget)
    }

    /// Reads any datagrams still queued after establishment. Bounded; no
    /// timer is advanced, so this only exercises the established path with
    /// the duplicates/retransmissions already on the wire.
    fn settle(&mut self) {
        for _ in 0..SETTLE_ROUNDS {
            if !self.pump_once() {
                return;
            }
        }
    }

    /// One round: drain and send every queued flight, then consume every
    /// datagram currently available on both sockets. Returns whether the
    /// round moved any bytes.
    fn pump_once(&mut self) -> bool {
        let client_sent = self.transmit(Side::Client);
        let server_sent = self.transmit(Side::Server);
        let client_received = self.receive(Side::Client);
        let server_received = self.receive(Side::Server);
        client_sent || server_sent || client_received || server_received
    }

    /// Emits the machine's queued flight, one datagram per record, honouring
    /// the impairment for this flight index.
    fn transmit(&mut self, side: Side) -> bool {
        let mut records: Vec<Vec<u8>> = Vec::new();
        let mut failure = None;
        {
            let machine = match side {
                Side::Client => &mut self.client,
                Side::Server => &mut self.server,
            };
            let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
            while records.len() < MAX_FLIGHT_RECORDS {
                match machine.poll_transmit(&mut buffer) {
                    Ok(Some(len)) => records.push(buffer[..len].to_vec()),
                    Ok(None) => break,
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            }
        }
        if let Some(error) = failure {
            self.record_error(side, error);
        }
        if records.is_empty() {
            return false;
        }

        let flight = match side {
            Side::Client => {
                let flight = self.client_flights;
                self.client_flights += 1;
                flight
            }
            Side::Server => {
                let flight = self.server_flights;
                self.server_flights += 1;
                flight
            }
        };
        let (dropped, duplicated) = (
            self.impairment.drop == Some((side, flight)),
            self.impairment.duplicate == Some((side, flight)),
        );
        if dropped {
            return true;
        }
        for record in &records {
            self.send_datagram(side, record);
            if duplicated {
                // Duplicate on the wire, not in the machine: the peer sees
                // the identical record (same record sequence number) twice.
                self.send_datagram(side, record);
            }
        }
        true
    }

    /// Sends `payload` from `path`'s socket to the peer endpoint.
    fn send_datagram(&mut self, path: Side, payload: &[u8]) {
        // Count only datagrams that actually reach the wire, so a dropped
        // flight is not counted and a duplicate is counted twice.
        match path {
            Side::Client => self.client_datagrams += 1,
            Side::Server => self.server_datagrams += 1,
        }
        let socket = match path {
            Side::Client => &self.client_socket,
            Side::Server => &self.server_socket,
        };
        let destination = match path {
            Side::Client => self.server_addr,
            Side::Server => self.client_addr,
        };
        let mut attempts = 0u8;
        loop {
            match socket.send_to(payload, destination) {
                Ok(_) => return,
                Err(error)
                    if error.kind() == ErrorKind::WouldBlock && attempts < MAX_SEND_ATTEMPTS =>
                {
                    attempts += 1;
                    std::hint::spin_loop();
                }
                Err(error) => panic!("sending datagram to {destination}: {error}"),
            }
        }
    }

    /// Sends an arbitrary datagram to `destination`, bypassing the machines.
    fn deliver(&mut self, destination: Side, payload: &[u8]) {
        self.send_datagram(destination.peer(), payload);
    }

    /// Reads every available datagram addressed to `side` and feeds it to
    /// that machine. Errors are recorded, not raised.
    fn receive(&mut self, side: Side) -> bool {
        let mut received = false;
        let mut buffer = [0u8; MAX_DATAGRAM_LEN];
        for _ in 0..MAX_RECV_BATCH {
            let socket = match side {
                Side::Client => &self.client_socket,
                Side::Server => &self.server_socket,
            };
            let (len, source) = match socket.recv_from(&mut buffer) {
                Ok(value) => value,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => panic!("receiving datagram: {error}"),
            };
            received = true;
            let source = rtx_addr(source);
            let destination = match side {
                Side::Client => rtx_addr(self.client_addr),
                Side::Server => rtx_addr(self.server_addr),
            };
            let meta = DatagramMeta {
                now: self.now,
                source,
                destination,
                ecn: None,
            };
            let result = match side {
                Side::Client => self.client.handle_input(Input::Datagram {
                    meta,
                    payload: &buffer[..len],
                }),
                Side::Server => self.server.handle_input(Input::Datagram {
                    meta,
                    payload: &buffer[..len],
                }),
            };
            if let Err(error) = result {
                self.record_error(side, error);
            }
        }
        received
    }

    fn record_error(&mut self, side: Side, error: HandshakeError) {
        let slot = match side {
            Side::Client => &mut self.client_error,
            Side::Server => &mut self.server_error,
        };
        if slot.is_none() {
            *slot = Some(error);
        }
    }

    /// Fires the earliest pending retransmission timer on the injected clock.
    fn advance_timer(&mut self) -> Result<(), PumpFailure> {
        let client_wakeup = self.client.next_wakeup();
        let server_wakeup = self.server.next_wakeup();
        let deadline = match (client_wakeup, server_wakeup) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        };
        let Some(deadline) = deadline else {
            return Err(PumpFailure::Stalled);
        };
        // Keep the injected clock monotonic even if a timer is already due.
        self.now = if deadline.as_micros() > self.now.as_micros() {
            deadline
        } else {
            Timestamp::from_micros(self.now.as_micros().saturating_add(1))
        };
        if client_wakeup == Some(deadline) {
            self.timeouts += 1;
            if let Err(error) = self.client.handle_input(Input::Timeout(deadline)) {
                self.record_error(Side::Client, error);
            }
        }
        if server_wakeup == Some(deadline) {
            self.timeouts += 1;
            if let Err(error) = self.server.handle_input(Input::Timeout(deadline)) {
                self.record_error(Side::Server, error);
            }
        }
        Ok(())
    }

    /// Asserts that a run reached `Established` on both sides with no machine
    /// error, then prints the recorded errors if it did not.
    fn run_to_establishment(&mut self) {
        match self.run() {
            Ok(()) => {}
            Err(failure) => panic!(
                "pump stopped with {failure:?} (client error {:?}, server error {:?})",
                self.client_error, self.server_error
            ),
        }
        assert!(
            self.client_error.is_none(),
            "client error: {:?}",
            self.client_error
        );
        assert!(
            self.server_error.is_none(),
            "server error: {:?}",
            self.server_error
        );
        assert!(
            self.client.is_established(),
            "client state: {:?}",
            self.client.state()
        );
        assert!(
            self.server.is_established(),
            "server state: {:?}",
            self.server.state()
        );
    }

    /// Takes each side's single `Established` event, compares the RFC 5764
    /// material byte for byte, and requires no second event.
    fn assert_single_establishment(&mut self) {
        let client_material = established_material(&mut self.client);
        let server_material = established_material(&mut self.server);
        assert_eq!(
            client_material, server_material,
            "DTLS-SRTP keying material differs between the two sides"
        );
        assert!(
            self.client.poll_event().is_none(),
            "client emitted a second Established event"
        );
        assert!(
            self.server.poll_event().is_none(),
            "server emitted a second Established event"
        );
    }
}

fn bind_loopback() -> (UdpSocket, StdSocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind 127.0.0.1:0");
    socket.set_nonblocking(true).expect("non-blocking socket");
    let address = socket.local_addr().expect("local socket address");
    (socket, address)
}

fn rtx_addr(address: StdSocketAddr) -> SocketAddr {
    match address {
        StdSocketAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4.ip().octets()), v4.port()),
        StdSocketAddr::V6(v6) => SocketAddr::new(IpAddr::V6(v6.ip().octets()), v6.port()),
    }
}

fn established_material(machine: &mut Machine) -> KeyingMaterial {
    match machine.poll_event() {
        Some(HandshakeEvent::Established { keying_material }) => (
            keying_material.profile(),
            *keying_material.client_write_key(),
            *keying_material.server_write_key(),
            *keying_material.client_write_salt(),
            *keying_material.server_write_salt(),
        ),
        None => panic!("machine did not emit an Established event"),
    }
}

// DTLS-UDP-001 — the minimal handshake runs over real loopback UDP and both
// sides derive identical DTLS-SRTP material.
#[test]
fn handshake_completes_over_real_udp() {
    let mut pump = Pump::new(Impairment::default());
    pump.run_to_establishment();
    assert_eq!(pump.client.state(), HandshakeState::Established);
    assert_eq!(pump.server.state(), HandshakeState::Established);
    assert_eq!(
        pump.client_datagrams, BASELINE_CLIENT_DATAGRAMS,
        "lossless client should send exactly its two flights"
    );
    assert_eq!(
        pump.server_datagrams, BASELINE_SERVER_DATAGRAMS,
        "lossless server should send exactly its two flights"
    );
    assert_eq!(
        pump.timeouts, 0,
        "lossless handshake should not need a retransmission timer"
    );
    pump.assert_single_establishment();
}

// DTLS-UDP-002 — losing one complete flight in either direction is recovered
// by the retransmission timer over real UDP. Each case drops exactly one
// flight: the client's ClientHello, the server's first flight, and the
// client's final flight.
#[test]
fn single_flight_loss_is_recovered_by_retransmission() {
    let cases = [
        (Impairment::drop_client(0), Side::Client),
        (Impairment::drop_server(0), Side::Server),
        (Impairment::drop_client(1), Side::Client),
    ];
    for (impairment, sender) in cases {
        let mut pump = Pump::new(impairment);
        pump.run_to_establishment();
        pump.assert_single_establishment();
        assert!(
            pump.timeouts > 0,
            "loss recovery did not fire a retransmission timer"
        );
        // A dropped flight is never counted on the wire, so count the
        // flights the sender emitted: the lossless count is two per side.
        match sender {
            Side::Client => assert!(
                pump.client_flights > 2,
                "client did not retransmit after a dropped flight (emitted {} flights)",
                pump.client_flights
            ),
            Side::Server => assert!(
                pump.server_flights > 2,
                "server did not retransmit after a dropped flight (emitted {} flights)",
                pump.server_flights
            ),
        }
    }
}

// DTLS-UDP-003 — duplicating every datagram of a flight on the wire does not
// disturb the handshake: replay windows drop the copies, both sides still
// establish, and each emits exactly one Established event.
#[test]
fn duplicated_flights_still_establish_once() {
    let cases = [
        (Impairment::duplicate_client(0), Side::Client),
        (Impairment::duplicate_server(0), Side::Server),
        (Impairment::duplicate_client(1), Side::Client),
    ];
    for (impairment, sender) in cases {
        let mut pump = Pump::new(impairment);
        pump.run_to_establishment();
        pump.settle();
        pump.assert_single_establishment();
        match sender {
            Side::Client => assert!(
                pump.client_datagrams > BASELINE_CLIENT_DATAGRAMS,
                "client duplicates were not injected (sent {})",
                pump.client_datagrams
            ),
            Side::Server => assert!(
                pump.server_datagrams > BASELINE_SERVER_DATAGRAMS,
                "server duplicates were not injected (sent {})",
                pump.server_datagrams
            ),
        }
    }
}

// DTLS-UDP-004 — deterministic garbage datagrams delivered over UDP never
// panic a machine. The contract allows either ignoring a datagram or moving
// to `Failed`; handshake success is deliberately not asserted.
#[test]
fn garbage_datagrams_do_not_panic() {
    let seeds = [
        0x0000_0000_0000_0001,
        0xDEAD_BEEF_CAFE_F00D,
        0x0BAD_F00D_1234_5678,
        0x5EED_5EED_5EED_5EED,
    ];
    for seed in seeds {
        let mut pump = Pump::new(Impairment::default());
        let mut rng = Lcg::new(seed);
        for _ in 0..16 {
            let len = usize::try_from(rng.next_u64() % 128).expect("small length") + 1;
            let payload = rng.bytes(len);
            pump.deliver(Side::Client, &payload);
            let payload = rng.bytes(len);
            pump.deliver(Side::Server, &payload);
        }
        // Only receive: do not transmit, so no real handshake can start.
        pump.receive(Side::Client);
        pump.receive(Side::Server);
        pump.receive(Side::Client);
        pump.receive(Side::Server);

        assert!(!pump.client.is_established());
        assert!(!pump.server.is_established());
        assert!(
            pump.client.poll_event().is_none(),
            "garbage produced a client Established event"
        );
        assert!(
            pump.server.poll_event().is_none(),
            "garbage produced a server Established event"
        );
        assert!(
            matches!(
                pump.client.state(),
                HandshakeState::WaitServerHello | HandshakeState::Failed
            ),
            "unexpected client state after garbage: {:?}",
            pump.client.state()
        );
        assert!(
            matches!(
                pump.server.state(),
                HandshakeState::WaitClientHello | HandshakeState::Failed
            ),
            "unexpected server state after garbage: {:?}",
            pump.server.state()
        );
    }
}

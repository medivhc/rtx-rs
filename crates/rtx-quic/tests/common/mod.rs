//! Shared test harness: an in-process pump between a server endpoint and one
//! or more client endpoints. No socket, no sleep, no wall clock.
#![allow(dead_code)]

use rtx_core::{Duration, IpAddr, SocketAddr, Timestamp};
use rtx_quic::{
    ConnectionId, Endpoint, EndpointConfig, Event, EventKind, StreamError, StreamId, StreamRead,
    TransportConfig,
};

pub const ALPN: &[u8] = b"h3";

/// Throw-away self-signed certificate for `localhost`.
pub struct TestPki {
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
}

impl TestPki {
    pub fn new() -> Self {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed localhost certificate");
        Self {
            certificate_der: certified.cert.der().to_vec(),
            private_key_der: certified.key_pair.serialize_der(),
        }
    }
}

pub fn client_config(pki: &TestPki, alpn: &[&[u8]]) -> EndpointConfig {
    EndpointConfig::new()
        .with_alpn(alpn.iter().map(|protocol| protocol.to_vec()).collect())
        .with_client_roots(vec![pki.certificate_der.clone()])
}

pub fn server_config(pki: &TestPki, alpn: &[&[u8]], transport: TransportConfig) -> EndpointConfig {
    EndpointConfig::new()
        .with_alpn(alpn.iter().map(|protocol| protocol.to_vec()).collect())
        .with_transport(transport)
        .with_server_identity(
            vec![pki.certificate_der.clone()],
            pki.private_key_der.clone(),
        )
}

pub fn address(last_octet: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4([10, 0, 0, last_octet]), port)
}

pub struct ClientEndpoint {
    pub endpoint: Endpoint,
    pub address: SocketAddr,
    pub connection: ConnectionId,
}

pub struct Harness {
    pub server: Endpoint,
    pub server_address: SocketAddr,
    pub clients: Vec<ClientEndpoint>,
    pub now: Timestamp,
}

impl Harness {
    pub fn new(server: Endpoint) -> Self {
        Self {
            server,
            server_address: address(1, 4433),
            clients: Vec::new(),
            now: Timestamp::from_micros(1_000_000),
        }
    }

    pub fn add_client(&mut self, mut endpoint: Endpoint) -> usize {
        let index = self.clients.len();
        let address = address(
            u8::try_from(index + 2).expect("test only uses a handful of clients"),
            40_000 + u16::try_from(index).expect("test only uses a handful of clients"),
        );
        let connection = endpoint
            .connect(self.now, self.server_address, "localhost")
            .expect("client connect");
        self.clients.push(ClientEndpoint {
            endpoint,
            address,
            connection,
        });
        index
    }

    pub fn advance(&mut self, micros: u64) {
        self.now += Duration::from_micros(micros);
    }

    pub fn advance_to(&mut self, timestamp: Timestamp) {
        if timestamp > self.now {
            self.now = timestamp;
        }
    }

    /// Move every currently available datagram, without advancing time.
    pub fn pump(&mut self) {
        self.pump_stepping(0, 512);
    }

    pub fn exchange_client_to_server(&mut self) -> bool {
        let mut buffer = Vec::new();
        let mut moved = false;
        for client in &mut self.clients {
            loop {
                let Some(transmit) = client.endpoint.poll_transmit(self.now, &mut buffer) else {
                    break;
                };
                let payload = buffer[..transmit.len].to_vec();
                self.server
                    .handle_datagram(self.now, client.address, None, &payload);
                moved = true;
            }
        }
        moved
    }

    pub fn exchange_server_to_client(&mut self) -> bool {
        let mut buffer = Vec::new();
        let mut moved = false;
        loop {
            let Some(transmit) = self.server.poll_transmit(self.now, &mut buffer) else {
                break;
            };
            let payload = buffer[..transmit.len].to_vec();
            if let Some(client) = self
                .clients
                .iter_mut()
                .find(|client| client.address == transmit.destination)
            {
                client
                    .endpoint
                    .handle_datagram(self.now, self.server_address, None, &payload);
            }
            moved = true;
        }
        moved
    }

    /// Pump with a fixed one-way delay between sending and delivery. Used to
    /// obtain non-zero RTT samples without sleeping.
    pub fn pump_latency(&mut self, latency_micros: u64, rounds: usize) {
        for _ in 0..rounds {
            let to_server = self.exchange_client_to_server();
            if to_server {
                self.advance(latency_micros);
            }
            let to_client = self.exchange_server_to_client();
            if to_client {
                self.advance(latency_micros);
            }
            if !to_server && !to_client {
                break;
            }
        }
    }

    /// Move datagrams for at most `rounds` rounds, advancing `step` microseconds
    /// per round.
    pub fn pump_stepping(&mut self, step: u64, rounds: usize) {
        let mut buffer = Vec::new();
        for _ in 0..rounds {
            let mut moved = false;
            for client in &mut self.clients {
                loop {
                    let Some(transmit) = client.endpoint.poll_transmit(self.now, &mut buffer)
                    else {
                        break;
                    };
                    let payload = buffer[..transmit.len].to_vec();
                    self.server
                        .handle_datagram(self.now, client.address, None, &payload);
                    moved = true;
                }
            }
            loop {
                let Some(transmit) = self.server.poll_transmit(self.now, &mut buffer) else {
                    break;
                };
                let payload = buffer[..transmit.len].to_vec();
                if let Some(client) = self
                    .clients
                    .iter_mut()
                    .find(|client| client.address == transmit.destination)
                {
                    client
                        .endpoint
                        .handle_datagram(self.now, self.server_address, None, &payload);
                }
                moved = true;
            }
            if moved {
                if step != 0 {
                    self.advance(step);
                }
            } else if step != 0 {
                self.advance(step);
            } else {
                break;
            }
        }
    }

    /// Pump, accept the first incoming connection, pump again, and return the
    /// server-side connection handle.
    pub fn establish(&mut self) -> ConnectionId {
        self.establish_with_step(0)
    }

    pub fn establish_with_step(&mut self, step: u64) -> ConnectionId {
        let mut buffer = Vec::new();
        self.pump_stepping(step, 32);
        let mut incoming = None;
        while let Some(event) = self.server.poll_event() {
            if matches!(event.kind, EventKind::Incoming) {
                incoming = Some(event.connection);
            }
        }
        let incoming = incoming.expect("server saw an incoming connection");
        self.server
            .accept(self.now, incoming, &mut buffer)
            .expect("server accepts the incoming connection");
        self.pump_stepping(step, 64);
        incoming
    }

    /// Establish a connection while every one-way delivery is delayed, which
    /// produces non-zero RTT samples deterministically.
    pub fn establish_with_latency(&mut self, latency_micros: u64) -> ConnectionId {
        let mut buffer = Vec::new();
        self.pump_latency(latency_micros, 32);
        let mut incoming = None;
        while let Some(event) = self.server.poll_event() {
            if matches!(event.kind, EventKind::Incoming) {
                incoming = Some(event.connection);
            }
        }
        let incoming = incoming.expect("server saw an incoming connection");
        self.server
            .accept(self.now, incoming, &mut buffer)
            .expect("server accepts the incoming connection");
        self.pump_latency(latency_micros, 64);
        incoming
    }

    pub fn next_timeout(&mut self) -> Option<Timestamp> {
        let mut earliest = self
            .clients
            .first_mut()
            .and_then(|c| c.endpoint.poll_timeout());
        for client in self.clients.iter_mut().skip(1) {
            if let Some(deadline) = client.endpoint.poll_timeout() {
                earliest = Some(earliest.map_or(deadline, |current| current.min(deadline)));
            }
        }
        if let Some(deadline) = self.server.poll_timeout() {
            earliest = Some(earliest.map_or(deadline, |current| current.min(deadline)));
        }
        earliest
    }

    pub fn read_from_server(&mut self, connection: ConnectionId, stream: StreamId) -> Vec<u8> {
        let mut collected = Vec::new();
        let mut buffer = vec![0u8; 4096];
        for _ in 0..512 {
            match self.server.read_stream(connection, stream, &mut buffer) {
                Ok(StreamRead::Data { len }) => collected.extend_from_slice(&buffer[..len]),
                Ok(StreamRead::Finished) => return collected,
                Err(StreamError::Blocked) => self.pump(),
                Err(error) => panic!("server read failed: {error}"),
            }
        }
        panic!("server stream did not finish");
    }

    pub fn read_from_client(
        &mut self,
        client: usize,
        connection: ConnectionId,
        stream: StreamId,
    ) -> Vec<u8> {
        let mut collected = Vec::new();
        let mut buffer = vec![0u8; 4096];
        for _ in 0..512 {
            match self.clients[client]
                .endpoint
                .read_stream(connection, stream, &mut buffer)
            {
                Ok(StreamRead::Data { len }) => collected.extend_from_slice(&buffer[..len]),
                Ok(StreamRead::Finished) => return collected,
                Err(StreamError::Blocked) => self.pump(),
                Err(error) => panic!("client read failed: {error}"),
            }
        }
        panic!("client stream did not finish");
    }
}

pub fn drain_events(endpoint: &mut Endpoint) -> Vec<Event> {
    let mut events = Vec::new();
    while let Some(event) = endpoint.poll_event() {
        events.push(event);
    }
    events
}

pub fn handshake_info(events: &[Event]) -> Option<&rtx_quic::HandshakeInfo> {
    events.iter().find_map(|event| match &event.kind {
        EventKind::HandshakeComplete(info) => Some(info),
        _ => None,
    })
}

pub fn handshake_failure(events: &[Event]) -> Option<rtx_quic::HandshakeFailure> {
    events.iter().find_map(|event| match &event.kind {
        EventKind::HandshakeFailed(failure) => Some(*failure),
        _ => None,
    })
}

pub fn close_reason(events: &[Event]) -> Option<&rtx_quic::CloseReason> {
    events.iter().find_map(|event| match &event.kind {
        EventKind::Closed(reason) => Some(reason),
        _ => None,
    })
}

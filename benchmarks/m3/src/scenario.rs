//! The `M3-P` scenario catalogue and runners (`M3-PS6`–`PS10`, `PB1`).
//!
//! Scenario identifiers are stable and map one-to-one to gate rows:
//!
//! | id prefix | gate row | parameters |
//! |---|---|---|
//! | `ps6-rtt-*` | `M3-PS6` | RTT 10/50/200 ms, QUIC and WebTransport |
//! | `ps7-handshake-*` | `M3-PS7` | concurrency 1/10/100, loss 0/1/5/10 % |
//! | `ps8-datagram-*` | `M3-PS8` | negotiated `max_datagram_frame_size`, 1000 pps, 60 s, loss × RTT |
//! | `ps9-stream-*` | `M3-PS9` | uni/bi, 1/16 MiB, concurrency 1/10/100 |
//! | `ps10-idle-*` | `M3-PS10` | idle 1/100/1000/10000 |
//! | `ps10-active-max` | `M3-PS10` | largest runnable active session count |
//! | `pb1-batch-*` | `M3-PB1` | batch 1/8/32/64 |
//!
//! `--smoke` reduces durations, packet counts and concurrency, and labels
//! every result `smoke: true`; the formal mode uses the gate parameters
//! verbatim. The harness never asserts a performance threshold: duration and
//! counters are measurements.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use rtx_core::Timestamp;
use rtx_quic::{ConnectionId, StreamError, StreamId};
use rtx_webtransport::datagram;
use rtx_webtransport::ids::SessionId;

use crate::meta::{self, Environment};
use crate::net::{self, Sim, StreamReadState};
use crate::result::Measurement;
use crate::wt::{self, WtClient, WtServer};

/// Static payload period (`M3-P` fixed payload: the `0..255` cycle).
const PATTERN_PERIOD: usize = 256;

/// Stream write chunk (a multiple of the pattern period).
const WRITE_CHUNK: usize = 64 * 1024;

/// Idle-session hard guard: stop connecting when process RSS is above this.
const SESSION_RSS_GUARD_BYTES: u64 = 768 * 1024 * 1024;

/// Engine bookkeeping reserve deducted from the negotiated
/// `max_datagram_frame_size` (`quinn-proto 0.11.19` rejects a received payload
/// whose length plus the internal `Datagram` header exceeds the advertised
/// receive window; the R6-3 evidence measured that reserve as 32 bytes).
const DATAGRAM_ENGINE_RESERVE: usize = 32;

/// Scenario direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Unidirectional streams.
    Uni,
    /// Bidirectional streams.
    Bi,
}

/// Scenario parameters.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    /// `PS6`: datagram echo latency under an injected RTT.
    Rtt {
        /// Injected round-trip time in milliseconds.
        rtt_millis: u64,
        /// Whether the DATAGRAM travel through a WebTransport session.
        webtransport: bool,
    },
    /// `PS7`: cold handshakes under loss.
    Handshake {
        /// Requested concurrent handshakes.
        concurrency: u32,
        /// Injected loss rate in percent.
        loss_percent: u8,
    },
    /// `PS8`: sustained WebTransport DATAGRAM at the negotiated size.
    Datagram {
        /// Injected round-trip time in milliseconds.
        rtt_millis: u64,
        /// Injected loss rate in percent.
        loss_percent: u8,
    },
    /// `PS9`: stream throughput.
    Stream {
        /// Stream direction.
        direction: Direction,
        /// Payload size per stream in MiB.
        size_mebibytes: u64,
        /// Requested concurrent streams.
        concurrency: u32,
    },
    /// `PS10`: idle sessions.
    Idle {
        /// Requested idle sessions.
        requested: u32,
    },
    /// `PS10`: largest runnable active session count.
    Active,
    /// `PB1`: datagram batching.
    Batch {
        /// Datagrams queued per pump round.
        batch: u32,
    },
}

/// One catalogue entry.
#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    /// Stable identifier written into the result file name.
    pub id: &'static str,
    /// Gate parameters.
    pub kind: Kind,
}

/// Runtime inputs shared by every scenario.
#[derive(Debug)]
pub struct RunConfig {
    /// Whether `--smoke` was requested.
    pub smoke: bool,
    /// Netem and endpoint RNG seed.
    pub seed: u64,
    /// DER certificate chain.
    pub certificate_der: Vec<u8>,
    /// DER PKCS#8 private key.
    pub private_key_der: Vec<u8>,
    /// Host/build metadata.
    pub environment: Environment,
}

/// Builds the catalogue: 51 scenarios covering every M3-owned gate row.
#[must_use]
pub fn list() -> Vec<Scenario> {
    let mut scenarios = Vec::new();
    for rtt_millis in [10_u64, 50, 200] {
        for webtransport in [false, true] {
            scenarios.push(Scenario {
                id: if webtransport {
                    match rtt_millis {
                        10 => "ps6-rtt-10-webtransport",
                        50 => "ps6-rtt-50-webtransport",
                        _ => "ps6-rtt-200-webtransport",
                    }
                } else {
                    match rtt_millis {
                        10 => "ps6-rtt-10-quic",
                        50 => "ps6-rtt-50-quic",
                        _ => "ps6-rtt-200-quic",
                    }
                },
                kind: Kind::Rtt {
                    rtt_millis,
                    webtransport,
                },
            });
        }
    }
    for concurrency in [1_u32, 10, 100] {
        for loss_percent in [0_u8, 1, 5, 10] {
            scenarios.push(Scenario {
                id: match (concurrency, loss_percent) {
                    (1, 0) => "ps7-handshake-c1-loss0",
                    (1, 1) => "ps7-handshake-c1-loss1",
                    (1, 5) => "ps7-handshake-c1-loss5",
                    (1, 10) => "ps7-handshake-c1-loss10",
                    (10, 0) => "ps7-handshake-c10-loss0",
                    (10, 1) => "ps7-handshake-c10-loss1",
                    (10, 5) => "ps7-handshake-c10-loss5",
                    (10, 10) => "ps7-handshake-c10-loss10",
                    (100, 0) => "ps7-handshake-c100-loss0",
                    (100, 1) => "ps7-handshake-c100-loss1",
                    (100, 5) => "ps7-handshake-c100-loss5",
                    _ => "ps7-handshake-c100-loss10",
                },
                kind: Kind::Handshake {
                    concurrency,
                    loss_percent,
                },
            });
        }
    }
    for rtt_millis in [10_u64, 50, 200] {
        for loss_percent in [0_u8, 1, 5, 10] {
            scenarios.push(Scenario {
                id: match (rtt_millis, loss_percent) {
                    (10, 0) => "ps8-datagram-rtt10-loss0",
                    (10, 1) => "ps8-datagram-rtt10-loss1",
                    (10, 5) => "ps8-datagram-rtt10-loss5",
                    (10, 10) => "ps8-datagram-rtt10-loss10",
                    (50, 0) => "ps8-datagram-rtt50-loss0",
                    (50, 1) => "ps8-datagram-rtt50-loss1",
                    (50, 5) => "ps8-datagram-rtt50-loss5",
                    (50, 10) => "ps8-datagram-rtt50-loss10",
                    (200, 0) => "ps8-datagram-rtt200-loss0",
                    (200, 1) => "ps8-datagram-rtt200-loss1",
                    (200, 5) => "ps8-datagram-rtt200-loss5",
                    _ => "ps8-datagram-rtt200-loss10",
                },
                kind: Kind::Datagram {
                    rtt_millis,
                    loss_percent,
                },
            });
        }
    }
    for direction in [Direction::Uni, Direction::Bi] {
        for size_mebibytes in [1_u64, 16] {
            for concurrency in [1_u32, 10, 100] {
                scenarios.push(Scenario {
                    id: match (direction, size_mebibytes, concurrency) {
                        (Direction::Uni, 1, 1) => "ps9-stream-uni-1mib-c1",
                        (Direction::Uni, 1, 10) => "ps9-stream-uni-1mib-c10",
                        (Direction::Uni, 1, 100) => "ps9-stream-uni-1mib-c100",
                        (Direction::Uni, 16, 1) => "ps9-stream-uni-16mib-c1",
                        (Direction::Uni, 16, 10) => "ps9-stream-uni-16mib-c10",
                        (Direction::Uni, 16, 100) => "ps9-stream-uni-16mib-c100",
                        (Direction::Bi, 1, 1) => "ps9-stream-bi-1mib-c1",
                        (Direction::Bi, 1, 10) => "ps9-stream-bi-1mib-c10",
                        (Direction::Bi, 1, 100) => "ps9-stream-bi-1mib-c100",
                        (Direction::Bi, 16, 1) => "ps9-stream-bi-16mib-c1",
                        (Direction::Bi, 16, 10) => "ps9-stream-bi-16mib-c10",
                        (Direction::Bi, 16, 100) => "ps9-stream-bi-16mib-c100",
                        _ => unreachable!("catalogue covers every combination"),
                    },
                    kind: Kind::Stream {
                        direction,
                        size_mebibytes,
                        concurrency,
                    },
                });
            }
        }
    }
    for requested in [1_u32, 100, 1000, 10000] {
        scenarios.push(Scenario {
            id: match requested {
                1 => "ps10-idle-1",
                100 => "ps10-idle-100",
                1000 => "ps10-idle-1000",
                _ => "ps10-idle-10000",
            },
            kind: Kind::Idle { requested },
        });
    }
    scenarios.push(Scenario {
        id: "ps10-active-max",
        kind: Kind::Active,
    });
    for batch in [1_u32, 8, 32, 64] {
        scenarios.push(Scenario {
            id: match batch {
                1 => "pb1-batch-1",
                8 => "pb1-batch-8",
                32 => "pb1-batch-32",
                _ => "pb1-batch-64",
            },
            kind: Kind::Batch { batch },
        });
    }
    scenarios
}

/// Looks a scenario up by id.
#[must_use]
pub fn find(id: &str) -> Option<Scenario> {
    list().into_iter().find(|scenario| scenario.id == id)
}

/// The latency measurement point text for a scenario.
#[must_use]
pub fn latency_point(kind: Kind) -> &'static str {
    match kind {
        Kind::Rtt { .. } | Kind::Datagram { .. } | Kind::Batch { .. } => {
            "client-observed DATAGRAM echo round trip / 2 (one-way estimate); echoes paired FIFO"
        }
        Kind::Handshake { .. } => {
            "client-observed handshake duration (connect call to HandshakeComplete)"
        }
        Kind::Stream { .. } | Kind::Idle { .. } | Kind::Active => "not measured for this scenario",
    }
}

/// Runs one measured scenario run and returns the measurement.
///
/// The allocator scene covers the whole scenario (endpoint construction,
/// handshake and data path), so `M3-P6` counts harness allocations too; the
/// result notes say so.
///
/// # Errors
///
/// Returns a message when the scenario cannot run to completion.
pub fn run(scenario: &Scenario, config: &RunConfig) -> Result<Measurement, String> {
    let tag = rtx_testkit::alloc::scene(scenario.id);
    rtx_testkit::alloc::reset(tag);
    let wall_start = Instant::now();
    let cpu_start = meta::cpu_time_micros(config.environment.clock_ticks_per_second);
    let rss_start = meta::rss_peak_bytes();
    let outcome = {
        let _scope = rtx_testkit::alloc::enter(tag);
        run_body(scenario, config)
    };
    let cpu_end = meta::cpu_time_micros(config.environment.clock_ticks_per_second);
    let rss_end = meta::rss_peak_bytes();
    let snapshot = rtx_testkit::alloc::snapshot(tag);

    let mut measurement = outcome?;
    measurement.wall_micros = meta::wall_micros(wall_start);
    measurement.cpu_micros = cpu_end.unwrap_or(0).saturating_sub(cpu_start.unwrap_or(0));
    measurement.rss_peak_bytes = rss_end.or(rss_start);
    measurement.heap_peak_bytes = snapshot.peak_live_bytes;
    measurement.alloc_count = snapshot.alloc_count;
    measurement.free_count = snapshot.free_count;
    measurement.allocated_bytes = snapshot.allocated_bytes;
    measurement.notes.push(
        "allocation counts cover the whole scenario, including harness bookkeeping".to_owned(),
    );
    Ok(measurement)
}

fn run_body(scenario: &Scenario, config: &RunConfig) -> Result<Measurement, String> {
    match scenario.kind {
        Kind::Rtt {
            rtt_millis,
            webtransport,
        } => run_rtt(config, rtt_millis, webtransport),
        Kind::Handshake {
            concurrency,
            loss_percent,
        } => run_handshake(config, concurrency, loss_percent),
        Kind::Datagram {
            rtt_millis,
            loss_percent,
        } => run_datagram(config, rtt_millis, loss_percent),
        Kind::Stream {
            direction,
            size_mebibytes,
            concurrency,
        } => run_stream(config, direction, size_mebibytes, concurrency),
        Kind::Idle { requested } => run_idle(config, requested),
        Kind::Active => run_active(config),
        Kind::Batch { batch } => run_batch(config, batch),
    }
}

fn smoke(config: &RunConfig) -> bool {
    config.smoke
}

fn new_sim(config: &RunConfig, loss_percent: u8, rtt_micros: u64) -> Result<Sim, String> {
    Sim::new(
        &config.certificate_der,
        &config.private_key_der,
        loss_percent,
        rtt_micros,
        config.seed,
    )
}

fn handshake_cap(config: &RunConfig) -> Duration {
    if smoke(config) {
        Duration::from_secs(5)
    } else {
        Duration::from_secs(15)
    }
}

fn connect_and_establish(
    sim: &mut Sim,
    config: &RunConfig,
) -> Result<(ConnectionId, ConnectionId), String> {
    let client = sim
        .connect_many(1)?
        .first()
        .copied()
        .ok_or("no connection")?;
    sim.pump_until(handshake_cap(config), |sim| {
        sim.client_handshakes >= 1 && sim.server_handshakes >= 1
    })
    .map_err(|error| {
        format!(
            "handshake failed: {error} (client {} server {} failures {}, transmits {}, wire_out {}, dropped {})",
            sim.client_handshakes,
            sim.server_handshakes,
            sim.handshake_failures,
            sim.transmits,
            sim.wire_bytes_out,
            sim.dropped()
        )
    })?;
    let server = sim
        .server_connections
        .first()
        .copied()
        .ok_or("server accepted no connection")?;
    Ok((client, server))
}

fn negotiated_datagram_size(sim: &Sim) -> Option<u64> {
    sim.client_info.as_ref().and_then(|info| {
        net::parse_max_datagram_frame_size(info.peer_transport_parameters.as_bytes())
    })
}

/// PS6: DATAGRAM echo under an injected RTT, raw QUIC or WebTransport.
fn run_rtt(config: &RunConfig, rtt_millis: u64, webtransport: bool) -> Result<Measurement, String> {
    let rtt_micros = rtt_millis * 1_000;
    let duration = if smoke(config) {
        Duration::from_millis(300)
    } else {
        Duration::from_secs(1)
    };
    let pps: u32 = if smoke(config) { 100 } else { 1_000 };
    let mut sim = new_sim(config, 0, rtt_micros)?;
    let (client, server) = connect_and_establish(&mut sim, config)?;
    let negotiated = negotiated_datagram_size(&sim);
    let capacity = usize::try_from(negotiated.unwrap_or(0))
        .unwrap_or(0)
        .saturating_sub(DATAGRAM_ENGINE_RESERVE);
    let payload_len = if webtransport {
        capacity.saturating_sub(1).max(1)
    } else {
        capacity.clamp(64, 1000)
    };
    let max_len = capacity.max(payload_len + 1);
    if webtransport && negotiated.is_none() {
        return Err("server did not advertise max_datagram_frame_size".to_owned());
    }
    let payload = pattern(payload_len);

    let mut session = None;
    let mut wt_client = WtClient::default();
    let mut wt_server = WtServer::default();
    if webtransport {
        wt::establish(
            &mut sim,
            &mut wt_client,
            &mut wt_server,
            client,
            server,
            AUTHORITY,
            max_len.max(payload_len + 8),
        )?;
        session = wt_client.session();
    }

    let drain =
        Duration::from_micros(rtt_micros.saturating_mul(2)).saturating_add(if smoke(config) {
            Duration::from_millis(100)
        } else {
            Duration::from_millis(500)
        });
    let pair_latency = true;
    let mut stats = EchoStats::default();
    let mut encoded = vec![0u8; max_len.max(payload_len + 8)];
    let mut receive = vec![0u8; max_len.max(payload_len + 8)];
    let mut pending: VecDeque<Timestamp> = VecDeque::new();
    let start = Instant::now();
    let interval = 1_000_000 / u64::from(pps.max(1));
    let send_until = start + duration;
    let mut next_send = sim.now();
    while Instant::now() < send_until {
        sim.tick()?;
        if sim.now() >= next_send {
            let accepted = send_one(
                &mut sim,
                client,
                session,
                &payload,
                max_len,
                &mut encoded,
                &mut stats,
            )?;
            if accepted {
                pending.push_back(sim.now());
                next_send = Timestamp::from_micros(next_send.as_micros().saturating_add(interval));
            }
        }
        service_webtransport(
            &mut sim,
            &mut wt_client,
            &mut wt_server,
            client,
            server,
            max_len,
        )?;
        if !webtransport {
            sim.echo_server_datagrams(server)?;
        }
        receive_echoes(
            &mut sim,
            client,
            session,
            max_len,
            payload_len,
            &mut receive,
            &mut pending,
            pair_latency,
            &mut stats,
        )?;
        sim.wait(Duration::from_micros(200))?;
    }
    let stop = Instant::now() + drain;
    while Instant::now() < stop && !pending.is_empty() {
        sim.tick()?;
        service_webtransport(
            &mut sim,
            &mut wt_client,
            &mut wt_server,
            client,
            server,
            max_len,
        )?;
        if !webtransport {
            sim.echo_server_datagrams(server)?;
        }
        receive_echoes(
            &mut sim,
            client,
            session,
            max_len,
            payload_len,
            &mut receive,
            &mut pending,
            pair_latency,
            &mut stats,
        )?;
        sim.wait(Duration::from_micros(200))?;
    }

    let measurement = finish_echo(&sim, stats, pending.len() as u64, negotiated, payload_len);
    Ok(measurement)
}

/// PS8: sustained WebTransport DATAGRAM at the negotiated payload size.
fn run_datagram(
    config: &RunConfig,
    rtt_millis: u64,
    loss_percent: u8,
) -> Result<Measurement, String> {
    let rtt_micros = rtt_millis * 1_000;
    let duration = if smoke(config) {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(60)
    };
    let pps: u32 = if smoke(config) { 100 } else { 1_000 };
    let mut sim = new_sim(config, loss_percent, rtt_micros)?;
    let (client, server) = connect_and_establish(&mut sim, config)?;
    let negotiated = negotiated_datagram_size(&sim)
        .ok_or_else(|| "server did not advertise max_datagram_frame_size".to_owned())?;
    let max_len = usize::try_from(negotiated)
        .unwrap_or(0)
        .saturating_sub(DATAGRAM_ENGINE_RESERVE);
    // HTTP Datagram payload = quarter stream ID varint + WebTransport payload.
    // The quarter ID for the first client CONNECT stream fits one byte.
    let payload_len = max_len.saturating_sub(1).max(1);
    let payload = pattern(payload_len);

    let mut wt_client = WtClient::default();
    let mut wt_server = WtServer::default();
    wt::establish(
        &mut sim,
        &mut wt_client,
        &mut wt_server,
        client,
        server,
        AUTHORITY,
        max_len,
    )?;
    let session = wt_client.session();

    let pair_latency = loss_percent == 0;
    let mut stats = EchoStats::default();
    let mut encoded = vec![0u8; max_len];
    let mut receive = vec![0u8; max_len];
    let mut pending: VecDeque<Timestamp> = VecDeque::new();
    let start = Instant::now();
    let interval = 1_000_000 / u64::from(pps.max(1));
    let send_until = start + duration;
    let mut next_send = sim.now();
    while Instant::now() < send_until {
        sim.tick()?;
        if sim.now() >= next_send {
            let accepted = send_one(
                &mut sim,
                client,
                session,
                &payload,
                max_len,
                &mut encoded,
                &mut stats,
            )?;
            if accepted {
                pending.push_back(sim.now());
                next_send = Timestamp::from_micros(next_send.as_micros().saturating_add(interval));
            }
        }
        service_webtransport(
            &mut sim,
            &mut wt_client,
            &mut wt_server,
            client,
            server,
            max_len,
        )?;
        receive_echoes(
            &mut sim,
            client,
            session,
            max_len,
            payload_len,
            &mut receive,
            &mut pending,
            pair_latency,
            &mut stats,
        )?;
        sim.wait(Duration::from_micros(200))?;
    }
    let drain =
        Duration::from_micros(rtt_micros.saturating_mul(2)).saturating_add(if smoke(config) {
            Duration::from_millis(100)
        } else {
            Duration::from_millis(500)
        });
    let stop = Instant::now() + drain;
    while Instant::now() < stop && !pending.is_empty() {
        sim.tick()?;
        service_webtransport(
            &mut sim,
            &mut wt_client,
            &mut wt_server,
            client,
            server,
            max_len,
        )?;
        receive_echoes(
            &mut sim,
            client,
            session,
            max_len,
            payload_len,
            &mut receive,
            &mut pending,
            pair_latency,
            &mut stats,
        )?;
        sim.wait(Duration::from_micros(200))?;
    }

    let mut measurement = finish_echo(
        &sim,
        stats,
        pending.len() as u64,
        Some(negotiated),
        payload_len,
    );
    measurement.notes.push(format!(
        "payload {payload_len} B derived from the negotiated max_datagram_frame_size ({negotiated} B): minus {DATAGRAM_ENGINE_RESERVE} B engine accounting and the quarter-stream-ID varint"
    ));
    if loss_percent > 0 {
        measurement.notes.push(
            "latency samples suppressed under induced loss: QUIC DATAGRAM echo pairing is FIFO and cannot attribute a round trip to a specific send"
                .to_owned(),
        );
    }
    Ok(measurement)
}

/// PS7: cold handshakes under loss.
fn run_handshake(
    config: &RunConfig,
    concurrency: u32,
    loss_percent: u8,
) -> Result<Measurement, String> {
    let effective = if smoke(config) {
        concurrency.min(4)
    } else {
        concurrency
    };
    let mut sim = new_sim(config, loss_percent, 0)?;
    sim.connect_many(effective)?;
    let start = Instant::now();
    let cap = if smoke(config) {
        Duration::from_secs(3)
    } else {
        Duration::from_secs(10)
    };
    loop {
        sim.tick()?;
        if sim.client_handshakes >= u64::from(effective)
            && sim.server_handshakes >= u64::from(effective)
        {
            break;
        }
        if start.elapsed() >= cap {
            break;
        }
        sim.wait(Duration::from_millis(1))?;
    }
    let completed = sim.client_handshakes;
    if completed == 0 {
        return Err(format!(
            "no handshake completed within {} ms at {loss_percent}% loss (transmits {}, wire_out {}, wire_in {}, accepted {}, dropped {})",
            cap.as_millis(),
            sim.transmits,
            sim.wire_bytes_out,
            sim.wire_bytes_in,
            sim.server_connections.len(),
            sim.dropped()
        ));
    }
    let mut measurement = Measurement {
        packets_sent: 0,
        packets_received: 0,
        payload_bytes: 0,
        wire_bytes_out: sim.wire_bytes_out,
        wire_bytes_in: sim.wire_bytes_in,
        packets_dropped: sim.dropped(),
        connections: u64::from(effective),
        handshakes: completed,
        streams: 0,
        wall_micros: 0,
        cpu_micros: 0,
        rss_peak_bytes: None,
        heap_peak_bytes: 0,
        alloc_count: 0,
        free_count: 0,
        allocated_bytes: 0,
        latency_samples: sim.handshake_samples(),
        queue_max_depth: sim.queue_max_depth(),
        backpressure_events: sim.datagram_send_blocked,
        max_datagram_frame_size: None,
        datagram_payload_bytes: None,
        requested_sessions: None,
        effective_sessions: None,
        notes: Vec::new(),
    };
    if completed < u64::from(effective) {
        measurement.notes.push(format!(
            "only {completed} of {effective} handshakes completed within the cap"
        ));
    }
    if effective < concurrency {
        measurement.notes.push(format!(
            "smoke mode caps concurrency {concurrency} -> {effective}"
        ));
    }
    Ok(measurement)
}

/// PS9: uni/bi stream throughput.
fn run_stream(
    config: &RunConfig,
    direction: Direction,
    size_mebibytes: u64,
    concurrency: u32,
) -> Result<Measurement, String> {
    let effective = if smoke(config) {
        concurrency.min(2)
    } else {
        concurrency
    };
    let size_bytes = size_mebibytes.saturating_mul(1024 * 1024);
    let mut sim = new_sim(config, 0, 0)?;
    let (client, server) = connect_and_establish(&mut sim, config)?;
    let chunk = pattern(WRITE_CHUNK);

    let mut streams: Vec<(StreamId, u64, bool)> = Vec::new();
    for _ in 0..effective {
        let stream = match direction {
            Direction::Uni => sim.client.open_uni(client),
            Direction::Bi => sim.client.open_bi(client),
        }
        .map_err(|error| format!("open stream: {error}"))?;
        streams.push((stream, size_bytes, false));
    }
    let mut states: BTreeMap<StreamId, StreamReadState> = BTreeMap::new();
    let cap = if smoke(config) {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(300)
    };
    let start = Instant::now();
    let mut total_read = 0u64;
    let mut finished = 0u64;
    loop {
        for (stream, remaining, finished_written) in &mut streams {
            while *remaining > 0 {
                let length =
                    usize::try_from((*remaining).min(WRITE_CHUNK as u64)).unwrap_or(WRITE_CHUNK);
                match sim.client.write_stream(client, *stream, &chunk[..length]) {
                    Ok(0) => break,
                    Ok(written) => {
                        *remaining = remaining.saturating_sub(written as u64);
                    }
                    Err(StreamError::Blocked) => break,
                    Err(error) => return Err(format!("write_stream: {error}")),
                }
            }
            if *remaining == 0 && !*finished_written {
                sim.client
                    .finish_stream(client, *stream)
                    .map_err(|error| format!("finish_stream: {error}"))?;
                *finished_written = true;
            }
        }
        sim.tick()?;
        let (bytes, newly_finished) = sim.read_server_streams(server, &mut states)?;
        total_read = total_read.saturating_add(bytes);
        finished = finished.saturating_add(newly_finished);
        if finished >= u64::from(effective)
            && total_read >= size_bytes.saturating_mul(u64::from(effective))
        {
            break;
        }
        if start.elapsed() >= cap {
            return Err(format!(
                "stream scenario did not complete within {} ms ({total_read} of {} bytes read)",
                cap.as_millis(),
                size_bytes.saturating_mul(u64::from(effective))
            ));
        }
        sim.wait(Duration::from_micros(200))?;
    }
    let mut measurement = Measurement {
        packets_sent: 0,
        packets_received: 0,
        payload_bytes: total_read,
        wire_bytes_out: sim.wire_bytes_out,
        wire_bytes_in: sim.wire_bytes_in,
        packets_dropped: sim.dropped(),
        connections: 1,
        handshakes: 1,
        streams: finished,
        wall_micros: 0,
        cpu_micros: 0,
        rss_peak_bytes: None,
        heap_peak_bytes: 0,
        alloc_count: 0,
        free_count: 0,
        allocated_bytes: 0,
        latency_samples: Vec::new(),
        queue_max_depth: sim.queue_max_depth(),
        backpressure_events: sim.datagram_send_blocked,
        max_datagram_frame_size: None,
        datagram_payload_bytes: None,
        requested_sessions: None,
        effective_sessions: None,
        notes: Vec::new(),
    };
    if effective < concurrency {
        measurement.notes.push(format!(
            "smoke mode caps concurrency {concurrency} -> {effective}"
        ));
    }
    measurement.notes.push(format!(
        "{} streams, {size_mebibytes} MiB each, direction {direction:?}",
        effective
    ));
    Ok(measurement)
}

/// PS10: idle sessions at the requested tier.
fn run_idle(config: &RunConfig, requested: u32) -> Result<Measurement, String> {
    let effective = if smoke(config) {
        requested.min(20)
    } else {
        requested
    };
    let mut sim = new_sim(config, 0, 0)?;
    let mut connected = 0u32;
    let mut notes = Vec::new();
    let chunks = effective.div_ceil(100);
    for _ in 0..chunks {
        if meta::rss_peak_bytes().unwrap_or(0) > SESSION_RSS_GUARD_BYTES {
            notes.push(format!(
                "stopped connecting at {connected} connections: RSS guard {SESSION_RSS_GUARD_BYTES} B"
            ));
            break;
        }
        let chunk = (effective - connected).min(100);
        if chunk == 0 {
            break;
        }
        sim.connect_many(chunk)?;
        connected += chunk;
    }
    if connected == 0 {
        return Err("no idle connection was started".to_owned());
    }
    if sim
        .pump_until(handshake_cap(config), |sim| {
            sim.client_handshakes >= u64::from(connected)
        })
        .is_err()
    {
        notes.push(format!(
            "only {} of {connected} handshakes completed before the cap",
            sim.client_handshakes
        ));
    }
    let window = if smoke(config) {
        Duration::from_millis(100)
    } else {
        Duration::from_secs(1)
    };
    sim.run_for(window)?;
    let completed = sim.client_handshakes;
    if completed == 0 {
        return Err("no idle connection completed its handshake".to_owned());
    }
    if effective < requested {
        notes.push(format!(
            "smoke mode caps idle sessions {requested} -> {effective}"
        ));
    }
    let mut measurement = Measurement {
        packets_sent: 0,
        packets_received: 0,
        payload_bytes: 0,
        wire_bytes_out: sim.wire_bytes_out,
        wire_bytes_in: sim.wire_bytes_in,
        packets_dropped: sim.dropped(),
        connections: completed,
        handshakes: completed,
        streams: 0,
        wall_micros: 0,
        cpu_micros: 0,
        rss_peak_bytes: None,
        heap_peak_bytes: 0,
        alloc_count: 0,
        free_count: 0,
        allocated_bytes: 0,
        latency_samples: Vec::new(),
        queue_max_depth: sim.queue_max_depth(),
        backpressure_events: sim.datagram_send_blocked,
        max_datagram_frame_size: None,
        datagram_payload_bytes: None,
        requested_sessions: Some(u64::from(requested)),
        effective_sessions: Some(u64::from(connected)),
        notes,
    };
    measurement.notes.push(
        "idle window is 1 s (formal) / 100 ms (smoke); the harness records what the host actually ran"
            .to_owned(),
    );
    Ok(measurement)
}

/// PS10: largest runnable active session count, tried over a ladder.
fn run_active(config: &RunConfig) -> Result<Measurement, String> {
    let ladder: &[u32] = if smoke(config) {
        &[10, 20]
    } else {
        &[100, 500, 1000, 2500, 5000]
    };
    let mut best: Option<Measurement> = None;
    for &level in ladder {
        match run_active_level(config, level) {
            Ok(measurement) => best = Some(measurement),
            Err(_) => break,
        }
    }
    best.ok_or_else(|| "no active-session level ran".to_owned())
}

fn run_active_level(config: &RunConfig, level: u32) -> Result<Measurement, String> {
    let mut sim = new_sim(config, 0, 0)?;
    let ids = sim.connect_many(level)?;
    sim.pump_until(handshake_cap(config), |sim| {
        sim.client_handshakes >= u64::from(level)
    })?;
    let payload = pattern(64);
    let mut echoes = 0u64;
    for id in &ids {
        sim.try_send_datagram(*id, &payload)?;
    }
    let mut buffer = vec![0u8; 128];
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        sim.tick()?;
        for connection in sim.server_connections.clone() {
            sim.echo_server_datagrams(connection)?;
        }
        for id in &ids {
            loop {
                match sim.client.poll_datagram(*id, &mut buffer) {
                    Ok(Some(_)) => echoes = echoes.saturating_add(1),
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
        if echoes >= u64::from(level) {
            break;
        }
        sim.wait(Duration::from_millis(1))?;
    }
    if echoes < u64::from(level) / 2 {
        return Err(format!(
            "active level {level} produced {echoes} echoes, below half the sessions"
        ));
    }
    let mut measurement = Measurement {
        packets_sent: u64::from(level),
        packets_received: echoes,
        payload_bytes: echoes.saturating_mul(64),
        wire_bytes_out: sim.wire_bytes_out,
        wire_bytes_in: sim.wire_bytes_in,
        packets_dropped: sim.dropped(),
        connections: sim.client_handshakes,
        handshakes: sim.client_handshakes,
        streams: 0,
        wall_micros: 0,
        cpu_micros: 0,
        rss_peak_bytes: None,
        heap_peak_bytes: 0,
        alloc_count: 0,
        free_count: 0,
        allocated_bytes: 0,
        latency_samples: Vec::new(),
        queue_max_depth: sim.queue_max_depth(),
        backpressure_events: sim.datagram_send_blocked,
        max_datagram_frame_size: None,
        datagram_payload_bytes: Some(64),
        requested_sessions: Some(u64::from(level)),
        effective_sessions: Some(sim.client_handshakes),
        notes: vec![
            "active throughput is one 64 B DATAGRAM per session; the ladder stops at the first level that cannot echo half its sessions"
                .to_owned(),
        ],
    };
    if sim.client_handshakes < u64::from(level) {
        measurement.notes.push(format!(
            "{} of {level} handshakes completed",
            sim.client_handshakes
        ));
    }
    Ok(measurement)
}

/// PB1: datagram batching.
fn run_batch(config: &RunConfig, batch: u32) -> Result<Measurement, String> {
    let total = if smoke(config) { 500_u64 } else { 10_000 };
    let payload_len = 1_000usize;
    let payload = pattern(payload_len);
    let mut sim = new_sim(config, 0, 0)?;
    let (client, server) = connect_and_establish(&mut sim, config)?;
    let pair_latency = true;
    let mut stats = EchoStats::default();
    let mut receive = vec![0u8; 2048];
    let mut pending: VecDeque<Timestamp> = VecDeque::new();
    let start = Instant::now();
    let mut sent = 0u64;
    while sent < total {
        sim.tick()?;
        for _ in 0..batch {
            if sent >= total {
                break;
            }
            match sim.try_send_datagram(client, &payload) {
                Ok(true) => {
                    sent += 1;
                    pending.push_back(sim.now());
                    stats.packets_sent += 1;
                }
                Ok(false) => break,
                Err(error) => return Err(error),
            }
        }
        sim.echo_server_datagrams(server)?;
        receive_echoes(
            &mut sim,
            client,
            None,
            0,
            payload_len,
            &mut receive,
            &mut pending,
            pair_latency,
            &mut stats,
        )?;
        if start.elapsed() > Duration::from_secs(if smoke(config) { 5 } else { 120 }) {
            return Err("batch scenario exceeded its cap".to_owned());
        }
        sim.wait(Duration::from_micros(200))?;
    }
    let drain = Instant::now() + Duration::from_millis(500);
    while Instant::now() < drain && !pending.is_empty() {
        sim.tick()?;
        sim.echo_server_datagrams(server)?;
        receive_echoes(
            &mut sim,
            client,
            None,
            0,
            payload_len,
            &mut receive,
            &mut pending,
            pair_latency,
            &mut stats,
        )?;
        sim.wait(Duration::from_micros(200))?;
    }
    let mut measurement = finish_echo(&sim, stats, pending.len() as u64, None, payload_len);
    measurement.notes.push(format!(
        "batch={batch}: {batch} datagrams queued per pump round; rtx-quic has no batch syscall, so this is a harness-side grouping"
    ));
    Ok(measurement)
}

/// Fixed CONNECT authority used by the WebTransport rows.
const AUTHORITY: &str = "127.0.0.1:4433";

/// Accumulates echo statistics across the send/receive loops.
#[derive(Debug, Default)]
struct EchoStats {
    packets_sent: u64,
    packets_received: u64,
    payload_bytes: u64,
    latency_micros: Vec<u64>,
    oversized: u64,
}

fn service_webtransport(
    sim: &mut Sim,
    client: &mut WtClient,
    server: &mut WtServer,
    client_connection: ConnectionId,
    server_connection: ConnectionId,
    max_len: usize,
) -> Result<(), String> {
    if client.session().is_none() {
        return Ok(());
    }
    client.service(sim, client_connection, AUTHORITY)?;
    server.service(sim, server_connection, max_len)?;
    Ok(())
}

fn send_one(
    sim: &mut Sim,
    connection: ConnectionId,
    session: Option<SessionId>,
    payload: &[u8],
    max_len: usize,
    encoded: &mut [u8],
    stats: &mut EchoStats,
) -> Result<bool, String> {
    let bytes: &[u8] = match session {
        Some(session) => {
            let written = datagram::encode(session, payload, max_len, encoded)
                .map_err(|error| format!("datagram encode: {error:?}"))?;
            &encoded[..written]
        }
        None => payload,
    };
    match sim.try_send_datagram(connection, bytes) {
        Ok(true) => {
            stats.packets_sent = stats.packets_sent.saturating_add(1);
            Ok(true)
        }
        Ok(false) => Ok(false),
        Err(error) => Err(error),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the echo loop needs the connection, session, buffers, timing queue and counters in one place"
)]
fn receive_echoes(
    sim: &mut Sim,
    connection: ConnectionId,
    session: Option<SessionId>,
    max_len: usize,
    payload_len: usize,
    buffer: &mut [u8],
    pending: &mut VecDeque<Timestamp>,
    pair_latency: bool,
    stats: &mut EchoStats,
) -> Result<(), String> {
    loop {
        match sim.client.poll_datagram(connection, buffer) {
            Ok(Some(len)) => {
                if let Some(session) = session {
                    let (decoded, _) = datagram::decode(&buffer[..len], session, max_len)
                        .map_err(|error| format!("datagram decode: {error:?}"))?;
                    if decoded.payload().len() != payload_len {
                        return Err(format!(
                            "echo payload is {} B, expected {payload_len} B",
                            decoded.payload().len()
                        ));
                    }
                }
                if let Some(sent) = pending.pop_front()
                    && pair_latency
                {
                    let now = sim.now();
                    let round_trip = now.as_micros().saturating_sub(sent.as_micros());
                    stats.latency_micros.push(round_trip / 2);
                }
                stats.packets_received = stats.packets_received.saturating_add(1);
                stats.payload_bytes = stats
                    .payload_bytes
                    .saturating_add(u64::try_from(payload_len).unwrap_or(0));
            }
            Ok(None) => return Ok(()),
            Err(rtx_quic::DatagramError::BufferTooSmall { datagram_len }) => {
                stats.oversized = stats.oversized.saturating_add(1);
                let _ = datagram_len;
            }
            Err(rtx_quic::DatagramError::Closed)
            | Err(rtx_quic::DatagramError::UnknownConnection) => {
                return Ok(());
            }
            Err(error) => return Err(format!("client poll_datagram: {error}")),
        }
    }
}

fn finish_echo(
    sim: &Sim,
    stats: EchoStats,
    outstanding: u64,
    negotiated: Option<u64>,
    payload_len: usize,
) -> Measurement {
    let mut notes = Vec::new();
    if stats.oversized > 0 {
        notes.push(format!(
            "{} echoes were larger than the receive buffer",
            stats.oversized
        ));
    }
    if outstanding > 0 {
        notes.push(format!(
            "{outstanding} datagrams were still outstanding at the end"
        ));
    }
    Measurement {
        packets_sent: stats.packets_sent,
        packets_received: stats.packets_received,
        payload_bytes: stats.payload_bytes,
        wire_bytes_out: sim.wire_bytes_out,
        wire_bytes_in: sim.wire_bytes_in,
        packets_dropped: sim.dropped(),
        connections: 1,
        handshakes: 1,
        streams: 0,
        wall_micros: 0,
        cpu_micros: 0,
        rss_peak_bytes: None,
        heap_peak_bytes: 0,
        alloc_count: 0,
        free_count: 0,
        allocated_bytes: 0,
        latency_samples: stats.latency_micros,
        queue_max_depth: sim.queue_max_depth(),
        backpressure_events: sim.datagram_send_blocked,
        max_datagram_frame_size: negotiated,
        datagram_payload_bytes: Some(u64::try_from(payload_len).unwrap_or(0)),
        requested_sessions: None,
        effective_sessions: None,
        notes,
    }
}

/// Deterministic payload: the `0..=255` cycle, first `len` bytes.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % PATTERN_PERIOD).unwrap_or(0))
        .collect()
}

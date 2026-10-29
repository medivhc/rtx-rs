//! Result documents: per-run measurements, aggregation and schema validation
//! (`M3-PM3`, `M3-PM4`, `M3-PM6`).
//!
//! One JSON file is written per scenario. It carries the ten `M3-PM3`
//! metadata fields, the raw per-run measurements, the median/min/max
//! aggregate and the `M3-P1`–`P8` dimension block. A dimension the run did
//! not measure is `null` with a `reason` string; it is never filled with `0`
//! or an estimate.

use crate::json::{self, Json};
use crate::meta::Environment;

/// The schema identifier written into every result.
pub const SCHEMA: &str = "rtx-m3-result-v1";

/// Metadata keys `M3-PM3` requires; a result missing any of them is invalid.
pub const REQUIRED_METADATA: [&str; 10] = [
    "commit",
    "rustc",
    "target",
    "features",
    "cpu_model",
    "kernel",
    "batch",
    "loss_percent",
    "rtt_micros",
    "seed",
];

/// The `M3-P1`–`P8` dimension blocks.
pub const REQUIRED_DIMENSIONS: [&str; 8] = [
    "throughput",
    "packet_rate",
    "latency",
    "cpu",
    "memory",
    "allocations",
    "alloc_per",
    "queue",
];

/// Per-scenario parameters that end up in the metadata block.
#[derive(Debug, Clone, Copy, Default)]
pub struct Params {
    /// Datagram batch size (`M3-PB1`); `1` for every other scenario.
    pub batch: u32,
    /// Simulated loss rate in percent.
    pub loss_percent: u8,
    /// Simulated RTT in microseconds (`0` when the scenario does not inject
    /// delay).
    pub rtt_micros: u64,
    /// Netem seed.
    pub seed: u64,
    /// Sessions requested by the scenario (idle/active only).
    pub requested_sessions: Option<u64>,
    /// Sessions the harness actually ran (idle/active only).
    pub effective_sessions: Option<u64>,
}

/// One scenario run's raw measurement.
#[derive(Debug, Clone, Default)]
pub struct Measurement {
    /// DATAGRAMs the client sent successfully.
    pub packets_sent: u64,
    /// DATAGRAM echoes the client received.
    pub packets_received: u64,
    /// Application payload bytes carried by the received echoes.
    pub payload_bytes: u64,
    /// UDP payload bytes emitted by both endpoints.
    pub wire_bytes_out: u64,
    /// UDP payload bytes received by both endpoints.
    pub wire_bytes_in: u64,
    /// Datagrams dropped by the deterministic simulator.
    pub packets_dropped: u64,
    /// Completed connections.
    pub connections: u64,
    /// Completed handshakes (client side).
    pub handshakes: u64,
    /// Streams completed by the server.
    pub streams: u64,
    /// Wall-clock duration of the measured region.
    pub wall_micros: u64,
    /// Process CPU time (`utime + stime`) during the measured region.
    pub cpu_micros: u64,
    /// Process RSS peak (`VmHWM`) at the end of the run, if available.
    pub rss_peak_bytes: Option<u64>,
    /// Allocator peak live bytes for the scenario slot.
    pub heap_peak_bytes: u64,
    /// Allocations recorded in the scenario slot.
    pub alloc_count: u64,
    /// Deallocations recorded in the scenario slot.
    pub free_count: u64,
    /// Requested allocation bytes in the scenario slot.
    pub allocated_bytes: u64,
    /// One-way latency estimates in microseconds.
    pub latency_samples: Vec<u64>,
    /// Peak netem queue depth.
    pub queue_max_depth: u64,
    /// Facade calls that reported `WouldBlock`.
    pub backpressure_events: u64,
    /// Negotiated `max_datagram_frame_size`, when a handshake was performed.
    pub max_datagram_frame_size: Option<u64>,
    /// Payload size used for DATAGRAM scenarios.
    pub datagram_payload_bytes: Option<u64>,
    /// Sessions requested by the scenario (idle/active only).
    pub requested_sessions: Option<u64>,
    /// Sessions the harness actually ran (idle/active only).
    pub effective_sessions: Option<u64>,
    /// Notes attached to this run (caps, approximations).
    pub notes: Vec<String>,
}

impl Measurement {
    /// Turns the raw measurement into the numeric metric map that is
    /// serialized per run and aggregated.
    #[must_use]
    pub fn metrics(&self) -> Vec<(&'static str, Option<f64>)> {
        let wall = if self.wall_micros == 0 {
            None
        } else {
            Some(self.wall_micros as f64)
        };
        let per_second = |value: u64| wall.map(|micros| value as f64 * 1_000_000.0 / micros);
        let wire_bytes = self.wire_bytes_out.saturating_add(self.wire_bytes_in);
        let mut samples = self.latency_samples.clone();
        samples.sort_unstable();
        vec![
            ("wire_bytes_per_second", per_second(wire_bytes)),
            ("payload_bytes_per_second", per_second(self.payload_bytes)),
            ("pps", per_second(self.packets_sent)),
            ("p50_us", percentile(&samples, 50.0)),
            ("p95_us", percentile(&samples, 95.0)),
            ("p99_us", percentile(&samples, 99.0)),
            ("latency_samples", Some(self.latency_samples.len() as f64)),
            ("wall_us", wall),
            ("cpu_us", Some(self.cpu_micros as f64)),
            (
                "cpu_percent",
                cpu_percent(self.cpu_micros, self.wall_micros),
            ),
            (
                "rss_peak_bytes",
                self.rss_peak_bytes.map(|value| value as f64),
            ),
            ("heap_peak_bytes", Some(self.heap_peak_bytes as f64)),
            ("alloc_count", Some(self.alloc_count as f64)),
            ("free_count", Some(self.free_count as f64)),
            ("allocated_bytes", Some(self.allocated_bytes as f64)),
            ("peak_live_bytes", Some(self.heap_peak_bytes as f64)),
            (
                "alloc_per_packet",
                ratio(
                    self.alloc_count,
                    self.packets_received.max(self.packets_sent),
                ),
            ),
            (
                "alloc_per_connection",
                ratio(self.alloc_count, self.connections),
            ),
            (
                "alloc_per_handshake",
                ratio(self.alloc_count, self.handshakes),
            ),
            ("packets_sent", Some(self.packets_sent as f64)),
            ("packets_received", Some(self.packets_received as f64)),
            ("packets_dropped", Some(self.packets_dropped as f64)),
            ("connections", Some(self.connections as f64)),
            ("handshakes", Some(self.handshakes as f64)),
            ("streams", Some(self.streams as f64)),
            ("queue_max_depth", Some(self.queue_max_depth as f64)),
            ("queue_drop_events", Some(self.packets_dropped as f64)),
            ("backpressure_events", Some(self.backpressure_events as f64)),
            (
                "max_datagram_frame_size",
                self.max_datagram_frame_size.map(|value| value as f64),
            ),
            (
                "datagram_payload_bytes",
                self.datagram_payload_bytes.map(|value| value as f64),
            ),
        ]
    }
}

fn ratio(count: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(count as f64 / denominator as f64)
    }
}

fn cpu_percent(cpu_micros: u64, wall_micros: u64) -> Option<f64> {
    if wall_micros == 0 {
        None
    } else {
        Some(cpu_micros as f64 * 100.0 / wall_micros as f64)
    }
}

/// Nearest-rank percentile over sorted samples.
fn percentile(sorted: &[u64], percent: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (percent / 100.0 * sorted.len() as f64).ceil();
    let index = (rank as usize).clamp(1, sorted.len()) - 1;
    sorted.get(index).map(|value| *value as f64)
}

/// Median of the finite values of one metric across runs.
fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted: Vec<f64> = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        let lower = sorted.get(middle - 1).copied().unwrap_or(0.0);
        let upper = sorted.get(middle).copied().unwrap_or(0.0);
        Some((lower + upper) / 2.0)
    } else {
        sorted.get(middle).copied()
    }
}

/// Aggregates metric maps across runs.
#[derive(Debug, Clone)]
pub struct Aggregate {
    /// Per-key median.
    pub median: Vec<(String, Option<f64>)>,
    /// Per-key minimum.
    pub min: Vec<(String, Option<f64>)>,
    /// Per-key maximum.
    pub max: Vec<(String, Option<f64>)>,
}

/// Aggregates the per-run metric maps.
#[must_use]
pub fn aggregate(runs: &[Measurement]) -> Aggregate {
    let maps: Vec<Vec<(&'static str, Option<f64>)>> =
        runs.iter().map(Measurement::metrics).collect();
    let keys: Vec<&'static str> = maps
        .first()
        .map(|map| map.iter().map(|(key, _)| *key).collect())
        .unwrap_or_default();
    let mut median_out = Vec::with_capacity(keys.len());
    let mut min_out = Vec::with_capacity(keys.len());
    let mut max_out = Vec::with_capacity(keys.len());
    for key in keys {
        let values: Vec<f64> = maps
            .iter()
            .filter_map(|map| {
                map.iter()
                    .find(|(name, _)| *name == key)
                    .and_then(|(_, value)| *value)
            })
            .collect();
        let median_value = median(&values);
        let min_value = values.iter().copied().reduce(f64::min);
        let max_value = values.iter().copied().reduce(f64::max);
        median_out.push((key.to_owned(), median_value));
        min_out.push((key.to_owned(), min_value));
        max_out.push((key.to_owned(), max_value));
    }
    Aggregate {
        median: median_out,
        min: min_out,
        max: max_out,
    }
}

/// The document builder's inputs.
#[derive(Debug, Clone)]
pub struct DocumentInput<'a> {
    /// Scenario identifier.
    pub scenario: &'a str,
    /// Latency measurement point, or a reason when none was sampled.
    pub latency_point: &'static str,
    /// Whether this was a `--smoke` run.
    pub smoke: bool,
    /// Whether the invocation ran the whole scenario suite.
    pub full_suite: bool,
    /// Host/build environment.
    pub environment: &'a Environment,
    /// Scenario parameters.
    pub params: Params,
    /// Number of warmup runs performed before the measured runs.
    pub warmup_runs: u32,
    /// Measured runs.
    pub runs: &'a [Measurement],
}

/// Builds the JSON document for one scenario.
#[must_use]
pub fn build(input: &DocumentInput<'_>) -> Json {
    let aggregate = aggregate(input.runs);
    let median = aggregate.median.clone();
    let base = input.runs.first();

    let metadata = Json::object(vec![
        ("commit", Json::Str(input.environment.commit.clone())),
        ("rustc", Json::Str(input.environment.rustc.clone())),
        ("target", Json::Str(input.environment.target.clone())),
        ("features", Json::Str(input.environment.features.clone())),
        ("cpu_model", Json::Str(input.environment.cpu_model.clone())),
        ("kernel", Json::Str(input.environment.kernel.clone())),
        ("batch", Json::Int(i64::from(input.params.batch))),
        (
            "loss_percent",
            Json::Int(i64::from(input.params.loss_percent)),
        ),
        ("rtt_micros", Json::from_u64(input.params.rtt_micros)),
        ("seed", Json::from_u64(input.params.seed)),
        ("affinity", Json::Str(input.environment.affinity.clone())),
        (
            "clock_ticks_per_second",
            Json::from_u64(input.environment.clock_ticks_per_second),
        ),
        (
            "clock_ticks_source",
            Json::Str(input.environment.clock_ticks_source.clone()),
        ),
    ]);

    let measurements: Vec<Json> = input
        .runs
        .iter()
        .map(|run| metric_object(run.metrics()))
        .collect();

    let dimensions = dimensions(input, &median, base);

    let counters = Json::object(vec![
        (
            "packets_sent",
            metric(median_value(&median, "packets_sent")),
        ),
        (
            "packets_received",
            metric(median_value(&median, "packets_received")),
        ),
        (
            "packets_dropped",
            metric(median_value(&median, "packets_dropped")),
        ),
        ("connections", metric(median_value(&median, "connections"))),
        ("handshakes", metric(median_value(&median, "handshakes"))),
        ("streams", metric(median_value(&median, "streams"))),
        (
            "wire_bytes",
            Json::from_u64(base.map_or(0, |run| run.wire_bytes_out + run.wire_bytes_in)),
        ),
        (
            "payload_bytes",
            Json::from_u64(base.map_or(0, |run| run.payload_bytes)),
        ),
        (
            "dropped_by_netem",
            Json::from_u64(base.map_or(0, |run| run.packets_dropped)),
        ),
        (
            "max_datagram_frame_size",
            Json::opt_u64(base.and_then(|run| run.max_datagram_frame_size)),
        ),
        (
            "datagram_payload_bytes",
            Json::opt_u64(base.and_then(|run| run.datagram_payload_bytes)),
        ),
        (
            "sessions_requested",
            Json::opt_u64(input.params.requested_sessions),
        ),
        (
            "sessions_effective",
            Json::opt_u64(input.params.effective_sessions),
        ),
    ]);

    let mut notes: Vec<Json> = base
        .map(|run| run.notes.iter().cloned().map(Json::Str).collect())
        .unwrap_or_default();
    if input.smoke {
        notes.insert(
            0,
            Json::Str(
                "smoke run: durations, concurrency and packet counts are reduced; this file is not a baseline"
                    .to_owned(),
            ),
        );
    }

    Json::object(vec![
        ("schema", Json::Str(SCHEMA.to_owned())),
        ("scenario", Json::Str(input.scenario.to_owned())),
        ("smoke", Json::Bool(input.smoke)),
        ("full_suite", Json::Bool(input.full_suite)),
        (
            "generated_by",
            Json::Str("benchmarks/m3 (rtx-m3-bench)".to_owned()),
        ),
        ("metadata", metadata),
        (
            "runs",
            Json::object(vec![
                (
                    "measured",
                    Json::Int(i64::try_from(input.runs.len()).unwrap_or(i64::MAX)),
                ),
                ("warmup", Json::Int(i64::from(input.warmup_runs))),
            ]),
        ),
        ("measurements", Json::Array(measurements)),
        (
            "aggregate",
            Json::object(vec![
                ("median", metric_object(aggregate.median)),
                ("min", metric_object(aggregate.min)),
                ("max", metric_object(aggregate.max)),
            ]),
        ),
        ("dimensions", dimensions),
        ("counters", counters),
        ("notes", Json::Array(notes)),
    ])
}

fn metric(value: Option<f64>) -> Json {
    Json::opt_f64(value)
}

fn metric_object<K: Into<String>>(map: Vec<(K, Option<f64>)>) -> Json {
    Json::Object(
        map.into_iter()
            .map(|(key, value)| (key.into(), Json::opt_f64(value)))
            .collect(),
    )
}

fn median_value(median: &[(String, Option<f64>)], key: &str) -> Option<f64> {
    median
        .iter()
        .find(|(name, _)| name == key)
        .and_then(|(_, value)| *value)
}

fn dimensions(
    input: &DocumentInput<'_>,
    median: &[(String, Option<f64>)],
    base: Option<&Measurement>,
) -> Json {
    let value = |key: &str| median_value(median, key);
    let throughput_wire = value("wire_bytes_per_second");
    let throughput_payload = value("payload_bytes_per_second");
    let pps = value("pps");
    let p50 = value("p50_us");
    let p95 = value("p95_us");
    let p99 = value("p99_us");
    let samples = base.map_or(0, |run| run.latency_samples.len());

    let cycles = std::env::var("RTX_BENCH_PERF_CYCLES")
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok());
    let cycles_command = std::env::var("RTX_BENCH_PERF_COMMAND")
        .ok()
        .filter(|text| !text.trim().is_empty());

    Json::object(vec![
        (
            "throughput",
            Json::object(vec![
                (
                    "wire_bytes_per_second",
                    metric(throughput_wire),
                ),
                (
                    "payload_bytes_per_second",
                    metric(throughput_payload),
                ),
                (
                    "reason",
                    reason(
                        throughput_wire.is_none() && throughput_payload.is_none(),
                        "no data-path traffic in this scenario",
                    ),
                ),
            ]),
        ),
        (
            "packet_rate",
            Json::object(vec![
                ("pps", metric(pps)),
                (
                    "reason",
                    reason(pps.is_none(), "no DATAGRAM traffic in this scenario"),
                ),
            ]),
        ),
        (
            "latency",
            Json::object(vec![
                ("p50_micros", metric(p50)),
                ("p95_micros", metric(p95)),
                ("p99_micros", metric(p99)),
                ("samples", Json::from_usize(samples)),
                (
                    "measurement_point",
                    if samples == 0 {
                        Json::Null
                    } else {
                        Json::Str(input.latency_point.to_owned())
                    },
                ),
                (
                    "reason",
                    reason(samples == 0, "no latency samples in this scenario"),
                ),
            ]),
        ),
        (
            "cpu",
            Json::object(vec![
                ("wall_micros", metric(value("wall_us"))),
                ("cpu_time_micros", metric(value("cpu_us"))),
                ("cpu_percent", metric(value("cpu_percent"))),
                ("cycles", Json::opt_u64(cycles)),
                (
                    "cycles_command",
                    cycles_command.map_or(Json::Null, Json::Str),
                ),
                (
                    "cycles_reason",
                    reason(cycles.is_none(), "perf stat cycles not collected by this run"),
                ),
                (
                    "clk_tck",
                    Json::from_u64(input.environment.clock_ticks_per_second),
                ),
            ]),
        ),
        (
            "memory",
            Json::object(vec![
                ("rss_peak_bytes", metric(value("rss_peak_bytes"))),
                ("heap_peak_bytes", metric(value("heap_peak_bytes"))),
                (
                    "rss_reason",
                    reason(
                        value("rss_peak_bytes").is_none(),
                        "VmHWM unavailable on this host",
                    ),
                ),
            ]),
        ),
        (
            "allocations",
            Json::object(vec![
                ("alloc_count", metric(value("alloc_count"))),
                ("free_count", metric(value("free_count"))),
                ("allocated_bytes", metric(value("allocated_bytes"))),
                ("peak_live_bytes", metric(value("peak_live_bytes"))),
            ]),
        ),
        (
            "alloc_per",
            Json::object(vec![
                ("packet", metric(value("alloc_per_packet"))),
                ("frame", Json::Null),
                (
                    "frame_reason",
                    Json::Str(
                        "frame-level attribution is not measured here; see m3_pt2_frame_codec_zero_alloc"
                            .to_owned(),
                    ),
                ),
                ("connection", metric(value("alloc_per_connection"))),
                ("handshake", metric(value("alloc_per_handshake"))),
            ]),
        ),
        (
            "queue",
            Json::object(vec![
                ("max_depth", metric(value("queue_max_depth"))),
                ("drop_events", metric(value("queue_drop_events"))),
                (
                    "backpressure_events",
                    metric(value("backpressure_events")),
                ),
                (
                    "scope",
                    Json::Str(
                        "harness-side netem queue depth and facade send backpressure; the harness does not endorse M3-P8"
                            .to_owned(),
                    ),
                ),
            ]),
        ),
    ])
}

fn reason(condition: bool, text: &str) -> Json {
    if condition {
        Json::Str(text.to_owned())
    } else {
        Json::Null
    }
}

/// Validates one result document against the harness schema.
///
/// # Errors
///
/// Returns a list of schema violations; an empty list means the document
/// conforms.
pub fn validate(document: &Json, expected_scenario: Option<&str>) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    if document.as_object().is_none() {
        return Err(vec!["document is not a JSON object".to_owned()]);
    }
    if document.get("schema").and_then(Json::as_str) != Some(SCHEMA) {
        problems.push(format!("schema must be {SCHEMA}"));
    }
    let scenario = document.get("scenario").and_then(Json::as_str);
    if scenario.is_none_or(str::is_empty) {
        problems.push("scenario must be a non-empty string".to_owned());
    }
    if let (Some(expected), Some(actual)) = (expected_scenario, scenario)
        && expected != actual
    {
        problems.push(format!("scenario is {actual:?}, expected {expected:?}"));
    }
    for flag in ["smoke", "full_suite"] {
        if document
            .get(flag)
            .and_then(|value| match value {
                Json::Bool(_) => Some(()),
                _ => None,
            })
            .is_none()
        {
            problems.push(format!("{flag} must be a boolean"));
        }
    }
    for section in ["metadata", "runs", "aggregate", "dimensions", "counters"] {
        if document.get(section).and_then(Json::as_object).is_none() {
            problems.push(format!("{section} must be an object"));
        }
    }
    if document
        .get("measurements")
        .and_then(Json::as_array)
        .is_none()
    {
        problems.push("measurements must be an array".to_owned());
    }

    let metadata = document.get("metadata");
    for key in REQUIRED_METADATA {
        let present = metadata
            .and_then(|section| section.get(key))
            .is_some_and(|value| !matches!(value, Json::Null));
        if !present {
            problems.push(format!("metadata.{key} is missing or null"));
        }
    }
    let commit = metadata
        .and_then(|section| section.get("commit"))
        .and_then(Json::as_str)
        .unwrap_or_default();
    if commit.is_empty() || commit == "unknown" {
        problems.push("metadata.commit must be a resolved commit".to_owned());
    }
    if metadata
        .and_then(|section| section.get("seed"))
        .and_then(Json::as_f64)
        .is_none()
    {
        problems.push("metadata.seed must be numeric".to_owned());
    }

    for key in REQUIRED_DIMENSIONS {
        if document
            .get("dimensions")
            .and_then(|section| section.get(key))
            .and_then(Json::as_object)
            .is_none()
        {
            problems.push(format!("dimensions.{key} must be an object"));
        }
    }

    let measurements = document
        .get("measurements")
        .and_then(Json::as_array)
        .map_or(0, <[Json]>::len);
    let measured = document
        .get("runs")
        .and_then(|section| section.get("measured"))
        .and_then(Json::as_f64)
        .unwrap_or(0.0);
    if measurements == 0 {
        problems.push("measurements must contain at least one run".to_owned());
    }
    if measured as usize != measurements {
        problems.push(format!(
            "runs.measured ({measured}) does not match measurements ({measurements})"
        ));
    }

    for section in ["median", "min", "max"] {
        if document
            .get("aggregate")
            .and_then(|aggregate| aggregate.get(section))
            .and_then(Json::as_object)
            .is_none()
        {
            problems.push(format!("aggregate.{section} must be an object"));
        }
    }

    // Every null latency/throughput/packet-rate must carry a reason.
    for (dimension, value_key) in [
        ("throughput", "wire_bytes_per_second"),
        ("packet_rate", "pps"),
        ("latency", "p50_micros"),
    ] {
        let block = document
            .get("dimensions")
            .and_then(|dimensions| dimensions.get(dimension));
        let has_value = block
            .and_then(|block| block.get(value_key))
            .and_then(Json::as_f64)
            .is_some();
        let has_reason = block
            .and_then(|block| block.get("reason"))
            .and_then(Json::as_str)
            .is_some_and(|text| !text.is_empty());
        if !has_value && !has_reason {
            problems.push(format!("dimensions.{dimension} is null without a reason"));
        }
    }

    if json::duplicate_keys(document).is_empty() {
        // no duplicates
    } else {
        problems.push("duplicate JSON keys".to_owned());
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// Serializes and writes one result document after validating it.
///
/// # Errors
///
/// Returns a message when the document fails validation or the file cannot be
/// written.
pub fn write(path: &std::path::Path, document: &Json) -> Result<(), String> {
    validate(document, None).map_err(|problems| format!("schema: {}", problems.join("; ")))?;
    let text = json::to_string(document);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    std::fs::write(path, text).map_err(|error| format!("write {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{Measurement, percentile};

    #[test]
    fn percentiles_use_nearest_rank() {
        let samples: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&samples, 50.0), Some(50.0));
        assert_eq!(percentile(&samples, 95.0), Some(95.0));
        assert_eq!(percentile(&samples, 99.0), Some(99.0));
        assert_eq!(percentile(&[], 50.0), None);
    }

    #[test]
    fn aggregation_reports_median_min_and_max() {
        let runs: Vec<Measurement> = [10_u64, 20, 30]
            .into_iter()
            .map(|value| Measurement {
                wall_micros: 1_000_000,
                cpu_micros: value * 1_000,
                ..Measurement::default()
            })
            .collect();
        let aggregate = super::aggregate(&runs);
        let cpu = aggregate
            .median
            .iter()
            .find(|(key, _)| key == "cpu_us")
            .and_then(|(_, value)| *value);
        assert_eq!(cpu, Some(20_000.0));
        let minimum = aggregate
            .min
            .iter()
            .find(|(key, _)| key == "cpu_us")
            .and_then(|(_, value)| *value);
        assert_eq!(minimum, Some(10_000.0));
    }
}

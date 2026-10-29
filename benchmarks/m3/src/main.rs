//! `M3-P` benchmark harness binary.
//!
//! Usage (see `benchmarks/m3/run.sh`, which supplies the DER certificate):
//!
//! ```text
//! rtx-m3-bench --list
//! rtx-m3-bench --scenario ps6-rtt-10-quic \
//!              --cert-chain-der /tmp/cert.der --key-der /tmp/key.der \
//!              --out /tmp/rtx-m3 --runs 5 --warmup 1 [--smoke]
//! rtx-m3-bench --verify /tmp/rtx-m3
//! ```
//!
//! The harness owns no protocol codec and writes no OS-specific tuning; it
//! refuses to write a result without a resolved commit (`M3-PM3`).

mod json;
mod meta;
mod net;
mod result;
mod scenario;
mod wt;

use std::path::PathBuf;
use std::process::ExitCode;

use meta::Environment;
use result::{DocumentInput, Measurement, Params};
use scenario::{RunConfig, Scenario};

/// Process-wide counting allocator (`M3-PM1` / `M3-PT2` consumer). Every
/// scenario run enters a labelled scene, so this allocator attributes
/// allocations to the running scenario.
#[global_allocator]
static GLOBAL_ALLOCATOR: rtx_testkit::alloc::CountingAlloc<std::alloc::System> =
    rtx_testkit::alloc::CountingAlloc::new(std::alloc::System);

const USAGE: &str = "\
rtx-m3-bench — M3-P benchmark harness

  --list                          print every scenario id, one per line
  --scenario <id>                 run one scenario
  --smoke                         reduced durations/counts, labelled smoke
  --full-suite                    mark the result as part of a full-suite run
  --out <dir>                     result directory
  --runs <n>                      measured runs (formal default 5)
  --warmup <n>                    warmup runs (formal default 1)
  --seed <n>                      netem/endpoint seed (default 42)
  --cert-chain-der <path>         server certificate (DER)
  --key-der <path>                server key (PKCS#8 DER)
  --commit <hex>                  override the resolved git commit
  --verify <dir>                  re-read and schema-check result files
";

#[derive(Debug)]
struct Args {
    scenario: Option<String>,
    smoke: bool,
    full_suite: bool,
    out: PathBuf,
    runs: Option<u32>,
    warmup: Option<u32>,
    seed: u64,
    certificate: Option<PathBuf>,
    key: Option<PathBuf>,
    commit: Option<String>,
    list: bool,
    verify: Option<PathBuf>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut args = Self {
            scenario: None,
            smoke: false,
            full_suite: false,
            out: PathBuf::from("benchmarks/m3/results"),
            runs: None,
            warmup: None,
            seed: 42,
            certificate: None,
            key: None,
            commit: None,
            list: false,
            verify: None,
        };
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--list" => args.list = true,
                "--smoke" => args.smoke = true,
                "--full-suite" => args.full_suite = true,
                "--scenario" => {
                    args.scenario = Some(next_value(&mut arguments, &argument)?);
                }
                "--out" => args.out = PathBuf::from(next_value(&mut arguments, &argument)?),
                "--runs" => {
                    args.runs = Some(parse_value(
                        &next_value(&mut arguments, &argument)?,
                        "--runs",
                    )?);
                }
                "--warmup" => {
                    args.warmup = Some(parse_value(
                        &next_value(&mut arguments, &argument)?,
                        "--warmup",
                    )?);
                }
                "--seed" => {
                    args.seed = parse_value(&next_value(&mut arguments, &argument)?, "--seed")?;
                }
                "--cert-chain-der" => {
                    args.certificate = Some(PathBuf::from(next_value(&mut arguments, &argument)?));
                }
                "--key-der" => {
                    args.key = Some(PathBuf::from(next_value(&mut arguments, &argument)?));
                }
                "--commit" => args.commit = Some(next_value(&mut arguments, &argument)?),
                "--verify" => {
                    args.verify = Some(PathBuf::from(next_value(&mut arguments, &argument)?));
                }
                "-h" | "--help" => {
                    println!("{USAGE}");
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument {other}\n\n{USAGE}")),
            }
        }
        Ok(args)
    }
}

fn next_value(arguments: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("missing value for {name}"))
}

fn parse_value<T: std::str::FromStr>(text: &str, name: &str) -> Result<T, String> {
    text.parse::<T>()
        .map_err(|_| format!("invalid value {text:?} for {name}"))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rtx-m3-bench: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse()?;
    if args.list {
        for scenario in scenario::list() {
            println!("{}", scenario.id);
        }
        return Ok(());
    }
    if let Some(directory) = &args.verify {
        return verify(directory);
    }
    let scenario = match args.scenario.as_deref() {
        Some(id) => scenario::find(id).ok_or_else(|| format!("unknown scenario {id:?}"))?,
        None => return Err(format!("--scenario or --list is required\n\n{USAGE}")),
    };
    let certificate = std::fs::read(
        args.certificate
            .as_deref()
            .ok_or("--cert-chain-der is required")?,
    )
    .map_err(|error| format!("read certificate: {error}"))?;
    let private_key = std::fs::read(args.key.as_deref().ok_or("--key-der is required")?)
        .map_err(|error| format!("read key: {error}"))?;

    let environment = Environment::discover(args.commit.as_deref())?;
    let config = RunConfig {
        smoke: args.smoke,
        seed: args.seed,
        certificate_der: certificate,
        private_key_der: private_key,
        environment: environment.clone(),
    };
    let measured_runs = if args.smoke {
        1
    } else {
        args.runs.unwrap_or(5)
    };
    let warmup_runs = if args.smoke {
        0
    } else {
        args.warmup.unwrap_or(1)
    };
    if measured_runs == 0 {
        return Err("--runs must be at least 1".to_owned());
    }

    for index in 0..warmup_runs {
        scenario::run(&scenario, &config)
            .map_err(|error| format!("warmup run {} failed: {error}", index + 1))?;
        eprintln!(
            "warmup {}/{} complete: {}",
            index + 1,
            warmup_runs,
            scenario.id
        );
    }
    let mut measurements: Vec<Measurement> = Vec::with_capacity(measured_runs as usize);
    for index in 0..measured_runs {
        let measurement = scenario::run(&scenario, &config)
            .map_err(|error| format!("run {} failed: {error}", index + 1))?;
        eprintln!(
            "run {}/{} complete: {} ({} ms)",
            index + 1,
            measured_runs,
            scenario.id,
            measurement.wall_micros / 1_000
        );
        measurements.push(measurement);
    }

    let params = params_for(&scenario, &config, measurements.first());
    let document = result::build(&DocumentInput {
        scenario: scenario.id,
        latency_point: scenario::latency_point(scenario.kind),
        smoke: args.smoke,
        full_suite: args.full_suite,
        environment: &config.environment,
        params,
        warmup_runs,
        runs: &measurements,
    });
    result::validate(&document, Some(scenario.id))
        .map_err(|problems| format!("schema: {}", problems.join("; ")))?;
    let path = args.out.join(format!("{}.json", scenario.id));
    result::write(&path, &document)?;
    println!(
        "scenario={} file={} smoke={} runs={}",
        scenario.id,
        path.display(),
        args.smoke,
        measured_runs
    );
    Ok(())
}

fn params_for(scenario: &Scenario, config: &RunConfig, first: Option<&Measurement>) -> Params {
    let (batch, loss_percent, rtt_micros) = match scenario.kind {
        scenario::Kind::Rtt { rtt_millis, .. } => (1, 0, rtt_millis.saturating_mul(1_000)),
        scenario::Kind::Handshake { loss_percent, .. } => (1, loss_percent, 0),
        scenario::Kind::Datagram {
            rtt_millis,
            loss_percent,
        } => (1, loss_percent, rtt_millis.saturating_mul(1_000)),
        scenario::Kind::Batch { batch } => (batch, 0, 0),
        _ => (1, 0, 0),
    };
    Params {
        batch,
        loss_percent,
        rtt_micros,
        seed: config.seed,
        requested_sessions: first.and_then(|run| run.requested_sessions),
        effective_sessions: first.and_then(|run| run.effective_sessions),
    }
}

fn verify(directory: &std::path::Path) -> Result<(), String> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| format!("read {}: {error}", directory.display()))?;
    let mut files = 0usize;
    let mut failures = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("read entry: {error}"))?;
        let path = entry.path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        match json::parse(&text) {
            Ok(document) => {
                let expected = path
                    .file_stem()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or_default()
                    .to_owned();
                if let Err(problems) = result::validate(&document, Some(&expected)) {
                    failures.push(format!("{}: {}", path.display(), problems.join("; ")));
                }
            }
            Err(error) => failures.push(format!("{}: {error}", path.display())),
        }
    }
    if files == 0 {
        return Err(format!("no JSON results in {}", directory.display()));
    }
    if failures.is_empty() {
        println!("verified {files} result files against {}", result::SCHEMA);
        Ok(())
    } else {
        for failure in &failures {
            eprintln!("INVALID {failure}");
        }
        Err(format!(
            "{} of {files} files failed validation",
            failures.len()
        ))
    }
}

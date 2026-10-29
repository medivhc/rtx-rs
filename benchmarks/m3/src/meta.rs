//! Build and host metadata (`M3-PM3`).
//!
//! The gate requires every result to record commit, rustc, target, feature
//! set, CPU model, kernel, batch, loss, RTT and seed; a result with a missing
//! field is invalid. Everything that is fixed at build time is injected by
//! `build.rs`; everything that describes the host or the run is read here.
//! `commit` is resolved at run time and the harness refuses to write a result
//! without it.

use std::process::Command;
use std::time::Instant;

/// Host and build environment shared by every scenario result.
#[derive(Debug, Clone)]
pub struct Environment {
    /// Repository commit (`RTX_BENCH_COMMIT` or `git rev-parse HEAD`).
    pub commit: String,
    /// `rustc -V` of the compiler that built the harness.
    pub rustc: String,
    /// Cargo target triple.
    pub target: String,
    /// Enabled features of the harness and its rtx dependencies.
    pub features: String,
    /// Host CPU model (`/proc/cpuinfo`), or `"unknown"`.
    pub cpu_model: String,
    /// Kernel release (`/proc/sys/kernel/osrelease`), or `"unknown"`.
    pub kernel: String,
    /// CPU affinity mask (`Cpus_allowed_list`), or `"unavailable"`.
    pub affinity: String,
    /// `USER_HZ` used to convert `/proc/self/stat` ticks, with its source.
    pub clock_ticks_per_second: u64,
    /// Where `clock_ticks_per_second` came from (`getconf`/`fallback`).
    pub clock_ticks_source: String,
}

impl Environment {
    /// Collects the environment or fails when the commit cannot be resolved.
    ///
    /// # Errors
    ///
    /// Returns an error when neither the override, `RTX_BENCH_COMMIT` nor
    /// `git rev-parse` yields a commit. A result without a commit is invalid
    /// by `M3-PM3`, so the harness never writes one.
    pub fn discover(commit_override: Option<&str>) -> Result<Self, String> {
        let (clock_ticks_per_second, clock_ticks_source) = read_clock_ticks();
        Ok(Self {
            commit: resolve_commit(commit_override)?,
            rustc: env!("RTX_BENCH_RUSTC").to_owned(),
            target: env!("RTX_BENCH_TARGET").to_owned(),
            features: features_string(),
            cpu_model: read_cpu_model(),
            kernel: read_kernel(),
            affinity: read_affinity(),
            clock_ticks_per_second,
            clock_ticks_source,
        })
    }
}

/// Resolves the commit from the override, the environment or from git.
fn resolve_commit(commit_override: Option<&str>) -> Result<String, String> {
    if let Some(commit) = commit_override {
        let trimmed = commit.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }
    if let Ok(commit) = std::env::var("RTX_BENCH_COMMIT") {
        let trimmed = commit.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .map_err(|error| format!("cannot run git: {error}"))?;
    if !output.status.success() {
        return Err("git rev-parse HEAD failed; set RTX_BENCH_COMMIT".to_owned());
    }
    let commit = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if commit.is_empty() {
        return Err("git rev-parse HEAD returned an empty commit".to_owned());
    }
    Ok(commit)
}

fn features_string() -> String {
    let harness = env!("RTX_BENCH_FEATURES");
    let harness = if harness.is_empty() {
        "none".to_owned()
    } else {
        harness.to_owned()
    };
    format!("harness={harness}; rtx-quic=std; rtx-testkit=std")
}

fn read_cpu_model() -> String {
    let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") else {
        return "unknown".to_owned();
    };
    for line in cpuinfo.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if matches!(key.trim(), "model name" | "Model" | "Hardware") {
            let value = value.trim();
            if !value.is_empty() {
                return value.to_owned();
            }
        }
    }
    "unknown".to_owned()
}

fn read_kernel() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned())
}

fn read_affinity() -> String {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return "unavailable".to_owned();
    };
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Cpus_allowed_list:") {
            let value = value.trim();
            if !value.is_empty() {
                return value.to_owned();
            }
        }
    }
    "unavailable".to_owned()
}

/// Reads `USER_HZ` (`getconf CLK_TCK`), falling back to 100.
fn read_clock_ticks() -> (u64, String) {
    let Ok(output) = Command::new("getconf").arg("CLK_TCK").output() else {
        return (100, "fallback".to_owned());
    };
    if !output.status.success() {
        return (100, "fallback".to_owned());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    match text.trim().parse::<u64>() {
        Ok(value) if value > 0 => (value, "getconf".to_owned()),
        _ => (100, "fallback".to_owned()),
    }
}

/// Reads the process CPU time (`utime + stime`) from `/proc/self/stat`.
///
/// Returns microseconds using `clock_ticks_per_second`.
#[must_use]
pub fn cpu_time_micros(clock_ticks_per_second: u64) -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let close = stat.rfind(')')?;
    let fields: Vec<&str> = stat.get(close + 1..)?.split_whitespace().collect();
    // After the comm field, the first field is state (field 3 of the manual).
    // utime is field 14 and stime field 15, so their indexes are 11 and 12.
    let user_ticks: u64 = fields.get(11)?.parse().ok()?;
    let system_ticks: u64 = fields.get(12)?.parse().ok()?;
    let total = user_ticks.checked_add(system_ticks)?;
    total
        .checked_mul(1_000_000)
        .map(|micros| micros / clock_ticks_per_second)
}

/// Reads the current peak RSS from `/proc/self/status` (`VmHWM`).
#[must_use]
pub fn rss_peak_bytes() -> Option<u64> {
    rtx_testkit::proc::rss_peak_bytes()
}

/// Milliseconds elapsed since `start`, saturating.
#[must_use]
pub fn wall_micros(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::features_string;

    #[test]
    fn features_string_names_the_rtx_features() {
        assert!(features_string().contains("rtx-quic=std"));
        assert!(features_string().contains("rtx-testkit=std"));
    }
}

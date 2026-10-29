//! `/proc/self/status` readers used by `M3-P5`.
//!
//! The gate separates the process RSS peak (`VmHWM`) from the allocator's
//! `peak_live_bytes`; this module supplies only the former. It is compiled
//! for `std` and test builds (it performs file I/O).

/// Reads the process peak resident set size from `/proc/self/status`
/// (`VmHWM`), in bytes.
///
/// Returns `None` when the file cannot be read (non-Linux host) or the line
/// is absent/malformed. The value is the peak since process start, not since
/// the last call.
#[must_use]
pub fn rss_peak_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_vm_hwm(&status)
}

/// Parses `VmHWM: <n> kB` out of a `/proc/self/status` body.
///
/// `VmHWM` is reported in kibibytes; the result is converted to bytes.
fn parse_vm_hwm(status: &str) -> Option<u64> {
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("VmHWM:") else {
            continue;
        };
        let rest = rest.trim();
        let kilobytes = rest.strip_suffix("kB")?.trim();
        let value: u64 = kilobytes.parse().ok()?;
        return value.checked_mul(1024);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{parse_vm_hwm, rss_peak_bytes};

    #[test]
    fn parses_vmhwm_lines() {
        let status = "Name:\trtx\nVmHWM:\t   4096 kB\nVmRSS:\t   2048 kB\n";
        assert_eq!(parse_vm_hwm(status), Some(4 * 1024 * 1024));
    }

    #[test]
    fn tolerates_extra_whitespace() {
        let status = "VmHWM:   123456   kB  \n";
        assert_eq!(parse_vm_hwm(status), Some(123_456 * 1024));
    }

    #[test]
    fn rejects_missing_and_malformed_lines() {
        assert_eq!(parse_vm_hwm("Name:\trtx\n"), None);
        assert_eq!(parse_vm_hwm("VmHWM:\t not-a-number kB\n"), None);
        assert_eq!(parse_vm_hwm("VmHWM:\t 12 MB\n"), None);
        assert_eq!(parse_vm_hwm("VmHWM:\t 999999999999999999999 kB\n"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_the_live_process_status() {
        assert!(
            rss_peak_bytes().is_some(),
            "Linux exposes /proc/self/status"
        );
    }
}

//! Injects build-time metadata into the harness binary (`M3-PM3`).
//!
//! `commit` is deliberately *not* baked in: `run.sh`/the harness resolves it
//! at run time (`RTX_BENCH_COMMIT` or `git rev-parse`), so a stale binary
//! cannot silently report an old commit. `rustc`, `target` and the feature
//! set are build properties and are recorded here.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTC");

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=RTX_BENCH_TARGET={target}");

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let version = Command::new(&rustc)
        .arg("-V")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    println!(
        "cargo:rustc-env=RTX_BENCH_RUSTC={}",
        version.replace('\n', " ")
    );

    let mut features: Vec<String> = std::env::vars()
        .filter_map(|(key, _)| key.strip_prefix("CARGO_FEATURE_").map(str::to_owned))
        .map(|name| name.to_lowercase())
        .collect();
    features.sort();
    println!("cargo:rustc-env=RTX_BENCH_FEATURES={}", features.join(","));
}

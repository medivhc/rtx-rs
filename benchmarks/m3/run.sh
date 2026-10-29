#!/usr/bin/env bash
# M3-P benchmark harness runner (gate M3-PM5).
#
# One command rebuilds every M3-owned scenario (M3-PS6-PS10, M3-PB1):
#
#   ./benchmarks/m3/run.sh              # formal mode: 5 measured runs + 1 warmup
#   ./benchmarks/m3/run.sh --smoke      # short PR-validation mode, temp output
#   ./benchmarks/m3/run.sh --scenario ps6-rtt-10-quic --smoke
#
# The script:
#   1. builds the standalone harness crate (not a workspace member);
#   2. generates a throw-away DER certificate with openssl in a mktemp
#      directory (never written into the repository);
#   3. pins CPU affinity with taskset when available, else records
#      `affinity: unavailable`;
#   4. optionally wraps the harness with `perf stat -e cycles` and records the
#      command plus a cycles sidecar; a missing or failing perf never fails the
#      run (the getrusage CPU-time route is always recorded);
#   5. runs each scenario with the gate parameters and verifies that the JSON
#      contains `runs.measured`/`runs.warmup` and the nine/ten PM3 metadata
#      fields (the harness itself refuses to write without a commit);
#   6. schema-checks every result with `rtx-m3-bench --verify`.
#
# Smoke output goes to a temporary directory by default; formal output goes to
# benchmarks/m3/results/. Nothing produced by this script is committed.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

SMOKE=0
SCENARIO=""
OUT=""
RUNS=""
WARMUP=""
PERF=1

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --smoke) SMOKE=1; shift ;;
    --scenario) [ $# -ge 2 ] || fail "--scenario needs a value"; SCENARIO="$2"; shift 2 ;;
    --out) [ $# -ge 2 ] || fail "--out needs a value"; OUT="$2"; shift 2 ;;
    --runs) [ $# -ge 2 ] || fail "--runs needs a value"; RUNS="$2"; shift 2 ;;
    --warmup) [ $# -ge 2 ] || fail "--warmup needs a value"; WARMUP="$2"; shift 2 ;;
    --no-perf) PERF=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

command -v cargo >/dev/null 2>&1 || fail "cargo is required"
if [ "$SMOKE" -eq 0 ]; then
  [ -n "$RUNS" ] || RUNS=5
  [ "$RUNS" -ge 5 ] || fail "formal mode requires at least 5 measured runs (M3-PM4)"
  [ -n "$WARMUP" ] || WARMUP=1
else
  [ -n "$RUNS" ] || RUNS=1
  [ -n "$WARMUP" ] || WARMUP=0
fi

WORK="$(mktemp -d)"
cleanup() {
  if [ "${KEEP_WORK:-0}" = "1" ]; then
    echo "KEEP_WORK=1: kept $WORK" >&2
    return
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

if [ -z "$OUT" ]; then
  if [ "$SMOKE" -eq 1 ]; then
    OUT="$WORK/results"
  else
    OUT="$HERE/results"
  fi
fi
mkdir -p "$OUT"

# ---------------------------------------------------------------- 1. certificate
if [ -n "${RTX_BENCH_CERT_CHAIN_DER:-}" ] && [ -n "${RTX_BENCH_KEY_DER:-}" ]; then
  CERT_DER="$RTX_BENCH_CERT_CHAIN_DER"
  KEY_DER="$RTX_BENCH_KEY_DER"
else
  command -v openssl >/dev/null 2>&1 \
    || fail "openssl is required to generate the runtime DER certificate (or set RTX_BENCH_CERT_CHAIN_DER/RTX_BENCH_KEY_DER)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1 \
    || fail "openssl certificate generation failed"
  openssl x509 -in "$WORK/cert.pem" -outform DER -out "$WORK/cert.der" >/dev/null 2>&1 \
    || fail "certificate PEM -> DER conversion failed"
  openssl pkcs8 -topk8 -nocrypt -in "$WORK/key.pem" -outform DER -out "$WORK/key.der" >/dev/null 2>&1 \
    || fail "private key PKCS#8 conversion failed"
  CERT_DER="$WORK/cert.der"
  KEY_DER="$WORK/key.der"
fi

# ---------------------------------------------------------------- 2. build
echo "building the standalone harness (not a workspace member)"
cargo build --release --manifest-path "$HERE/Cargo.toml" >/dev/null
BIN="$HERE/target/release/rtx-m3-bench"
[ -x "$BIN" ] || fail "harness binary not found at $BIN"

# ---------------------------------------------------------------- 3. affinity
AFFINITY="unavailable"
AFFINITY_WRAP=()
if command -v taskset >/dev/null 2>&1; then
  CPU="$(taskset -pc $$ 2>/dev/null | sed 's/.*list: //' | cut -d, -f1 | cut -d- -f1 || true)"
  if [ -n "${CPU:-}" ]; then
    AFFINITY="$CPU"
    AFFINITY_WRAP=(taskset -c "$CPU")
  fi
fi
echo "affinity: $AFFINITY"

# ---------------------------------------------------------------- 4. perf (optional)
PERF_OK=0
if [ "$PERF" -eq 1 ] && command -v perf >/dev/null 2>&1; then
  if perf stat -e cycles -o "$WORK/perf-probe.txt" true >/dev/null 2>&1; then
    PERF_OK=1
  else
    echo "perf is present but cannot count cycles (permissions?); continuing with the getrusage route"
  fi
fi
PERF_TSV="$OUT/perf-cycles.tsv"
if [ "$PERF_OK" -eq 1 ]; then
  : >"$PERF_TSV"
  echo "perf: cycles sidecar -> $PERF_TSV"
else
  echo "perf: unavailable -> cpu.cycles stays null (getrusage CPU time is still recorded)"
fi

# ---------------------------------------------------------------- 5. scenario list
if [ -z "$SCENARIO" ]; then
  IDS="$("$BIN" --list)"
else
  IDS="$("$BIN" --list | grep -x "$SCENARIO" || true)"
  [ -n "$IDS" ] || fail "unknown scenario: $SCENARIO"
fi

FULL_FLAG=()
if [ -z "$SCENARIO" ]; then
  FULL_FLAG=(--full-suite)
fi
SMOKE_FLAG=()
if [ "$SMOKE" -eq 1 ]; then
  SMOKE_FLAG=(--smoke)
fi

# ---------------------------------------------------------------- 6. run
LOG="$OUT/run.log"
: >"$LOG"
{
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "smoke=$SMOKE"
  echo "runs=$RUNS"
  echo "warmup=$WARMUP"
  echo "affinity=$AFFINITY"
  echo "perf=$PERF_OK"
  echo "git_commit=$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
} >>"$LOG"

RAN=0
for id in $IDS; do
  BASE_CMD=("${AFFINITY_WRAP[@]}" "$BIN" \
    --scenario "$id" \
    --out "$OUT" \
    --runs "$RUNS" \
    --warmup "$WARMUP" \
    --cert-chain-der "$CERT_DER" \
    --key-der "$KEY_DER" \
    "${SMOKE_FLAG[@]}" "${FULL_FLAG[@]}")

  if [ "$PERF_OK" -eq 1 ]; then
    PERF_FILE="$WORK/perf-$id.txt"
    CMD=(perf stat -e cycles:u -o "$PERF_FILE" -- "${BASE_CMD[@]}")
    RTX_BENCH_PERF_COMMAND="perf stat -e cycles:u -o <file> -- taskset -c ${AFFINITY} rtx-m3-bench --scenario $id ..." \
      "${CMD[@]}" >>"$LOG" 2>&1 || fail "scenario $id failed (see $LOG)"
  else
    CMD=("${BASE_CMD[@]}")
    "${CMD[@]}" >>"$LOG" 2>&1 || fail "scenario $id failed (see $LOG)"
  fi

  JSON="$OUT/$id.json"
  [ -s "$JSON" ] || fail "scenario $id produced no JSON"
  grep -q '"measured": '"$RUNS" "$JSON" \
    || fail "scenario $id did not record $RUNS measured runs"
  grep -q '"warmup": '"$WARMUP" "$JSON" \
    || fail "scenario $id did not record $WARMUP warmup runs"
  for field in commit rustc target features cpu_model kernel batch loss_percent rtt_micros seed; do
    grep -q "\"$field\":" "$JSON" || fail "scenario $id is missing metadata.$field"
  done
  if grep -q '"commit": null' "$JSON" || grep -q '"commit": ""' "$JSON"; then
    fail "scenario $id has no commit: the result is invalid (M3-PM3)"
  fi

  if [ "$PERF_OK" -eq 1 ]; then
    CYCLES="$(grep -Eo '[0-9][0-9,]* +cycles(:u)?' "$PERF_FILE" 2>/dev/null | head -n1 | tr -dc '0-9' || true)"
    [ -n "$CYCLES" ] || CYCLES=null
    echo -e "$id\t$CYCLES\tperf stat -e cycles:u -o $PERF_FILE -- ..." >>"$PERF_TSV"
  fi

  RAN=$((RAN + 1))
  echo "done: $id"
done

# ---------------------------------------------------------------- 7. schema check
"$BIN" --verify "$OUT" || fail "schema verification failed"
echo "ran $RAN scenario(s); results in $OUT"
echo "log: $LOG"
if [ "$SMOKE" -eq 1 ]; then
  echo "SMOKE: this output is PR evidence only and must not be committed as a baseline"
fi

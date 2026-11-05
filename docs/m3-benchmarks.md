# M3-P benchmark report

> **Status: first M3 baseline filled.** All 51 scenarios were measured on the
> coordinator's `xc` host with `benchmarks/m3/run.sh` in formal mode — 5
> measured runs + 1 warmup per scenario, median reported, per-run min/max
> dispersion in each JSON's `aggregate` — and the raw results are committed in
> `benchmarks/m3/results/*.json` (51 files, all `smoke: false`,
> `full_suite: true`, `schema: rtx-m3-result-v1`, accepted by
> `rtx-m3-bench --verify`). The cells below quote those medians. A `--smoke`
> run is PR evidence that the harness works and is never written into this
> file or into `benchmarks/m3/results/`.
>
> Baseline environment (identical in all 51 JSON `metadata` blocks): commit
> `dc205c31cf3ecea7eca3b73708116b6d7ded551f` (`dc205c3`), rustc
> `rustc 1.98.1 (48a229cea 2026-09-01)`, CPU
> `12th Gen Intel(R) Core(TM) i7-12700`, kernel `5.15.0-139-generic`; also
> uniform: target `x86_64-unknown-linux-gnu`, features `harness=none;
> rtx-quic=std; rtx-testkit=std`, seed `42`, affinity `0`.
>
> Reproducibility note: on the `xc` host (OpenSSL 1.1.1f), the certificate
> generation built into `run.sh` produces a certificate with duplicate Basic
> Constraints that rustls rejects, so the formal run supplied a clean DER
> certificate through the `RTX_BENCH_CERT_CHAIN_DER` / `RTX_BENCH_KEY_DER`
> environment variables that `run.sh` already supports. The harness and the
> scenarios themselves were not modified.

- Gate: `docs/m3-m4-gates.md` §1.4 (`M3-P1`–`P8`, `M3-PS1`–`PS10`, `M3-PB1`,
  `M3-PM1`–`PM6`, `M3-PT1`–`PT6`).
- Harness: `benchmarks/m3/` (standalone crate + `run.sh`); counting allocator
  and deterministic loss/RTT simulator: `crates/rtx-testkit/`.
- Raw results: `benchmarks/m3/results/*.json` (formal runs only; one file per
  scenario).
- Run: `./benchmarks/m3/run.sh` (formal: 5 measured runs + 1 warmup per
  scenario, median and min/max dispersion, `taskset` affinity when available,
  optional `perf stat -e cycles` sidecar).

## 1. Result metadata (`M3-PM3`)

Every result JSON carries all of the following; a result missing any field is
invalid and the harness refuses to write it (`run.sh` also checks each file).

| Field | Meaning | Source |
|---|---|---|
| `commit` | repository commit of the measured build | `RTX_BENCH_COMMIT`, `--commit`, or `git rev-parse HEAD` |
| `rustc` | compiler that built the harness | `build.rs` (`rustc -V`) |
| `target` | cargo target triple | `build.rs` (`TARGET`) |
| `features` | enabled feature set | `build.rs` + the fixed `rtx-quic/std`, `rtx-testkit/std` |
| `cpu_model` | host CPU model | `/proc/cpuinfo` |
| `kernel` | kernel release | `/proc/sys/kernel/osrelease` |
| `batch` | datagram batch size (`1` outside `M3-PB1`) | scenario parameters |
| `loss_percent` | simulated loss rate | scenario parameters |
| `rtt_micros` | simulated RTT | scenario parameters |
| `seed` | netem/endpoint seed | `--seed` (default 42) |

The gate (`M3-PM3`) enumerates ten names — commit, rustc, target, feature
set, CPU model, kernel, batch, loss, RTT and seed — and this file lists all
ten names verbatim. The harness additionally records `affinity`,
`clock_ticks_per_second` and `clock_ticks_source`.

Dimension units and measurement points:

| Dimension | Unit | Measurement point |
|---|---|---|
| `M3-P1` throughput | bytes/s | UDP payload bytes (wire) and WebTransport/QUIC payload bytes, separately, both directions |
| `M3-P2` packet rate | packets/s | DATAGRAM sends accepted by the facade |
| `M3-P3` latency | µs | client-observed DATAGRAM echo round trip divided by two (one-way estimate, FIFO pairing); handshake duration for `M3-PS7`; not sampled in stream/idle scenarios and not sampled under induced loss |
| `M3-P4` CPU | µs / % / cycles | `/proc/self/stat` `utime+stime` (`getrusage` route); `perf stat -e cycles` optional sidecar in `benchmarks/m3/results/perf-cycles.tsv` |
| `M3-P5` memory | bytes | `VmHWM` from `/proc/self/status` (`rss_peak_bytes`) and the counting allocator's `peak_live_bytes`, reported separately |
| `M3-P6` allocations | counts/bytes | `rtx-testkit` counting allocator scene `alloc_count`, `free_count`, `allocated_bytes`, `peak_live_bytes` |
| `M3-P7` allocations per unit | count | derived from `M3-P6` divided by packets / connections / handshakes; frame-level attribution is the separate `m3_pt2_frame_codec_zero_alloc` measurement |
| `M3-P8` queue/backpressure | count | harness-side netem queue depth, netem drop count and facade `WouldBlock` count; **not** an endorsement of the P8 product requirement |

## 2. Dimension × scenario matrix (`M3-PT1`)

All cells below are filled from the formal `xc` run at commit `dc205c3`. Cell
format: the **median of the 5 measured runs** per scenario (the JSON
`aggregate.median`, mirrored by the `dimensions` block), in the units of §1,
as the **min–max span across that column's scenario files**; the per-run
min/max dispersion (`M3-PM4`) lives in each JSON's `aggregate.min` /
`aggregate.max`. Empty-with-a-reason cells produced by the real run stay
`null + reason` in the JSON; they are quoted here as `null` with the JSON
reason, are not filled with `0` or estimates, and a missing cell means
`M3-PT1` is not satisfied.

| Dimension | PS6 RTT | PS7 handshake | PS8 DATAGRAM | PS9 streams | PS10 sessions | PB1 batch |
|---|---|---|---|---|---|---|
| P1 throughput | wire 1784913.793–4036533.438 bytes/s; payload 377547.024–972616.943 bytes/s | wire 86464.96–8537111.44 bytes/s; payload 0 bytes/s (measured; handshake-only, `counters.payload_bytes=0`) | wire 51778.803–4378379.669 bytes/s; payload 4567.797–1056730.43 bytes/s | wire 166819917.234–267275285.199 bytes/s; payload 69989053.531–127391964.622 bytes/s | wire 8676.132–1423970.593 bytes/s; payload 0 bytes/s (idle tiers, measured) – 397.257 bytes/s (active-max) | wire 15677266.62–35671416.854 bytes/s; payload 267090.335–3786013.029 bytes/s |
| P2 packet rate | 415.655–972.617 packets/s | 0 packets/s (measured; no DATAGRAM sent, `counters.packets_sent=0`) | 34.682–990.905 packets/s | 0 packets/s (measured; streams only, `counters.packets_sent=0`) | 0 packets/s (idle tiers, measured) – 6.207 packets/s (active-max) | 3786.013–17231.635 packets/s |
| P3 latency | echo RTT/2: p50 5311–597659, p95 5317–639198, p99 5318–641136 µs (samples 832–1000) | handshake duration: p50 1697–60642, p95 1697–1061881, p99 1697–6044353 µs (samples = concurrency 1/10/100) | echo RTT/2, loss=0 files only: p50 10365–245864, p95 21373–259382, p99 21385–569300 µs (samples 59654–59971); the 9 loss>0 files are `null` (note d) | `null` in all 12 files (note d) | `null` in all 5 files (note d) | echo RTT/2: p50 264–78842, p95 265–149940, p99 266–156286 µs (samples 155–10000; at batch>1 most echoes were still outstanding at the end, see the PT6 table) |
| P4 CPU | 30000–70000 µs; 2.723–3.466 % of wall; cycles `null` (note a) | 0–330000 µs; 0–105.731 % of wall (c1 files: below the 10 ms clock tick; c10-loss0: tick rounding above wall); cycles `null` (note a) | 1700000–2490000 µs; 2.752–4.112 % of wall; cycles `null` (note a) | 10000–7160000 µs; 41.385–79.416 % of wall; cycles `null` (note a) | 10000–42660000 µs; 0.997–99.992 % of wall; cycles `null` (note a) | 50000–140000 µs; 5.3–8.624 % of wall; cycles `null` (note a) |
| P5 memory | rss_peak 4689920–6045696 bytes; heap peak_live 268692–1317759 bytes | rss_peak 4718592–12226560 bytes; heap peak_live 248093–7265484 bytes | rss_peak 5505024–8065024 bytes; heap peak_live 764308–1852991 bytes | rss_peak 6139904–17551360 bytes; heap peak_live 1459007–10772641 bytes | rss_peak 4747264–304091136 bytes; heap peak_live 252796–291951355 bytes | rss_peak 4956160–5283840 bytes; heap peak_live 443063–698260 bytes |
| P6 allocations | alloc_count 56242–141351; allocated_bytes 22164924–301847062 bytes; peak_live_bytes 268692–1317759 bytes | alloc_count 616–128409; allocated_bytes 338396–87571107 bytes; peak_live_bytes 248093–7265484 bytes | alloc_count 4052311–4797551; allocated_bytes 9281462313–9822644869 bytes; peak_live_bytes 764308–1852991 bytes | alloc_count 7211–10222606; allocated_bytes 6736575–9721149416 bytes; peak_live_bytes 1459007–10772641 bytes | alloc_count 10140–1058976; allocated_bytes 3249273–4503125404 bytes; peak_live_bytes 252796–291951355 bytes | alloc_count 84432–250710; allocated_bytes 50904966–124478830 bytes; peak_live_bytes 443063–698260 bytes |
| P7 per packet/frame/connection/handshake | packet 56.242–141.351; frame `null` (note b); connection/handshake 56242–141351 | packet `null` (note c); frame `null` (note b); connection/handshake 475.1–1483.8 | packet 75.132–1880.79; frame `null` (note b); connection/handshake 4052311–4797551 | packet `null` (note c); frame `null` (note b); connection/handshake 7211–10222606 | packet 3350.71 (active-max), `null` in the 4 idle files (note c); frame `null` (note b); connection/handshake 711.03–17948.746 | packet 8.443–25.071; frame `null` (note b); connection/handshake 84432–250710 |
| P8 queue depth/backpressure | max_depth 7–302; drop 0; backpressure 0 | max_depth 0; drop 0–131 (netem); backpressure 0 | max_depth 9–489; drop 0–2708; backpressure 0–228961 | max_depth 0; drop 0; backpressure 0 | max_depth 0; drop 0; backpressure 0 | max_depth 0; drop 0; backpressure 0 |

Null and zero notes (every quoted reason string is verbatim from the JSONs):

- (a) `cpu.cycles` is `null` in **all 51 files**, reason `perf stat cycles
  not collected by this run`; no `results/perf-cycles.tsv` was produced. The
  P4 route reported here is the `getrusage` route (`cpu_time_micros` +
  `cpu_percent`).
- (b) `alloc_per.frame` is `null` in **all 51 files**, reason `frame-level
  attribution is not measured here; see m3_pt2_frame_codec_zero_alloc`.
- (c) `alloc_per.packet` is `null` in the **28 files that send no DATAGRAMs**
  (12 PS7 + 12 PS9 + 4 PS10-idle); per the harness convention this carries no
  reason field, and the absence of packets is visible in
  `counters.packets_sent = 0`.
- (d) latency is `null` with reason `no latency samples in this scenario` in
  the 12 PS9 and 5 PS10 files (not sampled in stream/idle scenarios, per the
  §1 unit table), and in the 9 PS8 loss>0 files, whose notes add: `latency
  samples suppressed under induced loss: QUIC DATAGRAM echo pairing is FIFO
  and cannot attribute a round trip to a specific send`.
- The zeros in the PS7/PS9/PS10 P1/P2 cells and the `0 µs / 0 %` of the four
  ps7-c1 files are **measured JSON values** (no DATAGRAM payload or sends in
  those scenarios; wall time below the 10 ms clock tick), not placeholders.
- `free_count` trails `alloc_count` by 1–4 in all 51 files (exact per-file
  values in each JSON's `allocations`).

Scenario coverage (51 identifiers; `run.sh` iterates the harness `--list`):

| Gate row | Scenario identifiers | Status |
|---|---|---|
| `M3-PS6` | `ps6-rtt-{10,50,200}-{quic,webtransport}` | harness implemented; measured on xc @ `dc205c3` — 6 files × (5 runs + 1 warmup) |
| `M3-PS7` | `ps7-handshake-c{1,10,100}-loss{0,1,5,10}` | harness implemented; measured on xc @ `dc205c3` — 12 files × (5 runs + 1 warmup) |
| `M3-PS8` | `ps8-datagram-rtt{10,50,200}-loss{0,1,5,10}` | harness implemented; measured on xc @ `dc205c3` — 12 files × (5 runs + 1 warmup) |
| `M3-PS9` | `ps9-stream-{uni,bi}-{1,16}mib-c{1,10,100}` | harness implemented; measured on xc @ `dc205c3` — 12 files × (5 runs + 1 warmup) |
| `M3-PS10` | `ps10-idle-{1,100,1000,10000}`, `ps10-active-max` | harness implemented; measured on xc @ `dc205c3` — 5 files × (5 runs + 1 warmup)；不可行档记录实际上限与原因：idle-1000 → 248/1000 and idle-10000 → 59/10000 handshakes completed before the harness cap (JSON notes + `counters.handshakes`); active-max = 100 sessions (`sessions_requested = sessions_effective = 100`; JSON note: the ladder stops at the first level that cannot echo half its sessions) |
| `M3-PB1` | `pb1-batch-{1,8,32,64}` | harness implemented; measured on xc @ `dc205c3` — 4 files × (5 runs + 1 warmup) |

## 3. Reference rows `M3-PS1`–`PS5` (M2 output, M3 reference)

The repository contains **no M2 benchmark report** at the time this skeleton
was created: `docs/progress-report.md` has no benchmark section and
`measurements/` contains only the three `m3/deps` dependency trees. These rows
are therefore registered as missing references, not as results:

| Gate row | Scenario | Status | GAP |
|---|---|---|---|
| `M3-PS1` | WebRTC handshake (1/10/100 concurrency; 0/1/5/10 % loss) | 引用缺失 | `GAP-M3-PS1-01` |
| `M3-PS2` | RTP TX/RX (fixed bitrate and burst input) | 引用缺失 | `GAP-M3-PS2-01` |
| `M3-PS3` | 1080p30 media payload path (pre-encoded payload) | 引用缺失 | `GAP-M3-PS3-01` |
| `M3-PS4` | 4K media payload path (pre-encoded payload) | 引用缺失 | `GAP-M3-PS4-01` |
| `M3-PS5` | TWCC/NACK under 0/1/5/10 % loss | 引用缺失 | `GAP-M3-PS5-01` |

Each GAP ID is independent; none reuses another row's ID. The rows stay open
until an M2 report (file path + commit) is linked or a later measurement is
commissioned. If the M3 path actually carries RTP, the gate converts these
rows to M3-executed work instead of references.

## 4. Thresholds (`M3-PT1`–`PT6`)

| Item | Status in this baseline report |
|---|---|
| `M3-PT1` completeness | **not claimed**: the matrix cells carry the formal-run medians, but null-with-reason cells remain — `cpu.cycles` (all 51 files), `alloc_per.frame` (all 51 files), `alloc_per.packet` (28 no-DATAGRAM files), latency (9 PS8 loss>0 files, all 12 PS9 files, all 5 PS10 files) — and null-with-reason cells in a real run still fail PT1 |
| `M3-PT2` zero-allocation frame codec | measurement test `m3_pt2_frame_codec_zero_alloc` exists (`crates/rtx-testkit/src/pt2.rs`, run by `cargo test -p rtx-testkit`); it reports a **measured** delta. No “optimization completed” statement is made: `M3-F3` requires the new-decoder fuzz targets first, and those targets do not exist yet |
| `M3-PT3` DATAGRAM allocations/packet | must be measured and recorded per scenario (`datagram-*.json` `alloc_per.packet`); no zero-allocation promise is made |
| `M3-PT4` regression baseline | **this file is now the first baseline**: the formal `xc` run at commit `dc205c3`, 51 result JSONs, medians quoted above. No result here claims “no regression” — there was no earlier baseline to compare against — and a >10 % deterioration against this first baseline requires a waiver |
| `M3-PT5` queue bound | the harness records only its own netem queue depth / drop / backpressure counters (`queue.scope = harness`); it does not certify the P8 product queue limit |
| `M3-PT6` batch comparison | pps measured from `pb1-batch-*.json` (table below); cycles/packet is still `null` — the formal run did not collect `perf stat -e cycles` and no `results/perf-cycles.tsv` exists — so **PT6 is not yet satisfied**; the bottleneck column quotes the JSON notes: `rtx-quic` has no batch syscall, so the batching is harness-side grouping |

### `M3-PT6` bottleneck table (filled from the formal run at `dc205c3`; medians of 5 runs)

| batch | pps | cycles/packet | bottleneck |
|---|---|---|---|
| 1 | 3786.013 | `null` (`perf stat cycles not collected by this run`) | `rtx-quic` has no batch syscall; batch=1 queues 1 datagram per pump round (harness-side grouping, JSON note); 10000/10000 echoes received |
| 8 | 11582.211 | `null` (same reason) | harness-side grouping (JSON note); 8750 datagrams still outstanding at the end (JSON note); 1250/10000 echoes received |
| 32 | 16133.013 | `null` (same reason) | harness-side grouping (JSON note); 9689 datagrams still outstanding at the end (JSON note); 311/10000 echoes received |
| 64 | 17231.635 | `null` (same reason) | harness-side grouping (JSON note); 9845 datagrams still outstanding at the end (JSON note); 155/10000 echoes received |

## 5. Not done in this change (explicit)

- **The perf-cycles sidecar was not collected.** The xc baseline itself has
  been run (formal mode, all 51 scenarios, 5 measured + 1 warmup each, commit
  `dc205c3`), but every JSON records `cpu.cycles: null` (`perf stat cycles
  not collected by this run`) and `results/perf-cycles.tsv` is absent, so the
  cycles route of `M3-P4` and the cycles/packet column of `M3-PT6` stay open.
- **No decoder optimization claim.** The M3-F fuzz targets for the new
  decoders (varint, H3 frame headers, SETTINGS, QPACK, capsule, DATAGRAM
  mapping) are not in the repository; `M3-F3` forbids optimization statements
  before they exist. The PT2 test only measures the frame-codec allocation
  delta.
- **`M3-PS1`–`PS5` references are missing** (GAP IDs in section 3); M3
  coverage of §19 is therefore incomplete.
- **P8 queue limit (PT5)** is measured only from the harness side; this file
  does not endorse the P8 product behaviour.
- **Chrome/Firefox interoperability, embedded profile, release work** are
  other units and are not claimed here.
- Smoke runs are PR evidence only; they are not a baseline and are excluded
  from `benchmarks/m3/results/`.

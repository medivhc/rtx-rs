# M3-P benchmark report (skeleton)

> **Status: skeleton.** This file is the report structure created by the P7
> harness change (`benchmarks/m3`). It contains **no measured numbers**. The
> first M3 baseline is produced on the coordinator's `xc` host with
> `benchmarks/m3/run.sh` in formal mode, after that PR is merged; until then
> every cell below reads “待 xc 基线”. A `--smoke` run is PR evidence that the
> harness works and is never written into this file or into
> `benchmarks/m3/results/`.

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

The gate describes this set as “nine” fields while enumerating ten names
above; this file lists all ten names verbatim. The harness additionally
records `affinity`, `clock_ticks_per_second` and `clock_ticks_source`.

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

All cells are **待 xc 基线**. Empty-with-a-reason cells produced by a real run
must stay `null + reason` in the JSON; they are not filled with `0` or
estimates, and a missing cell means `M3-PT1` is not satisfied.

| Dimension | PS6 RTT | PS7 handshake | PS8 DATAGRAM | PS9 streams | PS10 sessions | PB1 batch |
|---|---|---|---|---|---|---|
| P1 throughput | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 |
| P2 packet rate | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 |
| P3 latency | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 |
| P4 CPU | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 |
| P5 memory | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 |
| P6 allocations | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 |
| P7 per packet/frame/connection/handshake | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 |
| P8 queue depth/backpressure | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 |

Scenario coverage (51 identifiers; `run.sh` iterates the harness `--list`):

| Gate row | Scenario identifiers | Status |
|---|---|---|
| `M3-PS6` | `ps6-rtt-{10,50,200}-{quic,webtransport}` | harness implemented; 待 xc 基线 |
| `M3-PS7` | `ps7-handshake-c{1,10,100}-loss{0,1,5,10}` | harness implemented; 待 xc 基线 |
| `M3-PS8` | `ps8-datagram-rtt{10,50,200}-loss{0,1,5,10}` | harness implemented; 待 xc 基线 |
| `M3-PS9` | `ps9-stream-{uni,bi}-{1,16}mib-c{1,10,100}` | harness implemented; 待 xc 基线 |
| `M3-PS10` | `ps10-idle-{1,100,1000,10000}`, `ps10-active-max` | harness implemented; 待 xc 基线（不可行档记录实际上限与原因） |
| `M3-PB1` | `pb1-batch-{1,8,32,64}` | harness implemented; 待 xc 基线 |

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

| Item | Status in this skeleton |
|---|---|
| `M3-PT1` completeness | **not claimed**: every matrix cell is 待 xc 基线, and null-with-reason cells in a real run still fail PT1 |
| `M3-PT2` zero-allocation frame codec | measurement test `m3_pt2_frame_codec_zero_alloc` exists (`crates/rtx-testkit/src/pt2.rs`, run by `cargo test -p rtx-testkit`); it reports a **measured** delta. No “optimization completed” statement is made: `M3-F3` requires the new-decoder fuzz targets first, and those targets do not exist yet |
| `M3-PT3` DATAGRAM allocations/packet | must be measured and recorded per scenario (`datagram-*.json` `alloc_per.packet`); no zero-allocation promise is made |
| `M3-PT4` regression baseline | **this file has no baseline.** Until one exists, no result may claim “no regression”, and a >10 % deterioration against the first baseline requires a waiver |
| `M3-PT5` queue bound | the harness records only its own netem queue depth / drop / backpressure counters (`queue.scope = harness`); it does not certify the P8 product queue limit |
| `M3-PT6` batch comparison | **empty, pending the xc baseline.** The bottleneck discussion (syscall / crypto / copy) is added after `pb1-batch-*.json` exists |

### `M3-PT6` bottleneck table (to be filled after the xc baseline)

| batch | pps | cycles/packet | bottleneck |
|---|---|---|---|
| 1 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 |
| 8 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 |
| 32 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 |
| 64 | 待 xc 基线 | 待 xc 基线 | 待 xc 基线 |

## 5. Not done in this change (explicit)

- **The xc baseline has not been run.** This file is a skeleton; no numbers
  were produced, and no scenario was measured on the coordinator's host.
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

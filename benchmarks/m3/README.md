# benchmarks/m3 — M3-P benchmark harness

`benchmarks/m3` is the **harness** for gate `M3-P` (`docs/m3-m4-gates.md` §1.4),
not the M3 baseline. It drives the `rtx-quic` facade through the gate's
scenario catalogue on loopback UDP, applies deterministic loss/RTT, records
the `M3-P1`–`P8` dimensions and writes one JSON result per scenario. The
**first M3 baseline is produced on the coordinator's `xc` host** with
`benchmarks/m3/run.sh` in formal mode and committed to
`benchmarks/m3/results/` afterwards; a `--smoke` run is PR evidence only.

## Layout

```
benchmarks/m3/
├── Cargo.toml        # standalone crate: not a workspace member, path deps only
├── Cargo.lock        # committed for reproducible harness builds
├── build.rs          # injects rustc/target/feature metadata
├── run.sh            # one command rebuilds every M3-owned scenario (M3-PM5)
├── src/
│   ├── main.rs       # CLI, global counting allocator, result writing
│   ├── json.rs       # minimal deterministic JSON writer + parser (no serde)
│   ├── meta.rs       # PM3 metadata (commit, rustc, target, CPU, kernel, ...)
│   ├── net.rs        # two-endpoint loopback pump + deterministic netem layer
│   ├── wt.rs         # minimal WebTransport session (SETTINGS + CONNECT + datagrams)
│   ├── scenario.rs   # PS6–PS10 / PB1 catalogue and runners
│   └── result.rs     # per-run metrics, median/min/max aggregate, schema check
├── results/          # formal JSON results (filled on xc; smoke never lands here)
└── README.md
```

## Scenario catalogue

`./benchmarks/m3/target/release/rtx-m3-bench --list` prints the 51 identifiers.

| Gate row | Identifiers | Parameters |
|---|---|---|
| `M3-PS6` | `ps6-rtt-{10,50,200}-{quic,webtransport}` | RTT 10/50/200 ms × QUIC/WebTransport; 1 s at 1000 pps (formal) |
| `M3-PS7` | `ps7-handshake-c{1,10,100}-loss{0,1,5,10}` | cold start, concurrency 1/10/100, loss 0/1/5/10 % |
| `M3-PS8` | `ps8-datagram-rtt{10,50,200}-loss{0,1,5,10}` | negotiated `max_datagram_frame_size`, 1000 pps, 60 s, loss × RTT |
| `M3-PS9` | `ps9-stream-{uni,bi}-{1,16}mib-c{1,10,100}` | uni/bi, 1 MiB/16 MiB, concurrency 1/10/100 |
| `M3-PS10` | `ps10-idle-{1,100,1000,10000}`, `ps10-active-max` | idle tiers and the largest runnable active count |
| `M3-PB1` | `pb1-batch-{1,8,32,64}` | 8 datagrams per pump round, 1000-byte payloads |

`--smoke` reduces durations, packet counts and concurrency (each result carries
`smoke: true` and the effective cap in `notes`). The formal mode uses the gate
parameters verbatim.

### PS8 payload size

The payload is the **negotiated** `max_datagram_frame_size`, read from
`HandshakeInfo::peer_transport_parameters` (transport parameter `0x20`), never
hard-coded. `quinn-proto 0.11.19` rejects a received payload whose length plus
its internal `Datagram` header exceeds that window; the R6-3 evidence measured
that reserve as 32 bytes. For a 1100-byte advertisement the HTTP Datagram is
`1100 - 32 = 1068` bytes and the WebTransport payload is 1067 bytes. Both
numbers (`max_datagram_frame_size`, `datagram_payload_bytes`) and the
derivation are recorded in the JSON.

## Pump and wait mechanism

Both endpoints live in one process and are driven by two loopback UDP sockets.
A `tick` drains the sockets, handles events (accepting inbound connections),
drains `poll_transmit` from both endpoints through the loss/RTT layer, releases
delayed datagrams whose virtual release time has passed, then drains the sockets
again. Protocol time is always an injected `rtx_core::Timestamp` derived from
one monotonic `Instant` captured at construction — the wall clock is never
given to the facade or the simulator.

Waiting never advances protocol state:

- the netem verdict sequence is seeded (`SplitMix64`), so the same seed and
  input sequence reproduce the same decisions;
- delays are expressed as virtual microseconds; the pump wakes when the
  earliest release/deadline is due;
- waits up to 1 ms are handed to the OS scheduler (`thread::sleep`) purely as
  pacing, because `SO_RCVTIMEO` is rounded up to the host timer granularity
  (4–8 ms on CI sandboxes), which would otherwise dominate a 10 ms RTT;
- longer waits use the R6-3-style bounded socket timeout
  (`set_read_timeout(min(deadline, 1 ms))` on the server socket).

The sleep is **not** a protocol clock: every facade call still receives
`Timestamp` values derived from the injected monotonic epoch, and the sleep
duration is never used for a protocol decision.

## Metadata and JSON

Every result carries the `M3-PM3` fields — `commit`, `rustc`, `target`,
`features`, `cpu_model`, `kernel`, `batch`, `loss_percent`, `rtt_micros`,
`seed` — plus `affinity`, `clock_ticks_per_second` and
`clock_ticks_source`. `commit` comes from `RTX_BENCH_COMMIT`, `--commit`,
or `git rev-parse HEAD`; the harness **refuses to write a result without it**
and `run.sh` additionally greps every file.

The document also carries raw per-run measurements, the median/min/max
aggregate and the eight dimensions:

| Dimension | Fields |
|---|---|
| `throughput` | `wire_bytes_per_second`, `payload_bytes_per_second` (both directions) |
| `packet_rate` | `pps` |
| `latency` | `p50/p95/p99_micros`, `measurement_point`, `samples` |
| `cpu` | `wall_micros`, `cpu_time_micros` (`/proc/self/stat` utime+stime), `cpu_percent`, `cycles` (perf sidecar) |
| `memory` | `rss_peak_bytes` (`VmHWM`), `heap_peak_bytes` (allocator peak live) |
| `allocations` | `alloc_count`, `free_count`, `allocated_bytes`, `peak_live_bytes` |
| `alloc_per` | `packet`, `connection`, `handshake`; `frame` is measured by `m3_pt2_frame_codec_zero_alloc` instead |
| `queue` | `max_depth`, `drop_events`, `backpressure_events`, `scope: harness` |

A dimension the run cannot measure is `null` with a `reason`; nothing is filled
with `0` or an estimate. One exception: `alloc_per.packet` is `null` in
scenarios that send no DATAGRAMs and carries no `packet_reason` field; the
absence of packets is visible in `counters.packets_sent` /
`counters.packets_received`. Latency is only sampled when the netem loss is 0,
because FIFO echo pairing cannot attribute a round trip to a specific send
when datagrams are lost; the result notes say so.

CPU time comes from `getrusage`-equivalent `/proc/self/stat` ticks
(`getconf CLK_TCK`, fallback 100 with `clock_ticks_source: fallback`). `perf
stat -e cycles` is **not** collected in the library: `run.sh` optionally wraps
each invocation with perf when it can count cycles and writes
`results/perf-cycles.tsv`; a missing or permission-blocked perf never fails the
run. The JSON keeps `cycles: null` with the command that *would* collect it.

## Smoke vs formal

```bash
./benchmarks/m3/run.sh --smoke --scenario ps6-rtt-10-quic   # PR evidence
./benchmarks/m3/run.sh                                     # formal: 5 runs + 1 warmup -> results/
```

- Smoke output defaults to a `mktemp` directory and is **never** committed.
  PR evidence is the scenario list, per-scenario JSON paths and the smoke tag,
  reproduced in the pull request description.
- Formal mode requires at least 5 measured runs. `run.sh` passes `--runs 5
  --warmup 1`, then verifies every JSON records `runs.measured` and
  `runs.warmup` before accepting it. The harness runs the warmup, then the
  measured runs, and reports median/min/max.
- `--scenario` runs one identifier; its result is `full_suite: false` and must
  not be presented as a full baseline.
- CPU affinity: `taskset` is used when present; otherwise `affinity` in the
  metadata and the run log reads `unavailable`.

## Boundaries (explicitly)

- This directory does **not** produce the M3 baseline. The first baseline is
  the coordinator's `xc` run; `docs/m3-benchmarks.md` is an empty skeleton in
  this change.
- No Chrome/Firefox interoperability, no embedded profile, no M3-F fuzz
  targets, no decoder optimization claim. `M3-F3` forbids calling the decoders
  optimized before those fuzz targets exist; `m3_pt2_frame_codec_zero_alloc`
  only reports a measured delta.
- Loopback UDP is not a network: loss/RTT are injected by the deterministic
  simulator, never by `tc netem` and never by contacting an external host.
- The harness is not a workspace member and does not appear in the workspace
  coverage denominator or the `thumbv7em` check. Its only normal dependencies
  are path dependencies on `rtx-*` and `rtx-testkit`; there is no `tokio`,
  `quinn` (the QUIC engine `quinn-proto` arrives through `rtx-quic`, by design),
  `criterion` or other benchmark framework.
- `rtx-testkit` is test/benchmark-only: no production `rtx-*` crate may list it
  in its normal dependency graph.

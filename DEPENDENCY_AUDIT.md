# RTX Dependency Audit

Audit date: 2026-10-13  
Purpose: decide what to reuse, wrap, port or reimplement for a portable high-performance WebRTC/WebTransport stack.

## 1. Audited revisions

| Project | Revision | Role in audit |
|---|---|---|
| `algesten/str0m` | `634e76bb830e167e2208c6e743acfb4678e2675c` | WebRTC Sans-I/O reference and behavior/performance baseline |
| `webrtc-rs/rtc` | `5573fe50ccca69fb8c72272be60c8adde59b7ef0` | modular WebRTC protocol source and Sans-I/O pipeline reference |
| `quinn-rs/quinn` / `quinn-proto` | `9d729c1b6b7ad30d45d40265037eeeb9d98a7420` | QUIC protocol engine |
| `moq-dev/web-transport` / `web-transport-proto` | `d4e4e458da556ac3033c9b63f6db5110d3ab5adc` | WebTransport/H3 codec and handshake reference |

Pinned source URLs:

- https://github.com/algesten/str0m/tree/634e76bb830e167e2208c6e743acfb4678e2675c
- https://github.com/webrtc-rs/rtc/tree/5573fe50ccca69fb8c72272be60c8adde59b7ef0
- https://github.com/quinn-rs/quinn/tree/9d729c1b6b7ad30d45d40265037eeeb9d98a7420
- https://github.com/moq-dev/web-transport/tree/d4e4e458da556ac3033c9b63f6db5110d3ab5adc

### Audit limitation

The execution container could not resolve GitHub for a normal `git clone`, so this pass used the connected GitHub source interface to inspect pinned manifests and source files. This is a source-level static audit, but it does not yet include local `cargo tree`, cross-compilation, binary-size measurement or runtime allocation tracing. Those are listed as required follow-up experiments below.

## 2. Executive decision matrix

| Source/module | Linux direct reuse | Portable/MCU | Decision |
|---|---:|---:|---|
| str0m `Rtc` | yes | poor | use as baseline/oracle, not portable core |
| str0m BWE/TWCC/media algorithms | yes/reference | selective port | preserve behavior with trace-based differential tests |
| str0m crypto-provider architecture | reference | reference | borrow design ideas, not concrete ownership model |
| webrtc-rs RTP | yes | good port candidate | port/fork early |
| webrtc-rs RTCP | yes | very good port candidate | port/fork early |
| webrtc-rs STUN | yes | good with cleanup | port/fork |
| webrtc-rs SRTP | yes | good with provider adaptation | port/fork |
| webrtc-rs ICE | yes | moderate/high effort | selective fork/port |
| webrtc-rs DTLS | yes | moderate/high effort | fork/adapt after crypto API validation |
| webrtc-rs SCTP/DataChannel | yes | high footprint | Linux direct; embedded only if required |
| webrtc-rs root PeerConnection | yes | poor | not a portable-core dependency |
| quinn-proto | strongly yes | possible `alloc` port | reuse; do not rewrite QUIC |
| web-transport-proto codecs | yes/reference | poor direct fit | use as correctness reference |
| WebTransport/H3 minimal protocol | n/a | good reimplementation target | implement portable slice-based layer |

## 3. str0m

### 3.1 Dependency shape

At the audited revision, the main crate depends on, among others:

```text
str0m
├── str0m-proto
├── is
├── sctp-proto
├── dimpl
├── tracing
├── fastrand
├── combine
├── subtle
├── arrayvec
├── serde
├── time
└── selectable crypto backend
    ├── AWS-LC
    ├── RustCrypto
    ├── OpenSSL
    ├── Apple crypto
    └── Windows CNG
```

Default crypto is AWS-LC. The project already has a useful multi-backend provider architecture.

### 3.2 State-machine API

The core model is strongly suitable as an architectural reference:

```text
Rtc::handle_input(Input)
Rtc::poll_output() -> Output
```

Input distinguishes packet receive and timeout. Output represents runtime work such as transmit, application events and future timeout deadlines. This is a clean Sans-I/O boundary and should influence RTX.

### 3.3 Allocation/ownership behavior

The current code intentionally avoids some unnecessary boxing, but the full engine is heap-oriented:

- media payloads use `Arc<[u8]>` broadly;
- stream/session state uses `HashMap`, `Vec`, and `VecDeque`;
- ICE and other components use `Arc` and standard collections;
- media structures retain owned payloads for retransmission/reordering and frame assembly.

This is appropriate for a general Linux WebRTC stack but incompatible with a small deterministic embedded profile without major surgery.

### 3.4 `no_std` obstacles

Direct uses include:

- `std::time::Instant`;
- `std::net::SocketAddr`;
- `std::collections::*`;
- `std::sync::Arc`;
- `std::io` and OS/backend-specific functionality.

Conclusion: converting the root crate to `no_std` is an architectural port, not a feature-flag patch.

### 3.5 Crypto

The provider design is valuable: multiple crypto backends are already supported and crypto selection is separated from much of the protocol logic. However, portable RTX should avoid requiring `Arc`/dynamic dispatch in the lowest layer; static providers and opaque hardware key handles are more suitable for MCU use.

### 3.6 Decision

Use str0m for:

- WebRTC behavior comparisons;
- BWE/TWCC algorithm reference;
- interoperability;
- Linux benchmarks;
- Sans-I/O API inspiration.

Do not use the whole crate as the portable foundation.

## 4. webrtc-rs/rtc

### 4.1 Workspace modularity

The audited workspace is split into dedicated crates:

```text
rtc-crypto
rtc-datachannel
rtc-dtls
rtc-ice
rtc-interceptor
rtc-media
rtc-mdns
rtc-rtcp
rtc-rtp
rtc-sctp
rtc-sdp
rtc-shared
rtc-srtp
rtc-stun
rtc-turn
```

This makes it substantially more attractive than a monolith for selective reuse/porting.

### 4.2 State-machine API

The root `RTCPeerConnection` implements a `sansio::Protocol` pipeline. The API family uses operations such as:

```text
handle_read
poll_write
handle_event
poll_event
poll_read
handle_write
```

Protocol handlers are composed internally for demux, ICE, DTLS, SRTP, SCTP and endpoint processing. This is close to the desired RTX execution model.

### 4.3 Crypto backend

`rtc-crypto` exposes a provider-neutral `RTCCryptoProvider`. Built-in backends include Ring and AWS-LC-RS, while the public API is intended to permit application-defined providers such as OpenSSL/FIPS/HSM/platform implementations.

This is a strong candidate design source for RTX crypto boundaries.

Potential issue for embedded RTX: the existing stack commonly passes `Arc<dyn RTCCryptoProvider>`. RTX should keep the portable trait boundary allocation-free and permit static dispatch; a Linux adapter can add dynamic dispatch where desirable.

### 4.4 Lightweight protocol crates

#### `rtc-rtcp`

Very small direct dependency set: shared marshal support plus `bytes`. Excellent early port target.

#### `rtc-rtp`

Also relatively small: shared marshal, `bytes`, `rand`, `serde`, `memchr`. Good port target after deciding which optional conveniences are actually needed in the portable crate.

#### `rtc-srtp`

Depends on RTP/RTCP, crypto, shared replay/marshal helpers, `byteorder`, and `bytes`. The algorithmic/state footprint is manageable compared with PeerConnection/SCTP.

#### `rtc-stun`

Sans-I/O oriented and provider-aware, but it still pulls heap/std conveniences such as `bytes`, `url`, random generation and standard collections in stateful components.

### 4.5 Heavier components

#### ICE

Uses Sans-I/O concepts but carries candidate/check state and standard collections/time types. It is suitable for selective porting once RTX has fixed-capacity/alloc-backed table abstractions.

#### DTLS

Provider-neutral direction is promising, but certificate parsing, rustls/rcgen integration and owned handshake state make it a later-stage port.

#### SCTP/DataChannel

SCTP contains hash maps, deques, slabs and multiple queues by nature. Full DataChannel should not be part of the smallest embedded profile.

#### Root PeerConnection

The root crate composes many protocol modules, statistics, transceiver collections, queues and WebRTC-specific object models. It is useful directly on Linux but should not define the portable RTX architecture.

### 4.6 `no_std` obstacles

Across the workspace, direct use of these is common:

- `std::collections::{HashMap, HashSet, VecDeque}`;
- `std::time::{Instant, Duration}`;
- OS/network interface enumeration;
- heap-backed `bytes` types;
- `Arc` in provider/integration paths.

Sans-I/O has already solved the socket/runtime coupling problem, but not the `std`/allocator/resource-bound problem.

### 4.7 Decision

Preferred reuse sequence:

```text
RTCP -> RTP -> STUN/SRTP -> ICE -> DTLS -> SCTP/DataChannel
```

Before copying code, build differential tests against the pinned upstream revision so semantic drift is visible.

## 5. quinn-proto

### 5.1 Why it is strategically important

`quinn-proto` is explicitly the QUIC transport state machine rather than a runtime/socket wrapper. Its connection model consumes connection/endpoint events, emits endpoint/application events, exposes transmit polling and exposes timeout polling/handling.

Relevant API shape includes:

```text
poll_timeout
handle_timeout
handle_event
poll_transmit
```

This is already the correct high-level decomposition for RTX.

### 5.2 Dependencies

The audited `quinn-proto` manifest includes:

```text
bytes
lru-slab
rustc-hash
rand
rand_pcg
slab
tinyvec(alloc)
tracing
optional rustls/ring/aws-lc/qlog/bloom
```

The workspace currently enables `std` for important dependencies such as rustls/tracing, and the source imports `std` directly.

### 5.3 Allocation behavior

QUIC has inherently stateful, variable-size structures. The implementation uses heap-backed collections in critical areas, including:

- DATAGRAM queues (`VecDeque` + `Bytes`);
- send buffers (`VecDeque` + `Bytes`);
- packet-number spaces (`BTreeMap`, `VecDeque`);
- stream state maps/queues;
- connection-ID state;
- token caches (`HashMap`, `VecDeque`, `Arc`, `Mutex` in some support code).

This makes a `no_alloc` QUIC implementation unrealistic for a complete interoperable profile. The relevant embedded target is `no_std + alloc` or a bounded-container fork.

### 5.4 Crypto abstraction

The protocol layer defines crypto session/config traits rather than baking rustls into the entire state machine. This is important: an embedded port can in principle supply an alternative TLS/crypto backend while preserving QUIC logic.

### 5.5 `no_std` obstacles

Primary categories:

1. direct `std` imports for networking/time/collections;
2. `bytes` and dynamic collection ownership;
3. tracing/logging dependencies configured with `std`;
4. rustls integration configured with `std`;
5. assumptions about effectively unbounded stream/reassembly/ACK data structures.

### 5.6 Decision

Linux: reuse directly behind a narrow RTX QUIC facade.

Embedded: do not immediately fork. If a real MCU target requires full QUIC, port upstream `quinn-proto` with resource caps and differential tests. Do not reimplement QUIC from scratch unless the port is proven infeasible.

## 6. web-transport-proto

### 6.1 What it actually is

Despite the `-proto` name, the audited crate is not analogous to `quinn-proto`. Its source tree contains codec/handshake helpers such as:

```text
capsule.rs
connect.rs
frame.rs
huffman.rs
qpack.rs
settings.rs
stream.rs
varint.rs
```

Its direct dependencies include:

```text
bytes
http
sfv
thiserror
tokio(io-util)
url
```

### 6.2 Runtime coupling

Core codec files directly depend on `tokio::io::{AsyncRead, AsyncWrite}` and extension traits. Even QUIC varint parsing and settings/capsule processing are exposed through Tokio I/O helpers.

`ConnectRequest` also owns a `url::Url`, which is useful for application ergonomics but unnecessarily heavy for the lowest portable protocol layer.

### 6.3 Allocation behavior

`Bytes`/`BytesMut`, URL/HTTP types and async stream abstractions imply allocator/runtime coupling at places where a simple slice parser would be sufficient.

### 6.4 Decision

Use the crate as:

- protocol semantics reference;
- interoperability reference;
- source of test vectors/edge cases where licensing and provenance are preserved.

Do not use it as the portable core. Reimplement the small required H3/WebTransport subset on `rtx-wire`, with caller-provided buffers and no Tokio dependency.

## 7. Comparative summary

### State-machine API quality

| Project | Assessment |
|---|---|
| str0m | excellent single-engine Sans-I/O model |
| webrtc-rs/rtc | excellent composable Sans-I/O pipeline, useful modular crates |
| quinn-proto | excellent protocol-engine/runtime split |
| web-transport-proto | primarily async codec/helpers, not a Sans-I/O engine |

### Portable ownership quality

| Project | Assessment |
|---|---|
| str0m | Linux-friendly, broad `Arc`/collections ownership |
| webrtc-rs/rtc | modular but still `bytes`/std/collections heavy |
| quinn-proto | mature ownership optimized for general QUIC, necessarily heap-heavy |
| web-transport-proto | simple but unnecessarily tied to Tokio/Bytes/URL for portable-core use |

### Crypto abstraction quality

| Project | Assessment |
|---|---|
| str0m | strong multi-provider model |
| webrtc-rs/rtc | strong provider-neutral model, best source for RTX interface ideas |
| quinn-proto | strong crypto-session abstraction suitable for alternate TLS backends |
| web-transport-proto | crypto delegated below to QUIC/TLS; not a core concern |

## 8. Reuse categories

### Direct reuse on Linux

- `quinn-proto`;
- possibly `str0m` for a complete WebRTC engine depending on product boundary;
- `webrtc-rs/rtc` modules/root crate where API fit is better;
- current WebTransport implementations for baseline comparison/interoperability tests.

### Wrap behind an RTX facade

- `quinn-proto` first;
- Linux crypto providers;
- Linux buffer ownership and I/O runtime.

### Port/fork selectively

- webrtc-rs RTCP/RTP/STUN/SRTP;
- ICE after resource-table abstractions exist;
- DTLS after crypto-provider validation;
- `quinn-proto` only when a real embedded requirement justifies it.

### Reimplement

- foundational buffer/time/address/wire abstractions;
- portable WebTransport/H3 minimal codecs/state;
- resource-budget layer;
- runtime adapters;
- allocation/benchmark instrumentation.

## 9. Allocation audit targets

Static source review is insufficient to decide hot-path reuse. The next pass must instrument:

```text
alloc_count
free_count
allocated_bytes
peak_live_bytes
allocations_per_packet
allocations_per_frame
allocations_per_handshake
allocations_per_connection
```

Scenarios:

1. WebRTC handshake;
2. RTP RX/TX steady state;
3. SRTP encrypt/decrypt;
4. TWCC/NACK under loss;
5. QUIC handshake;
6. WebTransport DATAGRAM steady state;
7. WebTransport uni/bi stream steady state;
8. 1/100/1,000/10,000 idle connections where practical;
9. concurrent active streams;
10. forced backpressure and bounded-queue overflow.

Desired initial targets, subject to measurement:

```text
RTP header/packet fast path       0 mandatory allocations/packet
RTCP common encode/decode         0 mandatory allocations/packet
SRTP in-place crypt path          0 mandatory allocations/packet
STUN parse common path            0 mandatory allocations/message
WebTransport frame codec          0 mandatory allocations/frame
QUIC DATAGRAM steady state        minimize and measure; do not promise before profiling
```

## 10. Required dynamic follow-up

When full source materialization/network access is available, execute:

```bash
cargo tree -e features
cargo metadata --all-features
cargo build --no-default-features
```

Then target builds, depending on installed toolchains:

```bash
cargo build --target x86_64-unknown-linux-gnu
cargo build --target aarch64-unknown-linux-musl
cargo build --target thumbv7em-none-eabihf --no-default-features
cargo build --target thumbv8m.main-none-eabihf --no-default-features
```

For each candidate crate, produce a blocker table:

```text
crate
├── std closure
├── alloc closure
├── OS closure
├── crypto closure
├── files requiring change
└── estimated port risk
```

## 11. First experiments

### E1 — foundation compile matrix

Validate the four RTX base crates on Linux and a `no_std` target.

### E2 — RTP/RTCP port spike

Port or adapt the smallest webrtc-rs RTP/RTCP subset to `rtx-wire`; compare encoded bytes against upstream test vectors.

### E3 — allocation harness

Create a counting allocator on Linux and benchmark str0m, webrtc-rs and the RTX prototype on identical packet traces.

### E4 — Quinn facade

Drive `quinn-proto` directly without the high-level Quinn connection API, exposing only the subset needed by WebTransport. Measure calls/transmits/timers/allocations.

### E5 — WebTransport codec

Implement QUIC varint + H3 SETTINGS/frame + minimal CONNECT codec without Tokio; verify against moq-dev/web-transport and Chromium interop traces.

### E6 — embedded feasibility gate

Choose one real board/RTOS and answer with measurements:

- available RAM for transport state;
- crypto accelerator capabilities;
- MTU and network stack buffer ownership;
- whether browser-facing WebTransport is actually required on-device;
- maximum simultaneous connections/streams.

Only after E6 should an embedded Quinn fork begin.

## 12. Current recommendation

The highest-leverage architecture is a hybrid, not a rewrite:

```text
WebRTC portable pieces  <- selectively derived/ported from webrtc-rs
WebRTC behavior oracle  <- str0m
QUIC Linux engine       <- quinn-proto
WebTransport/H3 codec   <- RTX portable implementation
runtime/buffer/time      <- RTX-owned
crypto contract          <- RTX-owned, informed by webrtc-rs/str0m
```

This minimizes protocol-risk while retaining control over the two things that matter most for Linux/embedded convergence: memory ownership and execution/runtime boundaries.

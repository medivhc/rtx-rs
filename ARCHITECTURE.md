# RTX Architecture

Status: M0 foundation design  
Scope: portable real-time transport foundation for WebRTC and WebTransport  
Primary targets: x86_64/aarch64 Linux; later high-end MCU/RTOS and embedded Linux

## 1. Architectural decision

RTX does not attempt to build a new monolithic WebRTC/QUIC stack. It separates protocol behavior from runtime, memory ownership, clocks, cryptography and OS I/O so that proven upstream implementations can be reused where they fit and replaced only where their portability or allocation model is incompatible with the target.

The current source audit leads to these decisions:

1. `str0m` is a WebRTC behavioral/performance oracle and Linux option, not the portable core.
2. `webrtc-rs/rtc` is the preferred source of separable WebRTC protocol modules and Sans-I/O design patterns.
3. `quinn-proto` is the preferred QUIC protocol engine on Linux. QUIC will not be rewritten from scratch.
4. MCU QUIC, if required, should be an embedded port/fork of `quinn-proto` with explicit resource caps and a portable TLS/crypto boundary.
5. `web-transport-proto` is used as a protocol-correctness reference, but the portable WebTransport/H3 subset should be implemented as allocation-free/slice-based codec and state-machine crates.
6. `no_std` is not a single target. RTX distinguishes `no_alloc`, `heapless`, `alloc`, and `std` capability tiers.

## 2. Goals

RTX should provide:

- low-latency and high-throughput Linux paths without forcing protocol logic to depend on Tokio;
- Sans-I/O protocol state machines with explicit timer and transmit outputs;
- a packet-buffer abstraction compatible with `BytesMut`, slabs, registered io_uring buffers, static packet pools and DMA buffers;
- cryptography independent of Ring/AWS-LC/OpenSSL/RustCrypto or a specific MCU accelerator;
- explicit, configurable resource budgets for queues, streams, reassembly, retransmission and candidates;
- testability without real sockets or wall-clock time;
- reuse of mature WebRTC and QUIC implementations wherever the portability cost is lower than reimplementation risk.

## 3. Non-goals

M0-M2 do not include:

- a new QUIC implementation;
- new cryptographic primitives;
- a complete browser-compatible PeerConnection implementation from scratch;
- transparent support for every MCU class;
- a general async runtime abstraction;
- application-level media codecs.

## 4. Capability tiers

### Tier A: `no_std + no_alloc`

Suitable for wire formats and deterministic protocol primitives.

Expected crates/components:

- `rtx-core`
- `rtx-wire`
- fixed packet/header parsing
- RTP/RTCP wire codec
- STUN wire codec
- QUIC varint and selected H3 frame codecs
- crypto traits

No heap, no global allocator, no OS handles.

### Tier B: `no_std + heapless`

Suitable for small MCU profiles with compile-time or boot-time resource limits.

Typical components:

- bounded ICE candidate/check tables;
- SRTP replay windows;
- bounded timer structures;
- fixed RTP packet queues;
- fixed retransmission history.

### Tier C: `no_std + alloc`

Suitable for high-end embedded systems where dynamic storage is acceptable but `std`/OS integration is not.

Potential components:

- full ICE;
- DTLS;
- SCTP/DataChannel;
- an embedded QUIC backend;
- WebTransport session state.

Every dynamic structure must still have a configured maximum.

### Tier D: `std`

Linux/server profile. May use:

- Tokio or a custom event loop;
- epoll;
- io_uring;
- `sendmmsg`/`recvmmsg`;
- `Bytes`/`BytesMut`;
- slab/arena allocators;
- AWS-LC/OpenSSL/Ring/RustCrypto.

`std` is an adapter layer, not an assumption in portable protocol APIs.

## 5. Workspace direction

Initial foundation:

```text
rtx/
├── crates/
│   ├── rtx-core
│   ├── rtx-buffer
│   ├── rtx-wire
│   └── rtx-crypto
├── ARCHITECTURE.md
└── DEPENDENCY_AUDIT.md
```

Planned expansion:

```text
rtx/
├── crates/
│   ├── rtx-core
│   ├── rtx-buffer
│   ├── rtx-wire
│   ├── rtx-crypto
│   ├── rtx-stun
│   ├── rtx-ice
│   ├── rtx-rtp
│   ├── rtx-rtcp
│   ├── rtx-srtp
│   ├── rtx-dtls
│   ├── rtx-sctp
│   ├── rtx-webrtc
│   ├── rtx-quic
│   ├── rtx-h3
│   ├── rtx-webtransport
│   ├── rtx-media
│   ├── rtx-linux
│   ├── rtx-embassy
│   ├── rtx-smoltcp
│   └── rtx-testkit
```

## 6. Dependency direction

Portable crates must depend inward only:

```text
              applications
                  │
        ┌─────────┴─────────┐
        │                   │
   rtx-webrtc         rtx-webtransport
        │                   │
        │               rtx-h3
        │                   │
        ├────────┐      rtx-quic facade
        │        │           │
   RTP/RTCP   ICE/DTLS       │
        │        │           │
        └────────┴─────┬─────┘
                       │
       ┌───────────────┼────────────────┐
       │               │                │
   rtx-core        rtx-buffer       rtx-crypto
                       │
                   rtx-wire
```

OS/runtime adapters depend on protocol crates, never the reverse.

## 7. Core state-machine model

Protocol engines must be driveable without sockets or tasks.

Conceptually:

```text
receive packet / timeout / app command
                │
                ▼
        handle_input(...)
                │
                ▼
          protocol state
          /      |      \
         /       |       \
   transmit    event    next timer
```

The portable API must not expose `tokio::io`, `AsyncRead`, `AsyncWrite`, `UdpSocket`, `std::time::Instant`, or runtime task handles.

`rtx-core::ProtocolMachine` defines the minimum shape; individual protocol engines may expose richer typed input/output APIs where necessary.

## 8. Time model

Protocol logic must not use `std::time::Instant` directly.

RTX uses:

```rust
Timestamp(u64) // monotonic microseconds
Duration(u64)  // microseconds
```

The epoch is runtime-specific and meaningless to the protocol layer. Only ordering and duration arithmetic matter.

Runtime mappings:

- Linux: `CLOCK_MONOTONIC` or `CLOCK_MONOTONIC_RAW`;
- Embassy: `embassy_time::Instant` converted at the adapter boundary;
- RTOS/bare metal: hardware timer/tick counter extended to monotonic `u64`.

Rules:

- no wall-clock time in transport algorithms;
- use saturating arithmetic where a malformed or old timestamp must not wrap;
- timer APIs expose absolute `Timestamp` deadlines, not spawned timers.

## 9. Address model

Portable protocols must not depend on `std::net::SocketAddr`. `rtx-core` owns a small address representation:

```rust
IpAddr::V4([u8; 4])
IpAddr::V6([u8; 16])
SocketAddr { ip, port }
```

Runtime adapters perform conversion to/from OS or stack-specific address types.

## 10. Buffer ownership model

The major cross-platform boundary is packet ownership, not async execution.

Protocol crates accept a `PacketBuf`/slice contract rather than hard-coding:

- `Vec<u8>`;
- `BytesMut`;
- `Arc<[u8]>`;
- DMA storage;
- io_uring registered buffers.

The base contract is:

```rust
pub trait PacketBuf {
    fn capacity(&self) -> usize;
    fn len(&self) -> usize;
    fn set_len(&mut self, len: usize) -> Result<(), BufferError>;
    fn as_slice(&self) -> &[u8];
    fn as_mut_slice(&mut self) -> &mut [u8];
}
```

Linux implementations may use arenas/slabs/registered buffers. Embedded implementations may use static packet arrays or DMA-owned blocks.

### Zero-copy policy

“Zero copy” is not an absolute requirement. The policy is:

1. no mandatory copy at API boundaries;
2. parse headers by borrowing slices where lifetimes permit;
3. keep payload ownership separable from metadata;
4. make encryption/decryption in-place;
5. batch OS I/O at the Linux edge;
6. copy only when lifetime, fragmentation, retransmission or codec semantics require ownership.

## 11. Wire-codec model

Portable wire formats use explicit caller-owned buffers:

```rust
Decode<'a>::decode(&'a [u8]) -> (Message<'a>, consumed)
Encode::encode(&self, &mut [u8]) -> written
```

No codec should require Tokio I/O merely to parse a QUIC varint, STUN attribute, H3 frame or RTCP packet.

`rtx-wire::Cursor` and `Writer` are deliberately small; specialized codecs may bypass them when profiling demonstrates a measurable advantage.

## 12. Crypto model

The crypto boundary must support both Linux libraries and hardware-backed embedded implementations.

Requirements:

- provider-neutral;
- no allocation requirement at the trait boundary;
- in-place AEAD;
- caller-owned output buffers;
- opaque private-key handles so keys can remain inside an HSM/secure element;
- no assumption that provider types are dynamically dispatched or reference-counted.

Portable protocols should normally be generic over a provider or own a concrete provider handle chosen by the integration layer. A Linux convenience layer may add `Arc<dyn ...>` if useful, but this must not leak into portable crates.

Candidate providers:

- AWS-LC;
- Ring;
- OpenSSL;
- RustCrypto;
- platform CNG/Security.framework;
- mbedTLS/wolfSSL bridge;
- MCU hardware accelerators/secure elements.

## 13. WebRTC strategy

### Linux

Use `str0m` and `webrtc-rs/rtc` as comparison points. Avoid building an entire PeerConnection stack before lower layers are measured.

### Portable modules

Priority port candidates from `webrtc-rs/rtc`:

1. RTP/RTCP wire and packet structures;
2. SRTP;
3. STUN;
4. ICE;
5. DTLS;
6. SCTP/DataChannel if the target actually requires them.

The root `rtc` PeerConnection is not part of the first portable core because it aggregates many heap-backed queues/maps and `std`-centric support types.

### Media/BWE

`str0m` is a valuable algorithm/behavior reference for media handling, TWCC and bandwidth estimation. Algorithms should be ported only after trace-based comparison tests exist.

## 14. QUIC strategy

### Linux backend

`quinn-proto` is the default QUIC state-machine backend. The higher-level `quinn` runtime is optional.

RTX should build a narrow facade around capabilities actually required by WebTransport:

- endpoint/connection creation;
- handshake events;
- uni/bi streams;
- QUIC DATAGRAM;
- transmit polling;
- timeout polling/handling;
- connection close;
- transport metrics needed by pacing/observability.

Do not mirror the entire Quinn public API.

### Embedded backend

Do not fork immediately. First prove that an MCU-L target needs full QUIC.

If required, port `quinn-proto` in stages:

1. replace `std` imports with `core`/`alloc` equivalents;
2. abstract address and time types;
3. remove/feature-gate tracing and platform verification;
4. provide portable crypto/TLS integration;
5. add explicit limits for streams, ACK state, datagram queues, CIDs and reassembly;
6. replace unbounded maps/deques with bounded or allocator-aware structures;
7. build differential tests against upstream Quinn.

Reimplementing QUIC from scratch is explicitly out of scope unless the fork proves structurally infeasible.

## 15. WebTransport/H3 strategy

The audited `web-transport-proto` crate is primarily codec/handshake support and binds basic parsing to Tokio `AsyncRead`/`AsyncWrite`.

RTX should implement a small portable H3/WebTransport layer using `rtx-wire`, then bind it to the QUIC facade.

Initial subset:

- QUIC varint;
- H3 frame header;
- SETTINGS required by WebTransport;
- minimal QPACK/static/literal forms required by CONNECT;
- extended CONNECT request/response representation without `url::Url` in the core;
- WebTransport stream/session identifiers;
- capsules required by the selected protocol version;
- DATAGRAM mapping.

The exact subset must be driven by browser interop tests, not by trying to implement all of HTTP/3.

## 16. Resource budgeting

Every stateful protocol must expose or document limits. Examples:

```text
MAX_ICE_CANDIDATES
MAX_ICE_PAIRS
MAX_RTP_STREAMS
MAX_REORDERED_PACKETS
MAX_NACK_HISTORY
MAX_QUIC_STREAMS_BIDI
MAX_QUIC_STREAMS_UNI
MAX_QUIC_DATAGRAM_QUEUE_BYTES
MAX_REASSEMBLY_BYTES
MAX_CONNECTION_IDS
MAX_PENDING_TIMERS
```

For embedded profiles, exceeding a limit must produce an explicit backpressure/drop/error outcome; it must never silently grow the heap.

For Linux, limits may be large or allocator-backed, but should still exist to prevent unbounded memory amplification.

## 17. Linux fast path

The protocol layer should be agnostic, while `rtx-linux` may specialize aggressively:

- `recvmmsg`/`sendmmsg` batching;
- io_uring receive/send and registered buffers;
- GRO/GSO where protocol semantics permit;
- per-core connection sharding;
- slab/arena allocation for packet metadata;
- reusable crypto scratch buffers;
- batch decrypt/encrypt experiments;
- no cross-thread handoff on the hot path unless sharding requires it.

The target metric is not “zero allocations everywhere”; it is predictable allocation and zero steady-state allocation on selected packet fast paths where feasible.

## 18. Testing model

### Deterministic protocol tests

Use simulated clocks and packet queues; no real sleeps.

### Differential tests

Compare RTX behavior against upstream libraries for identical traces:

- STUN parsing/validation;
- RTP/RTCP encoding;
- SRTP vectors;
- ICE checks;
- H3/WebTransport handshakes;
- embedded Quinn fork vs upstream Quinn.

### Fuzzing

Fuzz all untrusted wire decoders before optimizing them.

### Interoperability

Required peers:

- Chromium/Chrome WebRTC/WebTransport;
- Firefox where applicable;
- str0m;
- webrtc-rs/rtc;
- Quinn/WebTransport reference implementation.

## 19. Performance metrics

Mandatory benchmark dimensions:

- throughput;
- packet rate;
- p50/p95/p99 latency;
- CPU cycles or CPU%;
- peak resident/live memory;
- allocation count and bytes;
- allocations per packet/frame/connection;
- queue depth and backpressure behavior.

Important scenarios:

- WebRTC handshake;
- RTP TX/RX;
- 1080p30 and 4K media payload paths;
- TWCC/NACK under 0/1/5/10% loss;
- 10/50/200 ms RTT;
- QUIC handshake;
- WebTransport DATAGRAM;
- uni/bi stream throughput;
- many concurrent idle and active sessions.

## 20. Milestones

### M0 — foundation

- freeze core time/address/buffer/wire/crypto contracts;
- CI matrix for `std` and `no_std` targets;
- architecture and dependency audit;
- allocation-counting benchmark harness design.

Exit criterion: foundation crates compile without default features on at least one `no_std` target and with `std` on Linux.

### M1 — wire protocols

- RTP/RTCP;
- STUN;
- QUIC varint/H3 frame primitives;
- test vectors and fuzz targets.

Exit criterion: differential codec tests pass against selected upstream implementations.

### M2 — secure WebRTC transport

- crypto providers for Linux;
- SRTP;
- ICE subset/full ICE decision;
- DTLS integration experiment.

Exit criterion: RTP media can be exchanged with a browser through a minimal interoperable path or a clearly defined remaining gap.

### M3 — QUIC/WebTransport Linux path

- `quinn-proto` backend facade;
- minimal H3/WebTransport handshake;
- browser DATAGRAM and stream interoperability;
- allocation and batching benchmarks.

### M4 — embedded profile

- choose a real MCU-L/RTOS target;
- prove or reject full QUIC requirement;
- port only the required WebRTC/QUIC components;
- enforce resource budgets and measure worst-case memory.

## 21. Immediate implementation order

1. Keep the four foundation crates intentionally small.
2. Add compile-test CI for Linux plus one `no_std` target.
3. Port/implement RTP and RTCP wire codecs first.
4. Add STUN wire codec and crypto-provider conformance tests.
5. Build a Linux benchmark harness with allocation counters.
6. Add a narrow `quinn-proto` adapter and measure WebTransport DATAGRAM/stream paths.
7. Only then decide whether ICE/DTLS/SRTP code is forked from webrtc-rs or rewritten around the new primitives.

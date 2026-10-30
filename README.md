# rtx

Portable, resource-bounded real-time transport building blocks for WebRTC and WebTransport.

This repository currently contains fifteen workspace crates:

- `rtx-core`: time, addresses, state-machine I/O primitives.
- `rtx-buffer`: packet-buffer and buffer-pool contracts.
- `rtx-wire`: allocation-free encode/decode cursors and traits.
- `rtx-crypto`: provider-neutral cryptographic contracts.
- `rtx-crypto-rustcrypto`: RustCrypto-backed `rtx-crypto` provider.
- `rtx-rtp`: allocation-free RTP wire codec.
- `rtx-rtcp`: zero-allocation RTCP wire codec and RFC 4585 feedback.
- `rtx-stun`: STUN messages, typed attributes and trailer attributes.
- `rtx-ice`: bounded ICE candidate/check tables and a sans-IO checklist state machine.
- `rtx-dtls`: DTLS 1.2 record layer and handshake with DTLS-SRTP key export.
- `rtx-srtp`: SRTP/SRTCP AES-CM/HMAC-SHA1-80 protection.
- `rtx-quic`: narrow sans-IO facade over `quinn-proto` for the Linux QUIC path (std-only).
- `rtx-webtransport`: minimal WebTransport over HTTP/3 codecs.
- `rtx-h3`: minimal HTTP/3 codecs (SETTINGS, CONNECT QPACK subset, extended CONNECT).
- `rtx-testkit`: test-only counting allocator and deterministic network simulator.

The portable layer is `no_std` by default. `std` is an adapter capability, not a core requirement.

See `ARCHITECTURE.md` and `DEPENDENCY_AUDIT.md` before adding protocol crates.

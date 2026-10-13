# rtx

Portable, resource-bounded real-time transport building blocks for WebRTC and WebTransport.

This repository skeleton intentionally starts with only four foundation crates:

- `rtx-core`: time, addresses, state-machine I/O primitives.
- `rtx-buffer`: packet-buffer and buffer-pool contracts.
- `rtx-wire`: allocation-free encode/decode cursors and traits.
- `rtx-crypto`: provider-neutral cryptographic contracts.

The portable layer is `no_std` by default. `std` is an adapter capability, not a core requirement.

See `ARCHITECTURE.md` and `DEPENDENCY_AUDIT.md` before adding protocol crates.

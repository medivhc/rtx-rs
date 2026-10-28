#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! Minimal WebTransport over HTTP/3 codec layer (unit R6-2, gate items `M3-H6`,
//! `M3-H7` and `M3-H8`).
//!
//! Scope: session and stream identifiers ([`ids`]), WebTransport capsules
//! ([`capsules`]) and the HTTP Datagram mapping ([`datagram`]). The H3 SETTINGS
//! frame, the minimal QPACK/CONNECT form and the extended CONNECT representation
//! (`M3-H3` to `M3-H5`) belong to a separate unit (`R6-2b`) and are deliberately
//! absent here.
//!
//! The codecs follow the `rtx-wire` model: input is a borrowed slice, output is
//! caller-owned storage, there is no task, no clock, no `url`, and no dependency
//! on `rtx-quic` or `quinn-proto`. No decoder allocates.
//!
//! # Resource budget (`ARCHITECTURE.md` section 16)
//!
//! | Bound | Source | Outcome on violation |
//! |---|---|---|
//! | Capsule payload length | caller-supplied `max_len` on [`capsules::Capsule::decode`] | [`capsules::CapsuleError::TooLarge`] |
//! | `WT_CLOSE_SESSION` message | 1024 bytes (`draft-ietf-webtrans-http3-15` section 6) | [`capsules::CapsuleError::Malformed`] |
//! | HTTP Datagram payload | caller-supplied negotiated `max_datagram_frame_size` (the same value `rtx-quic` reports as `DatagramError::TooLarge { max_len }`) | [`datagram::DatagramError::TooLarge`] |
//! | Session / stream identifiers | 62-bit QUIC stream IDs stored as `u64`; nothing is routed through `usize`, so 32-bit targets cannot truncate | [`ids::IdError::OutOfRange`] |
//!
//! Nothing grows without a bound: every decoder borrows its input, every type is
//! `Copy` or a borrowed view, and the two payload bounds above are supplied by
//! the caller rather than hard-coded here.

pub mod capsules;
pub mod datagram;
pub mod ids;

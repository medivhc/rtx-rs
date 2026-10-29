#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! Minimal HTTP/3 codec layer for the WebTransport subset (unit `R6-2b`,
//! gate items `M3-H3`, `M3-H4` and `M3-H5`).
//!
//! Scope: the SETTINGS payload the WebTransport subset needs ([`settings`]),
//! the minimal QPACK form behind extended CONNECT ([`qpack`]) and the
//! extended CONNECT request/response representation ([`connect`]). Everything
//! is a codec or a borrowed representation: there is no connection state, no
//! stream state and no server-push logic here. The WebTransport capsule and
//! DATAGRAM layer lives in `rtx-webtransport` (`R6-2`, `M3-H6` to `M3-H8`);
//! this crate deliberately does not depend on it, and it does not depend on
//! `rtx-quic` either.
//!
//! The codecs follow the `rtx-wire` model: input is a borrowed slice, output is
//! caller-owned storage, there is no task, no clock, no `url` and no
//! `quinn-proto`. No path allocates. The QUIC varint and the HTTP/3 frame
//! header are reused from [`rtx_wire`] instead of being re-implemented here.
//!
//! # Subset boundary
//!
//! Complete HTTP/3 is not a gate item (`ARCHITECTURE.md` section 15). This
//! crate has no QPACK dynamic table (capacity and blocked streams must stay
//! zero), no complete Huffman *encoder*, no server push and no H3 connection
//! or stream state machine. The QPACK decoder does decode Huffman-encoded
//! literals, because Chrome emits them; the encoder emits non-Huffman literals
//! only, and whether Chrome accepts that encoding is `R6-3` interoperability
//! work, not a claim made here.
//!
//! # Resource budget (`ARCHITECTURE.md` section 16)
//!
//! | Bound | Source | Outcome on violation |
//! |---|---|---|
//! | SETTINGS payload | the borrowed frame payload ([`settings::Settings::decode`]); at most [`settings::MAX_SETTINGS_ITEMS`] identifier/value pairs | [`settings::SettingError::TooManySettings`], or [`settings::SettingError::Wire`] when a varint is truncated |
//! | QPACK field lines per section | [`qpack::MAX_FIELD_LINES`] (64) | [`qpack::QpackError::TooManyFieldLines`] |
//! | QPACK decoded strings | caller-supplied scratch slice passed to [`qpack::FieldSection::next_field`]; a declared or decoded string longer than the scratch is rejected | [`qpack::QpackError::ScratchTooSmall`] |
//! | Extended CONNECT field line | decode scratch of [`connect::MAX_FIELD_LINE_LEN`] (1024) bytes; retained pseudo-header values are copied once into the caller-supplied [`connect::ConnectBuffers`] | [`connect::ConnectError::FieldTooLong`] |
//!
//! Nothing grows without a bound: every decoder borrows its input, every
//! encoder writes into a caller-owned slice, the QPACK string storage is
//! supplied by the caller, and the CONNECT field-line scratch has the compiled
//! cap above.

pub mod connect;
pub mod qpack;
pub mod settings;

#![cfg_attr(not(feature = "std"), no_std)]
//! Wire codec for the Real-time Transport Protocol (`RTP`).
//!
//! This crate decodes and encodes `RTP` packets as defined by [RFC 3550]
//! §5.1, together with the header extension mechanisms of [RFC 8285], on top
//! of the allocation-free [`rtx_wire`] codec contract ([`Decode`] and
//! [`Encode`]).
//!
//! Decoding is zero-copy: every variable-length region of a packet (the
//! contributing source list, the header extension payload and the media
//! payload) borrows directly from the input slice, and re-encoding a decoded
//! packet reproduces its bytes exactly.
//!
//! [RFC 3550]: https://www.rfc-editor.org/rfc/rfc3550
//! [RFC 8285]: https://www.rfc-editor.org/rfc/rfc8285
//!
//! # Packet layout
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|X|  CC   |M|     PT      |       sequence number         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           timestamp                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           synchronization source (SSRC) identifier            |
//! +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//! |            contributing source (CSRC) identifiers             |
//! |                             ....                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! When the extension bit `X` is set, a four-byte extension header
//! (16-bit profile plus a 16-bit length in 32-bit words) and the extension
//! data itself follow the CSRC list.

pub mod extension;
pub mod header;
pub mod packet;

pub use header::Header;
pub use packet::RtpPacket;
pub use rtx_wire::{Decode, Encode, WireError};

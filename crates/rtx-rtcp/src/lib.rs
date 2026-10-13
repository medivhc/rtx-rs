//! Zero-allocation RTCP wire codec (RFC 3550 section 6).
//!
//! This crate parses and serializes RTCP (RTP Control Protocol) packets
//! without any heap allocation: every parsed packet borrows the input
//! buffer, and variable-length regions are kept as verbatim byte slices.
//!
//! Supported packet types:
//!
//! - Sender Report (SR, type 200) and Receiver Report (RR, type 201),
//!   including reception report blocks (RFC 3550 section 6.4).
//! - Source Description (SDES, type 202) with CNAME/NAME/... items
//!   (RFC 3550 section 6.5).
//! - Goodbye (BYE, type 203) with optional reason string
//!   (RFC 3550 section 6.6).
//! - Any other packet type is preserved verbatim as [`RawPacket`], and a
//!   stream of packets is walked by [`CompoundPacket`].
//!
//! # Wire layout (simplified)
//!
//! Every RTCP packet starts with a fixed 4-byte header:
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|  count  |   packet type |         length (32-bit words)  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `length` counts the number of 32-bit words after the header, so the
//! total packet size is `(length + 1) * 4` bytes.
//!
//! # Codec contract
//!
//! Implementations of [`Decode`] borrow the input buffer and return the
//! number of bytes consumed, which may be smaller than the input length
//! (used by [`CompoundPacket`] to walk back-to-back packets).
//! Implementations of [`Encode`] recompute the `length` field so that
//! `encode(decode(bytes))` round-trips for well-formed packets.
//!
//! [`Decode`]: rtx_wire::Decode
//! [`Encode`]: rtx_wire::Encode

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod compound;
pub mod goodbye;
pub mod header;
pub mod packet;
pub mod receiver_report;
pub mod reception_report;
pub mod sdes;
pub mod sender_report;

pub(crate) mod util;

pub use compound::CompoundPacket;
pub use goodbye::Goodbye;
pub use header::{Header, PacketType};
pub use packet::{RawPacket, RtcpPacket};
pub use receiver_report::ReceiverReport;
pub use reception_report::ReceptionReport;
pub use rtx_wire::{Decode, Encode, WireError};
pub use sdes::SourceDescription;
pub use sender_report::SenderReport;

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
//! - Transport-layer feedback (TSFB, type 205) and payload-specific
//!   feedback (PSFB, type 206) per RFC 4585, dispatched on the FMT
//!   value carried in the header `count` field:
//!   - Generic NACK (`FMT=1`, [`Nack`]),
//!   - Rapid Resynchronization Request (`FMT=5`, [`RapidResync`], a
//!     `draft-ietf-avt-rtcp-feedback` leftover deployed in the wild),
//!   - Transport-wide Congestion Control (`FMT=15`, [`Twcc`],
//!     draft-holmer-rmcat-transport-wide-cc-extensions),
//!   - Picture Loss Indication (`FMT=1`, [`Pli`]),
//!   - Slice Loss Indication (`FMT=2`, [`Sli`]),
//!   - Full Intra Request (`FMT=4`, [`Fir`], RFC 5104),
//!   - Receiver Estimated Maximum Bitrate (`FMT=15`, [`Remb`],
//!     draft-alvestrand-rmcat-remb).
//! - Feedback FMT values outside that list (e.g. the RFC 8888
//!   congestion control feedback, TSFB `FMT=11`) stay verbatim as
//!   [`RawPacket`].
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
//! total packet size is `(length + 1) * 4` bytes. For feedback packets
//! the `count` field is overloaded as the FMT value.
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
pub mod fir;
pub mod goodbye;
pub mod header;
pub mod nack;
pub mod packet;
pub mod pli;
pub mod rapid_resync;
pub mod receiver_report;
pub mod reception_report;
pub mod remb;
pub mod sdes;
pub mod sender_report;
pub mod sli;
pub mod twcc;

pub(crate) mod util;

pub use compound::CompoundPacket;
pub use fir::{Fir, FirEntry};
pub use goodbye::Goodbye;
pub use header::{Header, PacketType};
pub use nack::{Nack, NackPair};
pub use packet::{RawPacket, RtcpPacket};
pub use pli::Pli;
pub use rapid_resync::RapidResync;
pub use receiver_report::ReceiverReport;
pub use reception_report::ReceptionReport;
pub use remb::Remb;
pub use rtx_wire::{Decode, Encode, WireError};
pub use sdes::SourceDescription;
pub use sender_report::SenderReport;
pub use sli::{Sli, SliEntry};
pub use twcc::{
    ChunkSymbolIter, PacketStatusChunk, RunLengthChunk, StatusChunkTypeTcc, StatusVectorChunk,
    SymbolSizeTypeTcc, SymbolTypeTcc, Twcc, TwccPacketStatus, TwccRunLengthReport, TwccStatusIter,
    write_run_length_report,
};

//! Transport-wide Congestion Control feedback (PT=205, FMT=15).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|  FMT=15 |    PT=205     |           length              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     SSRC of packet sender                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      SSRC of media source                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      base sequence number     |      packet status count      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                 reference time                | fb pkt. count |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          packet chunk         |         packet chunk          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! .                                                               .
//! .                                                               .
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         packet chunk          |  recv delta   |  recv delta   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! .                                                               .
//! .                                                               .
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           recv delta          |  recv delta   | zero padding  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The report covers packets identified by their *transport-wide*
//! sequence number (the one the RTP header extension stamps on every
//! packet regardless of stream), which is why a single report can
//! cover audio and video together
//! (draft-holmer-rmcat-transport-wide-cc-extensions-01).
//!
//! # Wire format
//!
//! - The fixed part is 20 bytes: both SSRCs, the base sequence number,
//!   the packet status count, a 24-bit reference time and the feedback
//!   packet count.
//! - The **chunk region** packs per-packet status into 2-byte
//!   [`PacketStatusChunk`]s: a run-length chunk repeats one
//!   [`SymbolTypeTcc`] for up to 8191 packets; a status-vector chunk
//!   lists 14 one-bit or 7 two-bit symbols explicitly.
//! - The **recv delta region** follows the chunks: one unsigned byte
//!   per small delta (`0..=255` units of 250 us) or one signed 16-bit
//!   value per large delta. "Not received" and "received without
//!   delta" packets carry no bytes.
//!
//! # Design decisions
//!
//! - **Fully borrowed.** The chunk and delta regions are kept as
//!   verbatim byte slices, so decoding allocates nothing.
//!   [`Twcc::status_iter`] reconstructs the per-packet view
//!   (`seq`, `status`, `delta`) on the fly.
//! - **Padding is lenient.** Like upstream, decoding ignores trailing
//!   bytes: several upstream *unmarshal* vectors claim more padding
//!   bytes than they actually carry (e.g. `example2` ends with `0x03`
//!   but only one byte follows the delta region). Encoding always
//!   re-pads to the 32-bit boundary, so `encode(decode(v))` is
//!   byte-exact for the *marshal* vectors and field-exact for the
//!   *unmarshal* ones.
//! - **Hardening.** A run-length chunk with `run_length == 0` is
//!   rejected (upstream would loop forever on it), and the delta
//!   region must fit inside the `length` field (upstream checks only
//!   the first byte of each delta and can read into padding).
//! - **Trailing chunk.** A chunk that ends exactly at the `length`
//!   boundary is accepted; upstream requires one spare byte after it.

use rtx_wire::{Cursor, Decode, Encode, WireError, Writer};

use crate::header::{Header, PacketType};
use crate::util::{padding_size, write_padding};

/// FMT value of the transport-wide congestion control feedback.
pub const FMT_TWCC: u8 = 15;

/// Size of the fixed part: header, both SSRCs, base sequence number,
/// packet status count, reference time and feedback packet count.
pub const TWCC_FIXED_OCTET_COUNT: usize = 20;

/// Offset of the chunk region (same as the fixed part size).
pub const TWCC_CHUNK_OFFSET: usize = TWCC_FIXED_OCTET_COUNT;

/// Size of one packet status chunk in bytes.
pub const TWCC_STATUS_CHUNK_LENGTH: usize = 2;

/// Number of visible symbols in a status-vector chunk.
pub const TWCC_STATUS_VECTOR_SYMBOLS: usize = 14;

/// [`TWCC_STATUS_VECTOR_SYMBOLS`] as `u16`, for covered-packet counts.
const TWCC_STATUS_VECTOR_SYMBOLS_U16: u16 = 14;

/// Number of visible symbols in a two-bit status-vector chunk.
pub const TWCC_TWO_BIT_SYMBOLS: usize = 7;

/// [`TWCC_TWO_BIT_SYMBOLS`] as `u16`, for covered-packet counts.
const TWCC_TWO_BIT_SYMBOLS_U16: u16 = 7;

/// Maximum run length of a run-length chunk (13 bits).
pub const TWCC_MAX_RUN_LENGTH: u16 = 0x1FFF;

/// Maximum value of the 24-bit reference time.
pub const TWCC_MAX_REFERENCE_TIME: u32 = 0xFF_FFFF;

/// Recv deltas are multiples of 250 us (draft-holmer section 3.1.5).
pub const TWCC_DELTA_SCALE_FACTOR: i64 = 250;

/// Per-packet arrival status (draft-holmer section 3.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
#[repr(u16)]
pub enum SymbolTypeTcc {
    /// The packet was not received.
    #[default]
    PacketNotReceived = 0,
    /// The packet was received; a 1-byte delta follows.
    PacketReceivedSmallDelta = 1,
    /// The packet was received; a 2-byte signed delta follows.
    PacketReceivedLargeDelta = 2,
    /// The packet was received; no delta is carried.
    PacketReceivedWithoutDelta = 3,
}

impl SymbolTypeTcc {
    /// Wire value of the symbol (0..=3).
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            SymbolTypeTcc::PacketNotReceived => 0,
            SymbolTypeTcc::PacketReceivedSmallDelta => 1,
            SymbolTypeTcc::PacketReceivedLargeDelta => 2,
            SymbolTypeTcc::PacketReceivedWithoutDelta => 3,
        }
    }

    /// Number of recv-delta bytes this symbol contributes.
    #[must_use]
    pub const fn delta_octets(self) -> usize {
        match self {
            SymbolTypeTcc::PacketNotReceived | SymbolTypeTcc::PacketReceivedWithoutDelta => 0,
            SymbolTypeTcc::PacketReceivedSmallDelta => 1,
            SymbolTypeTcc::PacketReceivedLargeDelta => 2,
        }
    }
}

impl From<u16> for SymbolTypeTcc {
    /// Maps a 2-bit wire value to a symbol (3 is the reserved slot).
    fn from(value: u16) -> Self {
        match value {
            0 => SymbolTypeTcc::PacketNotReceived,
            1 => SymbolTypeTcc::PacketReceivedSmallDelta,
            2 => SymbolTypeTcc::PacketReceivedLargeDelta,
            _ => SymbolTypeTcc::PacketReceivedWithoutDelta,
        }
    }
}

/// Kind of packet status chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
#[repr(u16)]
pub enum StatusChunkTypeTcc {
    /// A run-length chunk: one status repeated for a run of packets.
    #[default]
    RunLengthChunk = 0,
    /// A status-vector chunk: explicit per-packet symbols.
    StatusVectorChunk = 1,
}

impl StatusChunkTypeTcc {
    /// Wire value of the chunk type (0 or 1).
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            StatusChunkTypeTcc::RunLengthChunk => 0,
            StatusChunkTypeTcc::StatusVectorChunk => 1,
        }
    }
}

impl From<u16> for StatusChunkTypeTcc {
    /// Maps the leading chunk bit to a chunk type.
    fn from(value: u16) -> Self {
        match value {
            0 => StatusChunkTypeTcc::RunLengthChunk,
            _ => StatusChunkTypeTcc::StatusVectorChunk,
        }
    }
}

/// Symbol width inside a status-vector chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
#[repr(u16)]
pub enum SymbolSizeTypeTcc {
    /// 14 one-bit symbols: received / not received.
    #[default]
    OneBit = 0,
    /// 7 two-bit symbols: any [`SymbolTypeTcc`].
    TwoBit = 1,
}

impl SymbolSizeTypeTcc {
    /// Wire value of the symbol size (0 or 1).
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            SymbolSizeTypeTcc::OneBit => 0,
            SymbolSizeTypeTcc::TwoBit => 1,
        }
    }

    /// Number of visible symbols carried by a chunk of this size.
    #[must_use]
    pub const fn visible_symbols(self) -> usize {
        match self {
            SymbolSizeTypeTcc::OneBit => TWCC_STATUS_VECTOR_SYMBOLS,
            SymbolSizeTypeTcc::TwoBit => TWCC_TWO_BIT_SYMBOLS,
        }
    }
}

impl From<u16> for SymbolSizeTypeTcc {
    /// Maps the symbol-size bit to a width.
    fn from(value: u16) -> Self {
        match value {
            0 => SymbolSizeTypeTcc::OneBit,
            _ => SymbolSizeTypeTcc::TwoBit,
        }
    }
}

/// Run-length chunk: `T=0 | S (2 bits) | Run Length (13 bits)`.
///
/// ```text
/// 0                   1
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |T=0| S |       Run Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RunLengthChunk {
    /// Always [`StatusChunkTypeTcc::RunLengthChunk`].
    pub type_tcc: StatusChunkTypeTcc,
    /// Status symbol repeated by this chunk.
    pub packet_status_symbol: SymbolTypeTcc,
    /// Number of consecutive packets with this status (1..=8191).
    pub run_length: u16,
}

impl RunLengthChunk {
    /// Creates a run-length chunk for `run_length` packets of `symbol`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when `run_length` is zero or
    /// exceeds the 13-bit field.
    pub const fn new(
        packet_status_symbol: SymbolTypeTcc,
        run_length: u16,
    ) -> Result<Self, WireError> {
        if run_length == 0 || run_length > TWCC_MAX_RUN_LENGTH {
            return Err(WireError::InvalidValue);
        }
        Ok(RunLengthChunk {
            type_tcc: StatusChunkTypeTcc::RunLengthChunk,
            packet_status_symbol,
            run_length,
        })
    }

    /// Decodes the two chunk bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        let symbol = SymbolTypeTcc::from(u16::from((bytes[0] >> 5) & 0x3));
        let run_length = (u16::from(bytes[0] & 0x1F) << 8) | u16::from(bytes[1]);
        RunLengthChunk {
            type_tcc: StatusChunkTypeTcc::RunLengthChunk,
            packet_status_symbol: symbol,
            run_length,
        }
    }

    /// Encodes the chunk into two bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 2] {
        let word =
            (self.packet_status_symbol.as_u16() << 13) | (self.run_length & TWCC_MAX_RUN_LENGTH);
        let bytes = word.to_be_bytes();
        [bytes[0], bytes[1]]
    }

    /// Number of packets covered by this chunk.
    #[must_use]
    pub const fn covered(&self) -> u16 {
        self.run_length
    }
}

/// Status-vector chunk: `T=1 | S | symbol list (14 bits)`.
///
/// ```text
/// 0                   1
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |T=1|S|       symbol list         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// `symbol_list` is a fixed 14-slot array; for
/// [`SymbolSizeTypeTcc::TwoBit`] only the first
/// [`TWCC_TWO_BIT_SYMBOLS`] slots are meaningful. [`from_bytes`](Self::from_bytes)
/// normalizes the hidden tail to
/// [`SymbolTypeTcc::PacketNotReceived`], and equality compares only
/// the visible prefix, so the hidden slots never leak into
/// comparisons.
#[derive(Debug, Clone, Copy)]
pub struct StatusVectorChunk {
    /// Always [`StatusChunkTypeTcc::StatusVectorChunk`].
    pub type_tcc: StatusChunkTypeTcc,
    /// Symbol width of this chunk.
    pub symbol_size: SymbolSizeTypeTcc,
    /// Up to 14 symbols; slots past the visible prefix are padding.
    pub symbol_list: [SymbolTypeTcc; TWCC_STATUS_VECTOR_SYMBOLS],
}

impl Default for StatusVectorChunk {
    fn default() -> Self {
        StatusVectorChunk {
            type_tcc: StatusChunkTypeTcc::StatusVectorChunk,
            symbol_size: SymbolSizeTypeTcc::OneBit,
            symbol_list: [SymbolTypeTcc::PacketNotReceived; TWCC_STATUS_VECTOR_SYMBOLS],
        }
    }
}

impl PartialEq for StatusVectorChunk {
    /// Compares type, size and the *visible* symbol prefix only.
    fn eq(&self, other: &Self) -> bool {
        self.type_tcc == other.type_tcc
            && self.symbol_size == other.symbol_size
            && self.symbol_list[..self.visible_len()] == other.symbol_list[..other.visible_len()]
    }
}

impl Eq for StatusVectorChunk {}

impl StatusVectorChunk {
    /// Decodes the two chunk bytes.
    ///
    /// One-bit chunks yield 14 symbols (6 from the first byte, 8 from
    /// the second); two-bit chunks yield 7 (3 + 4). Unused array slots
    /// are set to [`SymbolTypeTcc::PacketNotReceived`].
    #[must_use]
    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        let symbol_size = SymbolSizeTypeTcc::from(u16::from((bytes[0] >> 6) & 0x1));
        let mut symbol_list = [SymbolTypeTcc::PacketNotReceived; TWCC_STATUS_VECTOR_SYMBOLS];

        match symbol_size {
            SymbolSizeTypeTcc::OneBit => {
                // 6 symbols from the first byte, 8 from the second.
                for i in 0..6u8 {
                    symbol_list[usize::from(i)] =
                        SymbolTypeTcc::from(u16::from((bytes[0] >> (5 - i)) & 0x1));
                }
                for i in 0..8u8 {
                    symbol_list[usize::from(i) + 6] =
                        SymbolTypeTcc::from(u16::from((bytes[1] >> (7 - i)) & 0x1));
                }
            }
            SymbolSizeTypeTcc::TwoBit => {
                // 3 symbols from the first byte, 4 from the second.
                for i in 0..3u8 {
                    symbol_list[usize::from(i)] =
                        SymbolTypeTcc::from(u16::from((bytes[0] >> (4 - 2 * i)) & 0x3));
                }
                for i in 0..4u8 {
                    symbol_list[usize::from(i) + 3] =
                        SymbolTypeTcc::from(u16::from((bytes[1] >> (6 - 2 * i)) & 0x3));
                }
            }
        }

        StatusVectorChunk {
            type_tcc: StatusChunkTypeTcc::StatusVectorChunk,
            symbol_size,
            symbol_list,
        }
    }

    /// Encodes the chunk into two bytes (hidden slots are dropped).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 2] {
        let mut word: u16 = 1 << 15 | (self.symbol_size.as_u16() << 14);
        let visible = self.visible_len();

        match self.symbol_size {
            SymbolSizeTypeTcc::OneBit => {
                // Shift amounts 13, 12, ... down to 0 for the 14 slots.
                let shifts = [13u16, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
                for (symbol, &shift) in self.symbol_list[..visible].iter().zip(&shifts) {
                    word |= symbol.as_u16() << shift;
                }
            }
            SymbolSizeTypeTcc::TwoBit => {
                // Shift amounts 12, 10, ... down to 0 for the 7 slots.
                let shifts = [12u16, 10, 8, 6, 4, 2, 0];
                for (symbol, &shift) in self.symbol_list[..visible].iter().zip(&shifts) {
                    word |= symbol.as_u16() << shift;
                }
            }
        }

        let bytes = word.to_be_bytes();
        [bytes[0], bytes[1]]
    }

    /// Number of meaningful symbols in [`StatusVectorChunk::symbol_list`].
    #[must_use]
    pub const fn visible_len(&self) -> usize {
        self.symbol_size.visible_symbols()
    }

    /// Iterates over the visible symbols.
    pub fn symbols(&self) -> impl Iterator<Item = SymbolTypeTcc> + '_ {
        self.symbol_list[..self.visible_len()].iter().copied()
    }

    /// Number of packets covered by this chunk.
    #[must_use]
    pub const fn covered(&self) -> u16 {
        match self.symbol_size {
            SymbolSizeTypeTcc::OneBit => TWCC_STATUS_VECTOR_SYMBOLS_U16,
            SymbolSizeTypeTcc::TwoBit => TWCC_TWO_BIT_SYMBOLS_U16,
        }
    }
}

/// One packet status chunk, in either encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketStatusChunk {
    /// Run-length encoded chunk.
    RunLength(RunLengthChunk),
    /// Status-vector encoded chunk.
    StatusVector(StatusVectorChunk),
}

/// Iterator over the status symbols covered by a [`PacketStatusChunk`].
#[derive(Debug, Clone)]
pub struct ChunkSymbolIter {
    chunk: PacketStatusChunk,
    yielded: u16,
}

impl Iterator for ChunkSymbolIter {
    type Item = SymbolTypeTcc;

    fn next(&mut self) -> Option<Self::Item> {
        if self.yielded >= self.chunk.covered() {
            return None;
        }
        let index = usize::from(self.yielded);
        self.yielded += 1;
        Some(match &self.chunk {
            PacketStatusChunk::RunLength(chunk) => chunk.packet_status_symbol,
            // `covered()` for a vector chunk is its visible length, so
            // the index always lands inside the visible prefix.
            PacketStatusChunk::StatusVector(chunk) => chunk.symbol_list[index],
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.chunk.covered().saturating_sub(self.yielded));
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ChunkSymbolIter {}

impl PacketStatusChunk {
    /// Decodes the two chunk bytes, dispatching on the leading bit.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        if StatusChunkTypeTcc::from(u16::from(bytes[0] >> 7)) == StatusChunkTypeTcc::RunLengthChunk
        {
            PacketStatusChunk::RunLength(RunLengthChunk::from_bytes(bytes))
        } else {
            PacketStatusChunk::StatusVector(StatusVectorChunk::from_bytes(bytes))
        }
    }

    /// Encodes the chunk into two bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 2] {
        match self {
            PacketStatusChunk::RunLength(chunk) => chunk.to_bytes(),
            PacketStatusChunk::StatusVector(chunk) => chunk.to_bytes(),
        }
    }

    /// Iterates over the status symbols this chunk covers.
    #[must_use]
    pub fn symbols(&self) -> ChunkSymbolIter {
        ChunkSymbolIter {
            chunk: *self,
            yielded: 0,
        }
    }

    /// Number of packets covered by this chunk.
    #[must_use]
    pub const fn covered(&self) -> u16 {
        match self {
            PacketStatusChunk::RunLength(chunk) => chunk.covered(),
            PacketStatusChunk::StatusVector(chunk) => chunk.covered(),
        }
    }
}

/// One per-packet entry reconstructed by [`Twcc::status_iter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwccPacketStatus {
    /// Transport-wide sequence number (`base_sequence_number + offset`).
    pub seq: u16,
    /// Arrival status of the packet.
    pub status: SymbolTypeTcc,
    /// Arrival delta in microseconds, when carried.
    pub delta: Option<i64>,
}

/// State of the [`TwccStatusIter`] walk over the chunk region.
#[derive(Debug, Clone, Copy)]
enum IterState {
    /// Decode the next 2-byte chunk.
    Fetch,
    /// Inside a run-length chunk.
    Run {
        /// Repeated symbol.
        symbol: SymbolTypeTcc,
        /// Packets left in the run.
        left: u16,
    },
    /// Inside a status-vector chunk.
    Vector {
        /// Symbols of the chunk (only the visible prefix matters).
        symbols: [SymbolTypeTcc; TWCC_STATUS_VECTOR_SYMBOLS],
        /// Index of the next symbol.
        index: usize,
        /// Symbols left to yield.
        left: usize,
    },
}

/// Read-only iterator over the per-packet status of a [`Twcc`] report.
///
/// Yields one [`TwccPacketStatus`] per packet, in sequence-number
/// order starting at [`Twcc::base_sequence_number`] (wrapping modulo
/// 2^16). `delta` is `Some` exactly for
/// [`SymbolTypeTcc::PacketReceivedSmallDelta`] (1 byte) and
/// [`SymbolTypeTcc::PacketReceivedLargeDelta`] (2 bytes) symbols.
#[derive(Debug, Clone)]
pub struct TwccStatusIter<'a> {
    chunks: &'a [u8],
    deltas: &'a [u8],
    seq: u16,
    remaining: u16,
    state: IterState,
}

impl Iterator for TwccStatusIter<'_> {
    type Item = TwccPacketStatus;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining > 0 {
            match self.state {
                IterState::Fetch => {
                    let bytes = self.chunks.get(..TWCC_STATUS_CHUNK_LENGTH)?;
                    // The chunk is well-formed by construction of `Twcc`.
                    let chunk = PacketStatusChunk::from_bytes([bytes[0], bytes[1]]);
                    self.chunks = &self.chunks[TWCC_STATUS_CHUNK_LENGTH..];
                    match chunk {
                        PacketStatusChunk::RunLength(run) => {
                            self.state = IterState::Run {
                                symbol: run.packet_status_symbol,
                                left: run.run_length,
                            };
                        }
                        PacketStatusChunk::StatusVector(vector) => {
                            self.state = IterState::Vector {
                                symbols: vector.symbol_list,
                                index: 0,
                                left: vector.visible_len(),
                            };
                        }
                    }
                }
                IterState::Run { symbol, left } => {
                    if left == 0 {
                        self.state = IterState::Fetch;
                        continue;
                    }
                    self.state = IterState::Run {
                        symbol,
                        left: left - 1,
                    };
                    self.remaining -= 1;
                    return Some(self.make_status(symbol));
                }
                IterState::Vector {
                    symbols,
                    index,
                    left,
                } => {
                    if left == 0 {
                        self.state = IterState::Fetch;
                        continue;
                    }
                    self.state = IterState::Vector {
                        symbols,
                        index: index + 1,
                        left: left - 1,
                    };
                    self.remaining -= 1;
                    return Some(self.make_status(symbols[index]));
                }
            }
        }
        None
    }
}

impl TwccStatusIter<'_> {
    /// Builds one yielded item, consuming this symbol's delta bytes.
    fn make_status(&mut self, symbol: SymbolTypeTcc) -> TwccPacketStatus {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);

        let (delta, delta_len) = match symbol {
            SymbolTypeTcc::PacketReceivedSmallDelta => (
                self.deltas
                    .get(..1)
                    .map(|b| i64::from(b[0]) * TWCC_DELTA_SCALE_FACTOR),
                1,
            ),
            SymbolTypeTcc::PacketReceivedLargeDelta => (
                self.deltas
                    .get(..2)
                    .map(|b| i64::from(i16::from_be_bytes([b[0], b[1]])) * TWCC_DELTA_SCALE_FACTOR),
                2,
            ),
            _ => (None, 0),
        };
        // `Twcc::decode` guarantees the region holds every delta, but a
        // hand-built `Twcc` may be inconsistent: stop at the region end
        // instead of panicking.
        let consumed = delta_len.min(self.deltas.len());
        self.deltas = &self.deltas[consumed..];

        TwccPacketStatus {
            seq,
            status: symbol,
            delta,
        }
    }
}

/// Transport-wide congestion control feedback, borrowing its regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Twcc<'a> {
    /// SSRC of the packet sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source.
    pub media_ssrc: u32,
    /// Transport-wide sequence number of the first reported packet.
    pub base_sequence_number: u16,
    /// Number of packets covered by this report.
    pub packet_status_count: u16,
    /// 24-bit reference time in 64 ms units.
    pub reference_time: u32,
    /// Feedback packet counter (wraps at 256).
    pub feedback_packet_count: u8,
    /// Raw packet status chunks (2 bytes each), borrowed verbatim.
    pub chunks: &'a [u8],
    /// Raw recv deltas (1 or 2 bytes each), borrowed verbatim.
    pub recv_deltas: &'a [u8],
}

impl Twcc<'_> {
    /// Unpadded wire size (fixed part + chunk region + delta region).
    fn raw_len(&self) -> usize {
        TWCC_CHUNK_OFFSET + self.chunks.len() + self.recv_deltas.len()
    }

    /// Header implied by the current field values.
    ///
    /// `count` is the FMT value (15), never the packet count, and the
    /// padding flag reflects the padding [`Encode::encode`] appends.
    #[must_use]
    pub fn header(&self) -> Header {
        let pad = padding_size(self.raw_len());
        Header {
            padding: pad != 0,
            count: FMT_TWCC,
            packet_type: PacketType::Tsfb,
            length: u16::try_from((self.raw_len() + pad) / 4 - 1).unwrap_or(u16::MAX),
        }
    }

    /// Iterates over the per-packet status, in sequence-number order.
    #[must_use]
    pub fn status_iter(&self) -> TwccStatusIter<'_> {
        TwccStatusIter {
            chunks: self.chunks,
            deltas: self.recv_deltas,
            seq: self.base_sequence_number,
            remaining: self.packet_status_count,
            state: IterState::Fetch,
        }
    }

    /// Encodes the packet into `writer`, padding to the 32-bit
    /// boundary like upstream.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::OutputTooSmall`] when the writer lacks room.
    pub(crate) fn write_to(&self, writer: &mut Writer<'_>) -> Result<(), WireError> {
        let pad = padding_size(self.raw_len());
        let length =
            u16::try_from((self.raw_len() + pad) / 4 - 1).map_err(|_| WireError::Overflow)?;
        let header = Header {
            padding: pad != 0,
            count: FMT_TWCC,
            packet_type: PacketType::Tsfb,
            length,
        };
        header.write_to(writer)?;

        writer.u32_be(self.sender_ssrc)?;
        writer.u32_be(self.media_ssrc)?;
        writer.u16_be(self.base_sequence_number)?;
        writer.u16_be(self.packet_status_count)?;

        // 24-bit reference time, then the 8-bit feedback packet count.
        writer
            .u8(u8::try_from((self.reference_time >> 16) & 0xFF)
                .map_err(|_| WireError::Overflow)?)?;
        writer
            .u8(u8::try_from((self.reference_time >> 8) & 0xFF).map_err(|_| WireError::Overflow)?)?;
        writer.u8(u8::try_from(self.reference_time & 0xFF).map_err(|_| WireError::Overflow)?)?;
        writer.u8(self.feedback_packet_count)?;

        writer.put(self.chunks)?;
        writer.put(self.recv_deltas)?;

        if pad != 0 {
            write_padding(writer, pad)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for Twcc<'a> {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        if input.len() < TWCC_FIXED_OCTET_COUNT {
            return Err(WireError::UnexpectedEnd);
        }

        let (header, consumed) = Header::decode(input)?;
        if header.packet_type != PacketType::Tsfb || header.count != FMT_TWCC {
            return Err(WireError::InvalidValue);
        }

        // The length field must describe at least the fixed part; bytes
        // beyond it are ignored (the dispatcher slices one sub-packet
        // by the same field, so they only matter for direct calls).
        let total = usize::from(header.length)
            .checked_mul(4)
            .and_then(|words| words.checked_add(consumed))
            .ok_or(WireError::Overflow)?;
        if total < TWCC_FIXED_OCTET_COUNT || input.len() < total {
            return Err(WireError::UnexpectedEnd);
        }

        let mut cursor = Cursor::new(&input[consumed..]);
        let sender_ssrc = cursor.u32_be()?;
        let media_ssrc = cursor.u32_be()?;
        let base_sequence_number = cursor.u16_be()?;
        let packet_status_count = cursor.u16_be()?;
        let reference_time = {
            let bytes = cursor.take(3)?;
            u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8 | u32::from(bytes[2])
        };
        let feedback_packet_count = cursor.u8()?;

        // Walk the chunk region exactly like upstream: stop once
        // `packet_status_count` packets are covered and accumulate the
        // recv-delta octets each chunk implies.
        let mut pos = TWCC_CHUNK_OFFSET;
        let mut processed: u16 = 0;
        let mut delta_octets: usize = 0;
        while processed < packet_status_count {
            if pos + TWCC_STATUS_CHUNK_LENGTH > total {
                return Err(WireError::UnexpectedEnd);
            }
            // Bounds are guaranteed by the check above.
            let b0 = input[pos];
            let b1 = input[pos + 1];

            if StatusChunkTypeTcc::from(u16::from(b0 >> 7)) == StatusChunkTypeTcc::RunLengthChunk {
                let chunk = RunLengthChunk::from_bytes([b0, b1]);
                if chunk.run_length == 0 {
                    // Upstream would loop forever on a zero run.
                    return Err(WireError::InvalidValue);
                }
                let covered = chunk.run_length.min(packet_status_count - processed);
                delta_octets += usize::from(covered) * chunk.packet_status_symbol.delta_octets();
                processed += covered;
            } else {
                let chunk = StatusVectorChunk::from_bytes([b0, b1]);
                for symbol in chunk.symbols() {
                    delta_octets += symbol.delta_octets();
                }
                processed = processed.saturating_add(chunk.covered());
            }
            pos += TWCC_STATUS_CHUNK_LENGTH;
        }

        // The delta region must fit inside the packet; trailing bytes
        // (padding or an upstream padding-count inconsistency) are
        // ignored.
        if pos + delta_octets > total {
            return Err(WireError::UnexpectedEnd);
        }

        let chunks = &input[TWCC_CHUNK_OFFSET..pos];
        let recv_deltas = &input[pos..pos + delta_octets];

        let twcc = Twcc {
            sender_ssrc,
            media_ssrc,
            base_sequence_number,
            packet_status_count,
            reference_time,
            feedback_packet_count,
            chunks,
            recv_deltas,
        };
        Ok((twcc, input.len()))
    }
}

impl Encode for Twcc<'_> {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        self.raw_len() + padding_size(self.raw_len())
    }

    fn encode(&self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let mut writer = Writer::new(output);
        self.write_to(&mut writer)?;
        Ok(writer.offset())
    }
}

/// Parameters of a minimal single-run-length TWCC report, consumed by
/// [`write_run_length_report`].
///
/// The report covers `run_length` packets starting at
/// `base_sequence_number`, all sharing one status `symbol`, with the
/// recv delta bytes taken verbatim from `recv_deltas` (one byte per
/// small delta, two per large delta, none otherwise). The
/// `packet_status_count` is derived as `run_length`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwccRunLengthReport<'a> {
    /// SSRC of the packet sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source.
    pub media_ssrc: u32,
    /// Transport-wide sequence number of the first reported packet.
    pub base_sequence_number: u16,
    /// 24-bit reference time in 64 ms units.
    pub reference_time: u32,
    /// Feedback packet counter (wraps at 256).
    pub feedback_packet_count: u8,
    /// Status shared by every packet in the run.
    pub symbol: SymbolTypeTcc,
    /// Number of packets covered (also the `packet_status_count`).
    pub run_length: u16,
    /// Raw recv deltas, borrowed verbatim.
    pub recv_deltas: &'a [u8],
}

impl Default for TwccRunLengthReport<'_> {
    fn default() -> Self {
        TwccRunLengthReport {
            sender_ssrc: 0,
            media_ssrc: 0,
            base_sequence_number: 0,
            reference_time: 0,
            feedback_packet_count: 0,
            symbol: SymbolTypeTcc::PacketNotReceived,
            run_length: 1,
            recv_deltas: &[],
        }
    }
}

/// Writes a minimal single-run-length TWCC report.
///
/// # Errors
///
/// - [`WireError::InvalidValue`] when `run_length` is zero or exceeds
///   [`TWCC_MAX_RUN_LENGTH`], `reference_time` exceeds
///   [`TWCC_MAX_REFERENCE_TIME`], or `recv_deltas` does not match the
///   length implied by `symbol` and `run_length`.
/// - [`WireError::OutputTooSmall`] when the writer lacks room.
pub fn write_run_length_report(
    writer: &mut Writer<'_>,
    report: &TwccRunLengthReport<'_>,
) -> Result<(), WireError> {
    let TwccRunLengthReport {
        sender_ssrc,
        media_ssrc,
        base_sequence_number,
        reference_time,
        feedback_packet_count,
        symbol,
        run_length,
        recv_deltas,
    } = *report;

    if run_length == 0 || run_length > TWCC_MAX_RUN_LENGTH {
        return Err(WireError::InvalidValue);
    }
    if reference_time > TWCC_MAX_REFERENCE_TIME {
        return Err(WireError::InvalidValue);
    }
    let expected_delta_len = usize::from(run_length) * symbol.delta_octets();
    if recv_deltas.len() != expected_delta_len {
        return Err(WireError::InvalidValue);
    }

    let chunk = RunLengthChunk::new(symbol, run_length)?;
    let raw_len = TWCC_CHUNK_OFFSET + TWCC_STATUS_CHUNK_LENGTH + recv_deltas.len();
    let pad = padding_size(raw_len);
    let length = u16::try_from((raw_len + pad) / 4 - 1).map_err(|_| WireError::Overflow)?;
    let header = Header {
        padding: pad != 0,
        count: FMT_TWCC,
        packet_type: PacketType::Tsfb,
        length,
    };
    header.write_to(writer)?;

    writer.u32_be(sender_ssrc)?;
    writer.u32_be(media_ssrc)?;
    writer.u16_be(base_sequence_number)?;
    writer.u16_be(run_length)?;
    writer.u8(u8::try_from((reference_time >> 16) & 0xFF).map_err(|_| WireError::Overflow)?)?;
    writer.u8(u8::try_from((reference_time >> 8) & 0xFF).map_err(|_| WireError::Overflow)?)?;
    writer.u8(u8::try_from(reference_time & 0xFF).map_err(|_| WireError::Overflow)?)?;
    writer.u8(feedback_packet_count)?;

    let chunk_bytes = chunk.to_bytes();
    writer.u8(chunk_bytes[0])?;
    writer.u8(chunk_bytes[1])?;
    writer.put(recv_deltas)?;

    if pad != 0 {
        write_padding(writer, pad)?;
    }
    Ok(())
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// Differential vectors: upstream
    /// `rtcp/transport_feedbacks/transport_layer_cc/transport_layer_cc_test.rs:12-16`
    /// (run-length unmarshal, draft-holmer section 3.1.3 examples).
    const RUN_LENGTH_EXAMPLES: [([u8; 2], SymbolTypeTcc, u16); 2] = [
        ([0x00, 0xDD], SymbolTypeTcc::PacketNotReceived, 221),
        ([0x60, 0x18], SymbolTypeTcc::PacketReceivedWithoutDelta, 24),
    ];

    /// Differential vectors: upstream `transport_layer_cc_test.rs:100-104`
    /// (status-vector unmarshal, draft-holmer section 3.1.4 examples).
    const VECTOR_ONE_BIT: [u8; 2] = [0x9F, 0x1C];
    const VECTOR_TWO_BIT: [u8; 2] = [0xCD, 0x50];

    /// Differential vector: upstream `transport_layer_cc_test.rs:294-299`
    /// (unmarshal "example1", 24 bytes).
    const TWCC_UNMARSHAL_1: [u8; 24] = [
        0xaf, 0xcd, 0x0, 0x5, 0xfa, 0x17, 0xfa, 0x17, 0x43, 0x3, 0x2f, 0xa0, 0x0, 0x99, 0x0, 0x1,
        0x3d, 0xe8, 0x2, 0x17, 0x20, 0x1, 0x94, 0x1,
    ];

    /// Differential vector: upstream `transport_layer_cc_test.rs:301-309`
    /// (unmarshal "example2", 28 bytes).
    const TWCC_UNMARSHAL_2: [u8; 28] = [
        0xaf, 0xcd, 0x0, 0x6, 0xfa, 0x17, 0xfa, 0x17, 0x19, 0x3d, 0xd8, 0xbb, 0x1, 0x74, 0x0, 0xe,
        0x45, 0xb1, 0x5a, 0x40, 0xd8, 0x0, 0xf0, 0xff, 0xd0, 0x0, 0x0, 0x3,
    ];

    /// Differential vector: upstream `transport_layer_cc_test.rs:431-437`
    /// (unmarshal "example3": an empty report, 20 bytes).
    const TWCC_UNMARSHAL_3: [u8; 20] = [
        0x8f, 0xcd, 0x0, 0x4, 0x9a, 0xcb, 0x4, 0x42, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0,
    ];

    /// Differential vector: upstream `transport_layer_cc_test.rs:506-512`
    /// (unmarshal "example5", 28 bytes: one-bit vector, 4 small deltas).
    const TWCC_UNMARSHAL_5: [u8; 28] = [
        0xaf, 0xcd, 0x0, 0x6, 0xfa, 0x17, 0xfa, 0x17, 0x19, 0x3d, 0xd8, 0xbb, 0x0, 0x1, 0x0, 0xe,
        0x10, 0x63, 0x6d, 0x0, 0xba, 0x0, 0x10, 0xc, 0xc, 0x10, 0x0, 0x3,
    ];

    /// Differential vector: upstream `transport_layer_cc_test.rs:559-565`
    /// (unmarshal "example6", 32 bytes: two-bit vector + run-length).
    const TWCC_UNMARSHAL_6: [u8; 32] = [
        0xaf, 0xcd, 0x0, 0x7, 0x9b, 0x74, 0xf6, 0x1f, 0x93, 0x71, 0xdc, 0xbc, 0x85, 0x3c, 0x0, 0x9,
        0x63, 0xf9, 0x16, 0xb3, 0xd5, 0x52, 0x0, 0x30, 0x9b, 0xaa, 0x6a, 0xaa, 0x7b, 0x1, 0x9, 0x1,
    ];

    /// Differential vector: upstream `transport_layer_cc_test.rs:597-604`
    /// (marshal "example1", 24 bytes).
    const TWCC_MARSHAL_1: [u8; 24] = [
        0xaf, 0xcd, 0x0, 0x5, 0xfa, 0x17, 0xfa, 0x17, 0x43, 0x3, 0x2f, 0xa0, 0x0, 0x99, 0x0, 0x1,
        0x3d, 0xe8, 0x2, 0x17, 0x20, 0x1, 0x94, 0x1,
    ];

    /// Differential vector: upstream `transport_layer_cc_test.rs:689-696`
    /// (marshal "example2", 28 bytes, 1 padding byte).
    const TWCC_MARSHAL_2: [u8; 28] = [
        0xaf, 0xcd, 0x0, 0x6, 0xfa, 0x17, 0xfa, 0x17, 0x19, 0x3d, 0xd8, 0xbb, 0x1, 0x74, 0x0, 0x2,
        0x45, 0xb1, 0x5a, 0x40, 0xd8, 0x0, 0xf0, 0xff, 0xd0, 0x0, 0x0, 0x1,
    ];

    /// Differential vector: upstream `transport_layer_cc_test.rs:775-782`
    /// (marshal "example3", 32 bytes, no padding).
    const TWCC_MARSHAL_3: [u8; 32] = [
        0x8f, 0xcd, 0x0, 0x7, 0xfa, 0x17, 0xfa, 0x17, 0x19, 0x3d, 0xd8, 0xbb, 0x1, 0x74, 0x0, 0x6,
        0x45, 0xb1, 0x5a, 0x40, 0x40, 0x2, 0x20, 0x4, 0x1f, 0xfe, 0x1f, 0x9a, 0xd0, 0x0, 0xd0, 0x0,
    ];

    /// Differential vector: upstream `transport_layer_cc_test.rs:862-869`
    /// (marshal "example4", 32 bytes, 3 padding bytes).
    const TWCC_MARSHAL_4: [u8; 32] = [
        0xaf, 0xcd, 0x0, 0x7, 0xfa, 0x17, 0xfa, 0x17, 0x19, 0x3d, 0xd8, 0xbb, 0x0, 0x4, 0x0, 0x7,
        0x10, 0x63, 0x6e, 0x1, 0x20, 0x7, 0x4c, 0x24, 0x24, 0x10, 0xc, 0xc, 0x10, 0x0, 0x0, 0x3,
    ];

    /// Differential vector: upstream `transport_layer_cc_test.rs:920-927`
    /// (marshal "example5", 28 bytes, 2 padding bytes).
    const TWCC_MARSHAL_5: [u8; 28] = [
        0xaf, 0xcd, 0x0, 0x6, 0xfa, 0x17, 0xfa, 0x17, 0x19, 0x3d, 0xd8, 0xbb, 0x0, 0x1, 0x0, 0xe,
        0x10, 0x63, 0x6d, 0x0, 0xba, 0x0, 0x10, 0xc, 0xc, 0x10, 0x0, 0x2,
    ];

    /// Differential vector: upstream `transport_layer_cc_test.rs:919-926`
    /// (marshal "example6", 32 bytes, 3 padding bytes).
    const TWCC_MARSHAL_6: [u8; 32] = [
        0xaf, 0xcd, 0x0, 0x7, 0xfa, 0x17, 0xfa, 0x17, 0x43, 0x3, 0x2f, 0xa0, 0x9c, 0x14, 0x0, 0xc,
        0x75, 0x84, 0x20, 0x0, 0xbe, 0xc0, 0xc1, 0x3f, 0x3b, 0x3f, 0x53, 0x90, 0x3b, 0x0, 0x0, 0x3,
    ];

    /// Collects `(seq, status, delta)` tuples for assertions.
    fn statuses(twcc: &Twcc<'_>) -> Vec<(u16, SymbolTypeTcc, Option<i64>)> {
        twcc.status_iter()
            .map(|s| (s.seq, s.status, s.delta))
            .collect()
    }

    // RTCP-TWCC-001 — 差分：上游 run-length chunk 向量（3.1.3 两个例子）双向。
    #[test]
    fn rtcp_twcc_001_run_length_chunk_round_trip() {
        for (bytes, symbol, run_length) in RUN_LENGTH_EXAMPLES {
            let chunk = RunLengthChunk::from_bytes(bytes);
            assert_eq!(chunk.type_tcc, StatusChunkTypeTcc::RunLengthChunk);
            assert_eq!(chunk.packet_status_symbol, symbol);
            assert_eq!(chunk.run_length, run_length);
            assert_eq!(chunk.covered(), run_length);
            assert_eq!(chunk.to_bytes(), bytes);

            let rebuilt = RunLengthChunk::new(symbol, run_length).expect("valid run length");
            assert_eq!(rebuilt, chunk);
        }
    }

    // RTCP-TWCC-002 — 差分：上游 status-vector chunk（3.1.4 1-bit 例子）。
    #[test]
    fn rtcp_twcc_002_status_vector_one_bit_round_trip() {
        let chunk = StatusVectorChunk::from_bytes(VECTOR_ONE_BIT);
        assert_eq!(chunk.type_tcc, StatusChunkTypeTcc::StatusVectorChunk);
        assert_eq!(chunk.symbol_size, SymbolSizeTypeTcc::OneBit);
        assert_eq!(chunk.visible_len(), 14);
        let symbols: Vec<SymbolTypeTcc> = chunk.symbols().collect();
        assert_eq!(
            symbols,
            vec![
                SymbolTypeTcc::PacketNotReceived,
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketNotReceived,
                SymbolTypeTcc::PacketNotReceived,
                SymbolTypeTcc::PacketNotReceived,
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketNotReceived,
                SymbolTypeTcc::PacketNotReceived,
            ]
        );
        assert_eq!(chunk.to_bytes(), VECTOR_ONE_BIT);
    }

    // RTCP-TWCC-003 — 差分：上游 status-vector chunk（3.1.4 2-bit 例子）。
    #[test]
    fn rtcp_twcc_003_status_vector_two_bit_round_trip() {
        let chunk = StatusVectorChunk::from_bytes(VECTOR_TWO_BIT);
        assert_eq!(chunk.symbol_size, SymbolSizeTypeTcc::TwoBit);
        assert_eq!(chunk.visible_len(), 7);
        let symbols: Vec<SymbolTypeTcc> = chunk.symbols().collect();
        assert_eq!(
            symbols,
            vec![
                SymbolTypeTcc::PacketNotReceived,
                SymbolTypeTcc::PacketReceivedWithoutDelta,
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketReceivedSmallDelta,
                SymbolTypeTcc::PacketNotReceived,
                SymbolTypeTcc::PacketNotReceived,
            ]
        );
        assert_eq!(chunk.to_bytes(), VECTOR_TWO_BIT);
    }

    // RTCP-TWCC-004 — 属性：2-bit chunk 的隐藏尾槽归一化且不参与比较。
    #[test]
    fn rtcp_twcc_004_status_vector_hidden_tail_normalized() {
        let a = StatusVectorChunk::from_bytes(VECTOR_TWO_BIT);
        let mut b = a;
        // 改写隐藏的 7..14 槽，不应影响相等性与重新编码。
        b.symbol_list[7] = SymbolTypeTcc::PacketReceivedLargeDelta;
        b.symbol_list[13] = SymbolTypeTcc::PacketReceivedSmallDelta;
        assert_eq!(a, b);
        assert_eq!(a.to_bytes(), b.to_bytes());
        assert_eq!(b.to_bytes(), VECTOR_TWO_BIT);
        assert_eq!(b.symbols().count(), 7);
    }

    // RTCP-TWCC-005 — 差分：上游 unmarshal example1（count=1，单 run + small delta）。
    #[test]
    fn rtcp_twcc_005_upstream_unmarshal_example1() {
        let (twcc, consumed) = Twcc::decode(&TWCC_UNMARSHAL_1).expect("decode TWCC example1");
        assert_eq!(consumed, TWCC_UNMARSHAL_1.len());
        assert_eq!(twcc.sender_ssrc, 4_195_875_351);
        assert_eq!(twcc.media_ssrc, 1_124_282_272);
        assert_eq!(twcc.base_sequence_number, 153);
        assert_eq!(twcc.packet_status_count, 1);
        assert_eq!(twcc.reference_time, 4_057_090);
        assert_eq!(twcc.feedback_packet_count, 23);
        assert_eq!(twcc.chunks, [0x20, 0x01]);
        assert_eq!(twcc.recv_deltas, [0x94]);

        let header = twcc.header();
        assert_eq!(header.packet_type, PacketType::Tsfb);
        assert_eq!(header.count, FMT_TWCC);
        assert_eq!(header.length, 5);
        assert!(header.padding, "example1 carries 1 padding byte");

        assert_eq!(
            statuses(&twcc),
            vec![(153, SymbolTypeTcc::PacketReceivedSmallDelta, Some(37000))]
        );
    }

    // RTCP-TWCC-006 — 差分：上游 unmarshal example2（两个 2-bit 向量 + small/large delta）。
    #[test]
    fn rtcp_twcc_006_upstream_unmarshal_example2() {
        let (twcc, consumed) = Twcc::decode(&TWCC_UNMARSHAL_2).expect("decode TWCC example2");
        assert_eq!(consumed, TWCC_UNMARSHAL_2.len());
        assert_eq!(twcc.media_ssrc, 423_483_579);
        assert_eq!(twcc.base_sequence_number, 372);
        assert_eq!(twcc.packet_status_count, 14);
        assert_eq!(twcc.reference_time, 4_567_386);
        assert_eq!(twcc.feedback_packet_count, 64);
        assert_eq!(twcc.chunks, [0xd8, 0x0, 0xf0, 0xff]);
        assert_eq!(twcc.recv_deltas, [0xd0, 0x0, 0x0]);

        assert_eq!(
            statuses(&twcc),
            vec![
                (372, SymbolTypeTcc::PacketReceivedSmallDelta, Some(52000)),
                (373, SymbolTypeTcc::PacketReceivedLargeDelta, Some(0)),
                (374, SymbolTypeTcc::PacketNotReceived, None),
                (375, SymbolTypeTcc::PacketNotReceived, None),
                (376, SymbolTypeTcc::PacketNotReceived, None),
                (377, SymbolTypeTcc::PacketNotReceived, None),
                (378, SymbolTypeTcc::PacketNotReceived, None),
                (379, SymbolTypeTcc::PacketReceivedWithoutDelta, None),
                (380, SymbolTypeTcc::PacketNotReceived, None),
                (381, SymbolTypeTcc::PacketNotReceived, None),
                (382, SymbolTypeTcc::PacketReceivedWithoutDelta, None),
                (383, SymbolTypeTcc::PacketReceivedWithoutDelta, None),
                (384, SymbolTypeTcc::PacketReceivedWithoutDelta, None),
                (385, SymbolTypeTcc::PacketReceivedWithoutDelta, None),
            ]
        );
    }

    // RTCP-TWCC-007 — 差分：上游 unmarshal example5（1-bit 向量，4 个 small delta）。
    #[test]
    fn rtcp_twcc_007_upstream_unmarshal_example5() {
        let (twcc, _) = Twcc::decode(&TWCC_UNMARSHAL_5).expect("decode TWCC example5");
        assert_eq!(twcc.base_sequence_number, 1);
        assert_eq!(twcc.packet_status_count, 14);
        assert_eq!(twcc.reference_time, 1_074_029);
        assert_eq!(twcc.feedback_packet_count, 0);
        assert_eq!(twcc.chunks, [0xba, 0x0]);
        assert_eq!(twcc.recv_deltas, [0x10, 0xc, 0xc, 0x10]);

        assert_eq!(
            statuses(&twcc),
            vec![
                (1, SymbolTypeTcc::PacketReceivedSmallDelta, Some(4000)),
                (2, SymbolTypeTcc::PacketReceivedSmallDelta, Some(3000)),
                (3, SymbolTypeTcc::PacketReceivedSmallDelta, Some(3000)),
                (4, SymbolTypeTcc::PacketNotReceived, None),
                (5, SymbolTypeTcc::PacketReceivedSmallDelta, Some(4000)),
                (6, SymbolTypeTcc::PacketNotReceived, None),
                (7, SymbolTypeTcc::PacketNotReceived, None),
                (8, SymbolTypeTcc::PacketNotReceived, None),
                (9, SymbolTypeTcc::PacketNotReceived, None),
                (10, SymbolTypeTcc::PacketNotReceived, None),
                (11, SymbolTypeTcc::PacketNotReceived, None),
                (12, SymbolTypeTcc::PacketNotReceived, None),
                (13, SymbolTypeTcc::PacketNotReceived, None),
                (14, SymbolTypeTcc::PacketNotReceived, None),
            ]
        );
    }

    // RTCP-TWCC-008 — 差分：上游 unmarshal example6（2-bit 向量 + run-length，5 small + 1 large）。
    #[test]
    fn rtcp_twcc_008_upstream_unmarshal_example6() {
        let (twcc, _) = Twcc::decode(&TWCC_UNMARSHAL_6).expect("decode TWCC example6");
        assert_eq!(twcc.sender_ssrc, 2_608_133_663);
        assert_eq!(twcc.media_ssrc, 2_473_712_828);
        assert_eq!(twcc.base_sequence_number, 34108);
        assert_eq!(twcc.packet_status_count, 9);
        assert_eq!(twcc.reference_time, 6_551_830);
        assert_eq!(twcc.feedback_packet_count, 179);
        assert_eq!(twcc.chunks, [0xd5, 0x52, 0x0, 0x30]);
        assert_eq!(twcc.recv_deltas, [0x9b, 0xaa, 0x6a, 0xaa, 0x7b, 0x1, 0x9]);

        assert_eq!(
            statuses(&twcc),
            vec![
                (34108, SymbolTypeTcc::PacketReceivedSmallDelta, Some(38750)),
                (34109, SymbolTypeTcc::PacketReceivedSmallDelta, Some(42500)),
                (34110, SymbolTypeTcc::PacketReceivedSmallDelta, Some(26500)),
                (34111, SymbolTypeTcc::PacketReceivedSmallDelta, Some(42500)),
                (34112, SymbolTypeTcc::PacketReceivedSmallDelta, Some(30750)),
                (34113, SymbolTypeTcc::PacketNotReceived, None),
                (34114, SymbolTypeTcc::PacketReceivedLargeDelta, Some(66250)),
                (34115, SymbolTypeTcc::PacketNotReceived, None),
                (34116, SymbolTypeTcc::PacketNotReceived, None),
            ]
        );
    }

    // RTCP-TWCC-009 — 差分：上游 unmarshal example3（count=0 空报告）。
    #[test]
    fn rtcp_twcc_009_upstream_unmarshal_empty_report() {
        let (twcc, consumed) = Twcc::decode(&TWCC_UNMARSHAL_3).expect("decode TWCC example3");
        assert_eq!(consumed, TWCC_UNMARSHAL_3.len());
        assert_eq!(twcc.sender_ssrc, 2_596_996_162);
        assert_eq!(twcc.media_ssrc, 0);
        assert_eq!(twcc.packet_status_count, 0);
        assert!(twcc.chunks.is_empty());
        assert!(twcc.recv_deltas.is_empty());
        assert_eq!(statuses(&twcc), vec![]);
        assert_eq!(twcc.header().length, 4);
    }

    // RTCP-TWCC-010 — 差分：上游 marshal 向量字节级往返（example1）。
    #[test]
    fn rtcp_twcc_010_marshal_example1_byte_exact() {
        let (twcc, _) = Twcc::decode(&TWCC_MARSHAL_1).expect("decode marshal example1");
        let mut output = [0u8; 24];
        let written = twcc.encode(&mut output).expect("encode marshal example1");
        assert_eq!(written, 24);
        assert_eq!(written, twcc.encoded_len());
        assert_eq!(output, TWCC_MARSHAL_1);
    }

    // RTCP-TWCC-011 — 差分：上游 marshal example2 向量内部不一致
    // （count=2 与两个 7 符号向量块矛盾）：解码只保留第一个块及其
    // delta，重新编码补 3 字节填充；一致的 example2 数据在 unmarshal
    // 向量（count=14）中，重新编码仅修正其错误的填充计数字节。
    #[test]
    fn rtcp_twcc_011_marshal_example2_upstream_inconsistency() {
        let (twcc, _) = Twcc::decode(&TWCC_MARSHAL_2).expect("decode marshal example2");
        // count=2：走查在第一个 TwoBit 块（覆盖 7 个包）后就停止。
        assert_eq!(twcc.packet_status_count, 2);
        assert_eq!(twcc.chunks, [0xd8, 0x00]);
        // delta 紧跟第一个块顺序读取：Small→0xf0(60000us)，
        // Large→0xffd0(-12000us)。这与向量"意图"的 52000/0 不同——
        // 上游该向量自身不一致（count 与块数矛盾），unmarshal 结果
        // 同样如此，此处按上游语义差分。
        assert_eq!(twcc.recv_deltas, [0xf0, 0xff, 0xd0]);
        let items: Vec<TwccPacketStatus> = twcc.status_iter().collect();
        assert_eq!(items[0].delta, Some(60000));
        assert_eq!(items[1].delta, Some(-12000));

        let mut output = [0u8; 28];
        let written = twcc.encode(&mut output).expect("encode marshal example2");
        assert_eq!(written, 28);
        // raw = 20 + 2 + 3 = 25 → 3 个填充字节（00 00 03）。
        assert_eq!(&output[25..28], &[0x0, 0x0, 0x3]);

        // 一致的 example2（count=14）重新编码后仅填充计数字节不同：
        // 上游 unmarshal 向量尾字节 0x03 声称 3 个填充字节但只跟 1 字节，
        // 正确值应为 0x01。
        let (twcc, _) = Twcc::decode(&TWCC_UNMARSHAL_2).expect("decode unmarshal example2");
        let mut output = [0u8; 28];
        twcc.encode(&mut output).expect("encode unmarshal example2");
        let mut expected = TWCC_UNMARSHAL_2;
        expected[27] = 0x1;
        assert_eq!(output, expected);
    }

    // RTCP-TWCC-012 — 差分：上游 marshal 向量字节级往返（example3，P=0 无填充）。
    #[test]
    fn rtcp_twcc_012_marshal_example3_byte_exact() {
        let (twcc, _) = Twcc::decode(&TWCC_MARSHAL_3).expect("decode marshal example3");
        let mut output = [0u8; 32];
        let written = twcc.encode(&mut output).expect("encode marshal example3");
        assert_eq!(written, 32);
        assert_eq!(output, TWCC_MARSHAL_3);
        assert!(!twcc.header().padding);
    }

    // RTCP-TWCC-013 — 差分：上游 marshal 向量字节级往返（example4，3 个填充字节）。
    #[test]
    fn rtcp_twcc_013_marshal_example4_byte_exact() {
        let (twcc, _) = Twcc::decode(&TWCC_MARSHAL_4).expect("decode marshal example4");
        assert_eq!(twcc.packet_status_count, 7);
        let mut output = [0u8; 32];
        let written = twcc.encode(&mut output).expect("encode marshal example4");
        assert_eq!(written, 32);
        assert_eq!(output, TWCC_MARSHAL_4);
        assert_eq!(statuses(&twcc).len(), 7);
    }

    // RTCP-TWCC-014 — 差分：上游 marshal 向量字节级往返（example5/6）。
    #[test]
    fn rtcp_twcc_014_marshal_example5_and_6_byte_exact() {
        let (twcc5, _) = Twcc::decode(&TWCC_MARSHAL_5).expect("decode marshal example5");
        let mut output = [0u8; 28];
        twcc5.encode(&mut output).expect("encode marshal example5");
        assert_eq!(output, TWCC_MARSHAL_5);

        let (twcc6, _) = Twcc::decode(&TWCC_MARSHAL_6).expect("decode marshal example6");
        assert_eq!(twcc6.packet_status_count, 12);
        assert_eq!(twcc6.chunks, [0xbe, 0xc0]);
        let mut output = [0u8; 32];
        twcc6.encode(&mut output).expect("encode marshal example6");
        assert_eq!(output, TWCC_MARSHAL_6);
        assert_eq!(statuses(&twcc6).len(), 12);
    }

    // RTCP-TWCC-015 — 差分：上游 RecvDelta 向量（small 0xFF / large 0x7FFF / large 0x8000）。
    #[test]
    fn rtcp_twcc_015_recv_delta_scale_factor() {
        // 上游 `transport_layer_cc_test.rs:191-213` 的三个 RecvDelta 向量，
        // 经 write_run_length_report 构造成单包后解码验证。
        let cases: [(SymbolTypeTcc, &[u8], i64); 3] = [
            (SymbolTypeTcc::PacketReceivedSmallDelta, &[0xFF], 63750), // 255 * 250
            (
                SymbolTypeTcc::PacketReceivedLargeDelta,
                &[0x7F, 0xFF],
                8_191_750,
            ), // 32767 * 250
            (
                SymbolTypeTcc::PacketReceivedLargeDelta,
                &[0x80, 0x00],
                -8_192_000,
            ), // -32768 * 250
        ];
        for (symbol, delta_bytes, want) in cases {
            let mut buf = [0u8; 32];
            let written = {
                let mut writer = Writer::new(&mut buf);
                write_run_length_report(
                    &mut writer,
                    &TwccRunLengthReport {
                        sender_ssrc: 1,
                        media_ssrc: 2,
                        base_sequence_number: 100,
                        reference_time: 12345,
                        feedback_packet_count: 7,
                        symbol,
                        run_length: 1,
                        recv_deltas: delta_bytes,
                    },
                )
                .expect("write delta report");
                writer.offset()
            };
            let (twcc, _) = Twcc::decode(&buf[..written]).expect("decode delta report");
            let items: Vec<TwccPacketStatus> = twcc.status_iter().collect();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].status, symbol);
            assert_eq!(items[0].delta, Some(want), "delta for {symbol:?}");
        }

        // 真实向量中的 small delta：0x94 = 148 → 37000us。
        let (twcc, _) = Twcc::decode(&TWCC_UNMARSHAL_1).expect("decode");
        let items: Vec<TwccPacketStatus> = twcc.status_iter().collect();
        assert_eq!(items[0].delta, Some(37000));

        // 真实向量中的 large delta：0x0000 → 0us。
        let (twcc, _) = Twcc::decode(&TWCC_UNMARSHAL_2).expect("decode");
        let items: Vec<TwccPacketStatus> = twcc.status_iter().collect();
        assert_eq!(items[1].delta, Some(0));
    }

    // RTCP-TWCC-016 — 属性：write_run_length_report 最小构造路径 + 解码往返。
    #[test]
    fn rtcp_twcc_016_write_run_length_report_round_trip() {
        let mut buf = [0u8; 32];
        let mut writer = Writer::new(&mut buf);
        write_run_length_report(
            &mut writer,
            &TwccRunLengthReport {
                sender_ssrc: 0x1122_3344,
                media_ssrc: 0x5566_7788,
                base_sequence_number: 1000,
                reference_time: 0x0012_3456,
                feedback_packet_count: 9,
                symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
                run_length: 3,
                recv_deltas: &[0x0a, 0x14, 0x1e],
            },
        )
        .expect("write run-length report");
        let written = writer.offset();
        // raw = 20 + 2 + 3 = 25 → 3 padding bytes → 28 total。
        assert_eq!(written, 28);

        let (twcc, consumed) = Twcc::decode(&buf[..written]).expect("decode run-length report");
        assert_eq!(consumed, written);
        assert_eq!(twcc.sender_ssrc, 0x1122_3344);
        assert_eq!(twcc.media_ssrc, 0x5566_7788);
        assert_eq!(twcc.base_sequence_number, 1000);
        assert_eq!(twcc.packet_status_count, 3);
        assert_eq!(twcc.reference_time, 0x0012_3456);
        assert_eq!(twcc.feedback_packet_count, 9);
        assert_eq!(twcc.chunks.len(), 2);
        assert_eq!(
            statuses(&twcc),
            vec![
                (1000, SymbolTypeTcc::PacketReceivedSmallDelta, Some(2500)),
                (1001, SymbolTypeTcc::PacketReceivedSmallDelta, Some(5000)),
                (1002, SymbolTypeTcc::PacketReceivedSmallDelta, Some(7500)),
            ]
        );

        // 无 delta 的 run（PacketNotReceived）不允许携带 delta 字节。
        let mut writer = Writer::new(&mut buf);
        assert_eq!(
            write_run_length_report(
                &mut writer,
                &TwccRunLengthReport {
                    sender_ssrc: 1,
                    media_ssrc: 2,
                    base_sequence_number: 0,
                    reference_time: 0,
                    feedback_packet_count: 0,
                    symbol: SymbolTypeTcc::PacketNotReceived,
                    run_length: 4,
                    recv_deltas: &[0x01],
                },
            ),
            Err(WireError::InvalidValue)
        );
    }

    // RTCP-TWCC-017 — 错误路径：write_run_length_report 参数校验。
    #[test]
    fn rtcp_twcc_017_write_run_length_report_validation() {
        let mut buf = [0u8; 32];
        let mut writer = Writer::new(&mut buf);

        // run_length = 0。
        assert_eq!(
            write_run_length_report(
                &mut writer,
                &TwccRunLengthReport {
                    sender_ssrc: 1,
                    media_ssrc: 2,
                    base_sequence_number: 0,
                    reference_time: 0,
                    feedback_packet_count: 0,
                    symbol: SymbolTypeTcc::PacketNotReceived,
                    run_length: 0,
                    recv_deltas: &[],
                },
            ),
            Err(WireError::InvalidValue)
        );
        // run_length 超过 13 位。
        assert_eq!(
            write_run_length_report(
                &mut writer,
                &TwccRunLengthReport {
                    sender_ssrc: 1,
                    media_ssrc: 2,
                    base_sequence_number: 0,
                    reference_time: 0,
                    feedback_packet_count: 0,
                    symbol: SymbolTypeTcc::PacketNotReceived,
                    run_length: TWCC_MAX_RUN_LENGTH + 1,
                    recv_deltas: &[],
                },
            ),
            Err(WireError::InvalidValue)
        );
        // reference_time 超过 24 位。
        assert_eq!(
            write_run_length_report(
                &mut writer,
                &TwccRunLengthReport {
                    sender_ssrc: 1,
                    media_ssrc: 2,
                    base_sequence_number: 0,
                    reference_time: TWCC_MAX_REFERENCE_TIME + 1,
                    feedback_packet_count: 0,
                    symbol: SymbolTypeTcc::PacketNotReceived,
                    run_length: 1,
                    recv_deltas: &[],
                },
            ),
            Err(WireError::InvalidValue)
        );
        // delta 字节数不匹配。
        assert_eq!(
            write_run_length_report(
                &mut writer,
                &TwccRunLengthReport {
                    sender_ssrc: 1,
                    media_ssrc: 2,
                    base_sequence_number: 0,
                    reference_time: 0,
                    feedback_packet_count: 0,
                    symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
                    run_length: 2,
                    recv_deltas: &[0x01],
                },
            ),
            Err(WireError::InvalidValue)
        );
    }

    // RTCP-TWCC-018 — 错误路径：上游错误分支 + 截断 + 硬化（零 run / 越界 delta）。
    #[test]
    fn rtcp_twcc_018_error_paths() {
        // nil / 过短。
        assert_eq!(Twcc::decode(&[]), Err(WireError::UnexpectedEnd));
        assert_eq!(
            Twcc::decode(&TWCC_UNMARSHAL_1[..19]),
            Err(WireError::UnexpectedEnd)
        );

        // 错误 PT（0xce = PSFB）。
        let mut wrong_type = TWCC_UNMARSHAL_1;
        wrong_type[1] = 0xce;
        assert_eq!(Twcc::decode(&wrong_type), Err(WireError::InvalidValue));

        // 错误 FMT（0x81 = FMT 1，即 NACK）。
        let mut wrong_fmt = TWCC_UNMARSHAL_1;
        wrong_fmt[0] = 0x81;
        assert_eq!(Twcc::decode(&wrong_fmt), Err(WireError::InvalidValue));

        // length 字段过小（len=3 → 16 字节 < 20）。
        let mut short_length = TWCC_UNMARSHAL_1;
        short_length[3] = 0x3;
        assert_eq!(Twcc::decode(&short_length), Err(WireError::UnexpectedEnd));

        // length 字段声称更多字节。
        let mut truncated = TWCC_UNMARSHAL_1;
        truncated[3] = 0x6; // len=6 implies 28 bytes, only 24 present
        assert_eq!(Twcc::decode(&truncated), Err(WireError::UnexpectedEnd));

        // count 超出可用字节：count=2 但只有 1 个 chunk。
        let mut missing_chunk = TWCC_UNMARSHAL_1;
        missing_chunk[14] = 0x0;
        missing_chunk[15] = 0x2; // packet_status_count = 2
        assert_eq!(Twcc::decode(&missing_chunk), Err(WireError::UnexpectedEnd));

        // count=1 但 delta 区缺失：把 chunk 符号改成 small delta 且截掉 delta 字节。
        let mut missing_delta = TWCC_UNMARSHAL_1;
        missing_delta[20] = 0x20; // run-length, symbol=1 (small delta)
        missing_delta[3] = 0x4; // len=4 implies 20 bytes: chunk ends at 22 > 20
        assert_eq!(Twcc::decode(&missing_delta), Err(WireError::UnexpectedEnd));

        // 硬化：run_length=0 的 chunk（上游会死循环）。
        let mut zero_run = TWCC_UNMARSHAL_1;
        zero_run[20] = 0x00; // T=0, symbol=0
        zero_run[21] = 0x00; // run_length=0
        assert_eq!(Twcc::decode(&zero_run), Err(WireError::InvalidValue));
    }

    // RTCP-TWCC-019 — 属性：序号回绕（base 接近 u16::MAX）。
    #[test]
    fn rtcp_twcc_019_sequence_number_wraps() {
        let mut buf = [0u8; 28];
        let mut writer = Writer::new(&mut buf);
        write_run_length_report(
            &mut writer,
            &TwccRunLengthReport {
                sender_ssrc: 1,
                media_ssrc: 2,
                base_sequence_number: u16::MAX - 1,
                reference_time: 0,
                feedback_packet_count: 0,
                symbol: SymbolTypeTcc::PacketNotReceived,
                run_length: 4,
                recv_deltas: &[],
            },
        )
        .expect("write wrapping report");
        let written = writer.offset();
        let (twcc, _) = Twcc::decode(&buf[..written]).expect("decode wrapping report");
        let seqs: Vec<u16> = twcc.status_iter().map(|s| s.seq).collect();
        assert_eq!(seqs, vec![u16::MAX - 1, u16::MAX, 0, 1]);
    }
}

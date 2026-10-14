//! Full Intra Request (RFC 5104 section 3.5.1, PT=206, FMT=4).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|  FMT=4  |    PT=206     |           length              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of packet sender                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of media source                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              SSRC                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Seq nr.      |          Reserved (3 bytes)                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! :                              ...                              :
//! ```
//!
//! Each FCI entry is 8 bytes: the SSRC an intra frame is requested
//! from, a sequence number the receiver increments per request (so a
//! sender can ignore retransmitted duplicates), and 3 reserved bytes
//! that MUST be zero on the wire and are ignored on decode.
//!
//! RFC 5104 requires at least one entry, so `length` is at least 3 and
//! this crate rejects shorter packets. The media SSRC is *not*
//! required to be zero (unlike REMB) and is preserved verbatim, which
//! matches the upstream reference vectors.

use rtx_wire::{Cursor, Decode, Encode, WireError, Writer};

use crate::header::{Header, PacketType};

/// FMT value of the full intra request.
pub const FMT_FIR: u8 = 4;

/// Size of one FIR entry (`SSRC` + `Seq nr.` + 3 reserved bytes).
pub const FIR_ENTRY_LENGTH: usize = 8;

/// Offset of the first FIR entry (common header plus both SSRCs).
pub const FIR_ENTRY_OFFSET: usize = 12;

/// Minimum wire size: header, both SSRCs and at least one entry
/// (RFC 5104 section 3.5.1 requires one or more entries).
pub const FIR_MIN_OCTET_COUNT: usize = FIR_ENTRY_OFFSET + FIR_ENTRY_LENGTH;

/// One FIR entry: target SSRC plus request sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FirEntry {
    /// SSRC of the media source an intra frame is requested from.
    pub ssrc: u32,
    /// Sequence number, incremented per request by the receiver.
    pub sequence_number: u8,
}

impl FirEntry {
    /// Creates an entry for `ssrc` with request counter `sequence_number`.
    #[must_use]
    pub const fn new(ssrc: u32, sequence_number: u8) -> Self {
        FirEntry {
            ssrc,
            sequence_number,
        }
    }
}

/// Full Intra Request borrowing its entry region from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fir<'a> {
    /// SSRC of the packet sender (the requesting receiver).
    pub sender_ssrc: u32,
    /// SSRC of the media source.
    pub media_ssrc: u32,
    /// Raw FIR entries (8 bytes each), borrowed verbatim.
    pub entries: &'a [u8],
}

impl Fir<'_> {
    /// Iterates over the FIR entries.
    ///
    /// Each entry decodes infallibly because [`Decode`] for [`Fir`]
    /// guarantees the region length is a multiple of 8.
    pub fn entries(&self) -> impl Iterator<Item = FirEntry> + '_ {
        self.entries
            .chunks_exact(FIR_ENTRY_LENGTH)
            .map(|chunk| FirEntry {
                ssrc: u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                sequence_number: chunk[4],
            })
    }

    /// Header implied by the current field values.
    ///
    /// `count` is the FMT value (4), never the entry count.
    #[must_use]
    pub fn header(&self) -> Header {
        Header {
            padding: false,
            count: FMT_FIR,
            packet_type: PacketType::Psfb,
            length: u16::try_from(self.raw_len() / 4 - 1).unwrap_or(u16::MAX),
        }
    }

    /// Unpadded wire size (common header + both SSRCs + entry region).
    fn raw_len(&self) -> usize {
        FIR_ENTRY_OFFSET + self.entries.len()
    }

    /// Encodes the packet into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the entry region is not
    /// a multiple of 8 bytes or is empty (RFC 5104 requires at least
    /// one entry), and [`WireError::OutputTooSmall`] when the writer
    /// lacks room.
    pub(crate) fn write_to(&self, writer: &mut Writer<'_>) -> Result<(), WireError> {
        if self.entries.len() % FIR_ENTRY_LENGTH != 0 {
            return Err(WireError::InvalidValue);
        }
        if self.entries.is_empty() {
            return Err(WireError::InvalidValue);
        }
        let length = u16::try_from(self.raw_len() / 4 - 1).map_err(|_| WireError::Overflow)?;

        let header = Header {
            padding: false,
            count: FMT_FIR,
            packet_type: PacketType::Psfb,
            length,
        };
        header.write_to(writer)?;

        writer.u32_be(self.sender_ssrc)?;
        writer.u32_be(self.media_ssrc)?;
        writer.put(self.entries)?;
        Ok(())
    }
}

impl<'a> Decode<'a> for Fir<'a> {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        // The buffer must at least hold one full entry (upstream checks
        // this before touching the header).
        if input.len() < FIR_MIN_OCTET_COUNT {
            return Err(WireError::UnexpectedEnd);
        }

        let (header, consumed) = Header::decode(input)?;
        if header.packet_type != PacketType::Psfb || header.count != FMT_FIR {
            return Err(WireError::InvalidValue);
        }

        // The entry count comes from the length field: length = 2 + 2n.
        let total = usize::from(header.length)
            .checked_mul(4)
            .and_then(|words| words.checked_add(consumed))
            .ok_or(WireError::Overflow)?;
        // A length field describing less than one entry is an invalid
        // header (upstream: Error::InvalidHeader); a buffer shorter
        // than the length field claims is a truncated packet.
        if total < FIR_MIN_OCTET_COUNT {
            return Err(WireError::InvalidValue);
        }
        if input.len() < total {
            return Err(WireError::UnexpectedEnd);
        }
        if (total - FIR_ENTRY_OFFSET) % FIR_ENTRY_LENGTH != 0 {
            return Err(WireError::InvalidValue);
        }

        let mut cursor = Cursor::new(&input[consumed..]);
        let sender_ssrc = cursor.u32_be()?;
        let media_ssrc = cursor.u32_be()?;
        let entries = cursor.take(total - FIR_ENTRY_OFFSET)?;

        let fir = Fir {
            sender_ssrc,
            media_ssrc,
            entries,
        };
        Ok((fir, input.len()))
    }
}

impl Encode for Fir<'_> {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        self.raw_len()
    }

    fn encode(&self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let mut writer = Writer::new(output);
        self.write_to(&mut writer)?;
        Ok(writer.offset())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// Differential vector: upstream
    /// `rtcp/payload_feedbacks/full_intra_request/full_intra_request_test.rs:9-17`
    /// ("valid", 20 bytes).
    const FIR_VALID: [u8; 20] = [
        0x84, 0xce, 0x0, 0x4, // v=2, p=0, FMT=4, PSFB, len=4
        0x0, 0x0, 0x0, 0x0, // sender=0
        0x4b, 0xc4, 0xfc, 0xb4, // media=0x4bc4fcb4
        0x12, 0x34, 0x56, 0x78, // entry ssrc=0x12345678
        0x42, 0x0, 0x0, 0x0, // Seqno=0x42, reserved
    ];

    /// Differential vector: upstream `full_intra_request_test.rs:28-38`
    /// ("also valid", 28 bytes: two entries).
    const FIR_ALSO_VALID: [u8; 28] = [
        0x84, 0xce, 0x0, 0x6, // v=2, p=0, FMT=4, PSFB, len=6
        0x0, 0x0, 0x0, 0x0, // sender=0
        0x4b, 0xc4, 0xfc, 0xb4, // media=0x4bc4fcb4
        0x12, 0x34, 0x56, 0x78, // entry 1 ssrc=0x12345678
        0x42, 0x0, 0x0, 0x0, // Seqno=0x42
        0x98, 0x76, 0x54, 0x32, // entry 2 ssrc=0x98765432
        0x57, 0x0, 0x0, 0x0, // Seqno=0x57
    ];

    /// Differential vector: upstream `full_intra_request_test.rs:39-44`
    /// ("packet too short": 4 bytes).
    const FIR_TOO_SHORT: [u8; 4] = [0x0, 0x0, 0x0, 0x0];

    /// Differential vector: upstream `full_intra_request_test.rs:46-57`
    /// ("invalid header": 20 zero bytes, version=0).
    const FIR_INVALID_HEADER: [u8; 20] = [0x0; 20];

    /// Differential vector: upstream `full_intra_request_test.rs:59-67`
    /// ("wrong type": FMT=4 but PT=201 RR).
    const FIR_WRONG_TYPE: [u8; 20] = [
        0x84, 0xc9, 0x0, 0x4, // v=2, p=0, FMT=4, RR, len=4
        0x0, 0x0, 0x0, 0x0, // sender=0
        0x4b, 0xc4, 0xfc, 0xb4, // media=0x4bc4fcb4
        0x12, 0x34, 0x56, 0x78, // entry ssrc=0x12345678
        0x42, 0x0, 0x0, 0x0, // Seqno=0x42
    ];

    /// Differential vector: upstream `full_intra_request_test.rs:69-77`
    /// ("wrong fmt": FMT=2 SLI).
    const FIR_WRONG_FMT: [u8; 20] = [
        0x82, 0xce, 0x0, 0x4, // v=2, p=0, FMT=2, PSFB, len=4
        0x0, 0x0, 0x0, 0x0, // sender=0
        0x4b, 0xc4, 0xfc, 0xb4, // media=0x4bc4fcb4
        0x12, 0x34, 0x56, 0x78, // entry ssrc=0x12345678
        0x42, 0x0, 0x0, 0x0, // Seqno=0x42
    ];

    /// Differential vector: upstream `full_intra_request_test.rs:79-87`
    /// ("wrong length": len=3 implies 16 bytes, less than one entry).
    const FIR_WRONG_LENGTH: [u8; 20] = [
        0x84, 0xce, 0x0, 0x3, // v=2, p=0, FMT=4, PSFB, len=3
        0x0, 0x0, 0x0, 0x0, // sender=0
        0x4b, 0xc4, 0xfc, 0xb4, // media=0x4bc4fcb4
        0x12, 0x34, 0x56, 0x78, // entry ssrc=0x12345678
        0x42, 0x0, 0x0, 0x0, // Seqno=0x42
    ];

    // RTCP-FIR-001 — 差分：上游 "valid" 向量逐字段 + encode 字节级往返。
    #[test]
    fn rtcp_fir_001_upstream_valid_vector_round_trip() {
        let (fir, consumed) = Fir::decode(&FIR_VALID).expect("decode FIR valid");
        assert_eq!(consumed, FIR_VALID.len());
        assert_eq!(fir.sender_ssrc, 0);
        assert_eq!(fir.media_ssrc, 0x4bc4_fcb4);

        let entries: Vec<FirEntry> = fir.entries().collect();
        assert_eq!(
            entries,
            vec![FirEntry {
                ssrc: 0x1234_5678,
                sequence_number: 0x42,
            }]
        );

        let header = fir.header();
        assert_eq!(header.packet_type, PacketType::Psfb);
        assert_eq!(header.count, FMT_FIR);
        assert_eq!(header.length, 4);

        // 上游向量的 length 字段本就是正确值，故字节级全等。
        let mut output = [0u8; 20];
        let written = fir.encode(&mut output).expect("encode FIR valid");
        assert_eq!(written, 20);
        assert_eq!(written, fir.encoded_len());
        assert_eq!(output, FIR_VALID);

        let (again, _) = Fir::decode(&output[..written]).expect("re-decode");
        assert_eq!(again, fir);
    }

    // RTCP-FIR-002 — 差分：上游 "also valid" 向量（两个条目）往返。
    #[test]
    fn rtcp_fir_002_two_entry_round_trip() {
        let (fir, consumed) = Fir::decode(&FIR_ALSO_VALID).expect("decode two-entry FIR");
        assert_eq!(consumed, FIR_ALSO_VALID.len());

        let entries: Vec<FirEntry> = fir.entries().collect();
        assert_eq!(
            entries,
            vec![
                FirEntry::new(0x1234_5678, 0x42),
                FirEntry::new(0x9876_5432, 0x57),
            ]
        );

        let mut output = [0u8; 28];
        let written = fir.encode(&mut output).expect("encode two-entry FIR");
        assert_eq!(written, 28);
        assert_eq!(output, FIR_ALSO_VALID);
    }

    // RTCP-FIR-003 — 差分：上游 roundtrip 用例（默认 SSRC 0，序号递增）。
    #[test]
    fn rtcp_fir_003_upstream_round_trip_cases() {
        // 上游 `full_intra_request_test.rs:108-119` 的两个 roundtrip 用例。
        let raw: [u8; 20] = [
            0x84, 0xce, 0x0, 0x4, 0x0, 0x0, 0x0, 0x1, // sender=1
            0x0, 0x0, 0x0, 0x2, // media=2
            0x0, 0x0, 0x0, 0x3, // entry ssrc=3
            0x2a, 0x0, 0x0, 0x0, // Seqno=42
        ];
        let (fir, _) = Fir::decode(&raw).expect("decode round-trip FIR");
        assert_eq!(fir.sender_ssrc, 1);
        assert_eq!(fir.media_ssrc, 2);
        let entries: Vec<FirEntry> = fir.entries().collect();
        assert_eq!(entries, vec![FirEntry::new(3, 42)]);

        let mut output = [0u8; 20];
        let written = fir.encode(&mut output).expect("encode round-trip FIR");
        assert_eq!(written, 20);
        assert_eq!(output, raw);
    }

    // RTCP-FIR-004 — 差分：上游错误路径（too short / invalid header / nil）。
    #[test]
    fn rtcp_fir_004_upstream_error_paths() {
        assert_eq!(Fir::decode(&FIR_TOO_SHORT), Err(WireError::UnexpectedEnd));
        // 20 个零字节：版本号 0 → Header::decode 报 InvalidValue。
        assert_eq!(
            Fir::decode(&FIR_INVALID_HEADER),
            Err(WireError::InvalidValue)
        );
        assert_eq!(Fir::decode(&[]), Err(WireError::UnexpectedEnd));
    }

    // RTCP-FIR-005 — 差分：上游 wrong type / wrong fmt / wrong length。
    #[test]
    fn rtcp_fir_005_wrong_type_fmt_length_rejected() {
        assert_eq!(Fir::decode(&FIR_WRONG_TYPE), Err(WireError::InvalidValue));
        assert_eq!(Fir::decode(&FIR_WRONG_FMT), Err(WireError::InvalidValue));
        // length=3 描述 16 字节，不足一个完整条目 → InvalidValue。
        assert_eq!(Fir::decode(&FIR_WRONG_LENGTH), Err(WireError::InvalidValue));
    }

    // RTCP-FIR-006 — 错误路径：length 字段声称更多条目字节 → UnexpectedEnd。
    #[test]
    fn rtcp_fir_006_truncated_entry_region_rejected() {
        let mut truncated = FIR_VALID;
        truncated[3] = 0x5; // len=5 implies 24 bytes, only 20 present
        assert_eq!(Fir::decode(&truncated), Err(WireError::UnexpectedEnd));
    }

    // RTCP-FIR-007 — 错误路径：entry 区非 8 字节倍数 → InvalidValue。
    #[test]
    fn rtcp_fir_007_unaligned_entry_region_rejected() {
        // length=5 描述 24 字节，entry 区为 24-12=12 字节（非 8 倍数）。
        let mut full = [0u8; 24];
        full[..4].copy_from_slice(&[0x84, 0xce, 0x0, 0x5]);
        assert_eq!(Fir::decode(&full), Err(WireError::InvalidValue));
    }

    // RTCP-FIR-008 — 错误路径：空 entry 区违反 RFC 5104 → encode InvalidValue。
    #[test]
    fn rtcp_fir_008_empty_entry_region_rejected_on_encode() {
        let fir = Fir {
            sender_ssrc: 1,
            media_ssrc: 2,
            entries: &[],
        };
        let mut output = [0u8; 12];
        assert_eq!(fir.encode(&mut output), Err(WireError::InvalidValue));
    }
}

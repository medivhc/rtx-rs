//! Slice Loss Indication (RFC 4585 section 6.3.2.2, PT=206, FMT=2).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|  FMT=2  |    PT=206     |           length              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of packet sender                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of media source                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            First        |        Number      |   PictureID   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! :                              ...                              :
//! ```
//!
//! Each FCI entry is 4 bytes and packs three fields (RFC 4585
//! section 6.3.2.2):
//!
//! - `First`: 13 bits, number of the first lost slice.
//! - `Number`: 13 bits, number of consecutive lost slices.
//! - `PictureID`: 6 bits, id of the picture the slices belong to.
//!
//! There is no per-entry SSRC; the media SSRC in the common header
//! identifies the media source for all entries.
//!
//! **Deviation from the task brief.** The brief specified
//! `[SSRC(4) first(1) number(1) picture(1)]*` (8 bytes per entry with
//! a repeating SSRC). Both RFC 4585 and the upstream webrtc-rs
//! reference use the 4-byte layout above, and the differential test
//! vectors come from upstream, so this crate implements the
//! RFC/upstream layout. See `docs/m1-2-implementation-notes.md`.
//!
//! A second deviation concerns the packet type: upstream's SLI test
//! vectors carry `PT=205` (TSFB), which contradicts both RFC 4585 and
//! upstream's own `PacketType::PayloadSpecificFeedback` constant
//! naming. This crate uses the RFC-correct `PT=206` (PSFB) on both
//! decode and encode and keeps the upstream body bytes for the
//! differential vectors.

use rtx_wire::{Cursor, Decode, Encode, WireError, Writer};

use crate::header::{Header, PacketType};

/// FMT value of the slice loss indication.
pub const FMT_SLI: u8 = 2;

/// Size of one SLI entry in bytes (`First` + `Number` + `PictureID`).
pub const SLI_ENTRY_LENGTH: usize = 4;

/// Offset of the first SLI entry (common header plus both SSRCs).
pub const SLI_ENTRY_OFFSET: usize = 12;

/// Minimum wire size: header plus both SSRCs (zero entries allowed,
/// matching upstream).
pub const SLI_MIN_OCTET_COUNT: usize = SLI_ENTRY_OFFSET;

/// Mask of the 13-bit `First` field inside one entry.
const SLI_FIRST_MASK: u32 = 0x1FFF;

/// Mask of the 13-bit `Number` field inside one entry.
const SLI_NUMBER_MASK: u32 = 0x1FFF;

/// Mask of the 6-bit `PictureID` field inside one entry.
const SLI_PICTURE_MASK: u32 = 0x3F;

/// One SLI entry: first lost slice, count and picture id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SliEntry {
    /// Number of the first lost slice (13 bits on the wire).
    pub first: u16,
    /// Number of consecutive lost slices (13 bits on the wire).
    pub number: u16,
    /// ID of the picture the slices belong to (6 bits on the wire).
    pub picture: u8,
}

impl SliEntry {
    /// Creates an entry, truncating each field to its wire width.
    #[must_use]
    pub const fn new(first: u16, number: u16, picture: u8) -> Self {
        SliEntry {
            first: first & 0x1FFF,
            number: number & 0x1FFF,
            picture: picture & 0x3F,
        }
    }
}

/// Slice Loss Indication borrowing its entry region from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sli<'a> {
    /// SSRC of the packet sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source the losses belong to.
    pub media_ssrc: u32,
    /// Raw SLI entries (4 bytes each), borrowed verbatim.
    pub entries: &'a [u8],
}

impl Sli<'_> {
    /// Iterates over the SLI entries.
    ///
    /// Each entry decodes infallibly because the region is a multiple
    /// of 4 bytes by construction ([`Encode::encoded_len`] rejects anything
    /// else) or by dispatcher slicing (the region always ends on the
    /// 32-bit boundary given by the `length` field).
    pub fn entries(&self) -> impl Iterator<Item = SliEntry> + '_ {
        self.entries.chunks_exact(SLI_ENTRY_LENGTH).map(|chunk| {
            let raw = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            SliEntry {
                #[allow(clippy::cast_possible_truncation)]
                first: ((raw >> 19) & SLI_FIRST_MASK) as u16,
                #[allow(clippy::cast_possible_truncation)]
                number: ((raw >> 6) & SLI_NUMBER_MASK) as u16,
                #[allow(clippy::cast_possible_truncation)]
                picture: (raw & SLI_PICTURE_MASK) as u8,
            }
        })
    }

    /// Header implied by the current field values.
    ///
    /// `count` is the FMT value (2), never the entry count.
    #[must_use]
    pub fn header(&self) -> Header {
        Header {
            padding: false,
            count: FMT_SLI,
            packet_type: PacketType::Psfb,
            length: u16::try_from(self.raw_len() / 4 - 1).unwrap_or(u16::MAX),
        }
    }

    /// Unpadded wire size (common header + both SSRCs + entry region).
    fn raw_len(&self) -> usize {
        SLI_ENTRY_OFFSET + self.entries.len()
    }

    /// Encodes the packet into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the entry region is not
    /// a multiple of 4 bytes, and [`WireError::OutputTooSmall`] when
    /// the writer lacks room.
    pub(crate) fn write_to(&self, writer: &mut Writer<'_>) -> Result<(), WireError> {
        if self.entries.len() % SLI_ENTRY_LENGTH != 0 {
            return Err(WireError::InvalidValue);
        }
        let length = u16::try_from(self.raw_len() / 4 - 1).map_err(|_| WireError::Overflow)?;

        let header = Header {
            padding: false,
            count: FMT_SLI,
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

impl<'a> Decode<'a> for Sli<'a> {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        let (header, consumed) = Header::decode(input)?;
        if header.packet_type != PacketType::Psfb || header.count != FMT_SLI {
            return Err(WireError::InvalidValue);
        }
        if input.len() < SLI_MIN_OCTET_COUNT {
            return Err(WireError::UnexpectedEnd);
        }

        // The entry count comes from the length field: length = 2 + n.
        let total = usize::from(header.length)
            .checked_mul(4)
            .and_then(|words| words.checked_add(consumed))
            .ok_or(WireError::Overflow)?;
        if total < SLI_MIN_OCTET_COUNT || input.len() < total {
            return Err(WireError::UnexpectedEnd);
        }

        let mut cursor = Cursor::new(&input[consumed..]);
        let sender_ssrc = cursor.u32_be()?;
        let media_ssrc = cursor.u32_be()?;
        let entries = cursor.take(total - SLI_ENTRY_OFFSET)?;

        let sli = Sli {
            sender_ssrc,
            media_ssrc,
            entries,
        };
        Ok((sli, input.len()))
    }
}

impl Encode for Sli<'_> {
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
    /// `rtcp/payload_feedbacks/slice_loss_indication/slice_loss_indication_test.rs:9-17`
    /// ("valid"). Upstream carries `PT=205` (0xcd); RFC 4585 section
    /// 6.3.2.2 and this crate use `PT=206` (0xce), so the first byte
    /// pair is rewritten while the body stays byte-identical.
    const SLI_VALID: [u8; 16] = [
        0x82, 0xce, 0x0, 0x3, // v=2, p=0, FMT=2, PSFB, len=3
        0x90, 0x2f, 0x9e, 0x2e, // sender=0x902f9e2e
        0x90, 0x2f, 0x9e, 0x2e, // media=0x902f9e2e
        0x55, 0x50, 0x00, 0x2C, // first=0xaaa, number=0, picture=0x2C
    ];

    /// Differential vector: upstream `slice_loss_indication_test.rs:28-33`
    /// ("short report": 8 bytes, only one SSRC present).
    const SLI_SHORT_REPORT: [u8; 8] = [0x82, 0xce, 0x0, 0x2, 0x90, 0x2f, 0x9e, 0x2e];

    /// Differential vector: upstream `slice_loss_indication_test.rs:37-49`
    /// ("wrong type": an SR packet).
    const SLI_WRONG_TYPE: [u8; 32] = [
        0x81, 0xc8, 0x0, 0x7, // v=2, p=0, count=1, SR, len=7
        0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
        0xbc, 0x5e, 0x9a, 0x40, // ssrc=0xbc5e9a40
        0x0, 0x0, 0x0, 0x0, // fracLost=0, totalLost=0
        0x0, 0x0, 0x46, 0xe1, // lastSeq=0x46e1
        0x0, 0x0, 0x1, 0x11, // jitter=273
        0x9, 0xf3, 0x64, 0x32, // lsr=0x9f36432
        0x0, 0x2, 0x4a, 0x79, // delay=150137
    ];

    // RTCP-SLI-001 — 差分：上游 "valid" 向量逐字段 + encode 字节级往返。
    #[test]
    fn rtcp_sli_001_upstream_valid_vector_round_trip() {
        let (sli, consumed) = Sli::decode(&SLI_VALID).expect("decode SLI valid");
        assert_eq!(consumed, SLI_VALID.len());
        assert_eq!(sli.sender_ssrc, 0x902f_9e2e);
        assert_eq!(sli.media_ssrc, 0x902f_9e2e);

        let entries: Vec<SliEntry> = sli.entries().collect();
        assert_eq!(
            entries,
            vec![SliEntry {
                first: 0xaaa,
                number: 0,
                picture: 0x2C,
            }]
        );

        let header = sli.header();
        assert_eq!(header.packet_type, PacketType::Psfb);
        assert_eq!(header.count, FMT_SLI);
        assert_eq!(header.length, 3);

        // 上游向量 length 字段本就是正确值，故字节级全等（仅 PT 字节不同）。
        let mut output = [0u8; 16];
        let written = sli.encode(&mut output).expect("encode SLI valid");
        assert_eq!(written, 16);
        assert_eq!(written, sli.encoded_len());
        assert_eq!(output, SLI_VALID);

        let (again, _) = Sli::decode(&output[..written]).expect("re-decode");
        assert_eq!(again, sli);
    }

    // RTCP-SLI-002 — 差分：上游 roundtrip 向量（两个 SliEntry）编解码往返。
    #[test]
    fn rtcp_sli_002_two_entry_round_trip() {
        // 上游 `slice_loss_indication_test.rs:89-105` 的 roundtrip 用例：
        // (first=1, number=0xAA, picture=0x1F) 与
        // (first=1034, number=0x05, picture=0x6)。
        // 手工展开上游 marshal 逻辑：
        // entry1 = (1 << 19) | (0xAA << 6) | 0x1F = 0x00082A9F
        // entry2 = (1034 << 19) | (0x05 << 6) | 0x6 = 0x20500146
        let expected: [u8; 20] = [
            0x82, 0xce, 0x0, 0x4, // v=2, p=0, FMT=2, PSFB, len=4
            0x90, 0x2f, 0x9e, 0x2e, // sender
            0x90, 0x2f, 0x9e, 0x2e, // media
            0x0, 0x8, 0x2a, 0x9f, // first=1, number=0xAA, picture=0x1F
            0x20, 0x50, 0x01, 0x46, // first=1034, number=0x05, picture=0x6
        ];

        let (sli, consumed) = Sli::decode(&expected).expect("decode two-entry SLI");
        assert_eq!(consumed, expected.len());
        let entries: Vec<SliEntry> = sli.entries().collect();
        assert_eq!(
            entries,
            vec![SliEntry::new(1, 0xAA, 0x1F), SliEntry::new(1034, 0x05, 0x6),]
        );

        let mut output = [0u8; 20];
        let written = sli.encode(&mut output).expect("encode two-entry SLI");
        assert_eq!(written, 20);
        assert_eq!(output, expected);
    }

    // RTCP-SLI-003 — 差分：上游错误路径（short report / wrong type / nil）。
    #[test]
    fn rtcp_sli_003_upstream_error_paths() {
        assert_eq!(
            Sli::decode(&SLI_SHORT_REPORT),
            Err(WireError::UnexpectedEnd)
        );
        assert_eq!(Sli::decode(&SLI_WRONG_TYPE), Err(WireError::InvalidValue));
        assert_eq!(Sli::decode(&[]), Err(WireError::UnexpectedEnd));
    }

    // RTCP-SLI-004 — 错误路径：FMT 不匹配（count=1 即 PLI）→ InvalidValue。
    #[test]
    fn rtcp_sli_004_wrong_fmt_rejected() {
        let mut wrong_fmt = SLI_VALID;
        wrong_fmt[0] = 0x81; // FMT=1 (Picture Loss Indication)
        assert_eq!(Sli::decode(&wrong_fmt), Err(WireError::InvalidValue));
    }

    // RTCP-SLI-005 — 错误路径：length 字段声称更多条目字节 → UnexpectedEnd。
    #[test]
    fn rtcp_sli_005_truncated_entry_region_rejected() {
        let mut truncated = SLI_VALID;
        truncated[3] = 0x4; // len=4 implies 20 bytes, only 16 present
        assert_eq!(Sli::decode(&truncated), Err(WireError::UnexpectedEnd));
    }

    // RTCP-SLI-006 — 错误路径：entry 区非 4 字节倍数 → encode InvalidValue。
    #[test]
    fn rtcp_sli_006_unaligned_entry_region_rejected_on_encode() {
        let sli = Sli {
            sender_ssrc: 1,
            media_ssrc: 2,
            entries: &[0, 1, 2],
        };
        let mut output = [0u8; 15];
        assert_eq!(sli.encode(&mut output), Err(WireError::InvalidValue));
    }

    // RTCP-SLI-007 — 属性：SliEntry::new 截断到线宽（13/13/6 位）。
    #[test]
    fn rtcp_sli_007_entry_new_truncates_to_wire_widths() {
        let entry = SliEntry::new(0xFFFF, 0xFFFF, 0xFF);
        assert_eq!(entry.first, 0x1FFF);
        assert_eq!(entry.number, 0x1FFF);
        assert_eq!(entry.picture, 0x3F);

        let max = SliEntry::new(0x1FFF, 0x1FFF, 0x3F);
        assert_eq!(max.first, 0x1FFF);
        assert_eq!(max.number, 0x1FFF);
        assert_eq!(max.picture, 0x3F);
    }
}

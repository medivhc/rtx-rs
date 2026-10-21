//! Picture Loss Indication (PT=206, FMT=1).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|  FMT=1  |    PT=206     |           length              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of packet sender                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of media source                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The message carries no Feedback Control Information: the `length`
//! field MUST be 2. It informs the encoder about the loss of an
//! undefined amount of coded video data belonging to one or more
//! pictures (RFC 4585 §6.3.1).

use rtx_wire::{Cursor, Decode, Encode, WireError, Writer};

use crate::header::{Header, PacketType};

/// FMT value of the picture loss indication.
pub const FMT_PLI: u8 = 1;

/// Wire size: common header plus both SSRCs (no FCI).
pub const PLI_LENGTH: usize = 12;

/// Header `length` field of a PLI packet: `(PLI_LENGTH / 4) - 1`.
const PLI_LENGTH_FIELD: u16 = 2;

/// Picture Loss Indication: sender SSRC plus media SSRC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pli {
    /// SSRC of the packet sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source.
    pub media_ssrc: u32,
}

impl Pli {
    /// Header implied by the current field values.
    ///
    /// `count` is the FMT value (1) and `length` is always 2.
    #[must_use]
    pub const fn header(&self) -> Header {
        Header {
            padding: false,
            count: FMT_PLI,
            packet_type: PacketType::Psfb,
            length: PLI_LENGTH_FIELD,
        }
    }

    /// Encodes the packet into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::OutputTooSmall`] when the writer lacks room.
    pub(crate) fn write_to(self, writer: &mut Writer<'_>) -> Result<(), WireError> {
        self.header().write_to(writer)?;
        writer.u32_be(self.sender_ssrc)?;
        writer.u32_be(self.media_ssrc)?;
        Ok(())
    }
}

impl<'a> Decode<'a> for Pli {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        let (header, consumed) = Header::decode(input)?;
        if header.packet_type != PacketType::Psfb || header.count != FMT_PLI {
            return Err(WireError::InvalidValue);
        }
        if input.len() < PLI_LENGTH {
            return Err(WireError::UnexpectedEnd);
        }

        // The length field must describe at least the fixed part; bytes
        // beyond it are ignored (the dispatcher slices one sub-packet by
        // the same field, so they only matter for direct calls).
        let total = usize::from(header.length)
            .checked_mul(4)
            .and_then(|words| words.checked_add(consumed))
            .ok_or(WireError::Overflow)?;
        if total < PLI_LENGTH || input.len() < total {
            return Err(WireError::UnexpectedEnd);
        }
        // PLI carries no FCI, so the model is exactly `PLI_LENGTH`. An
        // announced length beyond that would be dropped on re-encode, so it
        // is rejected instead of silently truncated.
        if total != PLI_LENGTH {
            return Err(WireError::InvalidValue);
        }

        let mut cursor = Cursor::new(&input[consumed..]);
        let sender_ssrc = cursor.u32_be()?;
        let media_ssrc = cursor.u32_be()?;

        let pli = Pli {
            sender_ssrc,
            media_ssrc,
        };
        Ok((pli, input.len()))
    }
}

impl Encode for Pli {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        PLI_LENGTH
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
    /// `rtcp/payload_feedbacks/picture_loss_indication/picture_loss_indication_test.rs:9-13`
    /// ("valid", 12 bytes).
    const PLI_VALID: [u8; 12] = [
        0x81, 0xce, 0x0, 0x2, // v=2, p=0, FMT=1, PSFB, len=2
        0x0, 0x0, 0x0, 0x0, // sender=0
        0x4b, 0xc4, 0xfc, 0xb4, // media=0x4bc4fcb4
    ];

    // RTCP-PLI-001 — 差分：上游 "valid" 向量逐字段 + encode 字节级往返。
    #[test]
    fn rtcp_pli_001_upstream_valid_vector_round_trip() {
        let (pli, consumed) = Pli::decode(&PLI_VALID).expect("decode PLI valid");
        assert_eq!(consumed, PLI_VALID.len());
        assert_eq!(pli.sender_ssrc, 0);
        assert_eq!(pli.media_ssrc, 0x4bc4_fcb4);

        let header = pli.header();
        assert_eq!(header.packet_type, PacketType::Psfb);
        assert_eq!(header.count, FMT_PLI);
        assert_eq!(header.length, 2);

        let mut output = [0u8; 12];
        let written = pli.encode(&mut output).expect("encode PLI valid");
        assert_eq!(written, 12);
        assert_eq!(written, pli.encoded_len());
        assert_eq!(output, PLI_VALID);

        let (again, _) = Pli::decode(&output[..written]).expect("re-decode");
        assert_eq!(again, pli);
    }

    // RTCP-PLI-002 — 差分：上游错误路径（nil / short report / wrong type）。
    #[test]
    fn rtcp_pli_002_upstream_error_paths() {
        assert_eq!(Pli::decode(&[]), Err(WireError::UnexpectedEnd));
        assert_eq!(Pli::decode(&PLI_VALID[..8]), Err(WireError::UnexpectedEnd));
        // "wrong type": upstream reuses a FIR vector (PT=206 FMT=4).
        let wrong_type: [u8; 20] = [
            0x84, 0xce, 0x0, 0x4, 0x4b, 0xc4, 0xfc, 0xb4, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0,
        ];
        assert_eq!(Pli::decode(&wrong_type), Err(WireError::InvalidValue));
    }

    // RTCP-PLI-003 — 错误路径：FMT 不匹配（count=2 即 SLI）。
    #[test]
    fn rtcp_pli_003_wrong_fmt_rejected() {
        // SLI header: PT=206 FMT=2, length=5 (one 4-byte entry + 2 SSRCs).
        let sli_header: [u8; 12] = [
            0x82, 0xce, 0x0, 0x2, 0x4b, 0xc4, 0xfc, 0xb4, 0x0, 0x0, 0x0, 0x0,
        ];
        assert_eq!(Pli::decode(&sli_header), Err(WireError::InvalidValue));
    }

    // RTCP-PLI-004 — 错误路径：length 字段小于 2。
    #[test]
    fn rtcp_pli_004_short_length_field_rejected() {
        let mut short_length = PLI_VALID;
        short_length[3] = 0x1; // len=1 implies 8 bytes
        assert_eq!(Pli::decode(&short_length), Err(WireError::UnexpectedEnd));
    }

    // RTCP-PLI-005 — 属性：默认值与往返一致性。
    #[test]
    fn rtcp_pli_005_default_round_trip() {
        let pli = Pli::default();
        assert_eq!(pli.sender_ssrc, 0);
        assert_eq!(pli.media_ssrc, 0);

        let mut output = [0u8; 12];
        let written = pli.encode(&mut output).expect("encode default");
        assert_eq!(written, 12);
        let (decoded, _) = Pli::decode(&output).expect("decode default");
        assert_eq!(decoded, pli);
    }

    // RTCP-PLI-006 — 回归：PLI 无 FCI，length 声称超过 12 字节的包必须被
    // 拒绝。原先只做下限校验，24 字节的包能解出但只写回 12 字节，破坏了
    // `encode(decode(bytes)) == bytes`（fuzz 输入 `85 cd 00 05 ...` 形态）。
    #[test]
    fn rtcp_pli_006_oversized_length_field_rejected() {
        let mut packet = [0x14u8; 24];
        packet[0] = 0x81; // v=2, p=0, FMT=1
        packet[1] = 0xce; // PSFB
        packet[2..4].copy_from_slice(&5u16.to_be_bytes()); // length 5 -> 24 bytes
        assert_eq!(Pli::decode(&packet), Err(WireError::InvalidValue));

        // Via the dispatcher the same input must fail too, so a compound
        // packet cannot smuggle it in.
        assert!(crate::packet::RtcpPacket::decode(&packet).is_err());
    }
}

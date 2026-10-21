//! Rapid Resynchronization Request (PT=205, FMT=5).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|  FMT=5  |    PT=205     |           length              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of packet sender                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of media source                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The message carries no Feedback Control Information: the `length`
//! field MUST be 2. It asks the encoder to achieve rapid
//! resynchronization after an undefined amount of coded data was lost.
//!
//! Provenance note: RRR was defined in the `draft-ietf-avt-rtcp-feedback`
//! series but is *not* part of the final RFC 4585 (which only assigns FMT
//! 1 to Generic NACK under PT=205). It remains widely deployed and is
//! implemented by the upstream webrtc-rs reference, so this crate models
//! it with the upstream wire layout: `PT=205`, `FMT=5`, both SSRCs, no
//! FCI. The header `count` field carries the FMT value.

use rtx_wire::{Cursor, Decode, Encode, WireError, Writer};

use crate::header::{Header, PacketType};

/// FMT value of the rapid resynchronization request.
pub const FMT_RAPID_RESYNC: u8 = 5;

/// Wire size: common header plus both SSRCs (no FCI).
pub const RAPID_RESYNC_LENGTH: usize = 12;

/// Header `length` field of an RRR packet: `(RAPID_RESYNC_LENGTH / 4) - 1`.
const RAPID_RESYNC_LENGTH_FIELD: u16 = 2;

/// Rapid Resynchronization Request: sender SSRC plus media SSRC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RapidResync {
    /// SSRC of the packet sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source.
    pub media_ssrc: u32,
}

impl RapidResync {
    /// Header implied by the current field values.
    ///
    /// `count` is the FMT value (5) and `length` is always 2.
    #[must_use]
    pub const fn header(&self) -> Header {
        Header {
            padding: false,
            count: FMT_RAPID_RESYNC,
            packet_type: PacketType::Tsfb,
            length: RAPID_RESYNC_LENGTH_FIELD,
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

impl<'a> Decode<'a> for RapidResync {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        let (header, consumed) = Header::decode(input)?;
        if header.packet_type != PacketType::Tsfb || header.count != FMT_RAPID_RESYNC {
            return Err(WireError::InvalidValue);
        }
        if input.len() < RAPID_RESYNC_LENGTH {
            return Err(WireError::UnexpectedEnd);
        }

        // The length field must describe at least the fixed part; bytes
        // beyond it are ignored (the dispatcher slices one sub-packet by
        // the same field, so they only matter for direct calls).
        let total = usize::from(header.length)
            .checked_mul(4)
            .and_then(|words| words.checked_add(consumed))
            .ok_or(WireError::Overflow)?;
        if total < RAPID_RESYNC_LENGTH || input.len() < total {
            return Err(WireError::UnexpectedEnd);
        }
        // RRR carries no FCI, so the model is exactly
        // `RAPID_RESYNC_LENGTH`. An announced length beyond that would be
        // dropped on re-encode, so it is rejected instead of silently
        // truncated.
        if total != RAPID_RESYNC_LENGTH {
            return Err(WireError::InvalidValue);
        }

        let mut cursor = Cursor::new(&input[consumed..]);
        let sender_ssrc = cursor.u32_be()?;
        let media_ssrc = cursor.u32_be()?;

        let request = RapidResync {
            sender_ssrc,
            media_ssrc,
        };
        Ok((request, input.len()))
    }
}

impl Encode for RapidResync {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        RAPID_RESYNC_LENGTH
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
    /// `rtcp/transport_feedbacks/rapid_resynchronization_request/rapid_resynchronization_request_test.rs:9-13`
    /// ("valid", 12 bytes).
    const RRR_VALID: [u8; 12] = [
        0x85, 0xcd, 0x0, 0x2, // v=2, p=0, FMT=5, TSFB, len=2
        0x90, 0x2f, 0x9e, 0x2e, // sender=0x902f9e2e
        0x90, 0x2f, 0x9e, 0x2e, // media=0x902f9e2e
    ];

    /// Differential vector: upstream `rapid_resynchronization_request_test.rs:28-32`
    /// ("short report", 8 bytes).
    const RRR_SHORT_REPORT: [u8; 8] = [0x85, 0xcd, 0x0, 0x2, 0x90, 0x2f, 0x9e, 0x2e];

    /// Differential vector: upstream `rapid_resynchronization_request_test.rs:37-48`
    /// ("wrong type": an SR packet).
    const RRR_WRONG_TYPE: [u8; 32] = [
        0x81, 0xc8, 0x0, 0x7, 0x90, 0x2f, 0x9e, 0x2e, 0xbc, 0x5e, 0x9a, 0x40, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x46, 0xe1, 0x0, 0x0, 0x1, 0x11, 0x9, 0xf3, 0x64, 0x32, 0x0, 0x2, 0x4a, 0x79,
    ];

    // RTCP-RRR-001 — 差分：上游 "valid" 向量逐字段 + encode 字节级往返。
    #[test]
    fn rtcp_rrr_001_upstream_valid_vector_round_trip() {
        let (rrr, consumed) = RapidResync::decode(&RRR_VALID).expect("decode RRR valid");
        assert_eq!(consumed, RRR_VALID.len());
        assert_eq!(rrr.sender_ssrc, 0x902f_9e2e);
        assert_eq!(rrr.media_ssrc, 0x902f_9e2e);

        let header = rrr.header();
        assert_eq!(header.packet_type, PacketType::Tsfb);
        assert_eq!(header.count, FMT_RAPID_RESYNC);
        assert_eq!(header.length, 2);

        let mut output = [0u8; 12];
        let written = rrr.encode(&mut output).expect("encode RRR valid");
        assert_eq!(written, 12);
        assert_eq!(written, rrr.encoded_len());
        assert_eq!(output, RRR_VALID);

        let (again, _) = RapidResync::decode(&output[..written]).expect("re-decode");
        assert_eq!(again, rrr);
    }

    // RTCP-RRR-002 — 差分：上游错误路径（short report / wrong type / nil）。
    #[test]
    fn rtcp_rrr_002_upstream_error_paths() {
        assert_eq!(
            RapidResync::decode(&RRR_SHORT_REPORT),
            Err(WireError::UnexpectedEnd)
        );
        assert_eq!(
            RapidResync::decode(&RRR_WRONG_TYPE),
            Err(WireError::InvalidValue)
        );
        assert_eq!(RapidResync::decode(&[]), Err(WireError::UnexpectedEnd));
    }

    // RTCP-RRR-003 — 错误路径：FMT 不匹配（count=1 即 NACK 向量）→ InvalidValue。
    #[test]
    fn rtcp_rrr_003_wrong_fmt_rejected() {
        // NACK_VALID 的头部：FMT=1 而非 5。
        let nack_header: [u8; 16] = [
            0x81, 0xcd, 0x0, 0x3, 0x90, 0x2f, 0x9e, 0x2e, 0x90, 0x2f, 0x9e, 0x2e, 0xaa, 0xaa, 0x55,
            0x55,
        ];
        assert_eq!(
            RapidResync::decode(&nack_header),
            Err(WireError::InvalidValue)
        );
    }

    // RTCP-RRR-004 — 错误路径：length 字段小于 2（无 FCI 的最短包）。
    #[test]
    fn rtcp_rrr_004_short_length_field_rejected() {
        let mut short_length = RRR_VALID;
        short_length[3] = 0x1; // len=1 implies 8 bytes
        assert_eq!(
            RapidResync::decode(&short_length),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTCP-RRR-005 — 属性：默认值与往返一致性。
    #[test]
    fn rtcp_rrr_005_default_round_trip() {
        let rrr = RapidResync::default();
        assert_eq!(rrr.sender_ssrc, 0);
        assert_eq!(rrr.media_ssrc, 0);

        let mut output = [0u8; 12];
        let written = rrr.encode(&mut output).expect("encode default");
        assert_eq!(written, 12);
        assert_eq!(
            output,
            [
                0x85, 0xcd, 0x0, 0x2, // v=2, p=0, FMT=5, TSFB, len=2
                0x0, 0x0, 0x0, 0x0, // sender=0
                0x0, 0x0, 0x0, 0x0, // media=0
            ]
        );
        let (decoded, _) = RapidResync::decode(&output).expect("decode default");
        assert_eq!(decoded, rrr);
    }

    // RTCP-RRR-005 — 回归：RRR 无 FCI，length 声称超过 12 字节的包必须被
    // 拒绝。原先只做下限校验，24 字节的包能解出但只写回 12 字节。
    #[test]
    fn rtcp_rrr_005_oversized_length_field_rejected() {
        let mut packet = [0x14u8; 24];
        packet[0] = 0x85; // v=2, p=0, FMT=5
        packet[1] = 0xcd; // TSFB
        packet[2..4].copy_from_slice(&5u16.to_be_bytes()); // length 5 -> 24 bytes
        assert_eq!(RapidResync::decode(&packet), Err(WireError::InvalidValue));
        assert!(crate::packet::RtcpPacket::decode(&packet).is_err());
    }
}

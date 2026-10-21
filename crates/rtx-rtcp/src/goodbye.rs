//! Goodbye packet (RFC 3550 section 6.4.4, type 203).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|   SC   |   PT=BYE=203  |             length            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           SSRC/CSRC                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! :                              ...                              :
//! +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//! (opt) |     length    |         reason for leaving            ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The reason is optional: when absent, the packet ends right after the
//! last SSRC and no length octet is present. Unlike the upstream
//! implementation (which always emits a zero length octet), this crate
//! models the reason as [`Option`] so that a reason-less packet
//! round-trips byte-exactly.

use rtx_wire::{Cursor, Decode, Encode, WireError, Writer};

use crate::header::{COUNT_MAX, Header, PacketType, SSRC_LENGTH};
use crate::util::padding_size;

/// Maximum length of the reason string (one length octet).
pub const REASON_MAX_OCTET_COUNT: usize = 255;

/// Goodbye packet borrowing its source list and reason from the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Goodbye<'a> {
    /// Verbatim source list (4 bytes per SSRC).
    pub sources: &'a [u8],
    /// Optional reason string, without its length octet.
    pub reason: Option<&'a [u8]>,
}

impl Goodbye<'_> {
    /// Iterates over the SSRC values in the source list.
    pub fn source_iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.sources
            .chunks_exact(SSRC_LENGTH)
            .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
    }

    /// Header implied by the current field values.
    ///
    /// `count` saturates at 31 and `length` at `u16::MAX` when the packet
    /// is too large; [`Encode`] performs the real validation.
    #[must_use]
    pub fn header(&self) -> Header {
        let count = u8::try_from(self.sources.len() / SSRC_LENGTH).unwrap_or(COUNT_MAX);
        Header {
            padding: false,
            count,
            packet_type: PacketType::Bye,
            length: u16::try_from(self.aligned_len() / 4 - 1).unwrap_or(u16::MAX),
        }
    }

    /// Unpadded wire size (common header + sources + optional reason).
    fn raw_len(&self) -> usize {
        let mut len = 4 + self.sources.len();
        if let Some(reason) = self.reason {
            len += 1 + reason.len();
        }
        len
    }

    /// Wire size rounded up to the next 32-bit boundary.
    ///
    /// RFC 3550 section 6.4.4 requires the reason to be followed by null
    /// octets up to a 32-bit boundary, and section 6.1 requires every RTCP
    /// packet to be a multiple of 32 bits. Without this rounding the
    /// `length` field would disagree with the number of bytes actually
    /// written (a 3-octet reason yields 11 bytes but would claim 8), and
    /// a receiver slicing by `length` would drop or mis-parse the tail.
    fn aligned_len(&self) -> usize {
        let raw = self.raw_len();
        raw + padding_size(raw)
    }

    /// Encodes the packet into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when there are more than 31
    /// sources or the reason exceeds 255 octets, and
    /// [`WireError::OutputTooSmall`] when the writer lacks room.
    pub(crate) fn write_to(&self, writer: &mut Writer<'_>) -> Result<(), WireError> {
        let count = self.sources.len() / SSRC_LENGTH;
        if count > usize::from(COUNT_MAX) {
            return Err(WireError::InvalidValue);
        }
        if self.sources.len() % SSRC_LENGTH != 0 {
            return Err(WireError::InvalidValue);
        }
        if let Some(reason) = self.reason {
            if reason.len() > REASON_MAX_OCTET_COUNT {
                return Err(WireError::InvalidValue);
            }
        }
        let length = u16::try_from(self.aligned_len() / 4 - 1).map_err(|_| WireError::Overflow)?;

        let header = Header {
            padding: false,
            count: u8::try_from(count).map_err(|_| WireError::InvalidValue)?,
            packet_type: PacketType::Bye,
            length,
        };
        header.write_to(writer)?;

        writer.put(self.sources)?;
        if let Some(reason) = self.reason {
            const ZEROS: [u8; 3] = [0, 0, 0];
            let len = u8::try_from(reason.len()).map_err(|_| WireError::InvalidValue)?;
            writer.u8(len)?;
            writer.put(reason)?;
            // RFC 3550 section 6.4.4: the reason is followed by null
            // octets up to the next 32-bit boundary. These are *not* the
            // generic RTCP padding of section 6.1 (no P bit, no trailing
            // count), so plain zero octets are written here.
            let pad = padding_size(self.raw_len());
            writer.put(&ZEROS[..pad])?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for Goodbye<'a> {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        let (header, consumed) = Header::decode(input)?;
        if header.packet_type != PacketType::Bye {
            return Err(WireError::InvalidValue);
        }

        // The upstream implementation requires the total length to be a
        // multiple of 4 (RFC 3550 section 6.4.4 alignment).
        if input.len() % 4 != 0 {
            return Err(WireError::UnexpectedEnd);
        }

        let reason_offset = 4 + usize::from(header.count) * SSRC_LENGTH;
        if reason_offset > input.len() {
            return Err(WireError::UnexpectedEnd);
        }

        let mut cursor = Cursor::new(&input[consumed..]);
        let sources = cursor.take(usize::from(header.count) * SSRC_LENGTH)?;

        let reason = if reason_offset < input.len() {
            let reason_len = usize::from(cursor.u8()?);
            let reason_end = reason_offset
                .checked_add(1 + reason_len)
                .ok_or(WireError::Overflow)?;
            if reason_end > input.len() {
                return Err(WireError::UnexpectedEnd);
            }
            Some(cursor.take(reason_len)?)
        } else {
            None
        };

        let bye = Goodbye { sources, reason };

        // A BYE packet has no field after the optional reason and its
        // 32-bit alignment padding, so the announced total length must match
        // exactly what this model can represent. Accepting a longer packet
        // would mean silently dropping trailing octets on re-encode, which
        // breaks the byte-exact round trip every other packet type upholds.
        if input.len() != bye.aligned_len() {
            return Err(WireError::InvalidValue);
        }

        Ok((bye, input.len()))
    }
}

impl Encode for Goodbye<'_> {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        self.aligned_len()
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

    /// Differential vector: upstream `rtcp/goodbye/goodbye_test.rs:8-12`
    /// ("valid", 12 bytes, bogus length 12 — real length is 2).
    const BYE_VALID: [u8; 12] = [
        0x81, 0xcb, 0x00, 0x0c, // v=2, p=0, count=1, BYE, len=12 (bogus)
        0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
        0x03, 0x46, 0x4f, 0x4f, // len=3, text=FOO
    ];

    /// Differential vector: upstream `rtcp/goodbye/goodbye_test.rs:21-25`
    /// ("invalid octet count": reason length 4 but only 3 bytes remain).
    const BYE_INVALID_OCTET_COUNT: [u8; 12] = [
        0x81, 0xcb, 0x00, 0x0c, 0x90, 0x2f, 0x9e, 0x2e, 0x04, 0x46, 0x4f, 0x4f,
    ];

    /// Differential vector: upstream `rtcp/goodbye/goodbye_test.rs:32-41`
    /// ("wrong type": SDES header).
    const BYE_WRONG_TYPE: [u8; 12] = [
        0x81, 0xca, 0x00, 0x0c, 0x90, 0x2f, 0x9e, 0x2e, 0x03, 0x46, 0x4f, 0x4f,
    ];

    /// Differential vector: upstream `rtcp/goodbye/goodbye_test.rs:46-51`
    /// ("short reason": reason "F" plus padding).
    const BYE_SHORT_REASON: [u8; 12] = [
        0x81, 0xcb, 0x00, 0x0c, 0x90, 0x2f, 0x9e, 0x2e, 0x01, 0x46, 0x00, 0x00,
    ];

    /// Differential vector: upstream `rtcp/goodbye/goodbye_test.rs:60-64`
    /// ("not byte aligned", 10 bytes).
    const BYE_NOT_ALIGNED: [u8; 10] = [0x81, 0xcb, 0x00, 0x0a, 0x90, 0x2f, 0x9e, 0x2e, 0x01, 0x46];

    /// Differential vector: upstream `rtcp/goodbye/goodbye_test.rs:73-77`
    /// ("bad count in header", 8 bytes).
    const BYE_BAD_COUNT: [u8; 8] = [0x82, 0xcb, 0x00, 0x0c, 0x90, 0x2f, 0x9e, 0x2e];

    /// Differential vector: upstream `rtcp/goodbye/goodbye_test.rs:85-88`
    /// ("empty packet", 4 bytes, bogus length 4 — real length is 0).
    const BYE_EMPTY: [u8; 4] = [0x80, 0xcb, 0x00, 0x04];

    // RTCP-BYE-001 — 差分：上游 "valid" 向量逐字段 + encode 字节级往返。
    #[test]
    fn rtcp_bye_001_upstream_valid_vector_round_trip() {
        let (bye, consumed) = Goodbye::decode(&BYE_VALID).expect("decode BYE valid");
        assert_eq!(consumed, BYE_VALID.len());
        let sources: Vec<u32> = bye.source_iter().collect();
        assert_eq!(sources, vec![0x902f_9e2e]);
        assert_eq!(bye.reason, Some(&b"FOO"[..]));

        let header = bye.header();
        assert_eq!(header.packet_type, PacketType::Bye);
        assert_eq!(header.count, 1);
        assert_eq!(header.length, 2);

        let mut output = [0u8; 12];
        let written = bye.encode(&mut output).expect("encode BYE valid");
        assert_eq!(written, 12);
        assert_eq!(written, bye.encoded_len());
        let mut expected = BYE_VALID;
        expected[2..4].copy_from_slice(&2u16.to_be_bytes()); // corrected length
        assert_eq!(&output[..written], &expected);

        let (again, _) = Goodbye::decode(&output[..written]).expect("re-decode");
        assert_eq!(again, bye);
    }

    // RTCP-BYE-002 — 差分：上游 "invalid octet count" → UnexpectedEnd。
    #[test]
    fn rtcp_bye_002_invalid_octet_count_rejected() {
        assert_eq!(
            Goodbye::decode(&BYE_INVALID_OCTET_COUNT),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTCP-BYE-003 — 差分：上游 "wrong type" → InvalidValue。
    #[test]
    fn rtcp_bye_003_wrong_type_rejected() {
        assert_eq!(
            Goodbye::decode(&BYE_WRONG_TYPE),
            Err(WireError::InvalidValue)
        );
    }

    // RTCP-BYE-004 — 差分：上游 "short reason"（reason 带 padding 字节）。
    #[test]
    fn rtcp_bye_004_short_reason_vector() {
        let (bye, _) = Goodbye::decode(&BYE_SHORT_REASON).expect("decode short reason");
        assert_eq!(bye.reason, Some(&b"F"[..]));
        let sources: Vec<u32> = bye.source_iter().collect();
        assert_eq!(sources, vec![0x902f_9e2e]);
    }

    // RTCP-BYE-005 — 差分：上游 "not byte aligned" → UnexpectedEnd。
    #[test]
    fn rtcp_bye_005_not_aligned_rejected() {
        assert_eq!(
            Goodbye::decode(&BYE_NOT_ALIGNED),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTCP-BYE-006 — 差分：上游 "bad count in header" → UnexpectedEnd。
    #[test]
    fn rtcp_bye_006_bad_count_rejected() {
        assert_eq!(
            Goodbye::decode(&BYE_BAD_COUNT),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTCP-BYE-007 — 差分：上游 "empty packet"（无 reason 时不写长度字节）。
    #[test]
    fn rtcp_bye_007_empty_packet_round_trip() {
        let (bye, consumed) = Goodbye::decode(&BYE_EMPTY).expect("decode empty BYE");
        assert_eq!(consumed, BYE_EMPTY.len());
        assert!(bye.sources.is_empty());
        assert_eq!(bye.reason, None);
        assert_eq!(bye.source_iter().count(), 0);

        let mut output = [0u8; 4];
        let written = bye.encode(&mut output).expect("encode empty BYE");
        assert_eq!(written, 4);
        let mut expected = BYE_EMPTY;
        expected[2..4].copy_from_slice(&0u16.to_be_bytes()); // corrected length
        assert_eq!(&output[..written], &expected);
    }

    // RTCP-BYE-008 — 差分：上游 "nil"（空输入）→ UnexpectedEnd。
    #[test]
    fn rtcp_bye_008_nil_input_rejected() {
        assert_eq!(Goodbye::decode(&[]), Err(WireError::UnexpectedEnd));
        assert_eq!(Goodbye::decode(&[0x81]), Err(WireError::UnexpectedEnd));
    }

    // RTCP-BYE-009 — 属性：多 source + 空 reason 往返（count>1）。
    #[test]
    fn rtcp_bye_009_multi_source_round_trip() {
        let sources = [0x1111_1111u32, 0x2222_2222, 0x3333_3333].map(u32::to_be_bytes);
        let sources: Vec<u8> = sources.iter().flatten().copied().collect();
        let bye = Goodbye {
            sources: &sources,
            reason: None,
        };
        let mut buffer = [0u8; 16];
        let written = bye.encode(&mut buffer).expect("encode multi");
        assert_eq!(written, 16);
        assert_eq!(buffer[0], 0x83); // count = 3
        let (decoded, consumed) = Goodbye::decode(&buffer).expect("decode multi");
        assert_eq!(decoded, bye);
        assert_eq!(consumed, written);
        let collected: Vec<u32> = decoded.source_iter().collect();
        assert_eq!(collected, vec![0x1111_1111, 0x2222_2222, 0x3333_3333]);
    }

    // RTCP-BYE-010 — 回归：reason 非 4 字节倍数时必须补零对齐，且
    // `length` 字段与实际写入字节数自洽（fuzz 发现的真实缺陷）。
    #[test]
    fn rtcp_bye_010_reason_is_zero_padded_to_32bit_boundary() {
        // 4 header + 4 SSRC + 1 length octet + 1-octet reason = 10 raw,
        // padded to 12 so that `length` == 2.
        let sources = 0x902f_9e2eu32.to_be_bytes();
        let bye = Goodbye {
            sources: &sources,
            reason: Some(b"F"),
        };
        assert_eq!(bye.encoded_len(), 12);
        assert_eq!(bye.header().length, 2);

        let mut buffer = [0xffu8; 12];
        let written = bye.encode(&mut buffer).expect("encode padded BYE");
        assert_eq!(written, 12);
        assert_eq!(
            &buffer[..],
            &[
                0x81, 0xcb, 0x00, 0x02, 0x90, 0x2f, 0x9e, 0x2e, 0x01, 0x46, 0x00, 0x00
            ]
        );

        // Byte-exact round trip through the decoder.
        let (decoded, consumed) = Goodbye::decode(&buffer).expect("decode padded BYE");
        assert_eq!(consumed, 12);
        assert_eq!(decoded, bye);
        assert_eq!(decoded.encoded_len(), consumed);
    }

    // RTCP-BYE-011 — 回归：空 reason（长度 0）同样需要 3 字节零填充，
    // 这是 fuzz 崩溃输入 `80 cb 00 01 00 7b c9 28 3a` 的形态。
    #[test]
    fn rtcp_bye_011_empty_reason_pads_to_32bit_boundary() {
        let bye = Goodbye {
            sources: &[],
            reason: Some(b""),
        };
        assert_eq!(bye.encoded_len(), 8);
        assert_eq!(bye.header().length, 1);

        let mut buffer = [0u8; 8];
        let written = bye.encode(&mut buffer).expect("encode empty reason");
        assert_eq!(written, 8);
        assert_eq!(
            &buffer[..],
            &[0x80, 0xcb, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(bye.encode(&mut buffer).expect("re-encode"), 8);
    }

    // RTCP-BYE-012 — 回归：reason 之后的多余尾部字节必须被拒绝。BYE 没有
    // reason 之后的字段，若 decode 接受更长的包，re-encode 就会静默丢弃
    // 尾部，破坏逐字节往返（fuzz 输入 `80 cb 00 0c 00 ...` 形态）。
    #[test]
    fn rtcp_bye_012_trailing_bytes_after_reason_rejected() {
        // count=0, reason_len=0 -> model size is 8, but length announces 52.
        let mut packet = [0u8; 52];
        packet[0] = 0x80;
        packet[1] = 0xcb; // BYE
        packet[2..4].copy_from_slice(&12u16.to_be_bytes()); // length 12 -> 52 bytes
        assert_eq!(Goodbye::decode(&packet), Err(WireError::InvalidValue));

        // The same shape truncated to the modelled size decodes fine.
        let mut exact = [0u8; 8];
        exact[0] = 0x80;
        exact[1] = 0xcb;
        exact[2..4].copy_from_slice(&1u16.to_be_bytes()); // length 1 -> 8 bytes
        let (bye, consumed) = Goodbye::decode(&exact).expect("exact-size BYE decodes");
        assert_eq!(consumed, 8);
        assert_eq!(bye.reason, Some(&b""[..]));
    }
}

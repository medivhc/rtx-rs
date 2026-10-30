//! Sender report packet (RFC 3550 section 6.4.1, type 200).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|   RC   |   PT=SR=200   |             length            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         SSRC of sender                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |              NTP timestamp, most significant word             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |              NTP timestamp, least significant word            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         RTP timestamp                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     sender's packet count                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      sender's octet count                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                 SSRC_1 (SSRC of first source)                 |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | report block 1 : fraction lost |  cumulative lost |  highest   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           ...                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  profile-specific extensions                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The number of report blocks is driven by the header `count` field, not
//! by `length` (this matches the upstream webrtc-rs implementation). The
//! profile-specific extension region is kept verbatim so that
//! `encode(decode(bytes))` reproduces the input exactly.

use rtx_wire::{Cursor, Decode, Encode, WireError, Writer};

use crate::header::{COUNT_MAX, Header, PacketType};
use crate::reception_report::{RECEPTION_REPORT_LENGTH, ReceptionReport};
use crate::util::{padding_size, write_padding};

/// Offset of the first report block (4-byte common header + 24-byte
/// sender-info section).
pub const SR_REPORT_OFFSET: usize = 28;

/// Size of the sender information section (SSRC through octet count).
pub const SENDER_INFO_LENGTH: usize = 24;

/// Minimum size of an SR packet: common header plus sender information.
pub const SR_FIXED_LENGTH: usize = 4 + SENDER_INFO_LENGTH;

/// Sender report packet borrowing its variable-length regions from the
/// input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderReport<'a> {
    /// SSRC of the sender.
    pub ssrc: u32,
    /// NTP wallclock timestamp (64 bits).
    pub ntp_time: u64,
    /// RTP timestamp corresponding to the NTP timestamp.
    pub rtp_time: u32,
    /// Number of RTP data packets transmitted.
    pub packet_count: u32,
    /// Number of payload octets transmitted.
    pub octet_count: u32,
    /// Raw report blocks (24 bytes each), borrowed verbatim.
    pub report_blocks: &'a [u8],
    /// Profile-specific extension data, borrowed verbatim.
    pub profile_extensions: &'a [u8],
}

impl SenderReport<'_> {
    /// Iterates over the reception report blocks.
    ///
    /// Each block decodes infallibly because [`Decode`] for
    /// [`SenderReport`] guarantees the region length is a multiple of 24.
    pub fn reports(&self) -> impl Iterator<Item = ReceptionReport> + '_ {
        self.report_blocks
            .chunks_exact(RECEPTION_REPORT_LENGTH)
            .map(|chunk| {
                ReceptionReport::decode(chunk)
                    .map_or_else(|_| ReceptionReport::default(), |(r, _)| r)
            })
    }

    /// Header implied by the current field values.
    ///
    /// `count` saturates at 31 and `length` at `u16::MAX` when the packet
    /// is too large; [`Encode`] performs the real validation.
    #[must_use]
    pub fn header(&self) -> Header {
        let raw_len = self.raw_len();
        let padding = padding_size(raw_len) != 0;
        let count =
            u8::try_from(self.report_blocks.len() / RECEPTION_REPORT_LENGTH).unwrap_or(COUNT_MAX);
        let length = u16::try_from((raw_len + padding_size(raw_len)) / 4 - 1).unwrap_or(u16::MAX);
        Header {
            padding,
            count,
            packet_type: PacketType::Sr,
            length,
        }
    }

    /// Unpadded wire size (common header + sender info + blocks + extensions).
    fn raw_len(&self) -> usize {
        HEADER_AND_SENDER + self.report_blocks.len() + self.profile_extensions.len()
    }

    /// Encodes the packet into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when there are more than 31
    /// report blocks or the block region is not a multiple of 24 bytes,
    /// and [`WireError::OutputTooSmall`] when the writer lacks room.
    pub(crate) fn write_to(&self, writer: &mut Writer<'_>) -> Result<(), WireError> {
        let count = self.report_blocks.len() / RECEPTION_REPORT_LENGTH;
        if count > usize::from(COUNT_MAX) {
            return Err(WireError::InvalidValue);
        }
        if self.report_blocks.len() % RECEPTION_REPORT_LENGTH != 0 {
            return Err(WireError::InvalidValue);
        }
        let raw_len = self.raw_len();
        let padding = padding_size(raw_len);
        let total = raw_len + padding;
        let length = u16::try_from(total / 4 - 1).map_err(|_| WireError::Overflow)?;

        let header = Header {
            padding: padding != 0,
            count: u8::try_from(count).map_err(|_| WireError::InvalidValue)?,
            packet_type: PacketType::Sr,
            length,
        };
        header.write_to(writer)?;

        writer.u32_be(self.ssrc)?;
        writer.put(&self.ntp_time.to_be_bytes())?;
        writer.u32_be(self.rtp_time)?;
        writer.u32_be(self.packet_count)?;
        writer.u32_be(self.octet_count)?;
        writer.put(self.report_blocks)?;
        writer.put(self.profile_extensions)?;
        if padding != 0 {
            write_padding(writer, padding)?;
        }
        Ok(())
    }
}

/// Common header (4) plus sender information (24).
const HEADER_AND_SENDER: usize = 4 + SENDER_INFO_LENGTH;
impl<'a> Decode<'a> for SenderReport<'a> {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        let (header, consumed) = Header::decode(input)?;
        if header.packet_type != PacketType::Sr {
            return Err(WireError::InvalidValue);
        }
        if input.len() < SR_FIXED_LENGTH {
            return Err(WireError::UnexpectedEnd);
        }

        let mut cursor = Cursor::new(&input[consumed..]);
        let ssrc = cursor.u32_be()?;
        let ntp_hi = u64::from(cursor.u32_be()?);
        let ntp_lo = u64::from(cursor.u32_be()?);
        let rtp_time = cursor.u32_be()?;
        let packet_count = cursor.u32_be()?;
        let octet_count = cursor.u32_be()?;

        // The count field drives the report block region (upstream ignores
        // the length field here).
        let blocks_end = SR_FIXED_LENGTH
            .checked_add(usize::from(header.count) * RECEPTION_REPORT_LENGTH)
            .ok_or(WireError::Overflow)?;
        if blocks_end > input.len() {
            return Err(WireError::UnexpectedEnd);
        }

        let report = SenderReport {
            ssrc,
            ntp_time: (ntp_hi << 32) | ntp_lo,
            rtp_time,
            packet_count,
            octet_count,
            report_blocks: &input[SR_FIXED_LENGTH..blocks_end],
            profile_extensions: &input[blocks_end..],
        };
        Ok((report, input.len()))
    }
}

impl Encode for SenderReport<'_> {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        let raw_len = self.raw_len();
        raw_len + padding_size(raw_len)
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

    /// Differential vector: upstream `rtcp/sender_report/sender_report_test.rs:14-27`
    /// ("valid", 52 bytes, bogus length 7 — real length is 12).
    const SR_VALID: [u8; 52] = [
        0x81, 0xc8, 0x00, 0x07, // v=2, p=0, count=1, SR, len=7 (bogus)
        0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
        0xda, 0x8b, 0xd1, 0xfc, 0xdd, 0xdd, 0xa0, 0x5a, // ntp=0xda8bd1fcdddda05a
        0xaa, 0xf4, 0xed, 0xd5, // rtp=0xaaf4edd5
        0x00, 0x00, 0x00, 0x01, // packetCount=1
        0x00, 0x00, 0x00, 0x02, // octetCount=2
        0xbc, 0x5e, 0x9a, 0x40, // report block ssrc=0xbc5e9a40
        0x00, 0x00, 0x00, 0x00, // fracLost=0, totalLost=0
        0x00, 0x00, 0x46, 0xe1, // lastSeq=0x46e1
        0x00, 0x00, 0x01, 0x11, // jitter=273
        0x09, 0xf3, 0x64, 0x32, // lsr=0x9f36432
        0x00, 0x02, 0x4a, 0x79, // delay=150137
    ];

    /// Differential vector: upstream `rtcp/sender_report/sender_report_test.rs:87-97`
    /// ("with extension", 56 bytes, bogus length 6 — real length is 13).
    const SR_WITH_EXTENSION: [u8; 56] = [
        0x80, 0xc8, 0x00, 0x06, // v=2, p=0, count=0, SR, len=6 (bogus)
        0x2b, 0x7e, 0xc0, 0xc5, // ssrc=0x2b7ec0c5
        0xe0, 0x20, 0xa2, 0xa9, 0x52, 0xa5, 0x3f, 0xc0, // ntp=0xe020a2a952a53fc0
        0x2e, 0x48, 0xa5, 0x52, // rtp=0x2e48a552
        0x00, 0x00, 0x00, 0x46, // packetCount=70
        0x00, 0x00, 0x12, 0x1d, // octetCount=4637
        0x81, 0xca, 0x00, 0x06, 0x2b, 0x7e, 0xc0, 0xc5, 0x01, 0x10, 0x4c, 0x63, 0x49, 0x66, 0x7a,
        0x58, 0x6f, 0x6e, 0x44, 0x6f, 0x72, 0x64, 0x53, 0x65, 0x57, 0x36, 0x00,
        0x00, // profile ext
    ];

    /// Differential vector: upstream `rtcp/sender_report/sender_report_test.rs:66-70`
    /// ("wrong type": RR header with SR payload).
    const SR_WRONG_TYPE: [u8; 32] = [
        0x81, 0xc9, 0x00, 0x07, // RR header
        0x90, 0x2f, 0x9e, 0x2e, 0xda, 0x8b, 0xd1, 0xfc, 0xdd, 0xdd, 0xa0, 0x5a, 0xaa, 0xf4, 0xed,
        0xd5, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0xbc, 0x5e, 0x9a, 0x40,
    ];

    // RTCP-SR-001 — 差分：上游 "valid" 向量逐字段断言（length 字段忽略）。
    #[test]
    fn rtcp_sr_001_upstream_valid_vector_fields() {
        let (sr, consumed) = SenderReport::decode(&SR_VALID).expect("decode SR valid");
        assert_eq!(consumed, SR_VALID.len());
        assert_eq!(sr.ssrc, 0x902f_9e2e);
        assert_eq!(sr.ntp_time, 0xda8b_d1fc_dddd_a05a);
        assert_eq!(sr.rtp_time, 0xaaf4_edd5);
        assert_eq!(sr.packet_count, 1);
        assert_eq!(sr.octet_count, 2);
        assert_eq!(sr.report_blocks.len(), RECEPTION_REPORT_LENGTH);
        assert_eq!(sr.profile_extensions, []);

        let reports: Vec<ReceptionReport> = sr.reports().collect();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].ssrc, 0xbc5e_9a40);
        assert_eq!(reports[0].jitter, 273);
        assert_eq!(reports[0].last_sr, 0x09f3_6432);
        assert_eq!(reports[0].delay_since_last_sr, 150_137);

        // header() 反映重算后的 length=12（上游 marshal 行为）。
        let header = sr.header();
        assert_eq!(header.packet_type, PacketType::Sr);
        assert_eq!(header.count, 1);
        assert_eq!(header.length, 12);
        assert!(!header.padding);
        assert_eq!(header.total_len(), 52);
    }

    // RTCP-SR-002 — 差分：encode(decode(v)) 除 length 字段外逐字节一致
    // （上游向量 length 为 bogus 值，encode 时按 RFC 重算）。
    #[test]
    fn rtcp_sr_002_encode_recomputes_length_field() {
        let (sr, _) = SenderReport::decode(&SR_VALID).expect("decode SR valid");
        let mut output = [0u8; 64];
        let written = sr.encode(&mut output).expect("encode SR valid");
        assert_eq!(written, 52);
        assert_eq!(written, sr.encoded_len());

        let mut expected = SR_VALID;
        expected[2..4].copy_from_slice(&12u16.to_be_bytes()); // corrected length
        assert_eq!(&output[..written], &expected);

        // 重编码结果可再次 decode 且字段一致。
        let (again, _) = SenderReport::decode(&output[..written]).expect("re-decode");
        assert_eq!(again, sr);
    }

    // RTCP-SR-003 — 差分：上游 "with extension" 向量（count=0，profile ext 吞剩余）。
    #[test]
    fn rtcp_sr_003_upstream_extension_vector_round_trip() {
        let (sr, consumed) = SenderReport::decode(&SR_WITH_EXTENSION).expect("decode SR ext");
        assert_eq!(consumed, SR_WITH_EXTENSION.len());
        assert_eq!(sr.ssrc, 0x2b7e_c0c5);
        assert_eq!(sr.ntp_time, 0xe020_a2a9_52a5_3fc0);
        assert_eq!(sr.rtp_time, 0x2e48_a552);
        assert_eq!(sr.packet_count, 70);
        assert_eq!(sr.octet_count, 4637);
        assert_eq!(sr.report_blocks, []);
        assert_eq!(sr.reports().count(), 0);
        assert_eq!(sr.profile_extensions.len(), 28);

        let mut output = [0u8; 64];
        let written = sr.encode(&mut output).expect("encode SR ext");
        assert_eq!(written, 56);
        let mut expected = SR_WITH_EXTENSION;
        expected[2..4].copy_from_slice(&13u16.to_be_bytes()); // corrected length
        assert_eq!(&output[..written], &expected);
    }

    // RTCP-SR-004 — 差分：错误类型头（RR 头 + SR 体）→ InvalidValue。
    #[test]
    fn rtcp_sr_004_wrong_type_rejected() {
        assert_eq!(
            SenderReport::decode(&SR_WRONG_TYPE),
            Err(WireError::InvalidValue)
        );
    }

    // RTCP-SR-005 — count 超出可用字节 → UnexpectedEnd（上游 "bad count"）。
    #[test]
    fn rtcp_sr_005_count_exceeds_input_rejected() {
        let mut short = SR_VALID;
        short[0] = 0x82; // count = 2 but only one block present
        assert_eq!(SenderReport::decode(&short), Err(WireError::UnexpectedEnd));
    }

    // RTCP-SR-006 — 短于 28 字节 → UnexpectedEnd（上游 "nil"/截断路径）。
    #[test]
    fn rtcp_sr_006_truncated_input_rejected() {
        for len in 0..SR_FIXED_LENGTH {
            assert_eq!(
                SenderReport::decode(&SR_VALID[..len]),
                Err(WireError::UnexpectedEnd),
                "length {len} must be rejected"
            );
        }
    }

    // RTCP-SR-007 — 属性：标量 round-trip（含 u64::MAX NTP 与边界值）。
    #[test]
    fn rtcp_sr_007_scalar_round_trip_property() {
        for (ssrc, ntp, rtp, packets, octets) in [
            (0u32, 0u64, 0u32, 0u32, 0u32),
            (1, u64::MAX, u32::MAX, u32::MAX, u32::MAX),
            (0x902f_9e2e, 0xda8b_d1fc_dddd_a05a, 0xaaf4_edd5, 1, 2),
        ] {
            let sr = SenderReport {
                ssrc,
                ntp_time: ntp,
                rtp_time: rtp,
                packet_count: packets,
                octet_count: octets,
                report_blocks: &[],
                profile_extensions: &[],
            };
            let mut buffer = [0u8; SR_FIXED_LENGTH];
            let written = sr.encode(&mut buffer).expect("encode");
            assert_eq!(written, sr.encoded_len());
            let (decoded, consumed) = SenderReport::decode(&buffer).expect("decode");
            assert_eq!(decoded, sr);
            assert_eq!(consumed, written);
        }
    }

    // RTCP-SR-008 — 非对齐 profile ext 时 encode 追加 padding 且置 P 标志。
    #[test]
    fn rtcp_sr_008_unaligned_extension_gets_padding() {
        let sr = SenderReport {
            ssrc: 0x2b7e_c0c5,
            ntp_time: 0xe020_a2a9_52a5_3fc0,
            rtp_time: 0x2e48_a552,
            packet_count: 70,
            octet_count: 4637,
            report_blocks: &[],
            profile_extensions: b"abc",
        };
        assert_eq!(sr.encoded_len(), 32); // 31 raw + 1 padding
        assert!(sr.header().padding);

        let mut buffer = [0u8; 32];
        let written = sr.encode(&mut buffer).expect("encode padded");
        assert_eq!(written, 32);
        assert_eq!(&buffer[28..31], b"abc");
        assert_eq!(buffer[31], 1); // padding count byte
        assert_eq!(buffer[0] & 0x20, 0x20); // P flag set

        // 再 decode：profile ext 吞掉全部剩余（含 padding），字段一致。
        let (decoded, _) = SenderReport::decode(&buffer).expect("decode padded");
        assert_eq!(decoded.ssrc, sr.ssrc);
        assert_eq!(decoded.profile_extensions, b"abc\x01");
    }
}

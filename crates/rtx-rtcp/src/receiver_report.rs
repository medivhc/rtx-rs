//! Receiver report packet (RFC 3550 section 6.4.2, type 201).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|   RC   |   PT=RR=201   |             length            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     SSRC of packet sender                     |
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
//! As with [`SenderReport`](crate::sender_report::SenderReport), the report block count comes from the header
//! `count` field and the extension region is kept verbatim.

use rtx_wire::{Cursor, Decode, Encode, WireError, Writer};

use crate::header::{COUNT_MAX, Header, PacketType};
use crate::reception_report::{RECEPTION_REPORT_LENGTH, ReceptionReport};
use crate::util::{padding_size, write_padding};

/// Offset of the first report block (4-byte common header + 4-byte SSRC).
pub const RR_REPORT_OFFSET: usize = 8;

/// Minimum size of an RR packet: common header plus sender SSRC.
pub const RR_FIXED_LENGTH: usize = RR_REPORT_OFFSET;

/// Receiver report packet borrowing its variable-length regions from the
/// input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverReport<'a> {
    /// SSRC of the receiver issuing this report.
    pub ssrc: u32,
    /// Raw report blocks (24 bytes each), borrowed verbatim.
    pub report_blocks: &'a [u8],
    /// Profile-specific extension data, borrowed verbatim.
    pub profile_extensions: &'a [u8],
}

impl ReceiverReport<'_> {
    /// Iterates over the reception report blocks.
    ///
    /// Each block decodes infallibly because [`Decode`] for
    /// [`ReceiverReport`] guarantees the region length is a multiple of 24.
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
        Header {
            padding: padding_size(raw_len) != 0,
            count: u8::try_from(self.report_blocks.len() / RECEPTION_REPORT_LENGTH)
                .unwrap_or(COUNT_MAX),
            packet_type: PacketType::Rr,
            length: u16::try_from((raw_len + padding_size(raw_len)) / 4 - 1).unwrap_or(u16::MAX),
        }
    }

    /// Unpadded wire size (common header + SSRC + blocks + extensions).
    fn raw_len(&self) -> usize {
        RR_FIXED_LENGTH + self.report_blocks.len() + self.profile_extensions.len()
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
            packet_type: PacketType::Rr,
            length,
        };
        header.write_to(writer)?;

        writer.u32_be(self.ssrc)?;
        writer.put(self.report_blocks)?;
        writer.put(self.profile_extensions)?;
        if padding != 0 {
            write_padding(writer, padding)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ReceiverReport<'a> {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        let (header, consumed) = Header::decode(input)?;
        if header.packet_type != PacketType::Rr {
            return Err(WireError::InvalidValue);
        }
        if input.len() < RR_FIXED_LENGTH {
            return Err(WireError::UnexpectedEnd);
        }

        let mut cursor = Cursor::new(&input[consumed..]);
        let ssrc = cursor.u32_be()?;

        // The count field drives the report block region (upstream ignores
        // the length field here).
        let blocks_end = RR_REPORT_OFFSET
            .checked_add(usize::from(header.count) * RECEPTION_REPORT_LENGTH)
            .ok_or(WireError::Overflow)?;
        if blocks_end > input.len() {
            return Err(WireError::UnexpectedEnd);
        }

        let report = ReceiverReport {
            ssrc,
            report_blocks: &input[RR_REPORT_OFFSET..blocks_end],
            profile_extensions: &input[blocks_end..],
        };
        Ok((report, input.len()))
    }
}

impl Encode for ReceiverReport<'_> {
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

    /// Differential vector: upstream `rtcp/receiver_report/receiver_report_test.rs:8-17`
    /// ("valid", 32 bytes, length 7 is correct).
    const RR_VALID: [u8; 32] = [
        0x81, 0xc9, 0x00, 0x07, // v=2, p=0, count=1, RR, len=7
        0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
        0xbc, 0x5e, 0x9a, 0x40, // report block ssrc=0xbc5e9a40
        0x00, 0x00, 0x00, 0x00, // fracLost=0, totalLost=0
        0x00, 0x00, 0x46, 0xe1, // lastSeq=0x46e1
        0x00, 0x00, 0x01, 0x11, // jitter=273
        0x09, 0xf3, 0x64, 0x32, // lsr=0x9f36432
        0x00, 0x02, 0x4a, 0x79, // delay=150137
    ];

    /// Differential vector: upstream `rtcp/receiver_report/receiver_report_test.rs:35-45`
    /// ("valid with extension data", 40 bytes, length 9 is correct).
    const RR_VALID_EXT: [u8; 40] = [
        0x81, 0xc9, 0x00, 0x09, // v=2, p=0, count=1, RR, len=9
        0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
        0xbc, 0x5e, 0x9a, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0xe1, 0x00, 0x00, 0x01,
        0x11, 0x09, 0xf3, 0x64, 0x32, 0x00, 0x02, 0x4a, 0x79, // report block
        0x54, 0x45, 0x53, 0x54, 0x44, 0x41, 0x54, 0x41, // profile ext "TESTDATA"
    ];

    /// Differential vector: upstream `rtcp/receiver_report/receiver_report_test.rs:66-70`
    /// ("short report", 12 bytes).
    const RR_SHORT: [u8; 12] = [
        0x81, 0xc9, 0x00, 0x0c, // v=2, p=0, count=1, RR, len=12 (bogus)
        0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
        0x00, 0x00, 0x00, 0x00, // report ends early
    ];

    /// Differential vector: upstream `rtcp/receiver_report/receiver_report_test.rs:78-88`
    /// ("wrong type", 32 bytes).
    const RR_WRONG_TYPE: [u8; 32] = [
        0x81, 0xc8, 0x00, 0x07, // SR header
        0x90, 0x2f, 0x9e, 0x2e, 0xbc, 0x5e, 0x9a, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        0xe1, 0x00, 0x00, 0x01, 0x11, 0x09, 0xf3, 0x64, 0x32, 0x00, 0x02, 0x4a, 0x79,
    ];

    /// Differential vector: upstream `rtcp/receiver_report/receiver_report_test.rs:94-103`
    /// ("bad count in header", 32 bytes).
    const RR_BAD_COUNT: [u8; 32] = [
        0x82, 0xc9, 0x00, 0x07, // count=2 but only one block
        0x90, 0x2f, 0x9e, 0x2e, 0xbc, 0x5e, 0x9a, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        0xe1, 0x00, 0x00, 0x01, 0x11, 0x09, 0xf3, 0x64, 0x32, 0x00, 0x02, 0x4a, 0x79,
    ];

    // RTCP-RR-001 — 差分：上游 "valid" 向量逐字段 + encode 字节级往返。
    #[test]
    fn rtcp_rr_001_upstream_valid_vector_round_trip() {
        let (rr, consumed) = ReceiverReport::decode(&RR_VALID).expect("decode RR valid");
        assert_eq!(consumed, RR_VALID.len());
        assert_eq!(rr.ssrc, 0x902f_9e2e);
        assert_eq!(rr.report_blocks.len(), RECEPTION_REPORT_LENGTH);
        assert!(rr.profile_extensions.is_empty());

        let reports: Vec<ReceptionReport> = rr.reports().collect();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].ssrc, 0xbc5e_9a40);
        assert_eq!(reports[0].last_sr, 0x09f3_6432);

        let header = rr.header();
        assert_eq!(header.packet_type, PacketType::Rr);
        assert_eq!(header.count, 1);
        assert_eq!(header.length, 7);

        let mut output = [0u8; 40];
        let written = rr.encode(&mut output).expect("encode RR valid");
        assert_eq!(written, 32);
        assert_eq!(written, rr.encoded_len());
        assert_eq!(&output[..written], &RR_VALID);
    }

    // RTCP-RR-002 — 差分：上游 "valid with extension data" 向量。
    #[test]
    fn rtcp_rr_002_upstream_extension_vector_round_trip() {
        let (rr, consumed) = ReceiverReport::decode(&RR_VALID_EXT).expect("decode RR ext");
        assert_eq!(consumed, RR_VALID_EXT.len());
        assert_eq!(rr.ssrc, 0x902f_9e2e);
        assert_eq!(rr.report_blocks.len(), RECEPTION_REPORT_LENGTH);
        assert_eq!(rr.profile_extensions, b"TESTDATA");
        assert_eq!(rr.header().length, 9);

        let mut output = [0u8; 40];
        let written = rr.encode(&mut output).expect("encode RR ext");
        assert_eq!(written, 40);
        assert_eq!(&output[..written], &RR_VALID_EXT);
    }

    // RTCP-RR-003 — 差分：上游 "short report" → UnexpectedEnd。
    #[test]
    fn rtcp_rr_003_short_report_rejected() {
        assert_eq!(
            ReceiverReport::decode(&RR_SHORT),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTCP-RR-004 — 差分：上游 "wrong type" → InvalidValue。
    #[test]
    fn rtcp_rr_004_wrong_type_rejected() {
        assert_eq!(
            ReceiverReport::decode(&RR_WRONG_TYPE),
            Err(WireError::InvalidValue)
        );
    }

    // RTCP-RR-005 — 差分：上游 "bad count in header" → UnexpectedEnd。
    #[test]
    fn rtcp_rr_005_bad_count_rejected() {
        assert_eq!(
            ReceiverReport::decode(&RR_BAD_COUNT),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTCP-RR-006 — 属性：count=0 空 RR 往返 + 非对齐 ext padding。
    #[test]
    fn rtcp_rr_006_empty_and_padded_round_trip() {
        let empty = ReceiverReport {
            ssrc: 0x902f_9e2e,
            report_blocks: &[],
            profile_extensions: &[],
        };
        let mut buffer = [0u8; RR_FIXED_LENGTH];
        let written = empty.encode(&mut buffer).expect("encode empty");
        assert_eq!(written, 8);
        assert_eq!(buffer, [0x80, 0xc9, 0x00, 0x01, 0x90, 0x2f, 0x9e, 0x2e]);
        let (decoded, consumed) = ReceiverReport::decode(&buffer).expect("decode empty");
        assert_eq!(decoded, empty);
        assert_eq!(consumed, written);

        let padded = ReceiverReport {
            ssrc: 1,
            report_blocks: &[],
            profile_extensions: b"xy",
        };
        let mut buffer = [0u8; 12];
        let written = padded.encode(&mut buffer).expect("encode padded");
        assert_eq!(written, 12);
        assert_eq!(buffer[0] & 0x20, 0x20); // P flag
        assert_eq!(&buffer[8..10], b"xy");
        assert_eq!(buffer[11], 2); // padding count byte
    }
}

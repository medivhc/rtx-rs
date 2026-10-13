//! Reception report block (RFC 3550 section 6.4.1, 24 bytes).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                             SSRC                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | fraction lost |       cumulative number of packets lost       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           extended highest sequence number received           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      interarrival jitter                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                 last SR (LSR) timestamp                       |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   delay since last SR (DLSR)                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use rtx_wire::{Cursor, Decode, Encode, WireError, Writer};

/// Size of one reception report block in bytes.
pub const RECEPTION_REPORT_LENGTH: usize = 24;

/// Maximum value of the 24-bit "cumulative number of packets lost" field.
pub const TOTAL_LOST_MAX: u32 = (1 << 24) - 1;

/// One reception report block describing the reception quality of a single
/// synchronization source (RFC 3550 section 6.4.1).
///
/// This is an owned value (24 bytes of scalars) so it can be yielded by the
/// report-block iterators of [`SenderReport`](crate::SenderReport) and
/// [`ReceiverReport`](crate::ReceiverReport).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReceptionReport {
    /// SSRC identifier of the observed source.
    pub ssrc: u32,
    /// Fraction of RTP data packets lost since the previous report (8-bit
    /// fixed point).
    pub fraction_lost: u8,
    /// Cumulative number of packets lost (24 bits).
    pub total_lost: u32,
    /// Extended highest sequence number received.
    pub highest_sequence: u32,
    /// Estimated interarrival jitter.
    pub jitter: u32,
    /// Middle 32 bits of the NTP timestamp of the last sender report.
    pub last_sr: u32,
    /// Delay since the last sender report, in units of 1/65536 seconds.
    pub delay_since_last_sr: u32,
}

impl ReceptionReport {
    /// Encodes the block into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when `total_lost` does not fit
    /// into the 24-bit wire field, or [`WireError::OutputTooSmall`] when
    /// the writer has no room.
    pub(crate) fn write_to(&self, writer: &mut Writer<'_>) -> Result<(), WireError> {
        if self.total_lost > TOTAL_LOST_MAX {
            return Err(WireError::InvalidValue);
        }
        writer.u32_be(self.ssrc)?;
        writer.u8(self.fraction_lost)?;
        let lost = self.total_lost.to_be_bytes();
        writer.put(&lost[1..4])?;
        writer.u32_be(self.highest_sequence)?;
        writer.u32_be(self.jitter)?;
        writer.u32_be(self.last_sr)?;
        writer.u32_be(self.delay_since_last_sr)?;
        Ok(())
    }
}

impl<'a> Decode<'a> for ReceptionReport {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        let mut cursor = Cursor::new(input);
        let ssrc = cursor.u32_be()?;
        let fraction_lost = cursor.u8()?;
        let lost = cursor.take(3)?;
        let highest_sequence = cursor.u32_be()?;
        let jitter = cursor.u32_be()?;
        let last_sr = cursor.u32_be()?;
        let delay_since_last_sr = cursor.u32_be()?;
        let report = ReceptionReport {
            ssrc,
            fraction_lost,
            total_lost: u32::from_be_bytes([0, lost[0], lost[1], lost[2]]),
            highest_sequence,
            jitter,
            last_sr,
            delay_since_last_sr,
        };
        Ok((report, cursor.offset()))
    }
}

impl Encode for ReceptionReport {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        RECEPTION_REPORT_LENGTH
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

    /// Builds a 24-byte reception report block for testing.
    fn block(
        ssrc: u32,
        fraction: u8,
        lost: u32,
        highest: u32,
        jitter: u32,
        lsr: u32,
        dlsr: u32,
    ) -> [u8; RECEPTION_REPORT_LENGTH] {
        let mut bytes = [0u8; RECEPTION_REPORT_LENGTH];
        bytes[0..4].copy_from_slice(&ssrc.to_be_bytes());
        bytes[4] = fraction;
        bytes[5..8].copy_from_slice(&lost.to_be_bytes()[1..4]);
        bytes[8..12].copy_from_slice(&highest.to_be_bytes());
        bytes[12..16].copy_from_slice(&jitter.to_be_bytes());
        bytes[16..20].copy_from_slice(&lsr.to_be_bytes());
        bytes[20..24].copy_from_slice(&dlsr.to_be_bytes());
        bytes
    }

    /// Differential vector: first reception report block of the upstream
    /// receiver report test (`rtcp/receiver_report/receiver_report_test.rs:8-17`).
    const RR_FIRST_BLOCK: [u8; RECEPTION_REPORT_LENGTH] = [
        0xbc, 0x5e, 0x9a, 0x40, // SSRC 0xbc5e9a40
        0x00, 0x00, 0x00, 0x00, // fraction 0, total lost 0
        0x00, 0x00, 0x46, 0xe1, // highest sequence 0x46e1
        0x00, 0x00, 0x01, 0x11, // jitter 273
        0x09, 0xf3, 0x64, 0x32, // last SR 0x9f36432
        0x00, 0x02, 0x4a, 0x79, // DLSR 150137
    ];

    // RTCP-RRBLK-001 — 差分：上游 RR 首 report block 逐字段 + 字节级往返。
    #[test]
    fn rtcp_rrblk_001_upstream_first_block_round_trip() {
        let (report, consumed) =
            ReceptionReport::decode(&RR_FIRST_BLOCK).expect("decode first block");
        assert_eq!(consumed, RECEPTION_REPORT_LENGTH);
        assert_eq!(report.ssrc, 0xbc5e_9a40);
        assert_eq!(report.fraction_lost, 0);
        assert_eq!(report.total_lost, 0);
        assert_eq!(report.highest_sequence, 0x46e1);
        assert_eq!(report.jitter, 273);
        assert_eq!(report.last_sr, 0x09f3_6432);
        assert_eq!(report.delay_since_last_sr, 150_137);

        let mut output = [0u8; RECEPTION_REPORT_LENGTH];
        let written = report.encode(&mut output).expect("encode block");
        assert_eq!(written, RECEPTION_REPORT_LENGTH);
        assert_eq!(output, RR_FIRST_BLOCK);
    }

    // RTCP-RRBLK-002 — 24 位 total_lost 边界（最大值往返、超限拒绝）。
    #[test]
    fn rtcp_rrblk_002_total_lost_24bit_bounds() {
        let max = block(1, 0, TOTAL_LOST_MAX, 2, 3, 4, 5);
        let (report, _) = ReceptionReport::decode(&max).expect("decode max lost");
        assert_eq!(report.total_lost, TOTAL_LOST_MAX);
        let mut output = [0u8; RECEPTION_REPORT_LENGTH];
        assert_eq!(report.encode(&mut output), Ok(RECEPTION_REPORT_LENGTH));
        assert_eq!(output, max);

        // 超过 24 位上限 → InvalidValue（上游此处有 1<<25 的 off-by-one bug，
        // 见 ARCHITECTURE.md §21.3 取舍记录）。
        let over = ReceptionReport {
            total_lost: TOTAL_LOST_MAX + 1,
            ..Default::default()
        };
        assert_eq!(over.encode(&mut output), Err(WireError::InvalidValue));
    }

    // RTCP-RRBLK-003 — 截断输入 → UnexpectedEnd。
    #[test]
    fn rtcp_rrblk_003_truncated_input_rejected() {
        for len in 0..RECEPTION_REPORT_LENGTH {
            let short = [0u8; RECEPTION_REPORT_LENGTH];
            assert_eq!(
                ReceptionReport::decode(&short[..len]),
                Err(WireError::UnexpectedEnd),
                "length {len} must be rejected"
            );
        }
    }

    // RTCP-RRBLK-004 — 属性：随机标量 round-trip（含 0 与 u32::MAX 边界）。
    #[test]
    fn rtcp_rrblk_004_scalar_round_trip_property() {
        let samples = [
            (0u32, 0u8, 0u32, 0u32, 0u32, 0u32, 0u32),
            (1, 0xFF, 0x00FF_FFFF, 2, 3, 4, 5),
            (u32::MAX, 0x80, 1, u32::MAX, 0xDEAD_BEEF, 0x0BAD_F00D, 7),
        ];
        for (ssrc, fraction, lost, highest, jitter, lsr, dlsr) in samples {
            let report = ReceptionReport {
                ssrc,
                fraction_lost: fraction,
                total_lost: lost,
                highest_sequence: highest,
                jitter,
                last_sr: lsr,
                delay_since_last_sr: dlsr,
            };
            let mut buffer = [0u8; RECEPTION_REPORT_LENGTH];
            let written = report.encode(&mut buffer).expect("encode");
            assert_eq!(written, report.encoded_len());
            let (decoded, consumed) = ReceptionReport::decode(&buffer).expect("decode");
            assert_eq!(decoded, report);
            assert_eq!(consumed, written);
        }
    }

    // RTCP-RRBLK-005 — 尾部多余字节不属于本块（consumed 契约）。
    #[test]
    fn rtcp_rrblk_005_trailing_bytes_not_consumed() {
        let mut input = [0u8; RECEPTION_REPORT_LENGTH + 4];
        input[..RECEPTION_REPORT_LENGTH].copy_from_slice(&RR_FIRST_BLOCK);
        let (report, consumed) =
            ReceptionReport::decode(&input).expect("decode with trailing bytes");
        assert_eq!(consumed, RECEPTION_REPORT_LENGTH);
        assert_eq!(report.ssrc, 0xbc5e_9a40);
    }
}

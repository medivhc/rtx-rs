//! Transport Layer NACK feedback (RFC 4585 section 6.2.1, PT=205, FMT=1).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|  FMT=1  |    PT=205     |           length              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of packet sender                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of media source                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            PID                |             BLP               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! :                              ...                              :
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Each FCI entry is a [`NackPair`]: `PID` names one lost RTP packet and
//! `BLP` bitmasks the 16 packets that follow it (bit `i`, LSB first, set
//! to 1 means packet `PID + i` is lost, modulo 2^16). The FCI field MUST
//! contain at least one pair (RFC 4585 section 6.2.1), so the `length`
//! field is at least 3 and this crate rejects shorter packets.
//!
//! The pair region is kept as a borrowed byte slice (4 bytes per pair),
//! so decoding allocates nothing; [`Nack::pairs`] yields typed
//! [`NackPair`] views and [`NackPair::packet_ids`] expands the bitmask
//! into individual sequence numbers.
//!
//! Note that the header `count` field carries the FMT value (1), *not*
//! the number of pairs — the pair count comes from `length`.

use rtx_wire::{Cursor, Decode, Encode, WireError, Writer};

use crate::header::{Header, PacketType};

/// FMT value of the transport layer NACK feedback message.
pub const FMT_NACK: u8 = 1;

/// Size of one NACK pair (`PID` + `BLP`) in bytes.
pub const NACK_PAIR_LENGTH: usize = 4;

/// Offset of the first NACK pair (common header plus both SSRCs).
pub const NACK_PAIR_OFFSET: usize = 12;

/// Minimum wire size: header, both SSRCs and at least one pair
/// (RFC 4585 section 6.2.1 requires one or more Generic NACKs).
pub const NACK_MIN_OCTET_COUNT: usize = NACK_PAIR_OFFSET + NACK_PAIR_LENGTH;

/// One Generic NACK: a lost packet id plus a bitmask of the next 16.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NackPair {
    /// Packet ID (RTP sequence number of the lost packet).
    pub packet_id: u16,
    /// Bitmask of lost packets following [`NackPair::packet_id`].
    pub lost_packets: u16,
}

impl NackPair {
    /// A pair naming a single lost sequence number, with no bitmask set.
    #[must_use]
    pub const fn new(packet_id: u16) -> Self {
        NackPair {
            packet_id,
            lost_packets: 0,
        }
    }

    /// Expands the pair into the individual sequence numbers it reports.
    ///
    /// The first item is always [`NackPair::packet_id`]; the remaining
    /// items follow in bit order (bit 0 first) and wrap modulo 2^16.
    pub fn packet_ids(&self) -> impl Iterator<Item = u16> + '_ {
        let packet_id = self.packet_id;
        let lost_packets = self.lost_packets;
        core::iter::once(packet_id).chain(
            (0..16u16)
                .filter(move |bit| (lost_packets >> bit) & 1 == 1)
                .map(move |bit| packet_id.wrapping_add(bit + 1)),
        )
    }
}

/// Transport Layer NACK feedback borrowing its pair region from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nack<'a> {
    /// SSRC of the packet sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source the losses belong to.
    pub media_ssrc: u32,
    /// Raw NACK pairs (4 bytes each), borrowed verbatim.
    pub nacks: &'a [u8],
}

impl Nack<'_> {
    /// Iterates over the NACK pairs.
    ///
    /// Each pair decodes infallibly because [`Decode`] for [`Nack`]
    /// guarantees the region length is a multiple of 4.
    pub fn pairs(&self) -> impl Iterator<Item = NackPair> + '_ {
        self.nacks
            .chunks_exact(NACK_PAIR_LENGTH)
            .map(|chunk| NackPair {
                packet_id: u16::from_be_bytes([chunk[0], chunk[1]]),
                lost_packets: u16::from_be_bytes([chunk[2], chunk[3]]),
            })
    }

    /// Header implied by the current field values.
    ///
    /// `count` is the FMT value (1), never the pair count.
    #[must_use]
    pub fn header(&self) -> Header {
        Header {
            padding: false,
            count: FMT_NACK,
            packet_type: PacketType::Tsfb,
            length: u16::try_from(self.raw_len() / 4 - 1).unwrap_or(u16::MAX),
        }
    }

    /// Unpadded wire size (common header + both SSRCs + pair region).
    fn raw_len(&self) -> usize {
        NACK_PAIR_OFFSET + self.nacks.len()
    }

    /// Encodes the packet into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the pair region is not a
    /// multiple of 4 bytes or is empty (RFC 4585 section 6.2.1 requires
    /// at least one Generic NACK), and [`WireError::OutputTooSmall`] when
    /// the writer lacks room.
    pub(crate) fn write_to(&self, writer: &mut Writer<'_>) -> Result<(), WireError> {
        if self.nacks.len() % NACK_PAIR_LENGTH != 0 {
            return Err(WireError::InvalidValue);
        }
        if self.nacks.is_empty() {
            return Err(WireError::InvalidValue);
        }
        let length = u16::try_from(self.raw_len() / 4 - 1).map_err(|_| WireError::Overflow)?;

        let header = Header {
            padding: false,
            count: FMT_NACK,
            packet_type: PacketType::Tsfb,
            length,
        };
        header.write_to(writer)?;

        writer.u32_be(self.sender_ssrc)?;
        writer.u32_be(self.media_ssrc)?;
        writer.put(self.nacks)?;
        Ok(())
    }
}

impl<'a> Decode<'a> for Nack<'a> {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        let (header, consumed) = Header::decode(input)?;
        if header.packet_type != PacketType::Tsfb || header.count != FMT_NACK {
            return Err(WireError::InvalidValue);
        }
        if input.len() < NACK_MIN_OCTET_COUNT {
            return Err(WireError::UnexpectedEnd);
        }

        // The pair count comes from the length field: length = 2 + n.
        let total = usize::from(header.length)
            .checked_mul(4)
            .and_then(|words| words.checked_add(consumed))
            .ok_or(WireError::Overflow)?;
        if total < NACK_MIN_OCTET_COUNT || input.len() < total {
            return Err(WireError::UnexpectedEnd);
        }

        let mut cursor = Cursor::new(&input[consumed..]);
        let sender_ssrc = cursor.u32_be()?;
        let media_ssrc = cursor.u32_be()?;
        let nacks = cursor.take(total - NACK_PAIR_OFFSET)?;

        let nack = Nack {
            sender_ssrc,
            media_ssrc,
            nacks,
        };
        Ok((nack, input.len()))
    }
}

impl Encode for Nack<'_> {
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
    /// `rtcp/transport_feedbacks/transport_layer_nack/transport_layer_nack_test.rs:10-16`
    /// ("valid", 16 bytes; the length field 3 is already correct).
    const NACK_VALID: [u8; 16] = [
        0x81, 0xcd, 0x0, 0x3, // v=2, p=0, FMT=1, TSFB, len=3
        0x90, 0x2f, 0x9e, 0x2e, // sender=0x902f9e2e
        0x90, 0x2f, 0x9e, 0x2e, // media=0x902f9e2e
        0xaa, 0xaa, 0x55, 0x55, // PID=0xaaaa, BLP=0x5555
    ];

    /// Differential vector: upstream `transport_layer_nack_test.rs:28-33`
    /// ("short report": 12 bytes, only one SSRC present).
    const NACK_SHORT_REPORT: [u8; 8] = [0x81, 0xcd, 0x0, 0x2, 0x90, 0x2f, 0x9e, 0x2e];

    /// Differential vector: upstream `transport_layer_nack_test.rs:38-49`
    /// ("wrong type": an SR packet).
    const NACK_WRONG_TYPE: [u8; 32] = [
        0x81, 0xc8, 0x0, 0x7, // v=2, p=0, count=1, SR, len=7
        0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
        0xbc, 0x5e, 0x9a, 0x40, // ssrc=0xbc5e9a40
        0x0, 0x0, 0x0, 0x0, // fracLost=0, totalLost=0
        0x0, 0x0, 0x46, 0xe1, // lastSeq=0x46e1
        0x0, 0x0, 0x1, 0x11, // jitter=273
        0x9, 0xf3, 0x64, 0x32, // lsr=0x9f36432
        0x0, 0x2, 0x4a, 0x79, // delay=150137
    ];

    // RTCP-NACK-001 — 差分：上游 "valid" 向量逐字段 + encode 字节级往返。
    #[test]
    fn rtcp_nack_001_upstream_valid_vector_round_trip() {
        let (nack, consumed) = Nack::decode(&NACK_VALID).expect("decode NACK valid");
        assert_eq!(consumed, NACK_VALID.len());
        assert_eq!(nack.sender_ssrc, 0x902f_9e2e);
        assert_eq!(nack.media_ssrc, 0x902f_9e2e);

        let pairs: Vec<NackPair> = nack.pairs().collect();
        assert_eq!(
            pairs,
            vec![NackPair {
                packet_id: 0xaaaa,
                lost_packets: 0x5555,
            }]
        );

        let header = nack.header();
        assert_eq!(header.packet_type, PacketType::Tsfb);
        assert_eq!(header.count, FMT_NACK);
        assert_eq!(header.length, 3);

        // 上游向量的 length 字段本就是正确值，故字节级全等。
        let mut output = [0u8; 16];
        let written = nack.encode(&mut output).expect("encode NACK valid");
        assert_eq!(written, 16);
        assert_eq!(written, nack.encoded_len());
        assert_eq!(output, NACK_VALID);

        let (again, _) = Nack::decode(&output[..written]).expect("re-decode");
        assert_eq!(again, nack);
    }

    // RTCP-NACK-002 — 差分：上游 roundtrip 向量（两个 NackPair）编解码往返。
    #[test]
    fn rtcp_nack_002_two_pair_round_trip() {
        // 上游 `transport_layer_nack_test.rs:90-104` 的 roundtrip 用例：
        // (PID=1, BLP=0xAA) 与 (PID=1034, BLP=0x05)。
        let expected: [u8; 20] = [
            0x81, 0xcd, 0x0, 0x4, // v=2, p=0, FMT=1, TSFB, len=4
            0x90, 0x2f, 0x9e, 0x2e, // sender
            0x90, 0x2f, 0x9e, 0x2e, // media
            0x0, 0x1, 0x0, 0xaa, // PID=1, BLP=0xAA
            0x4, 0xa, 0x0, 0x5, // PID=1034, BLP=0x05
        ];

        let (nack, consumed) = Nack::decode(&expected).expect("decode two-pair NACK");
        assert_eq!(consumed, expected.len());
        let pairs: Vec<NackPair> = nack.pairs().collect();
        assert_eq!(
            pairs,
            vec![
                NackPair {
                    packet_id: 1,
                    lost_packets: 0xAA,
                },
                NackPair {
                    packet_id: 1034,
                    lost_packets: 0x05,
                },
            ]
        );

        let mut output = [0u8; 20];
        let written = nack.encode(&mut output).expect("encode two-pair NACK");
        assert_eq!(written, 20);
        assert_eq!(output, expected);
    }

    // RTCP-NACK-003 — 差分：上游错误路径（short report / wrong type / nil）。
    #[test]
    fn rtcp_nack_003_upstream_error_paths() {
        assert_eq!(
            Nack::decode(&NACK_SHORT_REPORT),
            Err(WireError::UnexpectedEnd)
        );
        assert_eq!(Nack::decode(&NACK_WRONG_TYPE), Err(WireError::InvalidValue));
        assert_eq!(Nack::decode(&[]), Err(WireError::UnexpectedEnd));
    }

    // RTCP-NACK-004 — 错误路径：FMT 不匹配（count != 1）→ InvalidValue。
    #[test]
    fn rtcp_nack_004_wrong_fmt_rejected() {
        let mut wrong_fmt = NACK_VALID;
        wrong_fmt[1] = 0x85; // FMT=5 (Rapid Resynchronization Request)
        assert_eq!(Nack::decode(&wrong_fmt), Err(WireError::InvalidValue));
    }

    // RTCP-NACK-005 — 错误路径：length 字段声称更多 pair 字节 → UnexpectedEnd。
    #[test]
    fn rtcp_nack_005_truncated_pair_region_rejected() {
        let mut truncated = NACK_VALID;
        truncated[3] = 0x4; // len=4 implies 20 bytes, only 16 present
        assert_eq!(Nack::decode(&truncated), Err(WireError::UnexpectedEnd));
    }

    // RTCP-NACK-006 — 属性：NackPair 位图展开（差分自上游 test_nack_pair）。
    #[test]
    fn rtcp_nack_006_pair_bitmask_expansion() {
        let expand = |pair: NackPair| pair.packet_ids().collect::<Vec<u16>>();

        assert_eq!(expand(NackPair::new(42)), vec![42]);
        assert_eq!(
            expand(NackPair {
                packet_id: 42,
                lost_packets: 1,
            }),
            vec![42, 43]
        );
        assert_eq!(
            expand(NackPair {
                packet_id: 42,
                lost_packets: 2,
            }),
            vec![42, 44]
        );
        assert_eq!(
            expand(NackPair {
                packet_id: 42,
                lost_packets: 3,
            }),
            vec![42, 43, 44]
        );
        // 0x8000 = bit 15 → PID + 16。
        assert_eq!(
            expand(NackPair {
                packet_id: 42,
                lost_packets: 0x8000,
            }),
            vec![42, 58]
        );
        // 16 位回绕。
        assert_eq!(
            expand(NackPair {
                packet_id: 65534,
                lost_packets: 0b0000_0111,
            }),
            vec![65534, 65535, 0, 1]
        );
        // 空洞：bit 1 与 bit 3。
        assert_eq!(
            expand(NackPair {
                packet_id: 123,
                lost_packets: 0b0010_1010,
            }),
            vec![123, 125, 127, 129]
        );
    }

    // RTCP-NACK-007 — 错误路径：空 pair 区违反 RFC 4585 §6.2.1（至少一个）。
    #[test]
    fn rtcp_nack_007_empty_pair_region_rejected_on_encode() {
        let nack = Nack {
            sender_ssrc: 1,
            media_ssrc: 2,
            nacks: &[],
        };
        let mut output = [0u8; 12];
        assert_eq!(nack.encode(&mut output), Err(WireError::InvalidValue));
    }
}

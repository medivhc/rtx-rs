//! Compound RTCP packet: a back-to-back sequence of sub-packets.
//!
//! A compound packet (RFC 3550 section 6.1) is a stream of individual
//! RTCP packets packed into a single datagram. [`CompoundPacket`] borrows
//! the datagram and walks it with [`RtcpPacketIter`], slicing each
//! sub-packet by its `length` field.
//!
//! RFC 3550 requires that a compound packet starts with a sender or
//! receiver report and contains an SDES packet with a CNAME item before
//! any other packet type. Those rules are checked by
//! [`CompoundPacket::validate`] rather than during decoding, so that
//! non-conformant but structurally valid datagrams can still be walked.

use rtx_wire::{Decode, WireError};

use crate::packet::RtcpPacket;

/// A borrowed view over a compound RTCP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompoundPacket<'a> {
    data: &'a [u8],
}

impl<'a> CompoundPacket<'a> {
    /// Wraps a datagram buffer.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        CompoundPacket { data }
    }

    /// Returns the verbatim datagram bytes.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Iterates over the sub-packets of this datagram.
    ///
    /// Each successful item borrows exactly one sub-packet; an error item
    /// terminates the walk (the iterator is then exhausted).
    #[must_use]
    pub fn packets(&self) -> RtcpPacketIter<'a> {
        RtcpPacketIter {
            data: self.data,
            error: false,
        }
    }

    /// Validates the RFC 3550 compound packet rules.
    ///
    /// The datagram must be non-empty, start with a sender or receiver
    /// report, and contain an SDES packet carrying a CNAME item before any
    /// other packet type.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] for an empty datagram, a first
    /// packet that is neither SR nor RR, an SDES packet without a CNAME
    /// item, a non-RR packet before the CNAME, or a missing CNAME.
    pub fn validate(&self) -> Result<(), WireError> {
        let mut packets = self.packets();
        let first = packets.next().ok_or(WireError::InvalidValue)??;
        match first {
            RtcpPacket::SenderReport(_) | RtcpPacket::ReceiverReport(_) => {}
            _ => return Err(WireError::InvalidValue),
        }

        for packet in packets {
            let packet = packet?;
            match packet {
                // Additional receiver reports are allowed here.
                RtcpPacket::ReceiverReport(_) => {}
                RtcpPacket::SourceDescription(sdes) => {
                    if sdes.cname().is_none() {
                        return Err(WireError::InvalidValue);
                    }
                    return Ok(());
                }
                // Other packets are not permitted before the CNAME.
                _ => return Err(WireError::InvalidValue),
            }
        }

        // CNAME never reached.
        Err(WireError::InvalidValue)
    }

    /// Returns the CNAME of the first SDES chunk that carries one.
    ///
    /// Unlike [`CompoundPacket::validate`], the first packet is skipped
    /// without a type check, and SDES packets without a CNAME do not stop
    /// the search.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] for an empty datagram, a
    /// non-RR packet before the CNAME, or when no CNAME is found.
    pub fn cname(&self) -> Result<&'a [u8], WireError> {
        let mut packets = self.packets();
        if packets.next().is_none() {
            return Err(WireError::InvalidValue);
        }

        for packet in packets {
            let packet = packet?;
            match packet {
                RtcpPacket::SourceDescription(sdes) => {
                    if let Some(cname) = sdes.cname() {
                        return Ok(cname);
                    }
                }
                RtcpPacket::ReceiverReport(_) => {}
                _ => return Err(WireError::InvalidValue),
            }
        }

        Err(WireError::InvalidValue)
    }
}

impl<'a> Decode<'a> for CompoundPacket<'a> {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        // Walk eagerly so malformed datagrams are rejected here; the RFC
        // compound rules are checked separately by `validate`.
        let mut offset = 0usize;
        while offset < input.len() {
            let (_, consumed) = RtcpPacket::decode(&input[offset..])?;
            debug_assert!(consumed > 0, "sub-packet decode must make progress");
            offset += consumed;
        }
        let compound = CompoundPacket { data: input };
        Ok((compound, input.len()))
    }
}

/// Iterator over the sub-packets of a [`CompoundPacket`].
#[derive(Debug, Clone)]
pub struct RtcpPacketIter<'a> {
    data: &'a [u8],
    error: bool,
}

impl<'a> Iterator for RtcpPacketIter<'a> {
    type Item = Result<RtcpPacket<'a>, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.error || self.data.is_empty() {
            return None;
        }
        match RtcpPacket::decode(self.data) {
            Ok((packet, consumed)) => {
                debug_assert!(consumed > 0, "sub-packet decode must make progress");
                self.data = &self.data[consumed..];
                Some(Ok(packet))
            }
            Err(err) => {
                // Stop the walk after an error.
                self.data = &[];
                Some(Err(err))
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::header::PacketType;

    /// Differential vector: upstream
    /// `rtcp/compound_packet/compound_packet_test.rs:6-33`
    /// ("`REAL_PACKET`", 116 bytes: RR + SDES + BYE + PSFB + TSFB).
    const REAL_PACKET: [u8; 116] = [
        // Receiver Report (offset=0, 32 bytes)
        0x81, 0xc9, 0x00, 0x07, 0x90, 0x2f, 0x9e, 0x2e, 0xbc, 0x5e, 0x9a, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x46, 0xe1, 0x00, 0x00, 0x01, 0x11, 0x09, 0xf3, 0x64, 0x32, 0x00, 0x02,
        0x4a, 0x79, // Source Description (offset=32, 52 bytes)
        0x81, 0xca, 0x00, 0x0c, 0x90, 0x2f, 0x9e, 0x2e, 0x01, 0x26, 0x7b, 0x39, 0x63, 0x30, 0x30,
        0x65, 0x62, 0x39, 0x32, 0x2d, 0x31, 0x61, 0x66, 0x62, 0x2d, 0x39, 0x64, 0x34, 0x39, 0x2d,
        0x61, 0x34, 0x37, 0x64, 0x2d, 0x39, 0x31, 0x66, 0x36, 0x34, 0x65, 0x65, 0x65, 0x36, 0x39,
        0x66, 0x35, 0x7d, 0x00, 0x00, 0x00, 0x00, // Goodbye (offset=84, 8 bytes)
        0x81, 0xcb, 0x00, 0x01, 0x90, 0x2f, 0x9e, 0x2e,
        // Picture Loss Indication (offset=92, 12 bytes, PSFB)
        0x81, 0xce, 0x00, 0x02, 0x90, 0x2f, 0x9e, 0x2e, 0x90, 0x2f, 0x9e, 0x2e,
        // Rapid Resynchronization Request (offset=104, 12 bytes, TSFB)
        0x85, 0xcd, 0x00, 0x02, 0x90, 0x2f, 0x9e, 0x2e, 0x90, 0x2f, 0x9e, 0x2e,
    ];

    /// Differential vector: upstream
    /// `rtcp/compound_packet/compound_packet_test.rs:37-39`
    /// ("read eof", truncated header).
    const COMPOUND_SHORT_HEADER: [u8; 2] = [0x81, 0xc9];

    // RTCP-CPD-001 — 差分：REAL_PACKET 五个子包的类型与字段。
    #[test]
    fn rtcp_cpd_001_real_packet_sub_packets() {
        let (compound, consumed) = CompoundPacket::decode(&REAL_PACKET).expect("decode compound");
        assert_eq!(consumed, REAL_PACKET.len());
        assert_eq!(compound.data(), &REAL_PACKET);

        let packets: Vec<RtcpPacket<'_>> =
            compound.packets().collect::<Result<_, _>>().expect("walk");
        assert_eq!(packets.len(), 5);

        match &packets[0] {
            RtcpPacket::ReceiverReport(rr) => assert_eq!(rr.ssrc, 0x902f_9e2e),
            other => panic!("want ReceiverReport, got {other:?}"),
        }
        match &packets[1] {
            RtcpPacket::SourceDescription(sdes) => {
                assert_eq!(
                    sdes.cname(),
                    Some(&b"{9c00eb92-1afb-9d49-a47d-91f64eee69f5}"[..])
                );
            }
            other => panic!("want SourceDescription, got {other:?}"),
        }
        match &packets[2] {
            RtcpPacket::Goodbye(bye) => {
                assert_eq!(bye.source_iter().collect::<Vec<_>>(), vec![0x902f_9e2e]);
                assert_eq!(bye.reason, None);
            }
            other => panic!("want Goodbye, got {other:?}"),
        }
        // PSFB (206, FMT 1) → Pli 与 TSFB (205, FMT 5) → RapidResync
        // （M1-2 起反馈包有类型化变体，不再是 Raw）。
        match &packets[3] {
            RtcpPacket::Pli(pli) => {
                assert_eq!(pli.header().packet_type, PacketType::Psfb);
                assert_eq!(pli.header().count, 1);
                assert_eq!(pli.sender_ssrc, 0x902f_9e2e);
                assert_eq!(pli.media_ssrc, 0x902f_9e2e);
            }
            other => panic!("want Pli, got {other:?}"),
        }
        match &packets[4] {
            RtcpPacket::RapidResync(rrr) => {
                assert_eq!(rrr.header().packet_type, PacketType::Tsfb);
                assert_eq!(rrr.header().count, 5);
                assert_eq!(rrr.sender_ssrc, 0x902f_9e2e);
                assert_eq!(rrr.media_ssrc, 0x902f_9e2e);
            }
            other => panic!("want RapidResync, got {other:?}"),
        }

        // RFC validation passes on this real capture.
        assert_eq!(compound.validate(), Ok(()));
        assert_eq!(
            compound.cname(),
            Ok(&b"{9c00eb92-1afb-9d49-a47d-91f64eee69f5}"[..])
        );
    }

    // RTCP-CPD-002 — 差分：REAL_PACKET 尾部截断 → decode 报错（上游
    // "trailing data"）。
    #[test]
    fn rtcp_cpd_002_trailing_data_rejected() {
        let truncated = &REAL_PACKET[..34];
        assert_eq!(
            CompoundPacket::decode(truncated),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTCP-CPD-003 — 差分：短头 → UnexpectedEnd（上游 "read eof"）。
    #[test]
    fn rtcp_cpd_003_short_header_rejected() {
        assert_eq!(
            CompoundPacket::decode(&COMPOUND_SHORT_HEADER),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTCP-CPD-004 — 差分：BYE 开头违反 "must start with RR or SR"
    // （上游 "bad compound"，REAL_PACKET[84..104]）。
    #[test]
    fn rtcp_cpd_004_bad_first_packet_rejected() {
        let bad = &REAL_PACKET[84..104];
        let (compound, consumed) = CompoundPacket::decode(bad).expect("decode structurally");
        assert_eq!(consumed, bad.len());
        let packets: Vec<RtcpPacket<'_>> =
            compound.packets().collect::<Result<_, _>>().expect("walk");
        assert_eq!(packets.len(), 2);
        assert!(matches!(packets[0], RtcpPacket::Goodbye(_)));
        // REAL_PACKET[84..104] = BYE(8) + PLI(12)：PSFB (206, FMT 1) → Pli
        // （M1-2 起为类型化变体）。
        assert!(matches!(packets[1], RtcpPacket::Pli(_)));
        assert_eq!(compound.validate(), Err(WireError::InvalidValue));
    }

    // RTCP-CPD-005 — validate：SDES 无 CNAME → InvalidValue。
    #[test]
    fn rtcp_cpd_005_validate_missing_cname() {
        // RR (8 bytes, count 0) + SDES without any item.
        let no_cname = [
            0x80, 0xc9, 0x00, 0x01, 0x90, 0x2f, 0x9e, 0x2e, // RR
            0x81, 0xca, 0x00, 0x02, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00,
            0x00, // SDES no items
        ];
        let (compound, _) = CompoundPacket::decode(&no_cname).expect("decode");
        assert_eq!(compound.validate(), Err(WireError::InvalidValue));
    }

    // RTCP-CPD-006 — validate：CNAME 前的非 RR 包 → InvalidValue
    // （上游 "PacketBeforeCname"）。
    #[test]
    fn rtcp_cpd_006_validate_packet_before_cname() {
        // RR + BYE + SDES(with CNAME): BYE appears before the CNAME.
        let before_cname = [
            0x80, 0xc9, 0x00, 0x01, 0x90, 0x2f, 0x9e, 0x2e, // RR
            0x81, 0xcb, 0x00, 0x01, 0x90, 0x2f, 0x9e, 0x2e, // BYE
            0x81, 0xca, 0x00, 0x02, 0x01, 0x02, 0x03, 0x04, 0x01, 0x01, 0x41,
            0x00, // SDES CNAME
        ];
        let (compound, _) = CompoundPacket::decode(&before_cname).expect("decode");
        assert_eq!(compound.validate(), Err(WireError::InvalidValue));
    }

    // RTCP-CPD-007 — validate/cname：空 datagram 与 "just RR"（无 CNAME）。
    #[test]
    fn rtcp_cpd_007_empty_and_no_cname() {
        let empty = CompoundPacket::new(&[]);
        assert_eq!(empty.validate(), Err(WireError::InvalidValue));
        assert_eq!(empty.cname(), Err(WireError::InvalidValue));

        let just_rr = [
            0x80, 0xc9, 0x00, 0x01, 0x90, 0x2f, 0x9e, 0x2e, // RR
        ];
        let (compound, _) = CompoundPacket::decode(&just_rr).expect("decode");
        assert_eq!(compound.validate(), Err(WireError::InvalidValue));
        assert_eq!(compound.cname(), Err(WireError::InvalidValue));
    }

    // RTCP-CPD-008 — 属性：RR 后跟带 CNAME 的 SDES → validate/cname 通过。
    #[test]
    fn rtcp_cpd_008_valid_compound_property() {
        let valid = [
            0x80, 0xc9, 0x00, 0x01, 0x90, 0x2f, 0x9e, 0x2e, // RR
            0x81, 0xca, 0x00, 0x02, 0x01, 0x02, 0x03, 0x04, 0x01, 0x01, 0x41,
            0x00, // SDES CNAME "A"
        ];
        let (compound, _) = CompoundPacket::decode(&valid).expect("decode");
        assert_eq!(compound.validate(), Ok(()));
        assert_eq!(compound.cname(), Ok(&b"A"[..]));
    }
}

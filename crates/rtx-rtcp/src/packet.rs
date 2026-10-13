//! RTCP packet dispatch: typed variants plus a raw passthrough.
//!
//! [`RtcpPacket::decode`] reads the common header, uses the `length` field
//! to slice exactly one sub-packet out of the input, and dispatches to the
//! matching typed decoder. Packet types this crate does not model
//! (APP, TSFB, PSFB, XR, unknown) are preserved verbatim as
//! [`RawPacket`], which is also how [`CompoundPacket`] walks back-to-back
//! packets.

use rtx_wire::{Decode, Encode, WireError, Writer};

use crate::header::{Header, PacketType};

use crate::goodbye::Goodbye;
use crate::receiver_report::ReceiverReport;
use crate::sdes::SourceDescription;
use crate::sender_report::SenderReport;

/// One RTCP packet: a typed variant when the type is modelled, otherwise a
/// verbatim [`RawPacket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcpPacket<'a> {
    /// Sender report (type 200).
    SenderReport(SenderReport<'a>),
    /// Receiver report (type 201).
    ReceiverReport(ReceiverReport<'a>),
    /// Source description (type 202).
    SourceDescription(SourceDescription<'a>),
    /// Goodbye (type 203).
    Goodbye(Goodbye<'a>),
    /// Any other packet type, preserved verbatim.
    Raw(RawPacket<'a>),
}

impl RtcpPacket<'_> {
    /// Returns the common header of this packet.
    #[must_use]
    pub fn header(&self) -> Header {
        match self {
            RtcpPacket::SenderReport(p) => p.header(),
            RtcpPacket::ReceiverReport(p) => p.header(),
            RtcpPacket::SourceDescription(p) => p.header(),
            RtcpPacket::Goodbye(p) => p.header(),
            RtcpPacket::Raw(p) => p.header(),
        }
    }
}

impl<'a> Decode<'a> for RtcpPacket<'a> {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        let (header, consumed) = Header::decode(input)?;

        // Slice exactly one sub-packet: 4-byte header plus `length` words.
        let body_len = usize::from(header.length)
            .checked_mul(4)
            .ok_or(WireError::Overflow)?;
        let total = body_len.checked_add(consumed).ok_or(WireError::Overflow)?;
        if total > input.len() {
            return Err(WireError::Overflow);
        }
        let packet_bytes = &input[..total];

        let packet = match header.packet_type {
            PacketType::Sr => RtcpPacket::SenderReport(SenderReport::decode(packet_bytes)?.0),
            PacketType::Rr => RtcpPacket::ReceiverReport(ReceiverReport::decode(packet_bytes)?.0),
            PacketType::Sdes => {
                RtcpPacket::SourceDescription(SourceDescription::decode(packet_bytes)?.0)
            }
            PacketType::Bye => RtcpPacket::Goodbye(Goodbye::decode(packet_bytes)?.0),
            _ => RtcpPacket::Raw(RawPacket::decode(packet_bytes)?.0),
        };
        Ok((packet, total))
    }
}

impl Encode for RtcpPacket<'_> {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        match self {
            RtcpPacket::SenderReport(p) => p.encoded_len(),
            RtcpPacket::ReceiverReport(p) => p.encoded_len(),
            RtcpPacket::SourceDescription(p) => p.encoded_len(),
            RtcpPacket::Goodbye(p) => p.encoded_len(),
            RtcpPacket::Raw(p) => p.encoded_len(),
        }
    }

    fn encode(&self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let mut writer = Writer::new(output);
        match self {
            RtcpPacket::SenderReport(p) => p.write_to(&mut writer)?,
            RtcpPacket::ReceiverReport(p) => p.write_to(&mut writer)?,
            RtcpPacket::SourceDescription(p) => p.write_to(&mut writer)?,
            RtcpPacket::Goodbye(p) => p.write_to(&mut writer)?,
            RtcpPacket::Raw(p) => p.write_to(&mut writer)?,
        }
        Ok(writer.offset())
    }
}

/// Verbatim RTCP packet: header plus untouched body.
///
/// Used for packet types this crate does not model and as the passthrough
/// variant of [`RtcpPacket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawPacket<'a> {
    data: &'a [u8],
}

impl<'a> RawPacket<'a> {
    /// Wraps verbatim packet bytes (header plus body).
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        RawPacket { data }
    }

    /// Returns the verbatim packet bytes.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Returns the common header, or a default header when the bytes are
    /// too short to contain one.
    #[must_use]
    pub fn header(&self) -> Header {
        Header::decode(self.data).map_or_else(|_| Header::default(), |(h, _)| h)
    }

    /// Encodes the packet verbatim into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::OutputTooSmall`] when the writer lacks room.
    pub(crate) fn write_to(&self, writer: &mut Writer<'_>) -> Result<(), WireError> {
        writer.put(self.data)?;
        Ok(())
    }
}

impl<'a> Decode<'a> for RawPacket<'a> {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        // The header must at least be decodable (version check included);
        // the body is taken verbatim, ignoring the length field.
        Header::decode(input)?;
        Ok((RawPacket { data: input }, input.len()))
    }
}

impl Encode for RawPacket<'_> {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        self.data.len()
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

    /// Differential vector: upstream `rtcp/raw_packet.rs:106-110` ("valid").
    const RAW_VALID: [u8; 12] = [
        0x81, 0xcb, 0x00, 0x0c, // v=2, p=0, count=1, BYE, len=12
        0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
        0x03, 0x46, 0x4f, 0x4f, // len=3, text=FOO
    ];

    /// Differential vector: upstream `rtcp/raw_packet.rs:114-116`
    /// ("short header").
    const RAW_SHORT_HEADER: [u8; 1] = [0x80];

    /// Differential vector: upstream `rtcp/raw_packet.rs:120-123`
    /// ("invalid header": version 0).
    const RAW_INVALID_HEADER: [u8; 4] = [0x00, 0xc9, 0x00, 0x04];

    /// Differential vector: upstream `rtcp/packet.rs:246-250`
    /// ("invalid header length": BYE with length 100).
    const PACKET_INVALID_LENGTH: [u8; 4] = [0x81, 0xcb, 0x00, 0x64];

    /// Differential vector: upstream `rtcp/packet.rs:269-272`
    /// (firefox issue srtp#7, TSFB count 15, 28 bytes).
    const FIREFOX_1: [u8; 28] = [
        143, 205, 0, 6, 65, 227, 184, 49, 118, 243, 78, 96, 42, 63, 0, 5, 12, 162, 166, 0, 32, 5,
        200, 4, 0, 4, 0, 0,
    ];

    /// Differential vector: upstream `rtcp/packet.rs:273-276`
    /// (firefox issue srtp#7, 40 bytes).
    const FIREFOX_2: [u8; 40] = [
        143, 205, 0, 9, 65, 227, 184, 49, 118, 243, 78, 96, 42, 68, 0, 17, 12, 162, 167, 1, 32, 17,
        88, 0, 4, 0, 4, 8, 108, 0, 4, 0, 4, 12, 0, 4, 0, 4, 4, 0,
    ];

    /// Differential vector: upstream `rtcp/packet.rs:277-280`
    /// (firefox issue srtp#7, 36 bytes).
    const FIREFOX_3: [u8; 36] = [
        143, 205, 0, 8, 65, 227, 184, 49, 118, 243, 78, 96, 42, 91, 0, 12, 12, 162, 168, 3, 32, 12,
        220, 4, 0, 4, 0, 8, 128, 4, 0, 4, 0, 8, 0, 0,
    ];

    /// Differential vector: upstream `rtcp/packet.rs:281-284`
    /// (firefox issue srtp#7, 32 bytes).
    const FIREFOX_4: [u8; 32] = [
        143, 205, 0, 7, 65, 227, 184, 49, 118, 243, 78, 96, 42, 103, 0, 8, 12, 162, 169, 4, 32, 8,
        232, 4, 0, 4, 0, 4, 4, 0, 0, 0,
    ];

    // RTCP-PKT-001 — 差分：RawPacket "valid" 向量 verbatim 往返。
    #[test]
    fn rtcp_pkt_001_raw_valid_vector_round_trip() {
        let (raw, consumed) = RawPacket::decode(&RAW_VALID).expect("decode raw valid");
        assert_eq!(consumed, RAW_VALID.len());
        assert_eq!(raw.data(), &RAW_VALID);

        let header = raw.header();
        assert_eq!(header.packet_type, PacketType::Bye);
        assert_eq!(header.count, 1);
        assert_eq!(header.length, 12);

        let mut output = [0u8; 12];
        let written = raw.encode(&mut output).expect("encode raw");
        assert_eq!(written, 12);
        assert_eq!(written, raw.encoded_len());
        assert_eq!(output, RAW_VALID);
    }

    // RTCP-PKT-002 — 差分：RawPacket 错误路径（短头/version≠2）。
    #[test]
    fn rtcp_pkt_002_raw_error_paths() {
        assert_eq!(
            RawPacket::decode(&RAW_SHORT_HEADER),
            Err(WireError::UnexpectedEnd)
        );
        assert_eq!(
            RawPacket::decode(&RAW_INVALID_HEADER),
            Err(WireError::InvalidValue)
        );
    }

    // RTCP-PKT-003 — 差分：length 字段越界 → Overflow（上游 PacketTooShort）。
    #[test]
    fn rtcp_pkt_003_invalid_length_rejected() {
        assert_eq!(
            RtcpPacket::decode(&PACKET_INVALID_LENGTH),
            Err(WireError::Overflow)
        );
    }

    // RTCP-PKT-004 — 差分：firefox 向量（TSFB count=15 → Raw，字节级往返）。
    #[test]
    fn rtcp_pkt_004_firefox_vectors_are_raw_and_round_trip() {
        for vector in [
            &FIREFOX_1[..],
            &FIREFOX_2[..],
            &FIREFOX_3[..],
            &FIREFOX_4[..],
        ] {
            let (packet, consumed) = RtcpPacket::decode(vector).expect("decode firefox vector");
            assert_eq!(consumed, vector.len());
            match &packet {
                RtcpPacket::Raw(raw) => {
                    assert_eq!(raw.data(), vector);
                    assert_eq!(raw.header().packet_type, PacketType::Tsfb);
                    assert_eq!(raw.header().count, 15);
                }
                other => panic!("firefox vector must decode to Raw, got {other:?}"),
            }

            let mut output = [0u8; 40];
            let written = packet.encode(&mut output).expect("encode firefox vector");
            assert_eq!(written, vector.len());
            assert_eq!(&output[..written], vector);
        }
    }

    // RTCP-PKT-005 — 差分：dispatch 到各类型变体（RR/BYE 向量）。
    #[test]
    fn rtcp_pkt_005_dispatch_typed_variants() {
        // RR_VALID from receiver_report tests (length 7 is correct).
        let rr = [
            0x81, 0xc9, 0x00, 0x07, 0x90, 0x2f, 0x9e, 0x2e, 0xbc, 0x5e, 0x9a, 0x40, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x46, 0xe1, 0x00, 0x00, 0x01, 0x11, 0x09, 0xf3, 0x64, 0x32,
            0x00, 0x02, 0x4a, 0x79,
        ];
        let (packet, consumed) = RtcpPacket::decode(&rr).expect("decode rr");
        assert_eq!(consumed, rr.len());
        match &packet {
            RtcpPacket::ReceiverReport(inner) => {
                assert_eq!(inner.ssrc, 0x902f_9e2e);
                assert_eq!(inner.header().count, 1);
            }
            other => panic!("want ReceiverReport, got {other:?}"),
        }

        // BYE valid (length field bogus; dispatch slices 52 bytes but only 12
        // are present, so the typed decoder sees the full input).
        let bye = [
            0x81, 0xcb, 0x00, 0x02, 0x90, 0x2f, 0x9e, 0x2e, 0x03, 0x46, 0x4f, 0x4f,
        ];
        let (packet, consumed) = RtcpPacket::decode(&bye).expect("decode bye");
        assert_eq!(consumed, bye.len());
        match &packet {
            RtcpPacket::Goodbye(inner) => {
                assert_eq!(inner.reason, Some(&b"FOO"[..]));
            }
            other => panic!("want Goodbye, got {other:?}"),
        }
    }

    // RTCP-PKT-006 — dispatch 只消费一个子包（consumed 契约）。
    #[test]
    fn rtcp_pkt_006_dispatch_consumes_one_sub_packet() {
        // Two back-to-back RR packets: decode consumes only the first.
        let rr = [
            0x81, 0xc9, 0x00, 0x07, 0x90, 0x2f, 0x9e, 0x2e, 0xbc, 0x5e, 0x9a, 0x40, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x46, 0xe1, 0x00, 0x00, 0x01, 0x11, 0x09, 0xf3, 0x64, 0x32,
            0x00, 0x02, 0x4a, 0x79,
        ];
        let mut compound = Vec::new();
        compound.extend_from_slice(&rr);
        compound.extend_from_slice(&rr);
        let (packet, consumed) = RtcpPacket::decode(&compound).expect("decode first sub-packet");
        assert_eq!(consumed, 32);
        assert!(matches!(packet, RtcpPacket::ReceiverReport(_)));
        let (second, consumed2) =
            RtcpPacket::decode(&compound[consumed..]).expect("decode second sub-packet");
        assert_eq!(consumed2, 32);
        assert!(matches!(second, RtcpPacket::ReceiverReport(_)));
    }

    // RTCP-PKT-007 — 属性：typed 子包经 dispatch 往返（encode→decode 一致）。
    #[test]
    fn rtcp_pkt_007_typed_round_trip_through_dispatch() {
        let sdes = [
            0x81, 0xca, 0x00, 0x02, 0x01, 0x02, 0x03, 0x04, 0x01, 0x01, 0x41, 0x00,
        ];
        let (packet, consumed) = RtcpPacket::decode(&sdes).expect("decode sdes");
        assert_eq!(consumed, sdes.len());
        assert!(matches!(packet, RtcpPacket::SourceDescription(_)));

        let mut output = [0u8; 12];
        let written = packet.encode(&mut output).expect("encode sdes");
        assert_eq!(written, sdes.len());
        assert_eq!(&output[..written], &sdes);

        let (again, _) = RtcpPacket::decode(&output[..written]).expect("re-decode sdes");
        assert_eq!(again, packet);
    }
}

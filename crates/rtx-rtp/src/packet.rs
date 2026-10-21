//! The `RTP` packet: fixed header plus media payload ([RFC 3550] §5.1).
//!
//! An `RTP` packet has no length field of its own: the payload runs to the end
//! of the datagram. When the padding bit is set, the last payload octet counts
//! the padding octets (itself included); decoding strips them and encoding
//! re-derives them from the payload length so the packet ends on a 32-bit
//! boundary.
//!
//! [RFC 3550]: https://www.rfc-editor.org/rfc/rfc3550

use rtx_wire::{Decode, Encode, WireError, Writer};

use super::header::Header;

/// Number of bytes needed to pad `len` up to a 32-bit word boundary.
const fn padding_size(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

/// A decoded `RTP` packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpPacket<'a> {
    /// The fixed header (and, when present, the header extension).
    pub header: Header<'a>,
    /// The media payload with any trailing padding octets removed.
    pub payload: &'a [u8],
}

impl RtpPacket<'_> {
    /// Number of padding octets [`RtpPacket::encode`] appends.
    ///
    /// The count is derived from the payload length, so a payload that is
    /// already word-aligned receives a full word of padding
    /// ([RFC 3550] §5.1).
    #[must_use]
    pub fn padding_len(&self) -> usize {
        if self.header.padding {
            let pad = padding_size(self.payload.len());
            if pad == 0 { 4 } else { pad }
        } else {
            0
        }
    }
}

impl<'a> Decode<'a> for RtpPacket<'a> {
    type Error = WireError;

    /// Decodes one packet from the front of `input`, consuming all of it.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::UnexpectedEnd`] when the header (including its
    /// CSRC or extension regions) is truncated or the padding count exceeds
    /// the payload, [`WireError::InvalidValue`] for a bad version or a
    /// malformed extension block, and [`WireError::Overflow`] when the
    /// extension length field points past `input`.
    fn decode(input: &'a [u8]) -> Result<(Self, usize), WireError> {
        let (header, consumed) = Header::decode(input)?;
        let raw = input.get(consumed..).ok_or(WireError::UnexpectedEnd)?;
        let payload = if header.padding {
            let count = usize::from(*raw.last().ok_or(WireError::UnexpectedEnd)?);
            let end = raw
                .len()
                .checked_sub(count)
                .ok_or(WireError::UnexpectedEnd)?;
            raw.get(..end).ok_or(WireError::UnexpectedEnd)?
        } else {
            raw
        };
        Ok((RtpPacket { header, payload }, input.len()))
    }
}

impl Encode for RtpPacket<'_> {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        self.header.encoded_len() + self.payload.len() + self.padding_len()
    }

    /// Encodes the packet, re-deriving the padding from the payload length.
    ///
    /// # Errors
    ///
    /// Propagates the header validation errors of
    /// [`RtpPacket::encoded_len`] and returns
    /// [`WireError::OutputTooSmall`] when `output` is smaller than
    /// [`Encode::encoded_len`].
    fn encode(&self, output: &mut [u8]) -> Result<usize, WireError> {
        let mut writer = Writer::new(output);
        self.header.write_to(&mut writer)?;
        writer.put(self.payload)?;
        let pad = self.padding_len();
        if pad > 0 {
            // At most three zero octets precede the count octet.
            const ZEROS: [u8; 3] = [0, 0, 0];
            writer.put(&ZEROS[..pad - 1])?;
            let count = u8::try_from(pad).map_err(|_| WireError::Overflow)?;
            writer.u8(count)?;
        }
        Ok(writer.offset())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    // ---- RTP-PKT: differential vectors from upstream rtc-rtp ----------------
    //
    // Every vector is fed to `RtpPacket::decode`, the decoded fields are
    // checked against the upstream expectations, and `encode(decode(v)) == v`
    // is asserted byte for byte.

    // upstream packet_test.rs:17-20 (test_basic)
    const TEST_BASIC: [u8; 25] = [
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x00, 0x01, 0x00,
        0x01, 0xff, 0xff, 0xff, 0xff, 0x98, 0x36, 0xbe, 0x88, 0x9e,
    ];

    // upstream packet_test.rs:128-132 (test_padding)
    const TEST_PADDING: [u8; 40] = [
        0xa0, 0x60, 0x19, 0x58, 0x63, 0xff, 0x7d, 0x7c, 0x4b, 0x98, 0xd4, 0x0a, 0x67, 0x4d, 0x00,
        0x29, 0x9a, 0x64, 0x03, 0xc0, 0x11, 0x3f, 0x2c, 0xd4, 0x04, 0x04, 0x05, 0x00, 0x00, 0x03,
        0x03, 0xe8, 0x00, 0x00, 0xea, 0x60, 0x04, 0x00, 0x00, 0x03,
    ];

    // upstream packet_test.rs:175-178 (test_rfc_8285_one_byte_extension)
    const TEST_8285_ONE_BYTE: [u8; 25] = [
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xbe, 0xde, 0x00,
        0x01, 0x50, 0xaa, 0x00, 0x00, 0x98, 0x36, 0xbe, 0x88, 0x9e,
    ];

    // upstream packet_test.rs:217-221 (test_rfc_8285_one_byte_two_extension_of_two_bytes)
    const TEST_8285_ONE_BYTE_TWO: [u8; 25] = [
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xbe, 0xde, 0x00,
        0x01, 0x10, 0xaa, 0x20, 0xbb, 0x98, 0x36, 0xbe, 0x88, 0x9e,
    ];

    // upstream packet_test.rs:288-293 (test_rfc_8285_one_byte_multiple_extensions_with_padding)
    const TEST_8285_ONE_BYTE_PADDED: [u8; 33] = [
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xbe, 0xde, 0x00,
        0x03, 0x10, 0xaa, 0x21, 0xbb, 0xbb, 0x00, 0x00, 0x33, 0xcc, 0xcc, 0xcc, 0xcc, 0x98, 0x36,
        0xbe, 0x88, 0x9e,
    ];

    // upstream packet_test.rs:367-372 (test_rfc_8285_one_byte_multiple_extension)
    const TEST_8285_ONE_BYTE_MULTI: [u8; 33] = [
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xbe, 0xde, 0x00,
        0x03, 0x10, 0xaa, 0x21, 0xbb, 0xbb, 0x33, 0xcc, 0xcc, 0xcc, 0xcc, 0x00, 0x00, 0x98, 0x36,
        0xbe, 0x88, 0x9e,
    ];

    // upstream packet_test.rs:415-420 (test_rfc_8285_two_byte_extension)
    const TEST_8285_TWO_BYTE: [u8; 49] = [
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x10, 0x00, 0x00,
        0x07, 0x05, 0x18, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x98,
        0x36, 0xbe, 0x88, 0x9e,
    ];

    // upstream packet_test.rs:468-472 (test_rfc8285_two_byte_multiple_extension_with_padding)
    const TEST_8285_TWO_BYTE_PADDED: [u8; 33] = [
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x10, 0x00, 0x00,
        0x03, 0x01, 0x00, 0x02, 0x01, 0xbb, 0x00, 0x03, 0x04, 0xcc, 0xcc, 0xcc, 0xcc, 0x98, 0x36,
        0xbe, 0x88, 0x9e,
    ];

    // upstream packet_test.rs:520-525 (test_rfc8285_two_byte_multiple_extension_with_large_extension)
    const TEST_8285_TWO_BYTE_LARGE: [u8; 45] = [
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x10, 0x00, 0x00,
        0x06, 0x01, 0x00, 0x02, 0x01, 0xbb, 0x03, 0x11, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x98, 0x36, 0xbe, 0x88, 0x9e,
    ];

    // upstream packet_test.rs:894-897 (reserved id terminates parsing)
    const TEST_8285_RESERVED_ID: [u8; 23] = [
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xbe, 0xde, 0x00,
        0x01, 0xf0, 0xaa, 0x98, 0x36, 0xbe, 0x88, 0x9e,
    ];

    const VALID_VECTORS: [&[u8]; 10] = [
        &TEST_BASIC,
        &TEST_PADDING,
        &TEST_8285_ONE_BYTE,
        &TEST_8285_ONE_BYTE_TWO,
        &TEST_8285_ONE_BYTE_PADDED,
        &TEST_8285_ONE_BYTE_MULTI,
        &TEST_8285_TWO_BYTE,
        &TEST_8285_TWO_BYTE_PADDED,
        &TEST_8285_TWO_BYTE_LARGE,
        &TEST_8285_RESERVED_ID,
    ];

    // RTP-PKT-001 — the basic vector decodes to the upstream field values and
    // re-encodes byte for byte (upstream packet_test.rs:17-20).
    #[test]
    fn decode_basic_packet() {
        let (packet, consumed) = RtpPacket::decode(&TEST_BASIC).expect("decode basic");
        assert_eq!(consumed, TEST_BASIC.len());
        assert_eq!(packet.header.sequence_number, 27023);
        assert_eq!(packet.header.ssrc, 476_325_762);
        assert_eq!(packet.payload, &[0x98, 0x36, 0xbe, 0x88, 0x9e]);
        assert_eq!(packet.padding_len(), 0);

        let mut buffer = [0u8; TEST_BASIC.len()];
        let written = packet.encode(&mut buffer).expect("encode");
        assert_eq!(written, packet.encoded_len());
        assert_eq!(&buffer[..written], &TEST_BASIC);
    }

    // RTP-PKT-002 — the padding vector strips the padding octets and re-derives
    // them on encode (upstream packet_test.rs:128-132).
    #[test]
    fn decode_padding_packet() {
        let (packet, consumed) = RtpPacket::decode(&TEST_PADDING).expect("decode padding");
        assert_eq!(consumed, TEST_PADDING.len());
        // Upstream asserts the payload equals raw[12..12+25].
        assert_eq!(packet.payload, &TEST_PADDING[12..37]);
        assert_eq!(packet.padding_len(), 3);

        let mut buffer = [0u8; TEST_PADDING.len()];
        let written = packet.encode(&mut buffer).expect("encode");
        assert_eq!(&buffer[..written], &TEST_PADDING);
    }

    // RTP-PKT-003 — one-byte extension elements are reachable from the packet.
    #[test]
    fn decode_one_byte_extension_packet() {
        let (packet, _) = RtpPacket::decode(&TEST_8285_ONE_BYTE).expect("decode");
        let item = packet.header.find_extension(5).expect("extension 5");
        assert_eq!(item.payload, &[0xAA]);
    }

    // RTP-PKT-004 — two-byte extension elements are reachable from the packet.
    #[test]
    fn decode_two_byte_extension_packet() {
        let (packet, _) = RtpPacket::decode(&TEST_8285_TWO_BYTE).expect("decode");
        let item = packet.header.find_extension(5).expect("extension 5");
        assert_eq!(item.payload, &[0xAA; 24]);
    }

    // RTP-PKT-005 — the reserved-identifier vector keeps the whole extension
    // block and yields no elements (upstream packet_test.rs:894-897).
    //
    // Divergence from upstream (documented): upstream lets the unparsed tail of
    // the extension block leak into the payload (`raw[17..]`); this codec keeps
    // the block intact and starts the payload at the RFC 8285 boundary
    // (`raw[20..]`).
    #[test]
    fn decode_reserved_id_packet() {
        let (packet, consumed) = RtpPacket::decode(&TEST_8285_RESERVED_ID).expect("decode");
        assert_eq!(consumed, TEST_8285_RESERVED_ID.len());
        assert_eq!(packet.header.extensions().count(), 0);
        assert_eq!(packet.payload, &TEST_8285_RESERVED_ID[20..]);

        let mut buffer = [0u8; TEST_8285_RESERVED_ID.len()];
        let written = packet.encode(&mut buffer).expect("encode");
        assert_eq!(&buffer[..written], &TEST_8285_RESERVED_ID);
    }

    // RTP-PKT-006 — the padding bit with an empty payload is rejected.
    #[test]
    fn decode_rejects_padding_without_payload() {
        let bytes: [u8; 12] = [
            0xa0, 0x60, 0x19, 0x58, 0x63, 0xff, 0x7d, 0x7c, 0x4b, 0x98, 0xd4, 0x0a,
        ];
        assert_eq!(RtpPacket::decode(&bytes), Err(WireError::UnexpectedEnd));
    }

    // RTP-PKT-007 — a padding count larger than the payload is rejected.
    #[test]
    fn decode_rejects_padding_count_overflow() {
        // 12-byte header plus a single payload octet claiming 255 padding octets.
        let bytes: [u8; 13] = [
            0xa0, 0x60, 0x19, 0x58, 0x63, 0xff, 0x7d, 0x7c, 0x4b, 0x98, 0xd4, 0x0a, 0xff,
        ];
        assert_eq!(RtpPacket::decode(&bytes), Err(WireError::UnexpectedEnd));
    }

    // RTP-PKT-008 — every valid upstream vector round-trips byte for byte.
    #[test]
    fn all_upstream_vectors_roundtrip_byte_exact() {
        for vector in VALID_VECTORS {
            let (packet, consumed) = RtpPacket::decode(vector).expect("decode vector");
            assert_eq!(consumed, vector.len(), "consumed mismatch");
            let mut buffer = [0u8; 64];
            let written = packet
                .encode(&mut buffer)
                .expect("encode into 64-byte buffer");
            assert_eq!(&buffer[..written], vector, "round-trip mismatch");
        }
    }

    // RTP-PKT-009 — encode reports OutputTooSmall without touching the buffer.
    #[test]
    fn encode_rejects_small_output() {
        let (packet, _) = RtpPacket::decode(&TEST_BASIC).expect("decode basic");
        let mut buffer = [0u8; 8];
        assert_eq!(packet.encode(&mut buffer), Err(WireError::OutputTooSmall));
    }

    // RTP-PKT-010 — round-trip property over deterministic header/payload
    // combinations, including padding and CSRC entries.
    #[test]
    fn encode_decode_roundtrip_property() {
        let csrc = [0xA1u8, 0xA2, 0xA3, 0xA4];
        for padding in [false, true] {
            for payload_len in [0usize, 1, 4, 5, 12] {
                let header = Header {
                    version: 2,
                    padding,
                    extension: false,
                    marker: true,
                    payload_type: 96,
                    sequence_number: 1,
                    timestamp: 2,
                    ssrc: 3,
                    csrc: &csrc,
                    extension_profile: 0,
                    extension_data: &[],
                };
                let payload = [0x5Au8; 12];
                let packet = RtpPacket {
                    header,
                    payload: &payload[..payload_len],
                };
                let mut buffer = [0u8; 64];
                let written = packet.encode(&mut buffer).expect("encode");
                assert_eq!(written, packet.encoded_len());
                let (decoded, consumed) = RtpPacket::decode(&buffer[..written]).expect("decode");
                assert_eq!(consumed, written);
                assert_eq!(decoded.payload, packet.payload);
                assert_eq!(decoded.header, packet.header);
                if padding {
                    // Padding aligns the whole packet, not the payload.
                    assert_eq!(written % 4, 0);
                }
            }
        }
    }
}

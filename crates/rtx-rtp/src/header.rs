//! The `RTP` fixed header ([RFC 3550] §5.1).
//!
//! The first twelve octets carry the version, padding, extension and marker
//! flags, the payload type, sequence number, timestamp and SSRC; the CSRC list
//! and (when the extension bit is set) the header extension follow. The
//! `*_SHIFT` and `*_MASK` constants describe how the flags pack into the first
//! two octets.
//!
//! [RFC 3550]: https://www.rfc-editor.org/rfc/rfc3550

use rtx_wire::{Cursor, Decode, WireError, Writer};

use super::extension::{ExtensionItem, Extensions, validate_extension_block};

/// Length of the fixed part of the `RTP` header, in bytes.
pub const FIXED_HEADER_LENGTH: usize = 12;
/// Length of one CSRC entry, in bytes.
pub const CSRC_LENGTH: usize = 4;
/// Length of the extension header (profile plus length), in bytes.
pub const EXTENSION_HEADER_LENGTH: usize = 4;
/// The `RTP` version this codec speaks.
pub const RTP_VERSION: u8 = 2;
/// Largest CSRC count the 4-bit field can hold.
pub const CC_MAX: usize = 15;

/// Bit offset of the version field in the first header octet.
pub const VERSION_SHIFT: u8 = 6;
/// Bit mask of the version field once shifted.
pub const VERSION_MASK: u8 = 0x3;
/// Bit offset of the padding flag.
pub const PADDING_SHIFT: u8 = 5;
/// Bit mask of the padding flag once shifted.
pub const PADDING_MASK: u8 = 0x1;
/// Bit offset of the extension flag.
pub const EXTENSION_SHIFT: u8 = 4;
/// Bit mask of the extension flag once shifted.
pub const EXTENSION_MASK: u8 = 0x1;
/// Bit mask of the CSRC count field in the first header octet.
pub const CC_MASK: u8 = 0xF;
/// Bit offset of the marker flag.
pub const MARKER_SHIFT: u8 = 7;
/// Bit mask of the marker flag once shifted.
pub const MARKER_MASK: u8 = 0x1;
/// Bit mask of the payload type field in the second header octet.
pub const PT_MASK: u8 = 0x7F;

/// Number of bytes needed to pad `len` up to a 32-bit word boundary.
///
/// Used instead of `len % 4 == 0` style checks so the crate stays free of
/// `is_multiple_of`, which was stabilized after this crate's MSRV.
const fn word_padding(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

/// A decoded `RTP` header.
///
/// The `csrc` and `extension_data` regions borrow from the decoded input and
/// are re-encoded verbatim, which keeps `encode(decode(bytes)) == bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header<'a> {
    /// Always [`RTP_VERSION`] for packets this codec accepts.
    pub version: u8,
    /// Whether the packet ends with padding octets.
    pub padding: bool,
    /// Whether a header extension follows the CSRC list.
    pub extension: bool,
    /// The marker bit; its meaning depends on the payload type.
    pub marker: bool,
    /// The payload type (7 bits).
    pub payload_type: u8,
    /// The sequence number, incremented by one per packet.
    pub sequence_number: u16,
    /// The sampling instant of the first octet of the payload.
    pub timestamp: u32,
    /// The synchronization source identifier.
    pub ssrc: u32,
    /// The contributing source identifiers, four bytes each, verbatim.
    pub csrc: &'a [u8],
    /// The extension profile (`0xBEDE` and `0x1000` have element framing).
    pub extension_profile: u16,
    /// The extension data, verbatim, including any padding.
    pub extension_data: &'a [u8],
}

impl<'a> Header<'a> {
    /// Iterates the contributing source identifiers.
    pub fn csrcs(&self) -> impl Iterator<Item = u32> + '_ {
        let csrc = self.csrc;
        csrc.chunks_exact(CSRC_LENGTH)
            .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
    }

    /// Iterates the header extension elements.
    ///
    /// The iterator is empty when the extension flag is clear or the profile
    /// has no element framing.
    #[must_use]
    pub fn extensions(&self) -> Extensions<'a> {
        if self.extension {
            Extensions::new(self.extension_profile, self.extension_data)
        } else {
            Extensions::new(0, &[])
        }
    }

    /// Returns the extension element with the given identifier, if present.
    #[must_use]
    pub fn find_extension(&self, id: u8) -> Option<ExtensionItem<'a>> {
        self.extensions().find(|item| item.id == id)
    }

    /// Number of bytes [`Header::encoded_len`] reports.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        FIXED_HEADER_LENGTH
            + self.csrc.len()
            + if self.extension {
                EXTENSION_HEADER_LENGTH + self.extension_data.len()
            } else {
                0
            }
    }

    /// Encodes the header into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the version is not
    /// [`RTP_VERSION`], the payload type exceeds [`PT_MASK`], the CSRC list is
    /// not word-aligned or longer than [`CC_MAX`] entries, or the extension
    /// data is not word-aligned. Returns [`WireError::Overflow`] when the
    /// extension length does not fit its 16-bit field.
    pub(crate) fn write_to(&self, writer: &mut Writer<'_>) -> Result<(), WireError> {
        if self.version != RTP_VERSION {
            return Err(WireError::InvalidValue);
        }
        if self.payload_type > PT_MASK {
            return Err(WireError::InvalidValue);
        }
        if word_padding(self.csrc.len()) != 0 {
            // The CSRC list is a sequence of 32-bit words.
            return Err(WireError::InvalidValue);
        }
        let cc = self.csrc.len() / CSRC_LENGTH;
        if cc > CC_MAX {
            return Err(WireError::InvalidValue);
        }
        let cc = u8::try_from(cc).map_err(|_| WireError::Overflow)?;
        let first = (RTP_VERSION << VERSION_SHIFT)
            | (u8::from(self.padding) << PADDING_SHIFT)
            | (u8::from(self.extension) << EXTENSION_SHIFT)
            | cc;
        writer.u8(first)?;
        writer.u8((u8::from(self.marker) << MARKER_SHIFT) | (self.payload_type & PT_MASK))?;
        writer.u16_be(self.sequence_number)?;
        writer.u32_be(self.timestamp)?;
        writer.u32_be(self.ssrc)?;
        writer.put(self.csrc)?;
        if self.extension {
            if word_padding(self.extension_data.len()) != 0 {
                // The extension length field counts 32-bit words.
                return Err(WireError::InvalidValue);
            }
            let words = self.extension_data.len() / CSRC_LENGTH;
            let words = u16::try_from(words).map_err(|_| WireError::Overflow)?;
            writer.u16_be(self.extension_profile)?;
            writer.u16_be(words)?;
            writer.put(self.extension_data)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for Header<'a> {
    type Error = WireError;

    /// Decodes the header from the front of `input`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::UnexpectedEnd`] when the fixed header, the CSRC
    /// list or the extension header is truncated, [`WireError::Overflow`] when
    /// the extension length field points past `input`, and
    /// [`WireError::InvalidValue`] for a version other than [`RTP_VERSION`] or
    /// a malformed extension block.
    fn decode(input: &'a [u8]) -> Result<(Self, usize), WireError> {
        let mut cursor = Cursor::new(input);
        let fixed = cursor.take(FIXED_HEADER_LENGTH)?;
        let version = (fixed[0] >> VERSION_SHIFT) & VERSION_MASK;
        if version != RTP_VERSION {
            return Err(WireError::InvalidValue);
        }
        let padding = ((fixed[0] >> PADDING_SHIFT) & PADDING_MASK) > 0;
        let extension = ((fixed[0] >> EXTENSION_SHIFT) & EXTENSION_MASK) > 0;
        let cc = usize::from(fixed[0] & CC_MASK);
        let marker = ((fixed[1] >> MARKER_SHIFT) & MARKER_MASK) > 0;
        let payload_type = fixed[1] & PT_MASK;
        let sequence_number = u16::from_be_bytes([fixed[2], fixed[3]]);
        let timestamp = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let ssrc = u32::from_be_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]);

        let csrc = cursor.take(cc * CSRC_LENGTH)?;

        let (extension_profile, extension_data) = if extension {
            let profile = cursor.u16_be()?;
            let words = cursor.u16_be()?;
            let len = usize::from(words)
                .checked_mul(CSRC_LENGTH)
                .ok_or(WireError::Overflow)?;
            if len > cursor.remaining().len() {
                // The length field derives a range past the input.
                return Err(WireError::Overflow);
            }
            let data = cursor.take(len)?;
            validate_extension_block(profile, data)?;
            (profile, data)
        } else {
            (0, &[][..])
        };

        Ok((
            Header {
                version,
                padding,
                extension,
                marker,
                payload_type,
                sequence_number,
                timestamp,
                ssrc,
                csrc,
                extension_profile,
                extension_data,
            },
            cursor.offset(),
        ))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    // ---- RTP-HDR: differential vectors from upstream rtc-rtp ----------------

    // upstream packet_test.rs:17-20 (test_basic)
    const TEST_BASIC: [u8; 25] = [
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x00, 0x01, 0x00,
        0x01, 0xff, 0xff, 0xff, 0xff, 0x98, 0x36, 0xbe, 0x88, 0x9e,
    ];

    // upstream packet_test.rs:1167-1170 (ShortHeader)
    const ERR_SHORT_HEADER: [u8; 11] = [
        0x80, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27,
    ];

    // upstream packet_test.rs:1178-1181 (MissingCSRC)
    const ERR_MISSING_CSRC: [u8; 12] = [
        0x81, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82,
    ];

    // upstream packet_test.rs:1189-1192 (MissingExtension)
    const ERR_MISSING_EXTENSION: [u8; 12] = [
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82,
    ];

    // upstream packet_test.rs:1200-1204 (MissingExtensionData)
    const ERR_MISSING_EXTENSION_DATA: [u8; 16] = [
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xbe, 0xde, 0x00,
        0x03,
    ];

    // upstream packet_test.rs:1212-1218 (MissingExtensionDataPayload)
    const ERR_MISSING_EXTENSION_DATA_PAYLOAD: [u8; 18] = [
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xbe, 0xde, 0x00,
        0x01, 0x12, 0x00,
    ];

    // upstream packet_test.rs:1236-1239 (test_round_trip, version = 0)
    const TEST_VERSION_ZERO: [u8; 20] = [
        0x00, 0x10, 0x23, 0x45, 0x12, 0x34, 0x45, 0x67, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77,
    ];

    // RTP-HDR-001 — field-by-field decode of the upstream basic vector.
    #[test]
    fn decode_basic_fields() {
        let (header, consumed) = Header::decode(&TEST_BASIC).expect("decode basic");
        // The header decoder consumes the fixed part plus the extension
        // block (profile + length + data), leaving the payload behind.
        assert_eq!(consumed, 20);
        assert_eq!(header.version, 2);
        assert!(!header.padding);
        assert!(header.extension);
        assert!(header.marker);
        assert_eq!(header.payload_type, 96);
        assert_eq!(header.sequence_number, 27023);
        assert_eq!(header.timestamp, 3_653_407_706);
        assert_eq!(header.ssrc, 476_325_762);
        assert!(header.csrc.is_empty());
        // Legacy profile 1: opaque data, no element framing.
        assert_eq!(header.extension_profile, 1);
        assert_eq!(header.extension_data, &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(header.extensions().count(), 0);
        assert_eq!(header.encoded_len(), 20);
    }

    // RTP-HDR-002 — CSRC list decoding and iteration.
    #[test]
    fn decode_csrc_list() {
        // Two CSRC entries, extension disabled.
        let mut bytes = TEST_BASIC;
        bytes[0] = 0x82; // V=2, P=0, X=0, CC=2
        bytes[12..20].copy_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02]);
        let (header, consumed) = Header::decode(&bytes[..20]).expect("decode csrc");
        assert_eq!(consumed, 20);
        assert_eq!(header.csrcs().collect::<Vec<_>>(), vec![1, 2]);
        assert!(!header.extension);
    }

    // RTP-HDR-003 — extension lookup is empty when the extension flag is clear.
    #[test]
    fn find_extension_none_when_disabled() {
        let (header, _) = Header::decode(&TEST_BASIC).expect("decode basic");
        // The basic vector uses legacy profile 1, so no elements are framed.
        assert!(header.find_extension(0).is_none());

        let mut bytes = TEST_BASIC;
        bytes[0] = 0x80; // clear the extension bit
        let (header, _) = Header::decode(&bytes).expect("decode without extension");
        assert!(header.find_extension(5).is_none());
    }

    // RTP-HDR-004 — version 0 is rejected (stricter than upstream, which
    // accepts it); upstream packet_test.rs:1236-1239.
    #[test]
    fn decode_rejects_version_zero() {
        assert_eq!(
            Header::decode(&TEST_VERSION_ZERO),
            Err(WireError::InvalidValue)
        );
    }

    // RTP-HDR-005 — truncated fixed header; upstream packet_test.rs:1167-1170.
    #[test]
    fn decode_rejects_short_header() {
        assert_eq!(
            Header::decode(&ERR_SHORT_HEADER),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTP-HDR-006 — CSRC count exceeds the input; upstream packet_test.rs:1178-1181.
    #[test]
    fn decode_rejects_missing_csrc() {
        assert_eq!(
            Header::decode(&ERR_MISSING_CSRC),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTP-HDR-007 — extension bit set but extension header missing; upstream
    // packet_test.rs:1189-1192.
    #[test]
    fn decode_rejects_missing_extension_header() {
        assert_eq!(
            Header::decode(&ERR_MISSING_EXTENSION),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTP-HDR-008 — extension length field points past the input; upstream
    // packet_test.rs:1200-1204.
    #[test]
    fn decode_rejects_missing_extension_data() {
        assert_eq!(
            Header::decode(&ERR_MISSING_EXTENSION_DATA),
            Err(WireError::Overflow)
        );
    }

    // RTP-HDR-009 — extension data truncated inside the block; upstream
    // packet_test.rs:1212-1218.
    #[test]
    fn decode_rejects_missing_extension_payload() {
        assert_eq!(
            Header::decode(&ERR_MISSING_EXTENSION_DATA_PAYLOAD),
            Err(WireError::Overflow)
        );
    }

    // RTP-HDR-010 — a complete block with broken element framing is rejected.
    #[test]
    fn decode_rejects_malformed_extension_block() {
        // 0x21 claims a two-octet payload but only one octet remains.
        let bytes: [u8; 20] = [
            0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xbe, 0xde,
            0x00, 0x01, 0x21, 0xbb, 0xbb, 0x33,
        ];
        assert_eq!(Header::decode(&bytes), Err(WireError::InvalidValue));
    }

    // RTP-HDR-011 — encode reproduces the upstream basic vector byte for byte.
    #[test]
    fn encode_reproduces_basic_vector() {
        let (header, _) = Header::decode(&TEST_BASIC).expect("decode basic");
        let mut buffer = [0u8; TEST_BASIC.len()];
        let written = {
            let mut writer = Writer::new(&mut buffer);
            header.write_to(&mut writer).expect("write header");
            writer.offset()
        };
        assert_eq!(written, 20);
        assert_eq!(&buffer[..written], &TEST_BASIC[..20]);
    }

    // RTP-HDR-012 — encode rejects a bad version.
    #[test]
    fn encode_rejects_bad_version() {
        let (mut header, _) = Header::decode(&TEST_BASIC).expect("decode basic");
        header.version = 0;
        let mut buffer = [0u8; 32];
        let mut writer = Writer::new(&mut buffer);
        assert_eq!(header.write_to(&mut writer), Err(WireError::InvalidValue));
    }

    // RTP-HDR-013 — encode rejects a payload type beyond 7 bits.
    #[test]
    fn encode_rejects_bad_payload_type() {
        let (mut header, _) = Header::decode(&TEST_BASIC).expect("decode basic");
        header.payload_type = 0x80;
        let mut buffer = [0u8; 32];
        let mut writer = Writer::new(&mut buffer);
        assert_eq!(header.write_to(&mut writer), Err(WireError::InvalidValue));
    }

    // RTP-HDR-014 — encode rejects a CSRC list that is not word-aligned.
    #[test]
    fn encode_rejects_misaligned_csrc() {
        let (mut header, _) = Header::decode(&TEST_BASIC).expect("decode basic");
        header.csrc = &[0x00, 0x01];
        let mut buffer = [0u8; 32];
        let mut writer = Writer::new(&mut buffer);
        assert_eq!(header.write_to(&mut writer), Err(WireError::InvalidValue));
    }

    // RTP-HDR-015 — encode rejects more than CC_MAX CSRC entries.
    #[test]
    fn encode_rejects_too_many_csrc() {
        let (mut header, _) = Header::decode(&TEST_BASIC).expect("decode basic");
        header.csrc = &[0u8; 64]; // 16 entries
        let mut buffer = [0u8; 128];
        let mut writer = Writer::new(&mut buffer);
        assert_eq!(header.write_to(&mut writer), Err(WireError::InvalidValue));
    }

    // RTP-HDR-016 — encode rejects extension data that is not word-aligned.
    #[test]
    fn encode_rejects_misaligned_extension_data() {
        let (mut header, _) = Header::decode(&TEST_BASIC).expect("decode basic");
        header.extension_profile = 0xBEDE;
        header.extension_data = &[0x10, 0xAA];
        let mut buffer = [0u8; 32];
        let mut writer = Writer::new(&mut buffer);
        assert_eq!(header.write_to(&mut writer), Err(WireError::InvalidValue));
    }

    // RTP-HDR-017 — round-trip property over deterministic field combinations.
    #[test]
    fn encode_decode_roundtrip_property() {
        let csrc_bytes = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        for (index, padding) in [false, true].iter().enumerate() {
            for extension in [false, true] {
                let (cc, csrc) = if extension {
                    (2usize, &csrc_bytes[..8])
                } else {
                    (index, &csrc_bytes[..4 * index])
                };
                let extension_data: &[u8] = if extension {
                    &[0x10, 0xAA, 0x00, 0x00]
                } else {
                    &[]
                };
                let header = Header {
                    version: 2,
                    padding: *padding,
                    extension,
                    marker: index == 1,
                    payload_type: 0x60 | u8::try_from(index).unwrap_or(0),
                    sequence_number: 0x698F,
                    timestamp: 3_653_407_706,
                    ssrc: 476_325_762,
                    csrc,
                    extension_profile: if extension { 0xBEDE } else { 0 },
                    extension_data,
                };
                assert_eq!(header.csrc.len() / CSRC_LENGTH, cc);

                let mut buffer = [0u8; 64];
                let written = {
                    let mut writer = Writer::new(&mut buffer);
                    header.write_to(&mut writer).expect("write header");
                    writer.offset()
                };
                assert_eq!(written, header.encoded_len());

                let (decoded, consumed) =
                    Header::decode(&buffer[..written]).expect("decode header");
                assert_eq!(consumed, written);
                assert_eq!(decoded, header);
            }
        }
    }
}

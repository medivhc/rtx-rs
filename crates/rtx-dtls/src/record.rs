//! DTLS 1.2 record framing (RFC 6347 section 4.1).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | ContentType   |    Version    |            Epoch              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Sequence Number (6 bytes)                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            Length             |            Fragment           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The header is always 13 bytes. DTLS 1.2 fixes the version to
//! `{254, 253}`; no other version is accepted. `Record` is mode agnostic: its
//! `fragment` is the bytes on the wire, which are plaintext for an epoch-0
//! record and explicit-nonce plus ciphertext plus tag for a protected record.

use rtx_wire::{Cursor, WireError, Writer};

use crate::error::RecordError;

/// Fixed DTLS record header length in bytes.
pub const RECORD_HEADER_LEN: usize = 13;
/// DTLS 1.2 record version, `{254, 253}` (RFC 6347 section 4.1).
pub const DTLS12_VERSION: [u8; 2] = [254, 253];
/// Largest plaintext fragment DTLS 1.2 permits (2^14, RFC 6347 section 4.1).
pub const MAX_PLAINTEXT_LEN: usize = 16_384;
/// Length of the explicit nonce carried in a protected record.
pub const AEAD_EXPLICIT_NONCE_LEN: usize = 8;
/// Length of the AES-GCM authentication tag.
pub const AEAD_TAG_LEN: usize = 16;
/// Wire overhead a protected record adds to its plaintext.
pub const AEAD_OVERHEAD: usize = AEAD_EXPLICIT_NONCE_LEN + AEAD_TAG_LEN;
/// Largest fragment a record may declare on the wire: a full plaintext plus
/// the AEAD overhead.
pub const MAX_FRAGMENT_LEN: usize = MAX_PLAINTEXT_LEN + AEAD_OVERHEAD;
/// Largest value a 48-bit DTLS sequence number can carry.
pub const SEQUENCE_NUMBER_MAX: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Record content types defined by RFC 6347 section 12.
///
/// Heartbeat (RFC 6520, type 24) is intentionally absent: it belongs to an
/// extension this record layer does not implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
}

impl ContentType {
    /// Parses the one-byte content type.
    ///
    /// Returns `None` for any value RFC 6347 does not define.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }

    /// Returns the one-byte content type.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::ChangeCipherSpec => 20,
            Self::Alert => 21,
            Self::Handshake => 22,
            Self::ApplicationData => 23,
        }
    }
}

/// A 48-bit DTLS record sequence number.
///
/// The type makes the 48-bit bound unrepresentable rather than merely
/// documented: values above [`SEQUENCE_NUMBER_MAX`] cannot be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SequenceNumber(u64);

impl SequenceNumber {
    /// Sequence number zero, the first value of every epoch.
    pub const ZERO: Self = Self(0);
    /// Largest representable sequence number.
    pub const MAX: Self = Self(SEQUENCE_NUMBER_MAX);

    /// Builds a sequence number, rejecting values wider than 48 bits.
    #[must_use]
    pub const fn from_u64(value: u64) -> Option<Self> {
        if value <= SEQUENCE_NUMBER_MAX {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Returns the sequence number as a `u64` in `0..=2^48-1`.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Serializes the sequence number as the 6 wire bytes, big-endian.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 6] {
        let bytes = self.0.to_be_bytes();
        [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
    }

    /// Parses the 6 wire bytes, big-endian. Every 6-byte value is valid.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 6]) -> Self {
        Self(u64::from_be_bytes([
            0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
        ]))
    }
}

impl From<SequenceNumber> for u64 {
    fn from(value: SequenceNumber) -> Self {
        value.0
    }
}

/// A decoded DTLS record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    /// Record content type.
    pub content_type: ContentType,
    /// Epoch. Zero means the record is not protected.
    pub epoch: u16,
    /// 48-bit record sequence number, unique inside an epoch.
    pub sequence_number: SequenceNumber,
    /// Declared fragment length, in bytes.
    pub fragment_len: usize,
}

impl RecordHeader {
    /// Length of the encoded header. Always [`RECORD_HEADER_LEN`].
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        RECORD_HEADER_LEN
    }

    /// Decodes a header from the front of `input`, returning it and the
    /// number of bytes consumed (always [`RECORD_HEADER_LEN`]).
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::UnexpectedEnd`] when `input` is shorter than a
    /// header, [`RecordError::InvalidContentType`] for an unregistered type,
    /// [`RecordError::UnsupportedVersion`] unless the version is
    /// `{254, 253}`, and [`RecordError::RecordTooLong`] when the declared
    /// fragment exceeds [`MAX_FRAGMENT_LEN`].
    pub fn decode(input: &[u8]) -> Result<(Self, usize), RecordError> {
        if input.len() < RECORD_HEADER_LEN {
            return Err(RecordError::UnexpectedEnd);
        }
        let mut cursor = Cursor::new(input);
        let content_type = ContentType::from_u8(cursor.u8().map_err(wire_error)?)
            .ok_or(RecordError::InvalidContentType)?;
        let version = [
            cursor.u8().map_err(wire_error)?,
            cursor.u8().map_err(wire_error)?,
        ];
        if version != DTLS12_VERSION {
            return Err(RecordError::UnsupportedVersion);
        }
        let epoch = cursor.u16_be().map_err(wire_error)?;
        let sequence_bytes: [u8; 6] = cursor
            .take(6)
            .map_err(wire_error)?
            .try_into()
            .map_err(|_| RecordError::UnexpectedEnd)?;
        let fragment_len = usize::from(cursor.u16_be().map_err(wire_error)?);
        if fragment_len > MAX_FRAGMENT_LEN {
            return Err(RecordError::RecordTooLong);
        }
        Ok((
            Self {
                content_type,
                epoch,
                sequence_number: SequenceNumber::from_be_bytes(sequence_bytes),
                fragment_len,
            },
            RECORD_HEADER_LEN,
        ))
    }

    /// Encodes the header into the front of `output`, returning its length.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::RecordTooLong`] when `fragment_len` exceeds
    /// [`MAX_FRAGMENT_LEN`], and [`RecordError::OutputTooSmall`] when
    /// `output` is shorter than [`RECORD_HEADER_LEN`]. Nothing is written on
    /// error.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, RecordError> {
        if self.fragment_len > MAX_FRAGMENT_LEN {
            return Err(RecordError::RecordTooLong);
        }
        if output.len() < RECORD_HEADER_LEN {
            return Err(RecordError::OutputTooSmall);
        }
        let fragment_len =
            u16::try_from(self.fragment_len).map_err(|_| RecordError::RecordTooLong)?;
        let mut writer = Writer::new(output);
        writer.u8(self.content_type.to_u8()).map_err(wire_error)?;
        writer.u8(DTLS12_VERSION[0]).map_err(wire_error)?;
        writer.u8(DTLS12_VERSION[1]).map_err(wire_error)?;
        writer.u16_be(self.epoch).map_err(wire_error)?;
        writer
            .put(&self.sequence_number.to_be_bytes())
            .map_err(wire_error)?;
        writer.u16_be(fragment_len).map_err(wire_error)?;
        Ok(writer.offset())
    }
}

/// One DTLS record, borrowing its fragment from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// Decoded header.
    pub header: RecordHeader,
    /// Fragment as it appears on the wire.
    pub fragment: &'a [u8],
}

impl<'a> Record<'a> {
    /// Total encoded length of the record.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        RECORD_HEADER_LEN + self.fragment.len()
    }

    /// Decodes one record from the front of `input`, returning it and the
    /// number of bytes consumed.
    ///
    /// Unlike [`Record::decode`], trailing bytes are allowed: a datagram may
    /// carry several records back to back (RFC 6347 section 4.1), and the
    /// caller advances by the returned length.
    ///
    /// # Errors
    ///
    /// Returns the header errors of [`RecordHeader::decode`] and
    /// [`RecordError::UnexpectedEnd`] when fewer bytes remain than the
    /// declared fragment length.
    pub fn decode_prefix(input: &'a [u8]) -> Result<(Self, usize), RecordError> {
        let (header, header_len) = RecordHeader::decode(input)?;
        let total = header_len + header.fragment_len;
        let record_bytes = input.get(..total).ok_or(RecordError::UnexpectedEnd)?;
        let fragment = record_bytes
            .get(header_len..)
            .ok_or(RecordError::UnexpectedEnd)?;
        Ok((Self { header, fragment }, total))
    }

    /// Decodes exactly one record from `input`.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::LengthMismatch`] when `input` holds more bytes
    /// than the record declares, plus every error of
    /// [`Record::decode_prefix`].
    pub fn decode(input: &'a [u8]) -> Result<Self, RecordError> {
        let (record, consumed) = Self::decode_prefix(input)?;
        if consumed != input.len() {
            return Err(RecordError::LengthMismatch);
        }
        Ok(record)
    }

    /// Decodes exactly one unprotected record and enforces the 2^14 plaintext
    /// bound.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::RecordTooLong`] when the fragment exceeds
    /// [`MAX_PLAINTEXT_LEN`], plus every error of [`Record::decode`].
    pub fn decode_plaintext(input: &'a [u8]) -> Result<Self, RecordError> {
        let record = Self::decode(input)?;
        if record.header.fragment_len > MAX_PLAINTEXT_LEN {
            return Err(RecordError::RecordTooLong);
        }
        Ok(record)
    }

    /// Decodes exactly one protected record and requires the minimum AEAD
    /// fragment.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::CiphertextTooShort`] when the fragment cannot
    /// hold an explicit nonce and a tag, plus every error of
    /// [`Record::decode`].
    pub fn decode_protected(input: &'a [u8]) -> Result<Self, RecordError> {
        let record = Self::decode(input)?;
        if record.header.fragment_len < AEAD_OVERHEAD {
            return Err(RecordError::CiphertextTooShort);
        }
        Ok(record)
    }

    /// Encodes the record into the front of `output`, returning its length.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::LengthMismatch`] when `fragment.len()` differs
    /// from `header.fragment_len`, [`RecordError::RecordTooLong`] when the
    /// fragment exceeds [`MAX_FRAGMENT_LEN`], and
    /// [`RecordError::OutputTooSmall`] when `output` is too short. Nothing is
    /// written on error.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, RecordError> {
        if self.header.fragment_len != self.fragment.len() {
            return Err(RecordError::LengthMismatch);
        }
        let total = RECORD_HEADER_LEN + self.fragment.len();
        if self.fragment.len() > MAX_FRAGMENT_LEN || output.len() < total {
            return Err(if self.fragment.len() > MAX_FRAGMENT_LEN {
                RecordError::RecordTooLong
            } else {
                RecordError::OutputTooSmall
            });
        }
        self.header.encode(&mut output[..RECORD_HEADER_LEN])?;
        output[RECORD_HEADER_LEN..total].copy_from_slice(self.fragment);
        Ok(total)
    }
}

/// Maps an [`rtx_wire`] cursor/writer failure onto the record error space.
fn wire_error(error: WireError) -> RecordError {
    match error {
        WireError::OutputTooSmall => RecordError::OutputTooSmall,
        WireError::UnexpectedEnd | WireError::InvalidValue | WireError::Overflow => {
            RecordError::UnexpectedEnd
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    const SEQ: SequenceNumber = SequenceNumber::from_be_bytes([0, 0, 0, 0, 0, 7]);

    fn header_out(
        content_type: u8,
        version: [u8; 2],
        epoch: u16,
        sequence: [u8; 6],
        fragment_len: u16,
    ) -> [u8; RECORD_HEADER_LEN] {
        let mut bytes = [0u8; RECORD_HEADER_LEN];
        bytes[0] = content_type;
        bytes[1] = version[0];
        bytes[2] = version[1];
        bytes[3..5].copy_from_slice(&epoch.to_be_bytes());
        bytes[5..11].copy_from_slice(&sequence);
        bytes[11..13].copy_from_slice(&fragment_len.to_be_bytes());
        bytes
    }

    fn plaintext_bytes(fragment: &[u8]) -> Vec<u8> {
        let header = RecordHeader {
            content_type: ContentType::ApplicationData,
            epoch: 0,
            sequence_number: SEQ,
            fragment_len: fragment.len(),
        };
        let record = Record { header, fragment };
        let mut output = vec![0u8; record.encoded_len()];
        let written = record.encode(&mut output).expect("encode");
        assert_eq!(written, output.len());
        output
    }

    // DTLS-CT-001 — content type mapping covers every defined value.
    #[test]
    fn content_type_roundtrips_and_rejects_unknown_values() {
        for (value, content_type) in [
            (20, ContentType::ChangeCipherSpec),
            (21, ContentType::Alert),
            (22, ContentType::Handshake),
            (23, ContentType::ApplicationData),
        ] {
            assert_eq!(ContentType::from_u8(value), Some(content_type));
            assert_eq!(content_type.to_u8(), value);
        }
        for value in [0, 1, 19, 24, 25, 255] {
            assert_eq!(ContentType::from_u8(value), None);
        }
    }

    // DTLS-SEQ-001 — 48-bit construction, serialization and rejection.
    #[test]
    fn sequence_number_enforces_48_bits() {
        assert_eq!(SequenceNumber::ZERO.as_u64(), 0);
        assert_eq!(SequenceNumber::MAX.as_u64(), SEQUENCE_NUMBER_MAX);
        assert_eq!(
            SequenceNumber::from_u64(SEQUENCE_NUMBER_MAX),
            Some(SequenceNumber::MAX)
        );
        assert_eq!(SequenceNumber::from_u64(SEQUENCE_NUMBER_MAX + 1), None);
        assert_eq!(SequenceNumber::from_u64(u64::MAX), None);

        assert_eq!(SequenceNumber::MAX.to_be_bytes(), [0xFF; 6]);
        assert_eq!(SequenceNumber::ZERO.to_be_bytes(), [0; 6]);
        assert_eq!(
            SequenceNumber::from_be_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]).as_u64(),
            0x0000_0102_0304_0506
        );
        for value in [0, 1, 0x0000_00FF_FFFF_FFFF, u64::from(u32::MAX)] {
            let sequence = SequenceNumber::from_u64(value).expect("in range");
            assert_eq!(
                SequenceNumber::from_be_bytes(sequence.to_be_bytes()),
                sequence
            );
            assert_eq!(u64::from(sequence), value);
        }
    }

    // DTLS-HDR-001 — header encode/decode roundtrip over the field extremes.
    #[test]
    fn record_header_roundtrip_covers_field_extremes() {
        for (content_type, epoch, sequence, fragment_len) in [
            (
                ContentType::ChangeCipherSpec,
                0u16,
                SequenceNumber::ZERO,
                0usize,
            ),
            (
                ContentType::Handshake,
                1,
                SequenceNumber::from_u64(1).expect("in range"),
                12,
            ),
            (
                ContentType::Alert,
                u16::MAX,
                SequenceNumber::MAX,
                MAX_PLAINTEXT_LEN,
            ),
            (
                ContentType::ApplicationData,
                7,
                SequenceNumber::from_u64(0x0000_ABCD_EF01_2345).expect("in range"),
                MAX_FRAGMENT_LEN,
            ),
        ] {
            let header = RecordHeader {
                content_type,
                epoch,
                sequence_number: sequence,
                fragment_len,
            };
            assert_eq!(header.encoded_len(), RECORD_HEADER_LEN);
            let mut output = [0u8; RECORD_HEADER_LEN];
            let written = header.encode(&mut output).expect("encode header");
            assert_eq!(written, RECORD_HEADER_LEN);
            let (decoded, consumed) = RecordHeader::decode(&output).expect("decode header");
            assert_eq!(consumed, RECORD_HEADER_LEN);
            assert_eq!(decoded, header);
        }
    }

    // DTLS-HDR-002 — version must be exactly {254, 253}.
    #[test]
    fn record_header_rejects_every_other_version() {
        for version in [[254u8, 255u8], [3, 3], [254, 252], [253, 253], [0, 0]] {
            let bytes = header_out(22, version, 0, [0; 6], 0);
            assert_eq!(
                RecordHeader::decode(&bytes),
                Err(RecordError::UnsupportedVersion),
                "version {version:?}"
            );
        }
        let bytes = header_out(22, DTLS12_VERSION, 0, [0; 6], 0);
        assert!(RecordHeader::decode(&bytes).is_ok());
    }

    // DTLS-HDR-003 — invalid content type is rejected before any length use.
    #[test]
    fn record_header_rejects_unknown_content_types() {
        for content_type in [0u8, 19, 24, 25, 255] {
            let bytes = header_out(content_type, DTLS12_VERSION, 0, [0; 6], 0);
            assert_eq!(
                RecordHeader::decode(&bytes),
                Err(RecordError::InvalidContentType)
            );
        }
    }

    // DTLS-HDR-004 — every truncation of a header fails with UnexpectedEnd.
    #[test]
    fn record_header_truncation_table() {
        let bytes = header_out(22, DTLS12_VERSION, 9, [1, 2, 3, 4, 5, 6], 0);
        for len in 0..RECORD_HEADER_LEN {
            assert_eq!(
                RecordHeader::decode(&bytes[..len]),
                Err(RecordError::UnexpectedEnd),
                "truncated to {len}"
            );
        }
        assert!(RecordHeader::decode(&bytes).is_ok());
    }

    // DTLS-HDR-005 — declared fragment above the record limit is rejected
    // before the input length is considered.
    #[test]
    fn record_header_rejects_oversized_fragments() {
        let max = u16::try_from(MAX_FRAGMENT_LEN).expect("fits u16");
        let bytes = header_out(23, DTLS12_VERSION, 0, [0; 6], max);
        assert!(RecordHeader::decode(&bytes).is_ok());
        let bytes = header_out(23, DTLS12_VERSION, 0, [0; 6], max + 1);
        assert_eq!(
            RecordHeader::decode(&bytes),
            Err(RecordError::RecordTooLong)
        );
        let bytes = header_out(23, DTLS12_VERSION, 0, [0; 6], u16::MAX);
        assert_eq!(
            RecordHeader::decode(&bytes),
            Err(RecordError::RecordTooLong)
        );
    }

    // DTLS-HDR-006 — header encode failure paths leave the buffer untouched.
    #[test]
    fn record_header_encode_failure_is_transactional() {
        let header = RecordHeader {
            content_type: ContentType::Handshake,
            epoch: 3,
            sequence_number: SEQ,
            fragment_len: 4,
        };
        let mut sentinel = [0xAAu8; RECORD_HEADER_LEN - 1];
        assert_eq!(
            header.encode(&mut sentinel),
            Err(RecordError::OutputTooSmall)
        );
        assert_eq!(sentinel, [0xAA; RECORD_HEADER_LEN - 1]);

        let too_long = RecordHeader {
            fragment_len: MAX_FRAGMENT_LEN + 1,
            ..header
        };
        let mut output = [0xAAu8; RECORD_HEADER_LEN];
        assert_eq!(
            too_long.encode(&mut output),
            Err(RecordError::RecordTooLong)
        );
        assert_eq!(output, [0xAA; RECORD_HEADER_LEN]);
    }

    // DTLS-REC-001 — plaintext record encode/decode roundtrip.
    #[test]
    fn plaintext_record_roundtrip() {
        for fragment in [&b""[..], &b"a"[..], &b"rtx-dtls-record"[..]] {
            let bytes = plaintext_bytes(fragment);
            assert_eq!(bytes.len(), RECORD_HEADER_LEN + fragment.len());
            let record = Record::decode(&bytes).expect("decode record");
            assert_eq!(record.header.content_type, ContentType::ApplicationData);
            assert_eq!(record.header.epoch, 0);
            assert_eq!(record.header.sequence_number, SEQ);
            assert_eq!(record.fragment, fragment);
            assert_eq!(record.encoded_len(), bytes.len());

            let decoded = Record::decode_plaintext(&bytes).expect("plaintext decode");
            assert_eq!(decoded, record);
        }
    }

    // DTLS-REC-002 — consecutive records decode with the returned lengths.
    #[test]
    fn record_prefix_decodes_coalesced_records() {
        let first = plaintext_bytes(b"first");
        let second = plaintext_bytes(b"second");
        let mut datagram = first.clone();
        datagram.extend_from_slice(&second);

        let (record, consumed) = Record::decode_prefix(&datagram).expect("first record");
        assert_eq!(consumed, first.len());
        assert_eq!(record.fragment, b"first");
        let (record, consumed) = Record::decode_prefix(&datagram[consumed..]).expect("second");
        assert_eq!(consumed, second.len());
        assert_eq!(record.fragment, b"second");
    }

    // DTLS-REC-003 — strict decode rejects a length field that is shorter
    // than the datagram, while prefix decode reports the consumed prefix.
    #[test]
    fn record_strict_decode_detects_trailing_bytes() {
        let mut bytes = plaintext_bytes(b"body");
        bytes.push(0xFF);
        assert_eq!(Record::decode(&bytes), Err(RecordError::LengthMismatch));
        let (record, consumed) = Record::decode_prefix(&bytes).expect("prefix");
        assert_eq!(record.fragment, b"body");
        assert_eq!(consumed, bytes.len() - 1);
    }

    // DTLS-REC-004 — a truncated fragment is UnexpectedEnd, never a panic.
    #[test]
    fn record_truncation_table() {
        let bytes = plaintext_bytes(b"truncation");
        for len in 0..bytes.len() {
            assert_eq!(
                Record::decode(&bytes[..len]),
                Err(RecordError::UnexpectedEnd),
                "truncated to {len}"
            );
            assert_eq!(
                Record::decode_prefix(&bytes[..len]),
                Err(RecordError::UnexpectedEnd),
                "prefix truncated to {len}"
            );
        }
        assert!(Record::decode(&bytes).is_ok());
    }

    // DTLS-REC-005 — plaintext and protected length floors are distinct.
    #[test]
    fn record_mode_specific_length_checks() {
        // A plaintext record above 2^14 but below the protected wire limit.
        let oversized_plaintext = vec![0u8; MAX_PLAINTEXT_LEN + 1];
        let bytes = plaintext_bytes(&oversized_plaintext);
        assert_eq!(
            Record::decode_plaintext(&bytes),
            Err(RecordError::RecordTooLong)
        );
        assert!(Record::decode(&bytes).is_ok());

        // A protected record that cannot hold nonce plus tag.
        let short = plaintext_bytes(&[0u8; AEAD_OVERHEAD - 1]);
        assert_eq!(
            Record::decode_protected(&short),
            Err(RecordError::CiphertextTooShort)
        );
        let floor = plaintext_bytes(&[0u8; AEAD_OVERHEAD]);
        assert!(Record::decode_protected(&floor).is_ok());
    }

    // DTLS-REC-006 — encode validates header/fragment agreement and capacity
    // before writing anything.
    #[test]
    fn record_encode_failure_paths_are_transactional() {
        let header = RecordHeader {
            content_type: ContentType::Alert,
            epoch: 1,
            sequence_number: SEQ,
            fragment_len: 3,
        };
        let mut output = [0xAAu8; RECORD_HEADER_LEN + 3];
        let mismatched = Record {
            header,
            fragment: b"ab",
        };
        assert_eq!(
            mismatched.encode(&mut output),
            Err(RecordError::LengthMismatch)
        );
        assert_eq!(output, [0xAA; RECORD_HEADER_LEN + 3]);

        let record = Record {
            header,
            fragment: b"abc",
        };
        let mut small = [0xAAu8; RECORD_HEADER_LEN + 2];
        assert_eq!(record.encode(&mut small), Err(RecordError::OutputTooSmall));
        assert_eq!(small, [0xAA; RECORD_HEADER_LEN + 2]);

        let oversized_fragment = vec![0u8; MAX_FRAGMENT_LEN + 1];
        let oversized = Record {
            header: RecordHeader {
                fragment_len: MAX_FRAGMENT_LEN + 1,
                ..header
            },
            fragment: &oversized_fragment,
        };
        let mut roomy = vec![0xAAu8; MAX_FRAGMENT_LEN + 1 + RECORD_HEADER_LEN];
        assert_eq!(
            oversized.encode(&mut roomy),
            Err(RecordError::RecordTooLong)
        );
        assert!(roomy.iter().all(|&byte| byte == 0xAA));
    }

    // DTLS-REC-007 — maximum-size plaintext and protected fragments parse.
    #[test]
    fn record_maximum_fragment_roundtrip() {
        let plaintext = vec![0x5Au8; MAX_PLAINTEXT_LEN];
        let bytes = plaintext_bytes(&plaintext);
        let record = Record::decode_plaintext(&bytes).expect("max plaintext");
        assert_eq!(record.fragment.len(), MAX_PLAINTEXT_LEN);
        assert_eq!(
            record,
            Record {
                header: record.header,
                fragment: &plaintext
            }
        );

        let protected = vec![0x5Au8; MAX_FRAGMENT_LEN];
        let bytes = plaintext_bytes(&protected);
        let record = Record::decode_protected(&bytes).expect("max protected");
        assert_eq!(record.fragment.len(), MAX_FRAGMENT_LEN);
    }
}

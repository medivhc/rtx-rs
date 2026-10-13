//! RTCP common header (RFC 3550 section 6.4.1, 4 bytes).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|  count  |   packet type |          length               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `length` is the packet size in 32-bit words minus one, i.e. it does not
//! count the header itself.

use rtx_wire::{Cursor, Decode, Encode, WireError, Writer};

/// RTCP version implemented by this crate (RFC 3550 section 6.4.1).
pub const RTP_VERSION: u8 = 2;

/// Bit offset of the version field inside the first header byte.
pub const VERSION_SHIFT: u8 = 6;
/// Bit mask of the version field inside the first header byte.
pub const VERSION_MASK: u8 = 0x3;

/// Bit offset of the padding flag inside the first header byte.
pub const PADDING_SHIFT: u8 = 5;
/// Bit mask of the padding flag inside the first header byte.
pub const PADDING_MASK: u8 = 0x1;

/// Bit mask of the count field inside the first header byte (5 bits).
pub const COUNT_MASK: u8 = 0x1F;

/// Size of the fixed RTCP common header in bytes.
pub const HEADER_LENGTH: usize = 4;

/// Maximum value of the count field (5 bits).
pub const COUNT_MAX: u8 = 31;

/// Size of an SSRC / CSRC identifier field in bytes.
pub const SSRC_LENGTH: usize = 4;

/// RTCP packet type (RFC 3550 section 6.4.2, type values 200-204 plus
/// later RFCs 5506/3611). Unknown values are preserved verbatim via
/// [`PacketType::Unknown`] so that no information is lost on re-encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum PacketType {
    /// Reserved / unknown value (not a valid RTCP packet type).
    Unknown(u8) = 0,
    /// Sender report (RFC 3550 section 6.4.1).
    Sr = 200,
    /// Receiver report (RFC 3550 section 6.4.2).
    Rr = 201,
    /// Source description (RFC 3550 section 6.4.3).
    Sdes = 202,
    /// Goodbye (RFC 3550 section 6.4.4).
    Bye = 203,
    /// Application-defined (RFC 3550 section 6.7).
    App = 204,
    /// Transport layer feedback (RFC 4585 section 6.2).
    Tsfb = 205,
    /// Payload-specific feedback (RFC 4585 section 6.3).
    Psfb = 206,
    /// Extended report (RFC 3611).
    Xr = 207,
}

impl Default for PacketType {
    /// Defaults to the reserved/unknown value `Unknown(0)`.
    fn default() -> Self {
        PacketType::Unknown(0)
    }
}

impl PacketType {
    /// Returns the wire byte value of this packet type.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            PacketType::Unknown(value) => value,
            PacketType::Sr => 200,
            PacketType::Rr => 201,
            PacketType::Sdes => 202,
            PacketType::Bye => 203,
            PacketType::App => 204,
            PacketType::Tsfb => 205,
            PacketType::Psfb => 206,
            PacketType::Xr => 207,
        }
    }
}

impl From<u8> for PacketType {
    /// Maps a wire byte to a packet type, preserving unknown values.
    fn from(value: u8) -> Self {
        match value {
            200 => PacketType::Sr,
            201 => PacketType::Rr,
            202 => PacketType::Sdes,
            203 => PacketType::Bye,
            204 => PacketType::App,
            205 => PacketType::Tsfb,
            206 => PacketType::Psfb,
            207 => PacketType::Xr,
            other => PacketType::Unknown(other),
        }
    }
}

/// RTCP common header shared by all packet types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    /// Padding flag: the last byte of the packet contains the padding count.
    pub padding: bool,
    /// Count field (meaning depends on packet type, e.g. report blocks).
    pub count: u8,
    /// Packet type byte.
    pub packet_type: PacketType,
    /// Length in 32-bit words minus one (excludes the header itself).
    pub length: u16,
}

impl Header {
    /// Total packet size in bytes implied by the `length` field.
    #[must_use]
    pub const fn total_len(&self) -> usize {
        (self.length as usize + 1) * 4
    }

    /// Encodes the header, recomputing `count` bounds and `length` fields.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when `count` exceeds 31.
    pub(crate) fn write_to(self, writer: &mut Writer<'_>) -> Result<(), WireError> {
        if self.count > COUNT_MAX {
            return Err(WireError::InvalidValue);
        }
        let first = (RTP_VERSION << VERSION_SHIFT)
            | ((u8::from(self.padding)) << PADDING_SHIFT)
            | (self.count & COUNT_MASK);
        writer.u8(first)?;
        writer.u8(self.packet_type.as_u8())?;
        writer.u16_be(self.length)?;
        Ok(())
    }
}

impl<'a> Decode<'a> for Header {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        let mut cursor = Cursor::new(input);
        let first = cursor.u8()?;
        let version = first >> VERSION_SHIFT;
        if version != RTP_VERSION {
            return Err(WireError::InvalidValue);
        }
        let packet_type = cursor.u8()?;
        let length = cursor.u16_be()?;
        let header = Header {
            padding: (first >> PADDING_SHIFT) & PADDING_MASK == 1,
            count: first & COUNT_MASK,
            packet_type: PacketType::from(packet_type),
            length,
        };
        Ok((header, cursor.offset()))
    }
}

impl Encode for Header {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        HEADER_LENGTH
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

    /// Differential vector: upstream `rtcp/header.rs:228-231`
    /// (valid header, RR, count 1, length 7).
    const RTCP_HDR_VALID: [u8; 4] = [0x81, 0xc9, 0x00, 0x07];

    /// Differential vector: upstream `rtcp/header.rs:243-246`
    /// (padding flag set, APP, count 1, length 7).
    const RTCP_HDR_PADDING: [u8; 4] = [0xa1, 0xcc, 0x00, 0x07];

    /// Differential vector: upstream `rtcp/header.rs:256-259`
    /// (version 0 must be rejected).
    const RTCP_HDR_BAD_VERSION: [u8; 4] = [0x00, 0xc9, 0x00, 0x04];

    // RTCP-HDR-001 — 差分：合法 RR 头逐字段断言 + encode 字节级往返。
    #[test]
    fn rtcp_hdr_001_valid_sr_header_round_trip() {
        let (header, consumed) = Header::decode(&RTCP_HDR_VALID).expect("decode valid header");
        assert_eq!(consumed, HEADER_LENGTH);
        assert!(!header.padding);
        assert_eq!(header.count, 1);
        assert_eq!(header.packet_type, PacketType::Rr);
        assert_eq!(header.length, 7);
        assert_eq!(header.total_len(), 32);

        let mut output = [0u8; HEADER_LENGTH];
        let written = header.encode(&mut output).expect("encode valid header");
        assert_eq!(written, HEADER_LENGTH);
        assert_eq!(written, header.encoded_len());
        assert_eq!(output, RTCP_HDR_VALID);
    }

    // RTCP-HDR-002 — 差分：padding 标志 + APP 类型往返。
    #[test]
    fn rtcp_hdr_002_padding_app_header_round_trip() {
        let (header, consumed) = Header::decode(&RTCP_HDR_PADDING).expect("decode padded header");
        assert_eq!(consumed, HEADER_LENGTH);
        assert!(header.padding);
        assert_eq!(header.count, 1);
        assert_eq!(header.packet_type, PacketType::App);

        let mut output = [0u8; HEADER_LENGTH];
        header.encode(&mut output).expect("encode padded header");
        assert_eq!(output, RTCP_HDR_PADDING);
    }

    // RTCP-HDR-003 — 差分：version != 2 拒绝（上游 header_test.rs:256）。
    #[test]
    fn rtcp_hdr_003_bad_version_rejected() {
        assert_eq!(
            Header::decode(&RTCP_HDR_BAD_VERSION),
            Err(WireError::InvalidValue)
        );
    }

    // RTCP-HDR-004 — 截断输入（少于 4 字节）→ UnexpectedEnd。
    #[test]
    fn rtcp_hdr_004_truncated_input_rejected() {
        assert_eq!(Header::decode(&[]), Err(WireError::UnexpectedEnd));
        assert_eq!(Header::decode(&[0x81]), Err(WireError::UnexpectedEnd));
        assert_eq!(Header::decode(&[0x81, 0xc9]), Err(WireError::UnexpectedEnd));
        assert_eq!(
            Header::decode(&[0x81, 0xc9, 0x00]),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTCP-HDR-005 — count > 31 无法编码（5 位字段）+ 未知类型保留。
    #[test]
    fn rtcp_hdr_005_count_overflow_and_unknown_type_preserved() {
        let mut header = Header {
            padding: false,
            count: 32,
            packet_type: PacketType::Sdes,
            length: 0,
        };
        let mut output = [0u8; HEADER_LENGTH];
        assert_eq!(header.encode(&mut output), Err(WireError::InvalidValue));

        // 未知类型字节（如 205 TSFB 不在已知枚举中时保留原始值）。
        assert_eq!(PacketType::from(205), PacketType::Tsfb);
        let unknown = PacketType::from(99);
        assert_eq!(unknown, PacketType::Unknown(99));
        assert_eq!(unknown.as_u8(), 99);
        header.count = 31;
        assert_eq!(header.encode(&mut output), Ok(HEADER_LENGTH));
    }
}

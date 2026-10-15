//! STUN attribute types and the raw Type-Length-Value representation.
//!
//! Every attribute is a type code, a length and a value. This module defines
//! the code points — those from STUN itself ([RFC 5389]) plus the ones TURN
//! ([RFC 5766]), ICE ([RFC 8445]) and the NAT behaviour discovery extensions
//! ([RFC 5780]) add — while the typed accessors live in [`crate::addr`],
//! [`crate::xoraddr`], [`crate::textattrs`], [`crate::error_code`] and
//! [`crate::uattrs`].
//!
//! Codes below `0x8000` are *comprehension-required*: a receiver that does
//! not understand one must reject the message. Codes at or above `0x8000`
//! are comprehension-optional and may be ignored, which is how `FINGERPRINT`
//! and the ICE attributes can be added without breaking older peers.
//!
//! Decoding is zero-copy: [`RawAttribute`] borrows its value directly from
//! the input slice, and re-encoding reproduces the attribute bytes exactly
//! (modulo padding normalisation, see [`RawAttribute::encode`]).
//!
//! [RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389
//! [RFC 5766]: https://www.rfc-editor.org/rfc/rfc5766
//! [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
//! [RFC 5780]: https://www.rfc-editor.org/rfc/rfc5780

use core::fmt;

use rtx_wire::{Decode, Encode, WireError};

/// Bytes of type and length preceding each attribute value.
pub const ATTRIBUTE_HEADER_SIZE: usize = 4;

/// STUN aligns attributes on 32-bit boundaries ([RFC 5389] §15).
pub(crate) const PADDING: usize = 4;

/// Rounds `l` up to the next multiple of [`PADDING`].
///
/// `0` stays `0`; the multiplication form (rather than `(l + 3) & !3`) keeps
/// the helper total for arbitrary `usize` inputs.
pub(crate) fn nearest_padded_value_length(l: usize) -> usize {
    let mut n = PADDING * (l / PADDING);
    if n < l {
        n += PADDING;
    }
    n
}

/// Maps a wire type code to an [`AttrType`], translating the pre-RFC-5389
/// `0x8020` code for `XOR-MAPPED-ADDRESS` for backward compatibility
/// (draft-ietf-behave-rfc3489bis-02 / MS-TURN).
///
/// Only decoding applies this translation; encoding always writes the
/// canonical code the caller selected.
pub(crate) fn compat_attr_type(value: u16) -> AttrType {
    if value == 0x8020 {
        ATTR_XORMAPPED_ADDRESS
    } else {
        AttrType(value)
    }
}

/// An attribute type code.
#[derive(PartialEq, Eq, Debug, Default, Copy, Clone, Hash)]
pub struct AttrType(pub u16);

impl AttrType {
    /// Returns `true` if the type is from the comprehension-required range
    /// (`0x0000`-`0x7FFF`).
    #[must_use]
    pub const fn required(self) -> bool {
        self.0 <= 0x7FFF
    }

    /// Returns `true` if the type is from the comprehension-optional range
    /// (`0x8000`-`0xFFFF`).
    #[must_use]
    pub const fn optional(self) -> bool {
        self.0 >= 0x8000
    }

    /// Returns the `u16` wire representation of the attribute type.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

impl fmt::Display for AttrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            ATTR_MAPPED_ADDRESS => "MAPPED-ADDRESS",
            ATTR_USERNAME => "USERNAME",
            ATTR_ERROR_CODE => "ERROR-CODE",
            ATTR_MESSAGE_INTEGRITY => "MESSAGE-INTEGRITY",
            ATTR_UNKNOWN_ATTRIBUTES => "UNKNOWN-ATTRIBUTES",
            ATTR_REALM => "REALM",
            ATTR_NONCE => "NONCE",
            ATTR_XORMAPPED_ADDRESS => "XOR-MAPPED-ADDRESS",
            ATTR_SOFTWARE => "SOFTWARE",
            ATTR_ALTERNATE_SERVER => "ALTERNATE-SERVER",
            ATTR_FINGERPRINT => "FINGERPRINT",
            ATTR_PRIORITY => "PRIORITY",
            ATTR_USE_CANDIDATE => "USE-CANDIDATE",
            ATTR_ICE_CONTROLLED => "ICE-CONTROLLED",
            ATTR_ICE_CONTROLLING => "ICE-CONTROLLING",
            ATTR_CHANNEL_NUMBER => "CHANNEL-NUMBER",
            ATTR_LIFETIME => "LIFETIME",
            ATTR_XOR_PEER_ADDRESS => "XOR-PEER-ADDRESS",
            ATTR_DATA => "DATA",
            ATTR_XOR_RELAYED_ADDRESS => "XOR-RELAYED-ADDRESS",
            ATTR_EVEN_PORT => "EVEN-PORT",
            ATTR_REQUESTED_TRANSPORT => "REQUESTED-TRANSPORT",
            ATTR_DONT_FRAGMENT => "DONT-FRAGMENT",
            ATTR_RESERVATION_TOKEN => "RESERVATION-TOKEN",
            ATTR_CONNECTION_ID => "CONNECTION-ID",
            ATTR_REQUESTED_ADDRESS_FAMILY => "REQUESTED-ADDRESS-FAMILY",
            ATTR_MESSAGE_INTEGRITY_SHA256 => "MESSAGE-INTEGRITY-SHA256",
            ATTR_PASSWORD_ALGORITHM => "PASSWORD-ALGORITHM",
            ATTR_USER_HASH => "USERHASH",
            ATTR_PASSWORD_ALGORITHMS => "PASSWORD-ALGORITHMS",
            ATTR_ALTERNATE_DOMAIN => "ALTERNATE-DOMAIN",
            _ => return write!(f, "0x{:x}", self.0),
        };
        f.write_str(s)
    }
}

/// Attributes from comprehension-required range (0x0000-0x7FFF).
/// MAPPED-ADDRESS.
pub const ATTR_MAPPED_ADDRESS: AttrType = AttrType(0x0001);
/// USERNAME.
pub const ATTR_USERNAME: AttrType = AttrType(0x0006);
/// MESSAGE-INTEGRITY.
pub const ATTR_MESSAGE_INTEGRITY: AttrType = AttrType(0x0008);
/// ERROR-CODE.
pub const ATTR_ERROR_CODE: AttrType = AttrType(0x0009);
/// UNKNOWN-ATTRIBUTES.
pub const ATTR_UNKNOWN_ATTRIBUTES: AttrType = AttrType(0x000A);
/// REALM.
pub const ATTR_REALM: AttrType = AttrType(0x0014);
/// NONCE.
pub const ATTR_NONCE: AttrType = AttrType(0x0015);
/// XOR-MAPPED-ADDRESS.
pub const ATTR_XORMAPPED_ADDRESS: AttrType = AttrType(0x0020);

/// Attributes from comprehension-optional range (0x8000-0xFFFF).
/// SOFTWARE.
pub const ATTR_SOFTWARE: AttrType = AttrType(0x8022);
/// ALTERNATE-SERVER.
pub const ATTR_ALTERNATE_SERVER: AttrType = AttrType(0x8023);
/// FINGERPRINT.
pub const ATTR_FINGERPRINT: AttrType = AttrType(0x8028);

/// Attributes from RFC 5245 ICE.
/// PRIORITY.
pub const ATTR_PRIORITY: AttrType = AttrType(0x0024);
/// USE-CANDIDATE.
pub const ATTR_USE_CANDIDATE: AttrType = AttrType(0x0025);
/// ICE-CONTROLLED.
pub const ATTR_ICE_CONTROLLED: AttrType = AttrType(0x8029);
/// ICE-CONTROLLING.
pub const ATTR_ICE_CONTROLLING: AttrType = AttrType(0x802A);
/// NETWORK-COST.
pub const ATTR_NETWORK_COST: AttrType = AttrType(0xC057);

/// Attributes from RFC 5766 TURN.
/// CHANNEL-NUMBER.
pub const ATTR_CHANNEL_NUMBER: AttrType = AttrType(0x000C);
/// LIFETIME.
pub const ATTR_LIFETIME: AttrType = AttrType(0x000D);
/// XOR-PEER-ADDRESS.
pub const ATTR_XOR_PEER_ADDRESS: AttrType = AttrType(0x0012);
/// DATA.
pub const ATTR_DATA: AttrType = AttrType(0x0013);
/// XOR-RELAYED-ADDRESS.
pub const ATTR_XOR_RELAYED_ADDRESS: AttrType = AttrType(0x0016);
/// EVEN-PORT.
pub const ATTR_EVEN_PORT: AttrType = AttrType(0x0018);
/// REQUESTED-TRANSPORT.
pub const ATTR_REQUESTED_TRANSPORT: AttrType = AttrType(0x0019);
/// DONT-FRAGMENT.
pub const ATTR_DONT_FRAGMENT: AttrType = AttrType(0x001A);
/// RESERVATION-TOKEN.
pub const ATTR_RESERVATION_TOKEN: AttrType = AttrType(0x0022);

/// Attributes from RFC 5780 NAT Behavior Discovery.
/// CHANGE-REQUEST.
pub const ATTR_CHANGE_REQUEST: AttrType = AttrType(0x0003);
/// PADDING.
pub const ATTR_PADDING: AttrType = AttrType(0x0026);
/// RESPONSE-PORT.
pub const ATTR_RESPONSE_PORT: AttrType = AttrType(0x0027);
/// CACHE-TIMEOUT.
pub const ATTR_CACHE_TIMEOUT: AttrType = AttrType(0x8027);
/// RESPONSE-ORIGIN.
pub const ATTR_RESPONSE_ORIGIN: AttrType = AttrType(0x802B);
/// OTHER-ADDRESS.
pub const ATTR_OTHER_ADDRESS: AttrType = AttrType(0x802C);

/// Attributes from RFC 3489, removed by RFC 5389, but still used by
/// RFC 5389-implementing software like Vovida.org, reTURNServer, etc.
/// SOURCE-ADDRESS.
pub const ATTR_SOURCE_ADDRESS: AttrType = AttrType(0x0004);
/// CHANGED-ADDRESS.
pub const ATTR_CHANGED_ADDRESS: AttrType = AttrType(0x0005);

/// Attributes from RFC 6062 TURN Extensions for TCP Allocations.
/// CONNECTION-ID.
pub const ATTR_CONNECTION_ID: AttrType = AttrType(0x002A);

/// Attributes from RFC 6156 TURN IPv6.
/// REQUESTED-ADDRESS-FAMILY.
pub const ATTR_REQUESTED_ADDRESS_FAMILY: AttrType = AttrType(0x0017);

/// Attributes from "An Origin Attribute for the STUN Protocol".
/// ORIGIN.
pub const ATTR_ORIGIN: AttrType = AttrType(0x802F);

/// Attributes from RFC 8489 STUN.
/// MESSAGE-INTEGRITY-SHA256.
pub const ATTR_MESSAGE_INTEGRITY_SHA256: AttrType = AttrType(0x001C);
/// PASSWORD-ALGORITHM.
pub const ATTR_PASSWORD_ALGORITHM: AttrType = AttrType(0x001D);
/// USER-HASH.
pub const ATTR_USER_HASH: AttrType = AttrType(0x001E);
/// PASSWORD-ALGORITHMS.
pub const ATTR_PASSWORD_ALGORITHMS: AttrType = AttrType(0x8002);
/// ALTERNATE-DOMAIN.
pub const ATTR_ALTERNATE_DOMAIN: AttrType = AttrType(0x8003);

/// A Type-Length-Value (TLV) attribute that borrows its value from the
/// decoded input.
///
/// `length` is the unpadded value length as carried on the wire; the
/// attribute occupies `ATTRIBUTE_HEADER_SIZE + nearest_padded_value_length(length)`
/// bytes in a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawAttribute<'a> {
    /// Which attribute this is.
    pub typ: AttrType,
    /// The value length in bytes; recomputed when encoding, so it is ignored
    /// there.
    pub length: u16,
    /// The attribute's raw value, borrowed from the input.
    pub value: &'a [u8],
}

impl fmt::Display for RawAttribute<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.typ, self.value)
    }
}

impl<'a> Decode<'a> for RawAttribute<'a> {
    type Error = WireError;

    /// Decodes one attribute TLV from the front of `input`.
    ///
    /// Padding bytes after the value are consumed but not borrowed; their
    /// contents are ignored, as [RFC 5389] §15 permits any value there.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when fewer than
    /// [`ATTRIBUTE_HEADER_SIZE`] bytes remain, or
    /// [`WireError::UnexpectedEnd`] when the padded value does not fit.
    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        if input.len() < ATTRIBUTE_HEADER_SIZE {
            return Err(WireError::InvalidValue);
        }
        let typ = compat_attr_type(u16::from_be_bytes([input[0], input[1]]));
        let length = u16::from_be_bytes([input[2], input[3]]);
        let padded = nearest_padded_value_length(length as usize);
        let total = ATTRIBUTE_HEADER_SIZE + padded;
        let value = input
            .get(ATTRIBUTE_HEADER_SIZE..ATTRIBUTE_HEADER_SIZE + length as usize)
            .ok_or(WireError::UnexpectedEnd)?;
        if input.len() < total {
            return Err(WireError::UnexpectedEnd);
        }
        Ok((RawAttribute { typ, length, value }, total))
    }
}

impl Encode for RawAttribute<'_> {
    type Error = WireError;

    /// Writes the TLV plus zero padding up to the next 32-bit boundary.
    ///
    /// Re-encoding a decoded attribute reproduces its bytes exactly for
    /// canonically padded input; non-zero padding bytes are normalised to
    /// zero (they carry no meaning, [RFC 5389] §15).
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Overflow`] when the value does not fit the
    /// 16-bit length field, or [`WireError::OutputTooSmall`] when `output`
    /// lacks room for the padded TLV. Nothing is written on error.
    fn encoded_len(&self) -> usize {
        ATTRIBUTE_HEADER_SIZE + nearest_padded_value_length(self.value.len())
    }

    fn encode(&self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let length = u16::try_from(self.value.len()).map_err(|_| WireError::Overflow)?;
        let total = self.encoded_len();
        let end = total;
        if output.len() < end {
            return Err(WireError::OutputTooSmall);
        }
        output[0..2].copy_from_slice(&self.typ.value().to_be_bytes());
        output[2..4].copy_from_slice(&length.to_be_bytes());
        output[ATTRIBUTE_HEADER_SIZE..ATTRIBUTE_HEADER_SIZE + self.value.len()]
            .copy_from_slice(self.value);
        // Zero the padding bytes so re-encoding never leaks buffer contents.
        for byte in &mut output[ATTRIBUTE_HEADER_SIZE + self.value.len()..end] {
            *byte = 0;
        }
        Ok(end)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    // ---- ATTR-TLV ---------------------------------------------------------

    // ATTR-TLV-001 — 4 字节对齐值的 TLV 编解码往返。
    // 向量来源：上游 attributes_test.rs:5-18（RawAttribute add_to/get 语义）。
    #[test]
    fn stun_attr_001_aligned_tlv_roundtrip() {
        let attr = RawAttribute {
            typ: ATTR_PRIORITY,
            length: 4,
            value: &[0x01, 0x02, 0x03, 0x04],
        };
        let mut out = [0u8; 8];
        let written = attr.encode(&mut out).expect("encode aligned TLV");
        assert_eq!(written, 8);
        assert_eq!(written, attr.encoded_len());
        assert_eq!(out, [0x00, 0x24, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04]);

        let (decoded, consumed) = RawAttribute::decode(&out).expect("decode aligned TLV");
        assert_eq!(decoded, attr);
        assert_eq!(consumed, 8);
    }

    // ATTR-TLV-002 — 非 4 对齐值补零 padding；解码容忍非零 padding。
    // 向量来源：上游 attributes_test.rs:44-65（padding 表）。
    #[test]
    fn stun_attr_002_unaligned_value_padding_and_tolerance() {
        let attr = RawAttribute {
            typ: ATTR_USE_CANDIDATE,
            length: 2,
            value: &[0xAA, 0xBB],
        };
        let mut out = [0u8; 8];
        let written = attr.encode(&mut out).expect("encode unaligned TLV");
        assert_eq!(written, 8);
        assert_eq!(out, [0x00, 0x25, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x00]);

        // 非零 padding 在解码时被忽略（RFC 5389 §15：padding 位无语义）。
        let dirty = [0x00, 0x25, 0x00, 0x02, 0xAA, 0xBB, 0xDE, 0xAD];
        let (decoded, consumed) = RawAttribute::decode(&dirty).expect("decode dirty padding");
        assert_eq!(decoded.value, &[0xAA, 0xBB]);
        assert_eq!(consumed, 8);

        // 重编码把 padding 归一化为零。
        let mut reencoded = [0u8; 8];
        decoded
            .encode(&mut reencoded)
            .expect("re-encode decoded attribute");
        assert_eq!(reencoded, out);
    }

    // ATTR-TLV-003 — 值区不足 → UnexpectedEnd。
    #[test]
    fn stun_attr_003_value_short_of_declared_length() {
        // L=4 但值区只有 2 字节。
        assert_eq!(
            RawAttribute::decode(&[0x00, 0x24, 0x00, 0x04, 0x01, 0x02]),
            Err(WireError::UnexpectedEnd)
        );
        // L=2 需要 padded 4，尾部长 3 字节仍不足。
        assert_eq!(
            RawAttribute::decode(&[0x00, 0x25, 0x00, 0x02, 0xAA, 0xBB, 0x00]),
            Err(WireError::UnexpectedEnd)
        );
    }

    // ATTR-TLV-004 — TLV 头截断 → InvalidValue。
    #[test]
    fn stun_attr_004_truncated_tlv_header() {
        assert_eq!(
            RawAttribute::decode(&[0x00, 0x24, 0x00]),
            Err(WireError::InvalidValue)
        );
        assert_eq!(RawAttribute::decode(&[]), Err(WireError::InvalidValue));
    }

    // ATTR-TLV-005 — 零长值属性（USE-CANDIDATE）往返。
    #[test]
    fn stun_attr_005_zero_length_value_roundtrip() {
        let attr = RawAttribute {
            typ: ATTR_USE_CANDIDATE,
            length: 0,
            value: &[],
        };
        let mut out = [0u8; 4];
        let written = attr.encode(&mut out).expect("encode zero-length TLV");
        assert_eq!(written, 4);
        assert_eq!(out, [0x00, 0x25, 0x00, 0x00]);

        let (decoded, consumed) = RawAttribute::decode(&out).expect("decode zero-length TLV");
        assert_eq!(decoded.value, &[] as &[u8]);
        assert_eq!(consumed, 4);
    }

    // ATTR-TLV-006 — 输出缓冲不足 → OutputTooSmall 且不写任何字节。
    #[test]
    fn stun_attr_006_output_too_small_leaves_buffer_intact() {
        let attr = RawAttribute {
            typ: ATTR_PRIORITY,
            length: 4,
            value: &[0x01, 0x02, 0x03, 0x04],
        };
        let mut small = [0u8; 7];
        assert_eq!(attr.encode(&mut small), Err(WireError::OutputTooSmall));
        assert_eq!(small, [0u8; 7]);
    }

    // ATTR-TLV-007 — 值长超过 u16 → Overflow（严于上游 `as u16` 静默截断）。
    #[test]
    fn stun_attr_007_value_longer_than_u16_is_rejected() {
        static BIG: [u8; 65_536] = [0x5Au8; 65_536];
        let attr = RawAttribute {
            typ: ATTR_DATA,
            length: 0,
            value: &BIG,
        };
        let mut out = [0u8; 8];
        assert_eq!(attr.encode(&mut out), Err(WireError::Overflow));
    }

    // ---- ATTR-PAD ---------------------------------------------------------

    // ATTR-PAD-001 — nearest_padded_value_length 向量表。
    // 向量来源：上游 attributes_test.rs:44-65。
    #[test]
    fn stun_attr_008_nearest_padded_value_length_vectors() {
        let vectors = [
            (4, 4),
            (2, 4),
            (5, 8),
            (8, 8),
            (11, 12),
            (1, 4),
            (3, 4),
            (6, 8),
            (7, 8),
            (0, 0),
            (40, 40),
        ];
        for (input, expected) in vectors {
            let got = nearest_padded_value_length(input);
            assert_eq!(got, expected, "padd({input}) {got} != {expected}");
        }
    }

    // ---- ATTR-RANGE -------------------------------------------------------

    // ATTR-RANGE-001 — comprehension-required/optional 区间判定。
    // 向量来源：上游 attributes_test.rs:68-85。
    #[test]
    fn stun_attr_009_required_optional_ranges() {
        for a in [
            ATTR_PRIORITY,
            ATTR_ERROR_CODE,
            ATTR_USE_CANDIDATE,
            ATTR_EVEN_PORT,
            ATTR_REQUESTED_ADDRESS_FAMILY,
        ] {
            assert!(!a.optional() && a.required(), "{a} should be required");
        }
        for a in [ATTR_SOFTWARE, ATTR_ICE_CONTROLLED, ATTR_ORIGIN] {
            assert!(!a.required() && a.optional(), "{a} should be optional");
        }
    }

    // ---- ATTR-COMPAT ------------------------------------------------------

    // ATTR-COMPAT-001 — 0x8020 旧码解码时映射为 XOR-MAPPED-ADDRESS。
    // 向量来源：上游 attributes.rs:261-268（compat_attr_type）。
    #[test]
    fn stun_attr_010_legacy_xor_mapped_code_maps_on_decode() {
        assert_eq!(compat_attr_type(0x8020), ATTR_XORMAPPED_ADDRESS);
        assert_eq!(compat_attr_type(0x0020), ATTR_XORMAPPED_ADDRESS);
        assert_eq!(compat_attr_type(0x0001), ATTR_MAPPED_ADDRESS);
        assert_eq!(compat_attr_type(0x1234), AttrType(0x1234));

        // 经 TLV 解码路径同样生效。
        let wire = [0x80, 0x20, 0x00, 0x00];
        let (decoded, _) = RawAttribute::decode(&wire).expect("decode legacy xor-mapped");
        assert_eq!(decoded.typ, ATTR_XORMAPPED_ADDRESS);
    }

    // ---- ATTR-STR ---------------------------------------------------------

    // ATTR-STR-001 — AttrType stringer：已知名不以 0x 开头，未知码带 0x 前缀。
    // 向量来源：上游 message_test.rs:299-324。
    #[test]
    fn stun_attr_011_attr_type_stringer() {
        for a in [
            ATTR_MAPPED_ADDRESS,
            ATTR_USERNAME,
            ATTR_ERROR_CODE,
            ATTR_MESSAGE_INTEGRITY,
            ATTR_UNKNOWN_ATTRIBUTES,
            ATTR_REALM,
            ATTR_NONCE,
            ATTR_XORMAPPED_ADDRESS,
            ATTR_SOFTWARE,
            ATTR_ALTERNATE_SERVER,
            ATTR_FINGERPRINT,
        ] {
            assert!(!a.to_string().starts_with("0x"), "bad stringer {a}");
        }
        let non_standard = AttrType(0x512);
        assert!(
            non_standard.to_string().starts_with("0x512"),
            "bad prefix {non_standard}"
        );
    }
}

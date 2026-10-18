//! Address attributes: `MAPPED-ADDRESS` and the attributes that share its
//! encoding.
//!
//! `MAPPED-ADDRESS` ([RFC 5389] §15.1) carries a family, a port and an IP
//! address; the same value shape serves `ALTERNATE-SERVER` ([RFC 5389]
//! §15.11), `RESPONSE-ORIGIN` and `OTHER-ADDRESS` ([RFC 5780] §7), which
//! is why they are aliases of [`MappedAddress`] here.
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |x x x x x x x x|    Family     |           Port                |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           Address                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The address is [`rtx_core::IpAddr`], never `std::net`, per the workspace
//! address model (ARCHITECTURE §9). There is deliberately no `Display` for
//! these types — callers assert on the fields instead, keeping the crate
//! free of address-formatting policy.
//!
//! [RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389
//! [RFC 5780]: https://www.rfc-editor.org/rfc/rfc5780

use rtx_core::IpAddr;
use rtx_wire::WireError;

use crate::attributes::ATTRIBUTE_HEADER_SIZE;
use crate::message::MessageWriter;

/// Address family `0x01`: IPv4.
pub(crate) const FAMILY_IPV4: u16 = 0x01;
/// Address family `0x02`: IPv6.
pub(crate) const FAMILY_IPV6: u16 = 0x02;
/// Length of an IPv4 address on the wire.
pub(crate) const IPV4LEN: usize = 4;
/// Length of an IPv6 address on the wire.
pub(crate) const IPV6LEN: usize = 16;

/// `MAPPED-ADDRESS` ([RFC 5389] §15.1) and friends: a family, a port and
/// an IP address.
///
/// Used by servers for backwards compatibility with RFC 3489 clients, and
/// reused verbatim by `ALTERNATE-SERVER`, `RESPONSE-ORIGIN` and
/// `OTHER-ADDRESS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappedAddress {
    /// The IP address.
    pub ip: IpAddr,
    /// The port.
    pub port: u16,
}

impl Default for MappedAddress {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4([0; IPV4LEN]),
            port: 0,
        }
    }
}

impl MappedAddress {
    /// A mapped address of `ip` and `port`.
    #[must_use]
    pub const fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }

    /// Decodes an address attribute from its raw value.
    ///
    /// The value must be exactly `4 + 4` bytes for IPv4 or `4 + 16` for
    /// IPv6. Upstream instead truncates or zero-pads over-long and
    /// short values (`min(ip.len(), v[4..].len())`); this codec rejects
    /// them (see `docs/m1-3-test-vectors.md` difference 2), because a
    /// silently truncated address is a mis-routed packet.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the value is too short to
    /// hold family and port, the family is neither `0x01` nor `0x02`, or
    /// the length does not match the family exactly.
    pub fn from_value(value: &[u8]) -> Result<Self, WireError> {
        // Upstream rejects v.len() <= 4 here (ErrUnexpectedEof); the
        // semantic mapping is InvalidValue (test-vectors difference 4).
        if value.len() < ATTRIBUTE_HEADER_SIZE {
            return Err(WireError::InvalidValue);
        }
        let family = u16::from_be_bytes([value[0], value[1]]);
        let port = u16::from_be_bytes([value[2], value[3]]);
        let ip = match family {
            FAMILY_IPV4 => {
                if value.len() != ATTRIBUTE_HEADER_SIZE + IPV4LEN {
                    return Err(WireError::InvalidValue);
                }
                IpAddr::V4([value[4], value[5], value[6], value[7]])
            }
            FAMILY_IPV6 => {
                if value.len() != ATTRIBUTE_HEADER_SIZE + IPV6LEN {
                    return Err(WireError::InvalidValue);
                }
                let mut octets = [0u8; IPV6LEN];
                octets.copy_from_slice(&value[ATTRIBUTE_HEADER_SIZE..]);
                IpAddr::V6(octets)
            }
            _ => return Err(WireError::InvalidValue),
        };
        Ok(Self { ip, port })
    }

    /// Appends this address to `writer` as the `typ` attribute.
    ///
    /// `typ` is a parameter because the encoding is shared by
    /// `ALTERNATE-SERVER`, `RESPONSE-ORIGIN` and `OTHER-ADDRESS`.
    ///
    /// # Errors
    ///
    /// Propagates the errors of [`MessageWriter::push`].
    pub fn push_to(
        &self,
        typ: crate::attributes::AttrType,
        writer: &mut MessageWriter<'_>,
    ) -> Result<(), WireError> {
        let (family, ip) = match &self.ip {
            IpAddr::V4(v4) => (FAMILY_IPV4, v4 as &[u8]),
            IpAddr::V6(v6) => (FAMILY_IPV6, v6 as &[u8]),
        };
        let mut value = [0u8; ATTRIBUTE_HEADER_SIZE + IPV6LEN];
        value[0..2].copy_from_slice(&family.to_be_bytes());
        value[2..4].copy_from_slice(&self.port.to_be_bytes());
        value[ATTRIBUTE_HEADER_SIZE..ATTRIBUTE_HEADER_SIZE + ip.len()].copy_from_slice(ip);
        writer.push(typ, &value[..ATTRIBUTE_HEADER_SIZE + ip.len()])
    }

    /// Encoded length of the attribute value: `4 + 4` or `4 + 16`.
    #[must_use]
    pub const fn value_len(&self) -> usize {
        match self.ip {
            IpAddr::V4(_) => ATTRIBUTE_HEADER_SIZE + IPV4LEN,
            IpAddr::V6(_) => ATTRIBUTE_HEADER_SIZE + IPV6LEN,
        }
    }
}

/// `ALTERNATE-SERVER` ([RFC 5389] §15.11): same encoding as
/// [`MappedAddress`].
pub type AlternateServer = MappedAddress;

/// `RESPONSE-ORIGIN` ([RFC 5780] §7.3): same encoding as [`MappedAddress`].
pub type ResponseOrigin = MappedAddress;

/// `OTHER-ADDRESS` ([RFC 5780] §7.4): same encoding as [`MappedAddress`].
pub type OtherAddress = MappedAddress;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::attributes::{
        ATTR_ALTERNATE_SERVER, ATTR_MAPPED_ADDRESS, ATTR_OTHER_ADDRESS, ATTR_REALM,
    };
    use crate::message::{BINDING_REQUEST, Message, TransactionId};
    use rtx_wire::Decode;

    // 构造一个只带一个属性的消息，返回编码缓冲与已写长度。
    fn one_attr_message(typ: crate::attributes::AttrType, value: &[u8]) -> ([u8; 64], usize) {
        let mut buf = [0u8; 64];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0x11; 12]))
            .expect("64-byte buffer");
        writer.push(typ, value).expect("push attribute");
        let written = writer.written();
        (buf, written)
    }

    // ---- ADDR-MAPPED ------------------------------------------------------

    // ADDR-MAPPED-001 — IPv4 MAPPED-ADDRESS 往返（含字段断言）。
    // 向量来源：上游 addr_test.rs:5-64（test_mapped_address；断言字段而非
    // 字符串，见 test-vectors 差异 #10）。
    #[test]
    fn stun_addr_001_mapped_address_v4_roundtrip() {
        let addr = MappedAddress::new(IpAddr::V4([122, 12, 34, 5]), 5412);
        let mut buf = [0u8; 32];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0x22; 12]))
            .expect("32-byte buffer");
        addr.push_to(ATTR_MAPPED_ADDRESS, &mut writer)
            .expect("push mapped address");
        let written = writer.written();
        // 值 = 00 01 | 15 24 | 7A 0C 22 05
        assert_eq!(
            &buf[24..written],
            &[0x00, 0x01, 0x15, 0x24, 0x7A, 0x0C, 0x22, 0x05]
        );

        let (msg, consumed) = Message::decode(&buf[..written]).expect("decode");
        assert_eq!(consumed, written);
        let attr = msg.get(ATTR_MAPPED_ADDRESS).expect("mapped-address");
        let got = MappedAddress::from_value(attr.value).expect("decode address");
        assert_eq!(got, addr);
        assert_eq!(got.ip, IpAddr::V4([122, 12, 34, 5]));
        assert_eq!(got.port, 5412);
    }

    // ADDR-MAPPED-002 — IPv6 MAPPED-ADDRESS 往返（"::" 向量）。
    // 向量来源：上游 addr_test.rs:66-103（test_mapped_address_v6）。
    #[test]
    fn stun_addr_002_mapped_address_v6_roundtrip() {
        let addr = MappedAddress::new(IpAddr::V6([0; 16]), 5412);
        let mut buf = [0u8; 48];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0x33; 12]))
            .expect("48-byte buffer");
        addr.push_to(ATTR_MAPPED_ADDRESS, &mut writer)
            .expect("push mapped address");
        let written = writer.written();
        // 值 = 4（family+port）+ 16 地址 = 20 字节，无需 padding → TLV 24。
        assert_eq!(written, 20 + 4 + 20);

        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        let got = MappedAddress::from_value(msg.get(ATTR_MAPPED_ADDRESS).expect("attr").value)
            .expect("decode address");
        assert_eq!(got, addr);
        assert_eq!(got.ip, IpAddr::V6([0; 16]));
    }

    // ADDR-MAPPED-003 — 坏 family → InvalidValue。
    // 向量来源：上游 addr_test.rs:37-42（"Bad family" 块改 family=32；
    // 上游因 attributes.get 返回副本而实际未生效，此处改为显式构造坏值）。
    #[test]
    fn stun_addr_003_bad_family_rejected() {
        let value = [32, 0, 0x15, 0x24, 0x7A, 0x0C, 0x22, 0x05];
        assert_eq!(
            MappedAddress::from_value(&value),
            Err(WireError::InvalidValue)
        );
        // family=0（保留值）同样拒绝。
        let zero_family = [0, 0, 0x15, 0x24, 0x7A, 0x0C, 0x22, 0x05];
        assert_eq!(
            MappedAddress::from_value(&zero_family),
            Err(WireError::InvalidValue)
        );
    }

    // ADDR-MAPPED-004 — 长度不符 → InvalidValue（严于上游的截断容忍）。
    // 向量来源：上游 addr_test.rs:43-59（"Bad length" [1,2,3]）+
    // test-vectors 差异 #2（值长必须恰为 family 尺寸）。
    #[test]
    fn stun_addr_004_bad_length_rejected() {
        // 3 字节：连 family + port 都放不下。
        assert_eq!(
            MappedAddress::from_value(&[1, 2, 3]),
            Err(WireError::InvalidValue)
        );
        // 4 字节：有 family + port 但无地址（上游亦拒绝）。
        assert_eq!(
            MappedAddress::from_value(&[0, 1, 0, 0]),
            Err(WireError::InvalidValue)
        );
        // IPv4 family 但 9 字节（多 1 字节）：上游静默截断，本码拒绝。
        let long = [0, 1, 0x15, 0x24, 1, 2, 3, 4, 5];
        assert_eq!(
            MappedAddress::from_value(&long),
            Err(WireError::InvalidValue)
        );
        // IPv6 family 但 8 字节（短 12 字节）：上游补零，本码拒绝。
        let short = [0, 2, 0x15, 0x24, 1, 2, 3, 4];
        assert_eq!(
            MappedAddress::from_value(&short),
            Err(WireError::InvalidValue)
        );
    }

    // ADDR-MAPPED-005 — 属性缺失时 get 返回 None（对应上游
    // ErrAttributeNotFound 的 None 语义）。
    #[test]
    fn stun_addr_005_attribute_absent_is_none() {
        let (buf, written) = one_attr_message(ATTR_REALM, b"x");
        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        assert!(msg.get(ATTR_MAPPED_ADDRESS).is_none());
    }

    // ---- ADDR-ALIAS -------------------------------------------------------

    // ADDR-ALIAS-001 — ALTERNATE-SERVER / OTHER-ADDRESS 别名共用同一编码。
    // 向量来源：上游 addr_test.rs:105-143（test_alternate_server）与
    // :145-183（test_other_address）。
    #[test]
    fn stun_addr_006_aliases_share_encoding() {
        let addr = AlternateServer::new(IpAddr::V4([122, 12, 34, 5]), 5412);
        for typ in [ATTR_ALTERNATE_SERVER, ATTR_OTHER_ADDRESS] {
            let mut buf = [0u8; 32];
            let mut writer =
                MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0x44; 12]))
                    .expect("32-byte buffer");
            addr.push_to(typ, &mut writer).expect("push alias");
            let written = writer.written();
            let (msg, _) = Message::decode(&buf[..written]).expect("decode");
            let got =
                OtherAddress::from_value(msg.get(typ).expect("attr").value).expect("decode alias");
            assert_eq!(got, addr);
        }
        // ResponseOrigin 别名可构造（同一类型）。
        let origin = ResponseOrigin::new(IpAddr::V4([1, 2, 3, 4]), 9);
        assert_eq!(origin.port, 9);
    }

    // ADDR-MAPPED-006 — value_len 与编码长度一致。
    #[test]
    fn stun_addr_007_value_len_matches_encoding() {
        let v4 = MappedAddress::new(IpAddr::V4([1, 2, 3, 4]), 0);
        let v6 = MappedAddress::new(IpAddr::V6([0; 16]), 0);
        assert_eq!(v4.value_len(), 8);
        assert_eq!(v6.value_len(), 20);

        let mut buf = [0u8; 32];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0x55; 12]))
            .expect("32-byte buffer");
        v4.push_to(ATTR_MAPPED_ADDRESS, &mut writer)
            .expect("push v4");
        assert_eq!(writer.length(), 4 + 8);
        let mut big = [0u8; 48];
        let mut writer = MessageWriter::new(&mut big, BINDING_REQUEST, TransactionId([0x66; 12]))
            .expect("48-byte buffer");
        v6.push_to(ATTR_MAPPED_ADDRESS, &mut writer)
            .expect("push v6");
        assert_eq!(writer.length(), 4 + 20);
    }
}

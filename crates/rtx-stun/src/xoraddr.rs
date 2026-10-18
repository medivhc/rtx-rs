//! The `XOR-MAPPED-ADDRESS` attribute and the XOR helpers behind it.
//!
//! `XOR-MAPPED-ADDRESS` ([RFC 5389] §15.2) obfuscates the port and address
//! with the magic cookie and the message's transaction id, so that the
//! attribute looks like random bytes to middleboxes that inspect STUN
//! payloads. The same encoding serves TURN's `XOR-PEER-ADDRESS` and
//! `XOR-RELAYED-ADDRESS` ([RFC 5766] §14.5), which is why [`XorMappedAddress::push_to`]
//! takes the attribute type as a parameter.
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |x x x x x x x x|    Family     |         X-Port                |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                X-Address (Variable)                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The mask is the 16-byte concatenation `MAGIC_COOKIE || transaction_id`;
//! the port is `XORed` with the cookie's high 16 bits only.
//!
//! [RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389
//! [RFC 5766]: https://www.rfc-editor.org/rfc/rfc5766

use rtx_core::IpAddr;
use rtx_wire::WireError;

use crate::addr::{FAMILY_IPV4, FAMILY_IPV6, IPV4LEN, IPV6LEN};
use crate::attributes::{ATTRIBUTE_HEADER_SIZE, AttrType};
use crate::message::{MAGIC_COOKIE, MESSAGE_HEADER_SIZE, MessageWriter, TransactionId};

/// High 16 bits of [`MAGIC_COOKIE`] (`0x2112`), the mask for the port.
///
/// Kept as a literal rather than `(MAGIC_COOKIE >> 16) as u16` so the
/// narrowing never needs a cast.
const MAGIC_COOKIE_HIGH: u16 = 0x2112;

/// XORs `a` and `b` into `dst`, processing `min` of the three lengths.
///
/// Returns the number of bytes written. Ported from upstream's
/// `safe_xor_bytes` (the word-at-a-time fast path is x86-specific assembly
/// upstream and out of scope here).
pub(crate) fn xor_bytes(dst: &mut [u8], a: &[u8], b: &[u8]) -> usize {
    let mut n = a.len();
    if b.len() < n {
        n = b.len();
    }
    if dst.len() < n {
        n = dst.len();
    }
    // `zip` stops at the shortest operand, i.e. exactly `n` items.
    for (slot, (x, y)) in dst.iter_mut().zip(a.iter().zip(b.iter())) {
        *slot = x ^ y;
    }
    n
}

/// Builds the 16-byte XOR mask: magic cookie followed by the transaction id.
fn xor_mask(transaction_id: TransactionId) -> [u8; MESSAGE_HEADER_SIZE - 4] {
    let mut mask = [0u8; MESSAGE_HEADER_SIZE - 4];
    mask[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(&transaction_id.0);
    mask
}

/// `XOR-MAPPED-ADDRESS` ([RFC 5389] §15.2): a family, an XOR-masked port
/// and an XOR-masked address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XorMappedAddress {
    /// The IP address, unmasked.
    pub ip: IpAddr,
    /// The port, unmasked.
    pub port: u16,
}

impl Default for XorMappedAddress {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4([0; IPV4LEN]),
            port: 0,
        }
    }
}

impl XorMappedAddress {
    /// An XOR-mapped address of `ip` and `port`.
    #[must_use]
    pub const fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }

    /// Decodes an XOR-mapped address from its raw value, unmasking with
    /// `transaction_id` (the id of the message the attribute came from).
    ///
    /// The value must be exactly `4 + 4` bytes for IPv4 or `4 + 16` for
    /// IPv6. Upstream zero-pads short values and reports a size-overflow
    /// error for long ones; this codec rejects both (see
    /// `docs/m1-3-test-vectors.md` differences 3 and 4).
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the value is too short to
    /// hold family and port, the family is neither `0x01` nor `0x02`, or
    /// the length does not match the family exactly.
    pub fn from_value(value: &[u8], transaction_id: TransactionId) -> Result<Self, WireError> {
        if value.len() < ATTRIBUTE_HEADER_SIZE {
            return Err(WireError::InvalidValue);
        }
        let family = u16::from_be_bytes([value[0], value[1]]);
        let port = u16::from_be_bytes([value[2], value[3]]) ^ MAGIC_COOKIE_HIGH;
        let mask = xor_mask(transaction_id);
        let ip = match family {
            FAMILY_IPV4 => {
                if value.len() != ATTRIBUTE_HEADER_SIZE + IPV4LEN {
                    return Err(WireError::InvalidValue);
                }
                let mut octets = [0u8; IPV4LEN];
                xor_bytes(&mut octets, &value[ATTRIBUTE_HEADER_SIZE..], &mask);
                IpAddr::V4(octets)
            }
            FAMILY_IPV6 => {
                if value.len() != ATTRIBUTE_HEADER_SIZE + IPV6LEN {
                    return Err(WireError::InvalidValue);
                }
                let mut octets = [0u8; IPV6LEN];
                xor_bytes(&mut octets, &value[ATTRIBUTE_HEADER_SIZE..], &mask);
                IpAddr::V6(octets)
            }
            _ => return Err(WireError::InvalidValue),
        };
        Ok(Self { ip, port })
    }

    /// Appends this address to `writer` as the `typ` attribute, masked with
    /// the writer's transaction id.
    ///
    /// `typ` is a parameter because the encoding is shared by
    /// `XOR-PEER-ADDRESS` and `XOR-RELAYED-ADDRESS`.
    ///
    /// # Errors
    ///
    /// Propagates the errors of [`MessageWriter::push`].
    pub fn push_to(&self, typ: AttrType, writer: &mut MessageWriter<'_>) -> Result<(), WireError> {
        let (family, ip) = match &self.ip {
            IpAddr::V4(v4) => (FAMILY_IPV4, v4 as &[u8]),
            IpAddr::V6(v6) => (FAMILY_IPV6, v6 as &[u8]),
        };
        let mut value = [0u8; ATTRIBUTE_HEADER_SIZE + IPV6LEN];
        value[0..2].copy_from_slice(&family.to_be_bytes());
        let port = self.port ^ MAGIC_COOKIE_HIGH;
        value[2..4].copy_from_slice(&port.to_be_bytes());
        let mask = xor_mask(writer.transaction_id());
        xor_bytes(
            &mut value[ATTRIBUTE_HEADER_SIZE..ATTRIBUTE_HEADER_SIZE + ip.len()],
            ip,
            &mask,
        );
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

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::attributes::ATTR_XORMAPPED_ADDRESS;
    use crate::message::{BINDING_REQUEST, Message};
    use rtx_wire::Decode;

    // 上游 xoraddr_test.rs 使用的 base64 事务 ID "jxhBARZwX+rsC6er" 的解码值。
    const TX_BASE64_VECTOR: TransactionId =
        TransactionId([143, 24, 65, 1, 22, 112, 95, 234, 236, 11, 167, 171]);

    // ---- XOR-BYTES --------------------------------------------------------

    // XOR-BYTES-001 — xor_bytes 往返：xor 两次还原。
    // 向量来源：上游 xoraddr_test.rs:7-21（test_xor_safe）。
    #[test]
    fn stun_xor_001_xor_bytes_roundtrip() {
        let mut dst = [0u8; 8];
        let a = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let b = [8u8, 7, 7, 6, 6, 3, 4, 1];
        let n = xor_bytes(&mut dst, &a, &b);
        assert_eq!(n, 8);
        let c = dst;
        xor_bytes(&mut dst, &c, &a);
        assert_eq!(dst, b);
    }

    // XOR-BYTES-002 — b 短于 a/dst 时按最小长度处理。
    // 向量来源：上游 xoraddr_test.rs:22-35（test_xor_safe_bsmaller）。
    #[test]
    fn stun_xor_002_xor_bytes_short_operand() {
        let mut dst = [0u8; 5];
        let a = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let b = [8u8, 7, 7, 6, 6];
        let n = xor_bytes(&mut dst, &a, &b);
        assert_eq!(n, 5);
        let c = dst;
        xor_bytes(&mut dst, &c, &a);
        assert_eq!(dst, b);
    }

    // ---- XOR-GET ----------------------------------------------------------

    // XOR-GET-001 — 上游 base64 事务 ID + 属性值向量 → 地址与端口。
    // 向量来源：上游 xoraddr_test.rs:37-103（test_xormapped_address_get_from）。
    #[test]
    fn stun_xor_003_get_from_base64_tx_vector() {
        let value = [0x00, 0x01, 0x9c, 0xd5, 0xf4, 0x9f, 0x38, 0xae];
        let got = XorMappedAddress::from_value(&value, TX_BASE64_VECTOR).expect("decode xor addr");
        assert_eq!(got.ip, IpAddr::V4([213, 141, 156, 236]));
        assert_eq!(got.port, 48583);
    }

    // XOR-GET-002 — 值长 4（只有 family + port）→ InvalidValue。
    // 向量来源：上游 xoraddr_test.rs:57-78（"UnexpectedEOF" 块）。
    #[test]
    fn stun_xor_004_get_from_short_value_rejected() {
        assert_eq!(
            XorMappedAddress::from_value(&[0, 1, 3, 4], TX_BASE64_VECTOR),
            Err(WireError::InvalidValue)
        );
    }

    // XOR-GET-003 — IPv4 family 但值长 17 → InvalidValue（上游报 size
    // overflow，差异 #3/#4 统一映射）。
    // 向量来源：上游 xoraddr_test.rs:79-100（"AttrOverflowErr" 块）。
    #[test]
    fn stun_xor_005_get_from_overlong_value_rejected() {
        let value = [0, 1, 3, 4, 5, 6, 7, 8, 9, 1, 1, 1, 1, 1, 2, 3, 4];
        assert_eq!(
            XorMappedAddress::from_value(&value, TX_BASE64_VECTOR),
            Err(WireError::InvalidValue)
        );
    }

    // ---- XOR-ADD ----------------------------------------------------------

    // XOR-ADD-001 — IPv4 往返：编码值逐字节匹配上游向量，读回字段一致。
    // 向量来源：上游 xoraddr_test.rs:135-165（test_xormapped_address_add_to）。
    #[test]
    fn stun_xor_006_add_to_roundtrip_v4() {
        let addr = XorMappedAddress::new(IpAddr::V4([213, 141, 156, 236]), 21254);
        let mut buf = [0u8; 32];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TX_BASE64_VECTOR)
            .expect("32-byte buffer");
        addr.push_to(ATTR_XORMAPPED_ADDRESS, &mut writer)
            .expect("push xor mapped");
        let written = writer.written();
        // 掩码值：[0x00,0x01, port^0x2112, ip^mask]。
        assert_eq!(
            &buf[24..written],
            &[0x00, 0x01, 0x72, 0x14, 0xf4, 0x9f, 0x38, 0xae]
        );

        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        let got = XorMappedAddress::from_value(
            msg.get(ATTR_XORMAPPED_ADDRESS).expect("attr").value,
            msg.transaction_id,
        )
        .expect("decode xor addr");
        assert_eq!(got, addr);
    }

    // XOR-ADD-002 — IPv6 往返。
    // 向量来源：上游 xoraddr_test.rs:167-203（test_xormapped_address_add_to_ipv6）。
    #[test]
    fn stun_xor_007_add_to_roundtrip_v6() {
        let expected_ip = IpAddr::V6([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xdc, 0x2b, 0x44, 0xff, 0xfe, 0x20, 0x60, 0x09,
        ]);
        let addr = XorMappedAddress::new(expected_ip, 21254);
        let mut buf = [0u8; 48];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TX_BASE64_VECTOR)
            .expect("48-byte buffer");
        addr.push_to(ATTR_XORMAPPED_ADDRESS, &mut writer)
            .expect("push xor mapped");
        let written = writer.written();
        assert_eq!(written, 20 + 4 + 20);

        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        let got = XorMappedAddress::from_value(
            msg.get(ATTR_XORMAPPED_ADDRESS).expect("attr").value,
            msg.transaction_id,
        )
        .expect("decode xor addr");
        assert_eq!(got, addr);
        assert_eq!(got.ip, expected_ip);
        assert_eq!(got.port, 21254);
    }

    // XOR-ADD-003 — 篡改 family 字节后解码失败。
    // 向量来源：上游 xoraddr_test.rs:105-133（test_xormapped_address_get_from_invalid，
    // 上游改 raw[20+4+1] = 0x21）。
    #[test]
    fn stun_xor_008_tampered_family_rejected() {
        let addr = XorMappedAddress::new(IpAddr::V4([213, 141, 156, 236]), 21254);
        let mut buf = [0u8; 32];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TX_BASE64_VECTOR)
            .expect("32-byte buffer");
        addr.push_to(ATTR_XORMAPPED_ADDRESS, &mut writer)
            .expect("push xor mapped");
        let written = writer.written();

        // 与上游同一位置：属性值第 2 字节（family 低字节）。
        buf[MESSAGE_HEADER_SIZE + 4 + 1] = 0x21;
        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        assert_eq!(
            XorMappedAddress::from_value(
                msg.get(ATTR_XORMAPPED_ADDRESS).expect("attr").value,
                msg.transaction_id,
            ),
            Err(WireError::InvalidValue)
        );
    }

    // XOR-ADD-004 — value_len 与 family 对应。
    #[test]
    fn stun_xor_009_value_len_matches_family() {
        let v4 = XorMappedAddress::new(IpAddr::V4([1, 2, 3, 4]), 0);
        let v6 = XorMappedAddress::new(IpAddr::V6([0; 16]), 0);
        assert_eq!(v4.value_len(), 8);
        assert_eq!(v6.value_len(), 20);
    }
}

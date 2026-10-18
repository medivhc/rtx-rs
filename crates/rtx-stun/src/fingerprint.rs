//! The `FINGERPRINT` attribute ([RFC 5389] §15.5).
//!
//! A `FINGERPRINT` carries the CRC-32 of the STUN message up to (but
//! excluding) the attribute itself, `XORed` with `0x5354554e` (ASCII
//! `STUN`), so a STUN message is distinguishable from other UDP payloads
//! sharing its 5-tuple. Per [RFC 5389] §7 it is the last attribute in the
//! message and the header length field used in the CRC covers it.
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       CRC-32 XOR 0x5354554e                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The checksum is CRC-32/ISO-HDLC (the `zlib` variant): reflected
//! polynomial `0xEDB88320`, init `0xFFFFFFFF`, final XOR `0xFFFFFFFF`.
//! The lookup table is built at compile time, so there is no runtime
//! setup and the crate stays `no_std`.
//!
//! [RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389

use rtx_wire::WireError;

use crate::attributes::{ATTR_FINGERPRINT, ATTRIBUTE_HEADER_SIZE, find_attribute};
use crate::message::{Message, MessageWriter, header_bytes};

/// The value the CRC-32 is `XORed` with, `0x5354554e` — ASCII `STUN`.
pub const FINGERPRINT_XOR_VALUE: u32 = 0x5354_554e;
/// The attribute's value length in bytes.
pub const FINGERPRINT_SIZE: usize = 4;

/// The CRC-32/ISO-HDLC lookup table, built once at compile time.
const CRC_TABLE: [u32; 256] = build_crc_table();

/// Builds the reflected CRC-32 table for polynomial `0xEDB88320`.
const fn build_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0u32;
    while index < 256 {
        let mut crc = index;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index as usize] = crc;
        index += 1;
    }
    table
}

/// Continues a CRC-32/ISO-HDLC over `b`, starting from the intermediate
/// state `crc` (pass `0xFFFF_FFFF` to start a new checksum).
fn crc32_update(mut crc: u32, b: &[u8]) -> u32 {
    for &byte in b {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = CRC_TABLE[index] ^ (crc >> 8);
    }
    crc
}

/// Computes the `FINGERPRINT` value over `b`: CRC-32 `XORed` with
/// [`FINGERPRINT_XOR_VALUE`].
///
/// The input is the message bytes up to (but excluding) the `FINGERPRINT`
/// attribute, with the header length field covering the attribute — see
/// [`push_fingerprint`], which arranges exactly that.
#[must_use]
pub fn fingerprint_value(b: &[u8]) -> u32 {
    crc32_update(0xFFFF_FFFF, b) ^ 0xFFFF_FFFF ^ FINGERPRINT_XOR_VALUE
}

/// Appends the `FINGERPRINT` attribute to `writer`.
///
/// Must be called last, after every attribute the checksum covers. The
/// value is computed over the message with the header length field
/// temporarily increased by the attribute's own TLV size, as [RFC 5389]
/// §15.5 requires.
///
/// # Errors
///
/// Returns [`WireError::Overflow`] when the adjusted length does not fit
/// the 16-bit length field, and propagates the errors of
/// [`MessageWriter::push`] (notably [`WireError::OutputTooSmall`]).
pub fn push_fingerprint(writer: &mut MessageWriter<'_>) -> Result<(), WireError> {
    let value =
        writer.with_trailer_length(ATTRIBUTE_HEADER_SIZE + FINGERPRINT_SIZE, fingerprint_value)?;
    writer.push(ATTR_FINGERPRINT, &value.to_be_bytes())
}

/// Checks the `FINGERPRINT` attribute of a decoded message.
///
/// The attribute is located by walking the region (not by assuming it is
/// last), and the checksum covers the header — with the decoded length
/// field — plus every attribute preceding it.
///
/// # Errors
///
/// Returns [`WireError::InvalidValue`] when the attribute is missing, its
/// value is not exactly [`FINGERPRINT_SIZE`] bytes, or the checksum does
/// not match (upstream: `ErrAttributeNotFound`, `ErrAttrSizeInvalid`,
/// `ErrCRCMismatch`).
pub fn check(msg: &Message<'_>) -> Result<(), WireError> {
    let (offset, value) =
        find_attribute(msg.attribute_region, ATTR_FINGERPRINT).ok_or(WireError::InvalidValue)?;
    if value.len() != FINGERPRINT_SIZE {
        return Err(WireError::InvalidValue);
    }
    let got = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    // The CRC input uses the decoded (final) length field, which already
    // accounts for the FINGERPRINT TLV itself.
    let header = header_bytes(msg.typ, msg.length, msg.transaction_id);
    let crc = crc32_update(0xFFFF_FFFF, &header);
    let crc = crc32_update(crc, &msg.attribute_region[..offset]);
    let expected = crc ^ 0xFFFF_FFFF ^ FINGERPRINT_XOR_VALUE;
    if got == expected {
        Ok(())
    } else {
        Err(WireError::InvalidValue)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::attributes::ATTR_SOFTWARE;
    use crate::message::{BINDING_REQUEST, MessageType, TransactionId};
    use crate::textattrs::Software;
    use rtx_wire::{Decode, Encode};

    /// A zero transaction id, matching upstream's `Message::new()` default
    /// so the packet-level vectors reproduce byte for byte.
    const ZERO_TX: TransactionId = TransactionId([0; 12]);

    // ---- FP-CRC -----------------------------------------------------------

    // FP-CRC-001 — CRC-32/ISO-HDLC 参数自测：经典 check 值 "123456789"。
    // 向量来源：CRC-32/ISO-HDLC 目录项（poly 0xEDB88320, init/xorout
    // 0xFFFFFFFF）；与上游 `crc` crate 的 CRC_32_ISO_HDLC 同参数。
    #[test]
    fn stun_fp_001_crc32_check_value() {
        let crc = crc32_update(0xFFFF_FFFF, b"123456789") ^ 0xFFFF_FFFF;
        assert_eq!(crc, 0xCBF4_3926);
    }

    // FP-CRC-002 — 增量与单段等价（check 路径用两段输入）。
    #[test]
    fn stun_fp_002_crc32_incremental_matches_single() {
        let whole = b"the quick brown fox";
        let (head, tail) = whole.split_at(9);
        let split = crc32_update(crc32_update(0xFFFF_FFFF, head), tail);
        assert_eq!(split, crc32_update(0xFFFF_FFFF, whole));
    }

    // ---- FP-ADD -----------------------------------------------------------

    // FP-ADD-001 — 整包字节向量：SOFTWARE "software" + FINGERPRINT。
    // 向量来源：上游 fingerprint_test.rs:7-25
    // （fingerprint_uses_crc_32_iso_hdlc）。上游 Message::new() 默认零
    // type 与零 transaction id，这里用 MessageType::default() 等价复刻。
    #[test]
    fn stun_fp_003_full_packet_vector() {
        let mut buf = [0u8; 64];
        let mut writer =
            MessageWriter::new(&mut buf, MessageType::default(), ZERO_TX).expect("64-byte buffer");
        Software::new(ATTR_SOFTWARE, "software")
            .push_to(&mut writer)
            .expect("push software");
        push_fingerprint(&mut writer).expect("push fingerprint");
        let written = writer.written();
        assert_eq!(written, 20 + 12 + 8);

        assert_eq!(
            &buf[0..written - 8],
            b"\x00\x00\x00\x14\x21\x12\xA4\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x22\x00\x08\x73\x6F\x66\x74\x77\x61\x72\x65"
        );
        assert_eq!(&buf[written - 4..written], [0xe4, 0x4c, 0x33, 0xd9]);
    }

    // FP-ADD-002 — BINDING_REQUEST + 非零事务 ID 的往返：编码、解码、
    // check 全通过，且值随消息内容变化。
    #[test]
    fn stun_fp_004_roundtrip_binding_request() {
        let mut buf = [0u8; 64];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0x5a; 12]))
            .expect("64-byte buffer");
        Software::new(ATTR_SOFTWARE, "stun lib")
            .push_to(&mut writer)
            .expect("push software");
        push_fingerprint(&mut writer).expect("push fingerprint");
        let written = writer.written();

        let (msg, consumed) = Message::decode(&buf[..written]).expect("decode");
        assert_eq!(consumed, written);
        check(&msg).expect("fingerprint checks out");

        // 不同内容 → 不同值。
        let mut other = [0u8; 64];
        let mut writer = MessageWriter::new(&mut other, BINDING_REQUEST, TransactionId([0x5a; 12]))
            .expect("64-byte buffer");
        Software::new(ATTR_SOFTWARE, "stun lib!")
            .push_to(&mut writer)
            .expect("push software");
        push_fingerprint(&mut writer).expect("push fingerprint");
        assert_ne!(other[written - 4..written], buf[written - 4..written]);
    }

    // ---- FP-CHECK ---------------------------------------------------------

    // FP-CHECK-001 — 篡改属性值一个字节 → check 失败。
    // 向量来源：上游 fingerprint_test.rs:27-42（test_fingerprint_check
    // 的失配路径，上游改 raw[3]，此处改属性内容——改长度字段会让
    // Message::decode 直接失败，见 stun_fp_006）。
    #[test]
    fn stun_fp_005_tampered_attribute_rejected() {
        let mut buf = [0u8; 64];
        let mut writer =
            MessageWriter::new(&mut buf, MessageType::default(), ZERO_TX).expect("64-byte buffer");
        Software::new(ATTR_SOFTWARE, "software")
            .push_to(&mut writer)
            .expect("push software");
        push_fingerprint(&mut writer).expect("push fingerprint");
        let written = writer.written();
        check(&Message::decode(&buf[..written]).expect("decode").0).expect("checks out");

        buf[24 + 4 + 1] ^= 0xff; // SOFTWARE 值第二个字节
        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        assert_eq!(check(&msg), Err(WireError::InvalidValue));
    }

    // FP-CHECK-002 — 缺失 FINGERPRINT → 失败（上游
    // test_fingerprint_check_bad 第一半）。
    #[test]
    fn stun_fp_006_absent_attribute_rejected() {
        let mut buf = [0u8; 64];
        let mut writer =
            MessageWriter::new(&mut buf, MessageType::default(), ZERO_TX).expect("64-byte buffer");
        Software::new(ATTR_SOFTWARE, "software")
            .push_to(&mut writer)
            .expect("push software");
        let written = writer.written();
        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        assert_eq!(check(&msg), Err(WireError::InvalidValue));
    }

    // FP-CHECK-003 — 坏长度（3 字节值）→ 失败（上游
    // test_fingerprint_check_bad 第二半，手写 TLV）。
    #[test]
    fn stun_fp_007_bad_length_rejected() {
        let mut buf = [0u8; 64];
        let mut writer =
            MessageWriter::new(&mut buf, MessageType::default(), ZERO_TX).expect("64-byte buffer");
        Software::new(ATTR_SOFTWARE, "software")
            .push_to(&mut writer)
            .expect("push software");
        // FINGERPRINT TLV，值长 3 + 1 字节 padding。
        writer
            .push(ATTR_FINGERPRINT, &[1, 2, 3])
            .expect("push bad fingerprint");
        let written = writer.written();
        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        assert_eq!(check(&msg), Err(WireError::InvalidValue));
    }

    // FP-CHECK-004 — 头部 length 字段与属性区不符（模拟上游 raw[3] += 1
    // 的手工构造场景）→ CRC 输入变化 → 失败。
    #[test]
    fn stun_fp_008_length_field_tamper_rejected() {
        let mut buf = [0u8; 64];
        let mut writer =
            MessageWriter::new(&mut buf, MessageType::default(), ZERO_TX).expect("64-byte buffer");
        Software::new(ATTR_SOFTWARE, "software")
            .push_to(&mut writer)
            .expect("push software");
        push_fingerprint(&mut writer).expect("push fingerprint");
        let written = writer.written();

        // 手工把 Message 的 length 字段 +1（保持 region 不变）。
        let (decoded, _) = Message::decode(&buf[..written]).expect("decode");
        let tampered = Message {
            length: decoded.length + 1,
            ..decoded
        };
        assert_eq!(check(&tampered), Err(WireError::InvalidValue));
    }

    // FP-CHECK-005 — 重编码往返保持 check 通过（Message::encode 逐字）。
    #[test]
    fn stun_fp_009_reencode_roundtrip() {
        let mut buf = [0u8; 64];
        let mut writer =
            MessageWriter::new(&mut buf, MessageType::default(), ZERO_TX).expect("64-byte buffer");
        Software::new(ATTR_SOFTWARE, "software")
            .push_to(&mut writer)
            .expect("push software");
        push_fingerprint(&mut writer).expect("push fingerprint");
        let written = writer.written();
        let (msg, _) = Message::decode(&buf[..written]).expect("decode");

        let mut out = [0u8; 64];
        let n = msg.encode(&mut out).expect("encode");
        assert_eq!(n, written);
        assert_eq!(&out[..n], &buf[..written]);
        let (msg2, _) = Message::decode(&out[..n]).expect("decode");
        check(&msg2).expect("checks out");
    }
}

//! The `MESSAGE-INTEGRITY` attribute ([RFC 5389] §15.4).
//!
//! `MESSAGE-INTEGRITY` carries an HMAC-SHA1 over the STUN message —
//! header and every attribute preceding the integrity attribute, with the
//! header length field adjusted to account for the integrity TLV itself.
//! It authenticates the message without encrypting it, and per [RFC 5389]
//! §15.4 it must appear *after* the attributes it covers and *before*
//! `FINGERPRINT`, which is always last.
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       HMAC-SHA1 (20 bytes)                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Keying and providers
//!
//! The MAC is injected as a [`MacFn`] rather than implemented here: this
//! crate is `no_std` and the workspace crypto provider lands in M2 (see
//! `docs/m1-3-test-vectors.md` difference 7). Only raw and short-term
//! keys are supported in M1-3 — long-term keys need MD5
//! (`MD5(username:realm:password)`), which `rtx-crypto` will provide.
//!
//! With a real HMAC-SHA1 provider the framing below is the RFC 5389
//! construction verbatim; the bundled tests use a deterministic mock
//! (an XOR fold) to pin the framing semantics.
//!
//! [RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389

use rtx_wire::WireError;

use crate::attributes::{
    ATTR_FINGERPRINT, ATTR_MESSAGE_INTEGRITY, ATTRIBUTE_HEADER_SIZE, find_attribute,
    nearest_padded_value_length,
};
use crate::message::{Message, MessageWriter, header_bytes};

/// The `MESSAGE-INTEGRITY` value length: HMAC-SHA1 output, 20 bytes.
pub const MESSAGE_INTEGRITY_SIZE: usize = 20;

/// A keyed MAC function.
///
/// Signs `input` (the message bytes, header first) into `output` using
/// `key`. `output.len()` is the tag length the caller expects — 20 for
/// HMAC-SHA1. An implementation that cannot produce that length fills
/// what it can; [`MessageIntegrity::check`] rejects tags of the wrong
/// length before comparing.
///
/// The signature is a plain `fn` pointer so callers can inject a provider
/// without allocation or `dyn` dispatch; the crate stays `no_std`.
pub type MacFn = fn(key: &[u8], input: &[&[u8]], output: &mut [u8]) -> Result<(), WireError>;

/// A `MESSAGE-INTEGRITY` key plus the MAC that signs with it.
///
/// The key is borrowed, not owned: STUN credentials outlive the message
/// they authenticate, and the crate does not allocate.
#[derive(Debug)]
pub struct MessageIntegrity<'a> {
    key: &'a [u8],
    mac: MacFn,
}

impl<'a> MessageIntegrity<'a> {
    /// A raw-key integrity attribute: `key` is the HMAC key verbatim.
    ///
    /// Short-term credentials are used the same way — the `SASLprep`'d
    /// password *is* the key ([RFC 5389] §10.2).
    #[must_use]
    pub const fn new_raw(key: &'a [u8], mac: MacFn) -> Self {
        Self { key, mac }
    }

    /// The HMAC key this attribute signs with.
    #[must_use]
    pub const fn key(&self) -> &'a [u8] {
        self.key
    }

    /// Appends `MESSAGE-INTEGRITY` to `writer`.
    ///
    /// The tag covers the message as written so far — header plus all
    /// preceding attributes — with the header length field temporarily
    /// increased by the integrity TLV size, per [RFC 5389] §15.4.
    /// `FINGERPRINT` must not already be present: it is computed over the
    /// final message and must come last.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the message already
    /// carries a `FINGERPRINT` attribute (upstream:
    /// `ErrFingerprintBeforeIntegrity`), [`WireError::Overflow`] when the
    /// adjusted length does not fit the 16-bit field, and propagates the
    /// MAC's and [`MessageWriter::push`]'s errors.
    pub fn add_to(&self, writer: &mut MessageWriter<'_>) -> Result<(), WireError> {
        if find_attribute(writer.written_attributes(), ATTR_FINGERPRINT).is_some() {
            return Err(WireError::InvalidValue);
        }
        let mut tag = [0u8; MESSAGE_INTEGRITY_SIZE];
        writer.with_trailer_length(ATTRIBUTE_HEADER_SIZE + MESSAGE_INTEGRITY_SIZE, |bytes| {
            (self.mac)(self.key, &[bytes], &mut tag)
        })??;
        writer.push(ATTR_MESSAGE_INTEGRITY, &tag)
    }

    /// Checks the `MESSAGE-INTEGRITY` attribute of a decoded message.
    ///
    /// The tag covers the header — with the length field reduced by the
    /// attributes *after* the integrity attribute — plus every attribute
    /// preceding it, mirroring what [`MessageIntegrity::add_to`] signed.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the attribute is missing,
    /// its value is not exactly [`MESSAGE_INTEGRITY_SIZE`] bytes, the
    /// length arithmetic underflows, the MAC fails, or the recomputed tag
    /// does not match (upstream: `ErrAttributeNotFound`,
    /// `ErrIntegrityMismatch`).
    pub fn check(msg: &Message<'_>, key: &[u8], mac: MacFn) -> Result<(), WireError> {
        let (offset, value) = find_attribute(msg.attribute_region, ATTR_MESSAGE_INTEGRITY)
            .ok_or(WireError::InvalidValue)?;
        if value.len() != MESSAGE_INTEGRITY_SIZE {
            return Err(WireError::InvalidValue);
        }
        // Reduce the length field by everything after the integrity TLV,
        // so the header matches what the signer used.
        let mut after_integrity = 0usize;
        let mut seen_integrity = false;
        for attr in msg.attributes() {
            if seen_integrity {
                after_integrity +=
                    ATTRIBUTE_HEADER_SIZE + nearest_padded_value_length(usize::from(attr.length));
            }
            if attr.typ == ATTR_MESSAGE_INTEGRITY {
                seen_integrity = true;
            }
        }
        let adjusted = usize::from(msg.length)
            .checked_sub(after_integrity)
            .ok_or(WireError::Overflow)?;
        let adjusted = u16::try_from(adjusted).map_err(|_| WireError::Overflow)?;

        let header = header_bytes(msg.typ, adjusted, msg.transaction_id);
        let mut computed = [0u8; MESSAGE_INTEGRITY_SIZE];
        mac(
            key,
            &[&header, &msg.attribute_region[..offset]],
            &mut computed,
        )?;
        if constant_time_eq(&computed, value) {
            Ok(())
        } else {
            Err(WireError::InvalidValue)
        }
    }
}

/// Compares two equal-length slices without an early exit, so a mismatch
/// position does not leak through timing (upstream: `constant_time_eq`).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::attributes::ATTR_SOFTWARE;
    use crate::fingerprint::push_fingerprint;
    use crate::message::{BINDING_REQUEST, TransactionId};
    use crate::textattrs::Software;
    use rtx_wire::Decode;

    /// A deterministic stand-in MAC: an XOR fold over key || input into a
    /// 20-byte tag — the same shape as upstream's `TestMac`. It exists to
    /// pin the framing semantics; RFC 5389 HMAC-SHA1 vectors arrive with
    /// the real provider in M2 (test-vectors §3).
    // `unnecessary_wraps`: the signature must match `MacFn`, which can fail.
    #[allow(clippy::unnecessary_wraps)]
    fn mock_mac(key: &[u8], input: &[&[u8]], output: &mut [u8]) -> Result<(), WireError> {
        output.fill(0);
        for (index, &byte) in key
            .iter()
            .chain(input.iter().flat_map(|part| part.iter()))
            .enumerate()
        {
            output[index % output.len()] ^= byte;
        }
        Ok(())
    }

    const KEY: &[u8] = b"password";
    const OTHER_KEY: &[u8] = b"Password";

    // 构造 "SOFTWARE + MESSAGE-INTEGRITY(+可选 trailer)" 的消息缓冲。
    fn signed_message(trailer: bool) -> ([u8; 128], usize) {
        let integrity = MessageIntegrity::new_raw(KEY, mock_mac);
        let mut buf = [0u8; 128];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0x31; 12]))
            .expect("128-byte buffer");
        Software::new(ATTR_SOFTWARE, "software")
            .push_to(&mut writer)
            .expect("push software");
        integrity.add_to(&mut writer).expect("add integrity");
        if trailer {
            push_fingerprint(&mut writer).expect("push fingerprint");
        }
        let written = writer.written();
        (buf, written)
    }

    // ---- INT-FRAME --------------------------------------------------------

    // INT-FRAME-001 — sign → decode → check 往返；tag 落在属性区且消息
    // 长度 = SOFTWARE TLV(12) + integrity TLV(24)。
    // 向量来源：上游 integrity_test.rs:238-252（test_message_integrity）
    // 的 framing 语义（mock provider 化，test-vectors §3）。
    #[test]
    fn stun_int_001_sign_decode_check_roundtrip() {
        let (buf, written) = signed_message(false);
        assert_eq!(written, 20 + 12 + 24);

        let (msg, consumed) = Message::decode(&buf[..written]).expect("decode");
        assert_eq!(consumed, written);
        MessageIntegrity::check(&msg, KEY, mock_mac).expect("integrity checks out");
    }

    // INT-FRAME-002 — HMAC 输入区间：SOFTWARE 在 integrity 之前，篡改它
    // 任何一个字节都使 check 失败。
    // 向量来源：上游 integrity_test.rs:206-218（d_m.raw[24] += 12 后
    // check 失败）。
    #[test]
    fn stun_int_002_input_region_is_prefix() {
        let (buf, written) = signed_message(false);
        let mut tampered = buf;
        tampered[24 + 4] ^= 0x01; // SOFTWARE 值第一个字节
        let (msg, _) = Message::decode(&tampered[..written]).expect("decode");
        assert_eq!(
            MessageIntegrity::check(&msg, KEY, mock_mac),
            Err(WireError::InvalidValue)
        );
    }

    // INT-FRAME-003 — integrity 之后的属性不计入 tag：追加 FINGERPRINT
    // 后 check 仍通过（长度字段扣除 after-integrity 尺寸）。
    // 向量来源：上游 integrity_test.rs:184-201
    //（test_message_integrity_with_fingerprint 的通过路径）。
    #[test]
    fn stun_int_003_trailing_attributes_excluded() {
        let (buf, written) = signed_message(true);
        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        MessageIntegrity::check(&msg, KEY, mock_mac).expect("integrity checks out");
        // 顺带验证 FINGERPRINT 自身也校验通过。
        crate::fingerprint::check(&msg).expect("fingerprint checks out");
    }

    // INT-FRAME-004 — 篡改 transaction id（header 的一部分）→ 失败。
    #[test]
    fn stun_int_004_header_tamper_rejected() {
        let (buf, written) = signed_message(false);
        let mut tampered = buf;
        tampered[8] ^= 0x80; // transaction id 第一个字节
        let (msg, _) = Message::decode(&tampered[..written]).expect("decode");
        assert_eq!(
            MessageIntegrity::check(&msg, KEY, mock_mac),
            Err(WireError::InvalidValue)
        );
    }

    // ---- INT-ORDER --------------------------------------------------------

    // INT-ORDER-001 — FINGERPRINT 先于 MESSAGE-INTEGRITY → 拒绝。
    // 向量来源：上游 integrity_test.rs:254-266
    //（test_message_integrity_before_fingerprint）。
    #[test]
    fn stun_int_005_fingerprint_before_integrity_rejected() {
        let mut buf = [0u8; 128];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0x32; 12]))
            .expect("128-byte buffer");
        push_fingerprint(&mut writer).expect("push fingerprint");
        let integrity = MessageIntegrity::new_raw(KEY, mock_mac);
        assert_eq!(integrity.add_to(&mut writer), Err(WireError::InvalidValue));
        // 失败不写坏消息：长度字段保持不动。
        assert_eq!(writer.length(), 8);
    }

    // ---- INT-CHECK --------------------------------------------------------

    // INT-CHECK-001 — 截断 tag（19 字节）→ InvalidValue。
    // 向量来源：上游 integrity_test.rs:147-174
    //（explicit_custom_provider_round_trip_and_truncated_tag_rejection，
    // TestProvider 化）。
    #[test]
    fn stun_int_006_truncated_tag_rejected() {
        let (buf, written) = signed_message(false);
        let mut tampered = buf;
        // integrity TLV 起始 = 20 + 12；把其 length 字段从 20 改为 19
        // （padded 尺寸不变，消息其余部分不动）。
        let tlv = 20 + 12;
        assert_eq!(&tampered[tlv + 2..tlv + 4], &[0, 20]);
        tampered[tlv + 2..tlv + 4].copy_from_slice(&19u16.to_be_bytes());
        let (msg, _) = Message::decode(&tampered[..written]).expect("decode");
        assert_eq!(
            MessageIntegrity::check(&msg, KEY, mock_mac),
            Err(WireError::InvalidValue)
        );
    }

    // INT-CHECK-002 — 换 key → 失败。
    #[test]
    fn stun_int_007_wrong_key_rejected() {
        let (buf, written) = signed_message(false);
        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        assert_eq!(
            MessageIntegrity::check(&msg, OTHER_KEY, mock_mac),
            Err(WireError::InvalidValue)
        );
    }

    // INT-CHECK-003 — 缺失 MESSAGE-INTEGRITY → InvalidValue。
    #[test]
    fn stun_int_008_absent_attribute_rejected() {
        let mut buf = [0u8; 128];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0x33; 12]))
            .expect("128-byte buffer");
        Software::new(ATTR_SOFTWARE, "software")
            .push_to(&mut writer)
            .expect("push software");
        let written = writer.written();
        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        assert_eq!(
            MessageIntegrity::check(&msg, KEY, mock_mac),
            Err(WireError::InvalidValue)
        );
    }

    // INT-CHECK-004 — mock MAC 确定性：同一消息两次签名 tag 一致，
    // 且 tag 覆盖内容变化敏感。
    #[test]
    fn stun_int_009_deterministic_and_sensitive() {
        let (a, _) = signed_message(false);
        let (b, _) = signed_message(false);
        assert_eq!(a[20 + 12 + 4..20 + 12 + 24], b[20 + 12 + 4..20 + 12 + 24]);

        let mut buf = [0u8; 128];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0x31; 12]))
            .expect("128-byte buffer");
        Software::new(ATTR_SOFTWARE, "software!")
            .push_to(&mut writer)
            .expect("push software");
        MessageIntegrity::new_raw(KEY, mock_mac)
            .add_to(&mut writer)
            .expect("add integrity");
        assert_ne!(buf[20 + 12 + 4..20 + 12 + 24], a[20 + 12 + 4..20 + 12 + 24]);
    }

    // INT-CHECK-005 — constant_time_eq 语义（等长真/假、不等长假）。
    #[test]
    fn stun_int_010_constant_time_eq_semantics() {
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(!constant_time_eq(b"abcd", b"abcde"));
        assert!(constant_time_eq(b"", b""));
    }
}

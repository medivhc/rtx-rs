//! Text-valued attributes: `USERNAME`, `REALM`, `NONCE` and `SOFTWARE`.
//!
//! All four share one encoding — a UTF-8 string in the attribute value
//! ([RFC 5389] §15.3, §15.7, §15.8, §15.10) — and one length ceiling per
//! attribute, enforced on encode. [`TextAttribute`] borrows its text from
//! the decoded input, so reading a message allocates nothing.
//!
//! [RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389

use rtx_wire::WireError;

use crate::attributes::{ATTR_NONCE, ATTR_REALM, ATTR_SOFTWARE, ATTR_USERNAME, AttrType};
use crate::message::MessageWriter;

/// `USERNAME` ceiling, in bytes (RFC 5389 §15.3: 513 bytes with `SASLprep`).
const MAX_USERNAME_B: usize = 513;
/// `REALM` ceiling, in bytes (RFC 5389 §15.7).
const MAX_REALM_B: usize = 763;
/// `SOFTWARE` ceiling, in bytes (RFC 5389 §15.10).
const MAX_SOFTWARE_B: usize = 763;
/// `NONCE` ceiling, in bytes (RFC 5389 §15.8).
const MAX_NONCE_B: usize = 763;

/// `USERNAME` attribute ([RFC 5389] §15.3).
pub type Username<'a> = TextAttribute<'a>;
/// `REALM` attribute ([RFC 5389] §15.7).
pub type Realm<'a> = TextAttribute<'a>;
/// `NONCE` attribute ([RFC 5389] §15.8).
pub type Nonce<'a> = TextAttribute<'a>;
/// `SOFTWARE` attribute ([RFC 5389] §15.10).
pub type Software<'a> = TextAttribute<'a>;

/// A text-valued attribute, borrowing its text from the decoded input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextAttribute<'a> {
    /// Which attribute this text belongs to.
    pub attr: AttrType,
    /// The text value, borrowed from the input.
    pub text: &'a str,
}

impl<'a> TextAttribute<'a> {
    /// A text attribute of type `attr` holding `text`.
    #[must_use]
    pub const fn new(attr: AttrType, text: &'a str) -> Self {
        Self { attr, text }
    }

    /// Decodes the text of the `attr` attribute from its raw value.
    ///
    /// The value must be valid UTF-8; there is deliberately no length
    /// ceiling on decode, matching upstream (the ceilings exist to police
    /// what *this* implementation sends).
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when `attr` is not one of the
    /// four text attributes or the value is not valid UTF-8.
    pub fn from_value(attr: AttrType, value: &'a [u8]) -> Result<Self, WireError> {
        if !matches!(
            attr,
            ATTR_USERNAME | ATTR_REALM | ATTR_SOFTWARE | ATTR_NONCE
        ) {
            return Err(WireError::InvalidValue);
        }
        let text = core::str::from_utf8(value).map_err(|_| WireError::InvalidValue)?;
        Ok(Self { attr, text })
    }

    /// Appends this attribute to `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the attribute type is not
    /// one of the four text attributes, or the text exceeds the type's
    /// ceiling ([`MAX_USERNAME_B`], [`MAX_REALM_B`], [`MAX_SOFTWARE_B`],
    /// [`MAX_NONCE_B`]). Propagates the errors of [`MessageWriter::push`].
    pub fn push_to(&self, writer: &mut MessageWriter<'_>) -> Result<(), WireError> {
        let max_len = match self.attr {
            ATTR_USERNAME => MAX_USERNAME_B,
            ATTR_REALM => MAX_REALM_B,
            ATTR_SOFTWARE => MAX_SOFTWARE_B,
            ATTR_NONCE => MAX_NONCE_B,
            _ => return Err(WireError::InvalidValue),
        };
        if self.text.len() > max_len {
            return Err(WireError::InvalidValue);
        }
        writer.push(self.attr, self.text.as_bytes())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::message::{BINDING_REQUEST, Message, TransactionId};
    use rtx_wire::Decode;

    fn writer_with(buf: &mut [u8]) -> MessageWriter<'_> {
        MessageWriter::new(buf, BINDING_REQUEST, TransactionId([0x77; 12]))
            .expect("buffer fits header")
    }

    // ---- TEXT-ATTR --------------------------------------------------------

    // TEXT-ATTR-001 — SOFTWARE 往返（含消息级编解码）。
    // 向量来源：上游 textattrs_test.rs:7-31（test_software_get_from）。
    #[test]
    fn stun_text_001_software_roundtrip() {
        let software = Software::new(ATTR_SOFTWARE, "Client v0.0.1");
        let mut buf = [0u8; 48];
        let mut writer = writer_with(&mut buf);
        software.push_to(&mut writer).expect("push software");
        let written = writer.written();

        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        let got = Software::from_value(
            ATTR_SOFTWARE,
            msg.get(ATTR_SOFTWARE).expect("software attr").value,
        )
        .expect("decode software");
        assert_eq!(got, software);
        assert_eq!(got.text, "Client v0.0.1");
    }

    // TEXT-ATTR-002 — SOFTWARE 超长（1024 > 763）→ InvalidValue，且消息中
    // 没有写入该属性。
    // 向量来源：上游 textattrs_test.rs:33-64（test_software_add_to_invalid）。
    #[test]
    fn stun_text_002_software_too_long_rejected() {
        let long_text = "\0".repeat(1024);
        let long = Software::new(ATTR_SOFTWARE, &long_text);
        let mut buf = [0u8; 32];
        let mut writer = writer_with(&mut buf);
        assert_eq!(long.push_to(&mut writer), Err(WireError::InvalidValue));
        assert_eq!(writer.length(), 0);

        let (msg, _) = Message::decode(writer.as_bytes()).expect("decode header only");
        assert!(msg.get(ATTR_SOFTWARE).is_none());
    }

    // TEXT-ATTR-003 — USERNAME 超长（600 > 513）→ InvalidValue。
    // 向量来源：上游 textattrs_test.rs:91-106（test_username "Bad length"）。
    #[test]
    fn stun_text_003_username_too_long_rejected() {
        let bad_text = "\0".repeat(600);
        let bad = Username::new(ATTR_USERNAME, &bad_text);
        let mut buf = [0u8; 32];
        let mut writer = writer_with(&mut buf);
        assert_eq!(bad.push_to(&mut writer), Err(WireError::InvalidValue));
    }

    // TEXT-ATTR-004 — USERNAME 往返。
    // 向量来源：上游 textattrs_test.rs:83-146（test_username）。
    #[test]
    fn stun_text_004_username_roundtrip() {
        let username = Username::new(ATTR_USERNAME, "username");
        let mut buf = [0u8; 48];
        let mut writer = writer_with(&mut buf);
        username.push_to(&mut writer).expect("push username");
        let written = writer.written();

        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        let got = Username::from_value(
            ATTR_USERNAME,
            msg.get(ATTR_USERNAME).expect("username attr").value,
        )
        .expect("decode username");
        assert_eq!(got.text, "username");
    }

    // TEXT-ATTR-005 — REALM 往返。
    // 向量来源：上游 textattrs_test.rs:148-186（test_realm_get_from）。
    #[test]
    fn stun_text_005_realm_roundtrip() {
        let realm = Realm::new(ATTR_REALM, "realm");
        let mut buf = [0u8; 48];
        let mut writer = writer_with(&mut buf);
        realm.push_to(&mut writer).expect("push realm");
        let written = writer.written();

        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        let got = Realm::from_value(ATTR_REALM, msg.get(ATTR_REALM).expect("realm attr").value)
            .expect("decode realm");
        assert_eq!(got.text, "realm");
    }

    // TEXT-ATTR-006 — NONCE 往返（值逐字节断言）。
    // 向量来源：上游 textattrs_test.rs:221-259 与 :294-307
    // （test_nonce_get_from / test_nonce_add_to）。
    #[test]
    fn stun_text_006_nonce_roundtrip() {
        let nonce = Nonce::new(ATTR_NONCE, "example.org");
        let mut buf = [0u8; 48];
        let mut writer = writer_with(&mut buf);
        nonce.push_to(&mut writer).expect("push nonce");
        let written = writer.written();

        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        let attr = msg.get(ATTR_NONCE).expect("nonce attr");
        assert_eq!(attr.value, b"example.org");
        let got = Nonce::from_value(ATTR_NONCE, attr.value).expect("decode nonce");
        assert_eq!(got.text, "example.org");
    }

    // TEXT-ATTR-007 — REALM/NONCE 超长（1024 > 763）→ InvalidValue。
    // 向量来源：上游 textattrs_test.rs:188-219 与 :261-292
    // （test_realm_add_to_invalid / test_nonce_add_to_invalid）。
    #[test]
    fn stun_text_007_realm_nonce_too_long_rejected() {
        for attr in [ATTR_REALM, ATTR_NONCE] {
            let long_text = "\0".repeat(1024);
            let long = TextAttribute::new(attr, &long_text);
            let mut buf = [0u8; 32];
            let mut writer = writer_with(&mut buf);
            assert_eq!(long.push_to(&mut writer), Err(WireError::InvalidValue));
        }
    }

    // TEXT-ATTR-008 — 非 UTF-8 值 → InvalidValue（上游 from_utf8 错误）。
    #[test]
    fn stun_text_008_invalid_utf8_rejected() {
        assert_eq!(
            Software::from_value(ATTR_SOFTWARE, &[0xff, 0xfe]),
            Err(WireError::InvalidValue)
        );
        // 截断的多字节序列同样拒绝。
        assert_eq!(
            Software::from_value(ATTR_SOFTWARE, &[0xE2, 0x82]),
            Err(WireError::InvalidValue)
        );
    }

    // TEXT-ATTR-009 — 非文本属性类型 → InvalidValue（上游 Unsupported
    // AttrType）。
    #[test]
    fn stun_text_009_unsupported_attr_type_rejected() {
        assert_eq!(
            TextAttribute::from_value(crate::attributes::ATTR_PRIORITY, b"x"),
            Err(WireError::InvalidValue)
        );
        let wrong = TextAttribute::new(crate::attributes::ATTR_PRIORITY, "x");
        let mut buf = [0u8; 32];
        let mut writer = writer_with(&mut buf);
        assert_eq!(wrong.push_to(&mut writer), Err(WireError::InvalidValue));
    }

    // TEXT-ATTR-010 — 恰好达到上限可通过（513 / 763 边界）。
    #[test]
    fn stun_text_010_length_ceiling_boundary_accepted() {
        let max_username_text = "a".repeat(MAX_USERNAME_B);
        let max_username = Username::new(ATTR_USERNAME, &max_username_text);
        let mut buf = [0u8; 1024];
        let mut writer = writer_with(&mut buf);
        max_username
            .push_to(&mut writer)
            .expect("push max username");
        assert_eq!(writer.length(), 4 + 516); // 513 补到 516

        let max_realm_text = "a".repeat(MAX_REALM_B);
        let max_realm = Realm::new(ATTR_REALM, &max_realm_text);
        let mut big = [0u8; 1024];
        let mut writer = writer_with(&mut big);
        max_realm.push_to(&mut writer).expect("push max realm");
        assert_eq!(writer.length(), 4 + 764); // 763 补到 764
    }
}

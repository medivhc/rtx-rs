//! The `ERROR-CODE` attribute ([RFC 5389] §15.6).
//!
//! An error response carries a numeric code plus a reason phrase. The
//! codes here span three specs — STUN's own (300, 400, 401, 420, 438,
//! 500), ICE's role conflict (487) and TURN's allocation failures (403,
//! 437, 441, 442, 446, 447, 440, 443, 486, 508) — because all three share
//! this attribute.
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Reserved, should be 0         |Class|     Number    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Reason Phrase (variable)                  ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The reserved bytes are always written as zero. [`ErrorCode::default_reason`]
//! maps each known code to the phrase it is normally sent with, so a
//! responder does not have to invent one.
//!
//! [RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389

use core::fmt;

use rtx_wire::WireError;

use crate::message::MessageWriter;

// Byte positions inside the attribute value.
const ERROR_CODE_CLASS_BYTE: usize = 2;
const ERROR_CODE_NUMBER_BYTE: usize = 3;
const ERROR_CODE_REASON_START: usize = 4;
/// Reason phrase ceiling, in bytes.
const ERROR_CODE_REASON_MAX_B: usize = 763;
/// Error codes split as `class * 100 + number`.
const ERROR_CODE_MODULO: u16 = 100;

/// A STUN error code, as carried in `ERROR-CODE`.
#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Default)]
pub struct ErrorCode(pub u16);

/// Possible error codes.
/// 300 Try Alternate.
pub const CODE_TRY_ALTERNATE: ErrorCode = ErrorCode(300);
/// 400 Bad Request: the request was malformed.
pub const CODE_BAD_REQUEST: ErrorCode = ErrorCode(400);
/// 401 Unauthorized: authentication is required, or the credentials were wrong.
pub const CODE_UNAUTHORIZED: ErrorCode = ErrorCode(401);
/// 420 Unknown Attribute: the request carried a comprehension-required
/// attribute the server does not understand.
pub const CODE_UNKNOWN_ATTRIBUTE: ErrorCode = ErrorCode(420);
/// 438 Stale Nonce: the nonce expired; retry with the one in this response.
pub const CODE_STALE_NONCE: ErrorCode = ErrorCode(438);
/// 487 Role Conflict: both ICE agents claimed the same role.
pub const CODE_ROLE_CONFLICT: ErrorCode = ErrorCode(487);
/// 500 Server Error: a temporary failure on the server.
pub const CODE_SERVER_ERROR: ErrorCode = ErrorCode(500);

/// DEPRECATED, use [`CODE_UNAUTHORIZED`].
pub const CODE_UNAUTHORISED: ErrorCode = CODE_UNAUTHORIZED;

/// 403 Forbidden (RFC 5766).
pub const CODE_FORBIDDEN: ErrorCode = ErrorCode(403);
/// 437 Allocation Mismatch (RFC 5766).
pub const CODE_ALLOC_MISMATCH: ErrorCode = ErrorCode(437);
/// 441 Wrong Credentials (RFC 5766).
pub const CODE_WRONG_CREDENTIALS: ErrorCode = ErrorCode(441);
/// 442 Unsupported Transport Protocol (RFC 5766).
pub const CODE_UNSUPPORTED_TRANS_PROTO: ErrorCode = ErrorCode(442);
/// 446 Connection Already Exists (RFC 6062).
pub const CODE_CONN_ALREADY_EXISTS: ErrorCode = ErrorCode(446);
/// 447 Connection Timeout or Failure (RFC 6062).
pub const CODE_CONN_TIMEOUT_OR_FAILURE: ErrorCode = ErrorCode(447);
/// 440 Address Family not Supported (RFC 6156).
pub const CODE_ADDR_FAMILY_NOT_SUPPORTED: ErrorCode = ErrorCode(440);
/// 443 Peer Address Family Mismatch (RFC 6156).
pub const CODE_PEER_ADDR_FAMILY_MISMATCH: ErrorCode = ErrorCode(443);
/// 486 Allocation Quota Reached (RFC 5766).
pub const CODE_ALLOC_QUOTA_REACHED: ErrorCode = ErrorCode(486);
/// 508 Insufficient Capacity (RFC 5766).
pub const CODE_INSUFFICIENT_CAPACITY: ErrorCode = ErrorCode(508);

/// The reason phrase each known [`ErrorCode`] is sent with.
///
/// A table rather than upstream's `lazy_static` map: the crate is `no_std`
/// by default and the lookup is a linear scan over ~18 entries.
const ERROR_REASONS: [(ErrorCode, &[u8]); 17] = [
    (CODE_TRY_ALTERNATE, b"Try Alternate"),
    (CODE_BAD_REQUEST, b"Bad Request"),
    (CODE_UNAUTHORIZED, b"Unauthorized"),
    (CODE_UNKNOWN_ATTRIBUTE, b"Unknown Attribute"),
    (CODE_STALE_NONCE, b"Stale Nonce"),
    (CODE_SERVER_ERROR, b"Server Error"),
    (CODE_ROLE_CONFLICT, b"Role Conflict"),
    // RFC 5766.
    (CODE_FORBIDDEN, b"Forbidden"),
    (CODE_ALLOC_MISMATCH, b"Allocation Mismatch"),
    (CODE_WRONG_CREDENTIALS, b"Wrong Credentials"),
    (
        CODE_UNSUPPORTED_TRANS_PROTO,
        b"Unsupported Transport Protocol",
    ),
    (CODE_ALLOC_QUOTA_REACHED, b"Allocation Quota Reached"),
    (CODE_INSUFFICIENT_CAPACITY, b"Insufficient Capacity"),
    // RFC 6062.
    (CODE_CONN_ALREADY_EXISTS, b"Connection Already Exists"),
    (
        CODE_CONN_TIMEOUT_OR_FAILURE,
        b"Connection Timeout or Failure",
    ),
    // RFC 6156.
    (
        CODE_ADDR_FAMILY_NOT_SUPPORTED,
        b"Address Family not Supported",
    ),
    (
        CODE_PEER_ADDR_FAMILY_MISMATCH,
        b"Peer Address Family Mismatch",
    ),
];

impl ErrorCode {
    /// The reason phrase this code is normally sent with, if known.
    #[must_use]
    pub fn default_reason(self) -> Option<&'static [u8]> {
        ERROR_REASONS
            .iter()
            .find(|(code, _)| *code == self)
            .map(|(_, reason)| *reason)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// `ERROR-CODE` ([RFC 5389] §15.6): a numeric code and a reason phrase.
///
/// The reason is borrowed bytes rather than a `String`: the wire value is
/// UTF-8 in practice but the attribute does not require it, and
/// [`Display`](fmt::Display) renders it lossily either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCodeAttribute<'a> {
    /// The numeric error code.
    pub code: ErrorCode,
    /// The reason phrase, borrowed from the input.
    pub reason: &'a [u8],
}

impl<'a> ErrorCodeAttribute<'a> {
    /// An `ERROR-CODE` of `code` with reason phrase `reason`.
    #[must_use]
    pub const fn new(code: ErrorCode, reason: &'a [u8]) -> Self {
        Self { code, reason }
    }

    /// Decodes the attribute from its raw value.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the value is shorter than
    /// the 4-byte code header (upstream: `ErrUnexpectedEof`).
    pub fn from_value(value: &'a [u8]) -> Result<Self, WireError> {
        if value.len() < ERROR_CODE_REASON_START {
            return Err(WireError::InvalidValue);
        }
        let class = u16::from(value[ERROR_CODE_CLASS_BYTE]);
        let number = u16::from(value[ERROR_CODE_NUMBER_BYTE]);
        Ok(Self {
            code: ErrorCode(class * ERROR_CODE_MODULO + number),
            reason: &value[ERROR_CODE_REASON_START..],
        })
    }

    /// Appends this attribute to `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the reason phrase exceeds
    /// [`ERROR_CODE_REASON_MAX_B`] bytes or the code's class byte does not
    /// fit `u8` (codes above 25599, which no STUN profile defines).
    /// Propagates the errors of [`MessageWriter::push`].
    pub fn push_to(&self, writer: &mut MessageWriter<'_>) -> Result<(), WireError> {
        if self.reason.len() > ERROR_CODE_REASON_MAX_B {
            return Err(WireError::InvalidValue);
        }
        let class =
            u8::try_from(self.code.0 / ERROR_CODE_MODULO).map_err(|_| WireError::InvalidValue)?;
        let number =
            u8::try_from(self.code.0 % ERROR_CODE_MODULO).map_err(|_| WireError::InvalidValue)?;

        let mut value = [0u8; ERROR_CODE_REASON_START + ERROR_CODE_REASON_MAX_B];
        // value[0..2] stays zero: the reserved bytes.
        value[ERROR_CODE_CLASS_BYTE] = class;
        value[ERROR_CODE_NUMBER_BYTE] = number;
        value[ERROR_CODE_REASON_START..ERROR_CODE_REASON_START + self.reason.len()]
            .copy_from_slice(self.reason);
        writer.push(
            crate::attributes::ATTR_ERROR_CODE,
            &value[..ERROR_CODE_REASON_START + self.reason.len()],
        )
    }

    /// Encoded length of the attribute value: `4 + reason.len()`.
    #[must_use]
    pub const fn value_len(&self) -> usize {
        ERROR_CODE_REASON_START + self.reason.len()
    }
}

impl fmt::Display for ErrorCodeAttribute<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.code.0)?;
        // Lossy UTF-8 without std: one U+FFFD per maximal invalid run,
        // matching String::from_utf8_lossy.
        for chunk in self.reason.utf8_chunks() {
            f.write_str(chunk.valid())?;
            if !chunk.invalid().is_empty() {
                f.write_str("\u{FFFD}")?;
            }
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::message::{BINDING_REQUEST, Message, TransactionId};
    use rtx_wire::Decode;

    // ---- ERR-ATTR ---------------------------------------------------------

    // ERR-ATTR-001 — 往返 + 线上字节（401 "Unauthorized"）。
    // 向量来源：上游 error_code_test.rs:3-10（test_display_valid_utf8）
    // 与 error_code.rs:50-71（class/number 编码）。
    #[test]
    fn stun_err_001_roundtrip_and_wire_bytes() {
        let attr = ErrorCodeAttribute::new(ErrorCode(401), b"Unauthorized");
        assert_eq!(attr.to_string(), "401: Unauthorized");
        assert_eq!(attr.value_len(), 4 + 12);

        let mut buf = [0u8; 64];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0xBB; 12]))
            .expect("64-byte buffer");
        attr.push_to(&mut writer).expect("push error code");
        let written = writer.written();
        assert_eq!(
            &buf[24..written],
            &[
                0x00, 0x00, // reserved
                0x04, // class 4
                0x01, // number 1
                b'U', b'n', b'a', b'u', b't', b'h', b'o', b'r', b'i', b'z', b'e', b'd',
            ]
        );

        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        let got = ErrorCodeAttribute::from_value(
            msg.get(crate::attributes::ATTR_ERROR_CODE)
                .expect("attr")
                .value,
        )
        .expect("decode error code");
        assert_eq!(got, attr);
    }

    // ERR-ATTR-002 — 非法 UTF-8 reason 的 lossy Display（两个 U+FFFD）。
    // 向量来源：上游 error_code_test.rs:12-20
    // （test_display_invalid_utf8_does_not_panic）。
    #[test]
    fn stun_err_002_display_invalid_utf8_lossy() {
        let attr = ErrorCodeAttribute::new(ErrorCode(401), &[0xc0, 0xaf]);
        assert_eq!(attr.to_string(), "401: \u{FFFD}\u{FFFD}");
    }

    // ERR-ATTR-003 — 值短于 4 字节 → InvalidValue。
    // 向量来源：上游 error_code.rs:78-80（ErrUnexpectedEof）。
    #[test]
    fn stun_err_003_short_value_rejected() {
        assert_eq!(
            ErrorCodeAttribute::from_value(&[0, 0, 4]),
            Err(WireError::InvalidValue)
        );
        // 恰好 4 字节（无 reason）合法。
        let empty = ErrorCodeAttribute::from_value(&[0, 0, 4, 1]).expect("decode empty reason");
        assert_eq!(empty.code, ErrorCode(401));
        assert!(empty.reason.is_empty());
    }

    // ERR-ATTR-004 — reason 超长（764 > 763）→ InvalidValue。
    // 向量来源：上游 error_code.rs:52-57（check_overflow）。
    #[test]
    fn stun_err_004_reason_too_long_rejected() {
        let long = ErrorCodeAttribute::new(ErrorCode(400), &[b'a'; 764]);
        let mut buf = [0u8; 32];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0xCC; 12]))
            .expect("32-byte buffer");
        assert_eq!(long.push_to(&mut writer), Err(WireError::InvalidValue));
        // 恰好 763 可通过。
        let max = ErrorCodeAttribute::new(ErrorCode(400), &[b'a'; 763]);
        let mut big = [0u8; 1024];
        let mut writer = MessageWriter::new(&mut big, BINDING_REQUEST, TransactionId([0xDD; 12]))
            .expect("1024-byte buffer");
        max.push_to(&mut writer).expect("push max reason");
        assert_eq!(writer.length(), 4 + 4 + 764); // 4+763=767 补到 768，加 TLV 头
    }

    // ERR-ATTR-005 — class/number 编解码向量表。
    #[test]
    fn stun_err_005_class_number_vectors() {
        let vectors = [
            (300u16, [0x00, 0x00, 0x03, 0x00]),
            (400, [0x00, 0x00, 0x04, 0x00]),
            (401, [0x00, 0x00, 0x04, 0x01]),
            (420, [0x00, 0x00, 0x04, 0x14]),
            (438, [0x00, 0x00, 0x04, 0x26]),
            (487, [0x00, 0x00, 0x04, 0x57]),
            (500, [0x00, 0x00, 0x05, 0x00]),
            (508, [0x00, 0x00, 0x05, 0x08]),
        ];
        for (code, expected) in vectors {
            let attr = ErrorCodeAttribute::new(ErrorCode(code), b"x");
            let mut buf = [0u8; 64];
            let mut writer =
                MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0xEE; 12]))
                    .expect("64-byte buffer");
            attr.push_to(&mut writer).expect("push error code");
            let bytes = writer.as_bytes();
            assert_eq!(&bytes[24..28], &expected, "wire bytes for {code}");
            let (msg, _) = Message::decode(bytes).expect("decode");
            let got = ErrorCodeAttribute::from_value(
                msg.get(crate::attributes::ATTR_ERROR_CODE)
                    .expect("attr")
                    .value,
            )
            .expect("decode");
            assert_eq!(got.code, ErrorCode(code));
        }
    }

    // ERR-ATTR-006 — ERROR_REASONS 表与上游逐条对齐（抽样 + 未知码 None）。
    // 向量来源：上游 error_code.rs:165-194（ERROR_REASONS map）。
    #[test]
    fn stun_err_006_default_reasons_table() {
        let vectors = [
            (CODE_TRY_ALTERNATE, &b"Try Alternate"[..]),
            (CODE_BAD_REQUEST, b"Bad Request"),
            (CODE_UNAUTHORIZED, b"Unauthorized"),
            (CODE_UNKNOWN_ATTRIBUTE, b"Unknown Attribute"),
            (CODE_STALE_NONCE, b"Stale Nonce"),
            (CODE_SERVER_ERROR, b"Server Error"),
            (CODE_ROLE_CONFLICT, b"Role Conflict"),
            (CODE_FORBIDDEN, b"Forbidden"),
            (CODE_ALLOC_MISMATCH, b"Allocation Mismatch"),
            (CODE_WRONG_CREDENTIALS, b"Wrong Credentials"),
            (
                CODE_UNSUPPORTED_TRANS_PROTO,
                b"Unsupported Transport Protocol",
            ),
            (CODE_ALLOC_QUOTA_REACHED, b"Allocation Quota Reached"),
            (CODE_INSUFFICIENT_CAPACITY, b"Insufficient Capacity"),
            (CODE_CONN_ALREADY_EXISTS, b"Connection Already Exists"),
            (
                CODE_CONN_TIMEOUT_OR_FAILURE,
                b"Connection Timeout or Failure",
            ),
            (
                CODE_ADDR_FAMILY_NOT_SUPPORTED,
                b"Address Family not Supported",
            ),
            (
                CODE_PEER_ADDR_FAMILY_MISMATCH,
                b"Peer Address Family Mismatch",
            ),
        ];
        for (code, reason) in vectors {
            assert_eq!(code.default_reason(), Some(reason), "reason for {code:?}");
        }
        assert_eq!(ErrorCode(999).default_reason(), None);
        // 表内条目数与上游一致（18 条含弃用别名共享条目）。
        assert_eq!(ERROR_REASONS.len(), 17);
    }

    // ERR-ATTR-007 — class 字节放不下的码（> 25599）→ InvalidValue。
    #[test]
    fn stun_err_007_class_byte_overflow_rejected() {
        let attr = ErrorCodeAttribute::new(ErrorCode(25600), b"x");
        let mut buf = [0u8; 32];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId([0xFF; 12]))
            .expect("32-byte buffer");
        assert_eq!(attr.push_to(&mut writer), Err(WireError::InvalidValue));
    }
}

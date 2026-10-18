//! The `UNKNOWN-ATTRIBUTES` attribute ([RFC 5389] §15.9).
//!
//! A server that does not understand a comprehension-required attribute
//! echoes the offending type codes — 16 bits each, in order — in an
//! `UNKNOWN-ATTRIBUTES` attribute of its error response, usually with
//! error code 420. [`UnknownAttributes`] borrows the value slice and
//! iterates it, so decoding allocates nothing.

use core::fmt;

use rtx_wire::WireError;

use crate::attributes::{ATTR_UNKNOWN_ATTRIBUTES, AttrType};
use crate::message::MessageWriter;

/// One type code is 16 bits.
const ATTR_TYPE_SIZE: usize = 2;

/// `UNKNOWN-ATTRIBUTES`: the echoed type codes, borrowed from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownAttributes<'a> {
    value: &'a [u8],
}

impl<'a> UnknownAttributes<'a> {
    /// Decodes the attribute from its raw value.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the value length is not a
    /// multiple of 2 (upstream: `ErrBadUnknownAttrsSize`).
    pub fn from_value(value: &'a [u8]) -> Result<Self, WireError> {
        // `is_multiple_of` is stable since 1.87; the workspace MSRV is 1.85.
        if value.len() % ATTR_TYPE_SIZE != 0 {
            return Err(WireError::InvalidValue);
        }
        Ok(Self { value })
    }

    /// Iterates the echoed type codes in order.
    pub fn types(&self) -> impl Iterator<Item = AttrType> + '_ {
        self.value
            .chunks_exact(ATTR_TYPE_SIZE)
            .map(|chunk| AttrType(u16::from_be_bytes([chunk[0], chunk[1]])))
    }

    /// The number of echoed type codes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.value.len() / ATTR_TYPE_SIZE
    }

    /// Returns `true` if no type codes are echoed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Appends an `UNKNOWN-ATTRIBUTES` attribute holding `types` to
    /// `writer`.
    ///
    /// The value is streamed through [`MessageWriter::push_with`], so any
    /// number of types fits without a scratch buffer or allocation.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Overflow`] when the encoded value exceeds the
    /// 16-bit length field, and [`WireError::OutputTooSmall`] when `writer`
    /// lacks room.
    pub fn push_to(writer: &mut MessageWriter<'_>, types: &[AttrType]) -> Result<(), WireError> {
        let value_len = types.len() * ATTR_TYPE_SIZE;
        writer.push_with(ATTR_UNKNOWN_ATTRIBUTES, value_len, |value| {
            for (slot, typ) in value.chunks_exact_mut(ATTR_TYPE_SIZE).zip(types) {
                slot.copy_from_slice(&typ.value().to_be_bytes());
            }
        })
    }
}

impl fmt::Display for UnknownAttributes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("<nil>");
        }
        for (index, typ) in self.types().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{typ}")?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::attributes::{ATTR_CHANNEL_NUMBER, ATTR_DONT_FRAGMENT};
    use crate::message::{BINDING_REQUEST, Message, TransactionId};
    use rtx_wire::Decode;

    // ---- UNK-ATTR ---------------------------------------------------------

    // UNK-ATTR-001 — 往返 + stringer（含空表 <nil>）。
    // 向量来源：上游 uattrs_test.rs:3-37（test_unknown_attributes）。
    #[test]
    fn stun_unk_001_roundtrip_and_stringer() {
        let types = [ATTR_DONT_FRAGMENT, ATTR_CHANNEL_NUMBER];
        assert_eq!(
            UnknownAttributes::from_value(&[])
                .expect("decode empty")
                .to_string(),
            "<nil>"
        );

        let mut buf = [0u8; 64];
        let mut writer = crate::message::MessageWriter::new(
            &mut buf,
            BINDING_REQUEST,
            TransactionId([0x88; 12]),
        )
        .expect("64-byte buffer");
        UnknownAttributes::push_to(&mut writer, &types).expect("push unknown attrs");
        let written = writer.written();
        // 值 = 00 1A 00 0C（DONT-FRAGMENT, CHANNEL-NUMBER）。
        assert_eq!(&buf[24..written], &[0x00, 0x1A, 0x00, 0x0C]);

        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        let got =
            UnknownAttributes::from_value(msg.get(ATTR_UNKNOWN_ATTRIBUTES).expect("attr").value)
                .expect("decode unknown attrs");
        assert_eq!(got.types().collect::<Vec<_>>(), types);
        assert_eq!(got.len(), 2);
        assert!(!got.is_empty());
        assert_eq!(got.to_string(), "DONT-FRAGMENT, CHANNEL-NUMBER");
    }

    // UNK-ATTR-002 — 奇数长度值 → InvalidValue。
    // 向量来源：上游 uattrs_test.rs:29-33（[1,2,3] 应报错）。
    #[test]
    fn stun_unk_002_odd_length_rejected() {
        assert_eq!(
            UnknownAttributes::from_value(&[1, 2, 3]),
            Err(WireError::InvalidValue)
        );
        assert_eq!(
            UnknownAttributes::from_value(&[1]),
            Err(WireError::InvalidValue)
        );
    }

    // UNK-ATTR-003 — 多类型流式编码（push_with 路径，无固定缓冲上限）。
    #[test]
    fn stun_unk_003_many_types_streaming() {
        // 100 个类型 → 200 字节值，远超任何小型栈缓冲。
        let types: Vec<AttrType> = (0..100u16).map(AttrType).collect();
        let mut buf = vec![0u8; 20 + 4 + 200];
        let mut writer = crate::message::MessageWriter::new(
            &mut buf,
            BINDING_REQUEST,
            TransactionId([0x99; 12]),
        )
        .expect("buffer");
        UnknownAttributes::push_to(&mut writer, &types).expect("push 100 types");
        let written = writer.written();
        assert_eq!(written, 20 + 4 + 200);
        assert_eq!(writer.length(), 204);

        let (msg, _) = Message::decode(&buf[..written]).expect("decode");
        let got =
            UnknownAttributes::from_value(msg.get(ATTR_UNKNOWN_ATTRIBUTES).expect("attr").value)
                .expect("decode");
        assert_eq!(got.len(), 100);
        assert_eq!(got.types().collect::<Vec<_>>(), types);
    }

    // UNK-ATTR-004 — 输出不足 → OutputTooSmall 且不改长度字段。
    #[test]
    fn stun_unk_004_output_too_small_keeps_length() {
        let types = [ATTR_DONT_FRAGMENT, ATTR_CHANNEL_NUMBER];
        let mut buf = [0u8; 20 + 4 + 3]; // 值区差 1 字节
        let mut writer = crate::message::MessageWriter::new(
            &mut buf,
            BINDING_REQUEST,
            TransactionId([0xAA; 12]),
        )
        .expect("buffer");
        assert_eq!(
            UnknownAttributes::push_to(&mut writer, &types),
            Err(WireError::OutputTooSmall)
        );
        assert_eq!(writer.length(), 0);
        assert_eq!(&buf[2..4], &[0x00, 0x00]);
    }
}

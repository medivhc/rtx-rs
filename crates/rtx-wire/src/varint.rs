//! QUIC variable-length integers (`RFC 9000` Appendix A).
//!
//! A varint stores a 62-bit unsigned value. The two most significant bits of
//! the first byte select the width; the remaining bits carry the value.
//!
//! | Width | Prefix | Value bits | Maximum value |
//! |---|---|---|---|
//! | 1 | `00` | 6 | `63` |
//! | 2 | `01` | 14 | `16383` |
//! | 4 | `10` | 30 | `2^30 - 1` |
//! | 8 | `11` | 62 | `2^62 - 1` |
//!
//! Decoders accept every width, including non-minimal encodings: `RFC 9000`
//! section 16 requires a receiver to accept any encoding of a value. Encoders
//! always emit the shortest form.
//!
//! Decoding follows the [`Decode`] contract (`(value, consumed)` from the front
//! of a borrowed slice) and encoding follows the [`Encode`] contract
//! (`encoded_len` plus a write into caller-owned storage). [`VarInt`] implements
//! both traits; the free functions [`decode`], [`encode`] and [`encoded_len`]
//! expose the same shape over raw `u64` values. No path allocates.

use crate::{Cursor, Decode, Encode, WireError};

/// Largest value a QUIC varint can carry: `2^62 - 1`.
pub const MAX_VARINT: u64 = (1 << 62) - 1;

/// Number of bytes the shortest encoding of `value` occupies.
///
/// Values above [`MAX_VARINT`] report `8`; [`encode`] rejects them.
#[must_use]
pub const fn encoded_len(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    }
}

/// Decodes a varint from the front of `input`.
///
/// Returns the value and the number of bytes consumed. Any width is accepted,
/// including non-minimal encodings.
///
/// # Errors
///
/// Returns [`WireError::UnexpectedEnd`] when `input` is shorter than the width
/// selected by the first byte.
pub fn decode(input: &[u8]) -> Result<(u64, usize), WireError> {
    let mut cursor = Cursor::new(input);
    let first = cursor.u8()?;
    let len = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3F);
    for _ in 1..len {
        value = (value << 8) | u64::from(cursor.u8()?);
    }
    Ok((value, len))
}

/// Encodes `value` as the shortest varint into `output`.
///
/// Returns the number of bytes written. Nothing is written when the call
/// errors.
///
/// # Errors
///
/// Returns [`WireError::InvalidValue`] when `value` exceeds [`MAX_VARINT`],
/// and [`WireError::OutputTooSmall`] when `output` cannot hold the encoding.
pub fn encode(value: u64, output: &mut [u8]) -> Result<usize, WireError> {
    if value > MAX_VARINT {
        return Err(WireError::InvalidValue);
    }
    let len = encoded_len(value);
    let target = output.get_mut(..len).ok_or(WireError::OutputTooSmall)?;
    let bytes = value.to_be_bytes();
    target.copy_from_slice(&bytes[8 - len..]);
    target[0] |= match len {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        _ => 0xC0,
    };
    Ok(len)
}

/// A QUIC varint value that passed the [`MAX_VARINT`] check on construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarInt(u64);

impl VarInt {
    /// Wraps `value` after checking the 62-bit bound.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when `value` exceeds [`MAX_VARINT`].
    pub const fn new(value: u64) -> Result<Self, WireError> {
        if value > MAX_VARINT {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(value))
    }

    /// Returns the wrapped value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'a> Decode<'a> for VarInt {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), WireError> {
        let (value, consumed) = decode(input)?;
        Ok((Self(value), consumed))
    }
}

impl Encode for VarInt {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        encoded_len(self.0)
    }

    fn encode(&self, output: &mut [u8]) -> Result<usize, WireError> {
        encode(self.0, output)
    }
}

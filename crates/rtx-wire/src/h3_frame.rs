//! HTTP/3 frame headers (`RFC 9114` section 7.2.1).
//!
//! A frame is a varint type, a varint payload length, then the payload. The
//! payload is exposed as a slice borrowed from the input, so the decoder never
//! copies it. `RFC 9114` requires a receiver to ignore unknown frame types: this
//! codec yields the type and payload unchanged so the caller can skip the frame
//! explicitly instead of the codec silently dropping it.
//!
//! Decoding follows the [`Decode`] contract and encoding follows the [`Encode`]
//! contract. No path allocates.

use crate::varint::{self, VarInt};
use crate::{Decode, Encode, WireError};

/// An HTTP/3 frame whose payload borrows the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    frame_type: VarInt,
    payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Builds a frame from a validated varint type and a borrowed payload.
    #[must_use]
    pub const fn new(frame_type: VarInt, payload: &'a [u8]) -> Self {
        Self {
            frame_type,
            payload,
        }
    }

    /// Returns the frame type, including types this codec does not interpret.
    #[must_use]
    pub const fn frame_type(self) -> VarInt {
        self.frame_type
    }

    /// Returns the payload slice borrowed from the decoded input.
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
}

impl<'a> Decode<'a> for Frame<'a> {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), WireError> {
        let (frame_type, type_len) = VarInt::decode(input)?;
        let (payload_len, len_len) = varint::decode(&input[type_len..])?;
        // A declared length wider than `usize` cannot fit in any input slice.
        let payload_len = usize::try_from(payload_len).map_err(|_| WireError::UnexpectedEnd)?;
        let start = type_len + len_len;
        let end = start.checked_add(payload_len).ok_or(WireError::Overflow)?;
        let payload = input.get(start..end).ok_or(WireError::UnexpectedEnd)?;
        Ok((
            Self {
                frame_type,
                payload,
            },
            end,
        ))
    }
}

impl Encode for Frame<'_> {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        let payload_len = self.payload.len();
        varint::encoded_len(self.frame_type.get())
            + varint::encoded_len(u64::try_from(payload_len).unwrap_or(u64::MAX))
            + payload_len
    }

    fn encode(&self, output: &mut [u8]) -> Result<usize, WireError> {
        let payload_len = u64::try_from(self.payload.len()).map_err(|_| WireError::Overflow)?;
        let type_len = varint::encoded_len(self.frame_type.get());
        let len_len = varint::encoded_len(payload_len);
        let total = type_len + len_len + self.payload.len();
        let target = output.get_mut(..total).ok_or(WireError::OutputTooSmall)?;
        varint::encode(self.frame_type.get(), target)?;
        varint::encode(payload_len, &mut target[type_len..])?;
        target[type_len + len_len..].copy_from_slice(self.payload);
        Ok(total)
    }
}

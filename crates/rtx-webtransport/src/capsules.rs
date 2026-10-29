//! WebTransport capsules over the Capsule Protocol (`RFC 9297` section 3.2).
//!
//! A capsule is a varint type, a varint payload length, then the payload
//! (`RFC 9297`: "Capsule Type" and "Capsule Length"). Capsules are framed by
//! length; unknown types never fail decoding, the caller receives them intact
//! and decides to skip them.
//!
//! # Draft basis
//!
//! The selected drafts and the type constants below are public draft values.
//! They have **not** been cross-checked against a Chrome capture; that check is
//! the browser-interop work of `R6-3` (`M3-B1`), not this unit.
//!
//! | Capsule | Type | Payload | Source |
//! |---|---|---|---|
//! | `WT_CLOSE_SESSION` | `0x2843` | 32-bit error code, then a UTF-8 message of at most 1024 bytes | `draft-ietf-webtrans-http3-15` section 6 and section 9.6 |
//! | `WT_DRAIN_SESSION` | `0x78AE` | empty | `draft-ietf-webtrans-http3-15` section 4.6 and section 9.6 |
//! | `WT_STREAM` (no FIN) | `0x190B_4D3C` | stream ID varint, then stream data | `draft-ietf-webtrans-http2-15` section 6.4 and section 11.4 |
//! | `WT_STREAM` (FIN) | `0x190B_4D3B` | same; the least significant type bit is the FIN flag | `draft-ietf-webtrans-http2-15` section 6.4 |
//!
//! The capsule-based WebTransport variant of `draft-ietf-webtrans-http3-15`
//! section 2.1.2 defers its stream capsules to the HTTP/2 document, which is
//! why the `WT_STREAM` values come from that draft. Flow-control capsules of
//! either draft (`WT_MAX_STREAMS`, `WT_MAX_DATA`, `WT_STREAMS_BLOCKED`,
//! `WT_DATA_BLOCKED`, ...) are not interpreted here and decode as
//! [`Capsule::Unknown`], which the caller may ignore.
//!
//! # Bounds
//!
//! [`Capsule::decode`] rejects a declared payload longer than the
//! caller-supplied `max_len` with [`CapsuleError::TooLarge`]; a
//! `WT_CLOSE_SESSION` message longer than [`MAX_CLOSE_MESSAGE_LEN`] is rejected
//! as [`CapsuleError::Malformed`]. Neither path allocates.

use crate::ids::StreamId;
use rtx_wire::varint;
use rtx_wire::{Encode, WireError};

/// `WT_CLOSE_SESSION` capsule type (`draft-ietf-webtrans-http3-15` section 9.6).
pub const WT_CLOSE_SESSION: u64 = 0x2843;

/// `WT_DRAIN_SESSION` capsule type (`draft-ietf-webtrans-http3-15` section 9.6).
pub const WT_DRAIN_SESSION: u64 = 0x78AE;

/// `WT_STREAM` capsule type without the FIN flag
/// (`draft-ietf-webtrans-http2-15` section 6.4).
pub const WT_STREAM_NO_FIN: u64 = 0x190B_4D3C;

/// `WT_STREAM` capsule type with the FIN flag set
/// (`draft-ietf-webtrans-http2-15` section 6.4).
pub const WT_STREAM_FIN: u64 = 0x190B_4D3B;

/// Largest `WT_CLOSE_SESSION` application message
/// (`draft-ietf-webtrans-http3-15` section 6).
pub const MAX_CLOSE_MESSAGE_LEN: usize = 1024;

/// Capsule decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleError {
    /// The input ended before the framing or the declared payload was complete,
    /// or a nested varint was truncated.
    Truncated,
    /// The declared payload length exceeds the caller-supplied limit.
    TooLarge {
        /// The limit the caller passed to [`Capsule::decode`].
        max_len: usize,
    },
    /// The payload violates the selected draft's semantics for its type.
    Malformed,
    /// The output buffer cannot hold the encoded capsule.
    OutputTooSmall,
    /// The underlying varint codec rejected a value while encoding.
    Wire(WireError),
}

/// One framed WebTransport capsule; payloads borrow the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capsule<'a> {
    /// `WT_CLOSE_SESSION`: application error code and UTF-8 message.
    CloseSession {
        /// 32-bit application error code.
        code: u32,
        /// UTF-8 error message, at most [`MAX_CLOSE_MESSAGE_LEN`] bytes.
        message: &'a str,
    },
    /// `WT_DRAIN_SESSION`: a zero-length graceful-shutdown signal.
    DrainSession,
    /// `WT_STREAM`: a stream ID association with optional FIN and data.
    Stream {
        /// WebTransport stream ID carried by the capsule.
        stream_id: StreamId,
        /// Whether the least significant type bit marks the end of the stream.
        fin: bool,
        /// Stream data following the stream ID.
        data: &'a [u8],
    },
    /// A capsule type this codec does not interpret, preserved for the caller.
    Unknown {
        /// Capsule type as read from the wire.
        capsule_type: u64,
        /// Payload bytes, unmodified.
        payload: &'a [u8],
    },
}

impl<'a> Capsule<'a> {
    /// Decodes one capsule from the front of `input`.
    ///
    /// Returns the capsule and the number of bytes consumed. `max_len` bounds
    /// the declared payload length; the caller chooses it per
    /// `ARCHITECTURE.md` section 16.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleError::TooLarge`] when the declared payload exceeds
    /// `max_len`, [`CapsuleError::Truncated`] when the framing or payload is
    /// incomplete, and [`CapsuleError::Malformed`] when a known capsule's
    /// payload violates the draft.
    pub fn decode(input: &'a [u8], max_len: usize) -> Result<(Self, usize), CapsuleError> {
        let (capsule_type, type_len) =
            varint::decode(input).map_err(|_| CapsuleError::Truncated)?;
        let (payload_len, len_len) =
            varint::decode(&input[type_len..]).map_err(|_| CapsuleError::Truncated)?;
        // A length wider than `usize` cannot fit in any input slice.
        let payload_len = usize::try_from(payload_len).map_err(|_| CapsuleError::Truncated)?;
        if payload_len > max_len {
            return Err(CapsuleError::TooLarge { max_len });
        }
        let start = type_len + len_len;
        let end = start
            .checked_add(payload_len)
            .ok_or(CapsuleError::Truncated)?;
        let payload = input.get(start..end).ok_or(CapsuleError::Truncated)?;
        let capsule = Self::from_payload(capsule_type, payload)?;
        Ok((capsule, end))
    }

    /// Number of bytes [`Encode::encode`] writes for this capsule.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let (capsule_type, payload_len) = self.framing();
        varint::encoded_len(capsule_type) + varint::encoded_len(len_u64(payload_len)) + payload_len
    }

    /// Capsule type and payload length used to frame the payload.
    fn framing(&self) -> (u64, usize) {
        match *self {
            Self::CloseSession { message, .. } => (WT_CLOSE_SESSION, 4 + message.len()),
            Self::DrainSession => (WT_DRAIN_SESSION, 0),
            Self::Stream {
                stream_id,
                data,
                fin,
            } => (
                if fin { WT_STREAM_FIN } else { WT_STREAM_NO_FIN },
                varint::encoded_len(stream_id.get()) + data.len(),
            ),
            Self::Unknown {
                capsule_type,
                payload,
            } => (capsule_type, payload.len()),
        }
    }

    /// Interprets the payload of a known capsule type.
    fn from_payload(capsule_type: u64, payload: &'a [u8]) -> Result<Self, CapsuleError> {
        match capsule_type {
            WT_CLOSE_SESSION => {
                let (code_bytes, message) =
                    payload.split_at_checked(4).ok_or(CapsuleError::Malformed)?;
                let code = u32::from_be_bytes([
                    code_bytes[0],
                    code_bytes[1],
                    code_bytes[2],
                    code_bytes[3],
                ]);
                if message.len() > MAX_CLOSE_MESSAGE_LEN {
                    return Err(CapsuleError::Malformed);
                }
                let message = core::str::from_utf8(message).map_err(|_| CapsuleError::Malformed)?;
                Ok(Self::CloseSession { code, message })
            }
            WT_DRAIN_SESSION => {
                if payload.is_empty() {
                    Ok(Self::DrainSession)
                } else {
                    Err(CapsuleError::Malformed)
                }
            }
            WT_STREAM_FIN | WT_STREAM_NO_FIN => {
                let (stream_id, id_len) =
                    varint::decode(payload).map_err(|_| CapsuleError::Malformed)?;
                let stream_id = StreamId::new(stream_id).map_err(|_| CapsuleError::Malformed)?;
                Ok(Self::Stream {
                    stream_id,
                    fin: capsule_type == WT_STREAM_FIN,
                    data: &payload[id_len..],
                })
            }
            capsule_type => Ok(Self::Unknown {
                capsule_type,
                payload,
            }),
        }
    }
}

impl Encode for Capsule<'_> {
    type Error = CapsuleError;

    fn encoded_len(&self) -> usize {
        Capsule::encoded_len(self)
    }

    fn encode(&self, output: &mut [u8]) -> Result<usize, CapsuleError> {
        let total = self.encoded_len();
        let target = output
            .get_mut(..total)
            .ok_or(CapsuleError::OutputTooSmall)?;
        let (capsule_type, payload_len) = self.framing();
        let type_len = varint::encode(capsule_type, target).map_err(CapsuleError::Wire)?;
        let len_len = varint::encode(len_u64(payload_len), &mut target[type_len..])
            .map_err(CapsuleError::Wire)?;
        let body = &mut target[type_len + len_len..];
        match *self {
            Self::CloseSession { code, message } => {
                body[..4].copy_from_slice(&code.to_be_bytes());
                body[4..].copy_from_slice(message.as_bytes());
            }
            Self::DrainSession => {}
            Self::Stream {
                stream_id, data, ..
            } => {
                let id_len = varint::encode(stream_id.get(), body).map_err(CapsuleError::Wire)?;
                body[id_len..].copy_from_slice(data);
            }
            Self::Unknown { payload, .. } => body.copy_from_slice(payload),
        }
        Ok(total)
    }
}

/// `usize` to `u64`; every supported target's `usize` fits `u64`.
fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

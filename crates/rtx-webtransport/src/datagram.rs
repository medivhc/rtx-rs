//! HTTP Datagram mapping to a WebTransport session
//! (`RFC 9298` section 2.1, `draft-ietf-webtrans-http3-15` section 4.5).
//!
//! The HTTP Datagram payload starts with the quarter stream ID of the CONNECT
//! stream that established the session, followed by the WebTransport payload.
//! A decoder therefore needs the caller's [`SessionId`] and rejects any payload
//! whose quarter stream ID denotes a different session.
//!
//! The size bound is the caller-negotiated QUIC `max_datagram_frame_size`
//! (`RFC 9221` section 3): the value `rtx-quic` reports in
//! `DatagramError::TooLarge { max_len }`. This crate takes that value per call
//! and never hard-codes or truncates it; an oversized payload is reported as
//! [`DatagramError::TooLarge`] before any parsing.

use crate::ids::{QuarterStreamId, SessionId};
use rtx_wire::varint;

/// Datagram decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramError {
    /// The payload exceeds the caller-supplied negotiated limit.
    TooLarge {
        /// The negotiated `max_datagram_frame_size` the caller passed in.
        max_len: usize,
    },
    /// The quarter stream ID belongs to a different session.
    WrongSession,
    /// The payload is empty, its quarter stream ID is truncated, or the quarter
    /// stream ID exceeds the 60-bit space.
    Malformed,
    /// The output buffer cannot hold the encoded datagram.
    OutputTooSmall,
}

/// A datagram payload associated with the session that owns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram<'a> {
    session: SessionId,
    payload: &'a [u8],
}

impl<'a> Datagram<'a> {
    /// Returns the session this datagram was validated against.
    #[must_use]
    pub const fn session(self) -> SessionId {
        self.session
    }

    /// Returns the WebTransport payload that followed the quarter stream ID.
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
}

/// Decodes an HTTP Datagram payload for `session`.
///
/// Returns the datagram and the number of bytes consumed (always the whole
/// input). `max_len` is the caller's negotiated `max_datagram_frame_size`.
///
/// # Errors
///
/// Returns [`DatagramError::TooLarge`] when `input` exceeds `max_len`,
/// [`DatagramError::Malformed`] when the quarter stream ID is truncated or out
/// of range, and [`DatagramError::WrongSession`] when the quarter stream ID
/// does not denote `session`.
pub fn decode(
    input: &[u8],
    session: SessionId,
    max_len: usize,
) -> Result<(Datagram<'_>, usize), DatagramError> {
    if input.len() > max_len {
        return Err(DatagramError::TooLarge { max_len });
    }
    let (quarter, header_len) = varint::decode(input).map_err(|_| DatagramError::Malformed)?;
    let quarter = QuarterStreamId::new(quarter).map_err(|_| DatagramError::Malformed)?;
    if quarter != session.quarter() {
        return Err(DatagramError::WrongSession);
    }
    Ok((
        Datagram {
            session,
            payload: &input[header_len..],
        },
        input.len(),
    ))
}

/// Encodes the HTTP Datagram payload for `session`.
///
/// Writes the quarter stream ID varint and then `payload`, returning the
/// number of bytes written. `max_len` is the caller's negotiated
/// `max_datagram_frame_size`.
///
/// # Errors
///
/// Returns [`DatagramError::TooLarge`] when the encoded payload would exceed
/// `max_len`, and [`DatagramError::OutputTooSmall`] when `output` cannot hold
/// it.
pub fn encode(
    session: SessionId,
    payload: &[u8],
    max_len: usize,
    output: &mut [u8],
) -> Result<usize, DatagramError> {
    let quarter = session.quarter();
    let header_len = quarter.encoded_len();
    let total = header_len
        .checked_add(payload.len())
        .ok_or(DatagramError::TooLarge { max_len })?;
    if total > max_len {
        return Err(DatagramError::TooLarge { max_len });
    }
    let target = output
        .get_mut(..total)
        .ok_or(DatagramError::OutputTooSmall)?;
    let written = varint::encode(quarter.get(), target).map_err(|_| DatagramError::Malformed)?;
    target[written..].copy_from_slice(payload);
    Ok(total)
}

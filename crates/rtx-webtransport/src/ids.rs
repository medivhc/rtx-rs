//! WebTransport over HTTP/3 identifiers
//! (`draft-ietf-webtrans-http3-15` section 2.2, `RFC 9298` section 2.1).
//!
//! - A WebTransport session is identified by the QUIC stream ID of the extended
//!   CONNECT request that established it ("Session ID"). That stream is always
//!   client-initiated and bidirectional: `RFC 9000` section 2.1 assigns it the
//!   type bits `00`.
//! - WebTransport data streams are identified by their 62-bit QUIC stream IDs.
//! - HTTP Datagrams carry a quarter stream ID: the CONNECT stream ID divided by
//!   four.
//!
//! Every identifier is stored as `u64`. Nothing is converted through `usize`,
//! so a 32-bit target cannot truncate an identifier; `2^62 - 1` remains an exact
//! round trip. The quarter stream ID varint codec reuses
//! [`rtx_wire::varint`] instead of defining a second varint implementation.

use rtx_wire::varint;
use rtx_wire::{Decode, Encode, WireError};

/// Largest valid QUIC stream ID: `2^62 - 1` (`RFC 9000` section 2.1).
const MAX_STREAM_ID: u64 = varint::MAX_VARINT;

/// Identifier validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdError {
    /// The value exceeds the 62-bit stream ID space, or the 60-bit quarter
    /// stream ID space derived from it.
    OutOfRange,
    /// The CONNECT stream ID is not client-initiated bidirectional.
    NotClientBidirectional,
    /// The stream ID is not divisible by four and has no quarter stream ID.
    NotQuarterAligned,
    /// The underlying varint codec failed.
    Wire(WireError),
}

/// A WebTransport data stream identifier (a 62-bit QUIC stream ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(u64);

impl StreamId {
    /// Largest valid stream ID.
    pub const MAX: u64 = MAX_STREAM_ID;

    /// Wraps a stream ID after the 62-bit range check.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::OutOfRange`] when `value` exceeds [`StreamId::MAX`].
    pub const fn new(value: u64) -> Result<Self, IdError> {
        if value > MAX_STREAM_ID {
            return Err(IdError::OutOfRange);
        }
        Ok(Self(value))
    }

    /// Returns the wrapped stream ID.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A WebTransport session identifier: the CONNECT stream ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u64);

impl SessionId {
    /// Wraps a CONNECT stream ID after range and stream-type validation.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::OutOfRange`] when the ID exceeds the 62-bit stream ID
    /// space, and [`IdError::NotClientBidirectional`] when the low two type bits
    /// are not `00` (`RFC 9000` section 2.1).
    pub const fn new(connect_stream_id: u64) -> Result<Self, IdError> {
        if connect_stream_id > MAX_STREAM_ID {
            return Err(IdError::OutOfRange);
        }
        if connect_stream_id & 0x03 != 0 {
            return Err(IdError::NotClientBidirectional);
        }
        Ok(Self(connect_stream_id))
    }

    /// Returns the wrapped CONNECT stream ID.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the quarter stream ID used by HTTP Datagrams for this session.
    ///
    /// The conversion is exact because [`SessionId::new`] guarantees the stream
    /// ID is a multiple of four.
    #[must_use]
    pub const fn quarter(self) -> QuarterStreamId {
        QuarterStreamId(self.0 >> 2)
    }
}

/// The quarter stream ID carried at the start of an HTTP Datagram payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QuarterStreamId(u64);

impl QuarterStreamId {
    /// Largest valid quarter stream ID: `(2^62 - 1) / 4`.
    pub const MAX: u64 = MAX_STREAM_ID >> 2;

    /// Wraps a quarter stream ID after the 60-bit range check.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::OutOfRange`] when `quarter` exceeds
    /// [`QuarterStreamId::MAX`].
    pub const fn new(quarter: u64) -> Result<Self, IdError> {
        if quarter > Self::MAX {
            return Err(IdError::OutOfRange);
        }
        Ok(Self(quarter))
    }

    /// Derives the quarter stream ID of a stream ID.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::OutOfRange`] when `stream_id` exceeds the 62-bit
    /// stream ID space, and [`IdError::NotQuarterAligned`] when it is not
    /// divisible by four.
    pub const fn from_stream_id(stream_id: u64) -> Result<Self, IdError> {
        if stream_id > MAX_STREAM_ID {
            return Err(IdError::OutOfRange);
        }
        if stream_id & 0x03 != 0 {
            return Err(IdError::NotQuarterAligned);
        }
        Ok(Self(stream_id >> 2))
    }

    /// Returns the wrapped quarter value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the stream ID this quarter belongs to.
    ///
    /// The value fits the 62-bit stream ID space because [`QuarterStreamId::new`]
    /// bounds it.
    #[must_use]
    pub const fn stream_id(self) -> u64 {
        self.0 << 2
    }

    /// Number of bytes the varint encoding of this value occupies.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        varint::encoded_len(self.0)
    }
}

impl<'a> Decode<'a> for QuarterStreamId {
    type Error = IdError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), IdError> {
        let (value, consumed) = varint::decode(input).map_err(IdError::Wire)?;
        let quarter = Self::new(value)?;
        Ok((quarter, consumed))
    }
}

impl Encode for QuarterStreamId {
    type Error = IdError;

    fn encoded_len(&self) -> usize {
        varint::encoded_len(self.0)
    }

    fn encode(&self, output: &mut [u8]) -> Result<usize, IdError> {
        varint::encode(self.0, output).map_err(IdError::Wire)
    }
}

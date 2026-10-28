//! Explicit, typed errors for every fallible facade operation.
//!
//! No operation panics on invalid state: a closed connection, a closed
//! stream, a wrong-direction stream or an oversized DATAGRAM is reported as a
//! value.

use std::fmt;

/// Failure to build or configure an [`crate::Endpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndpointError {
    /// A static configuration value is outside its legal range.
    InvalidConfiguration(&'static str),
    /// Rustls rejected the certificate chain, private key or trust roots.
    Tls(String),
    /// The provider did not offer the QUIC initial cipher suite.
    CipherSuite(String),
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(what) => {
                write!(f, "invalid QUIC endpoint configuration: {what}")
            }
            Self::Tls(error) => write!(f, "TLS configuration failed: {error}"),
            Self::CipherSuite(error) => write!(f, "QUIC initial cipher suite unavailable: {error}"),
        }
    }
}

impl std::error::Error for EndpointError {}

/// Failure to start an outgoing connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectError {
    /// The endpoint cannot create further connections.
    EndpointStopping,
    /// The connection-ID space is exhausted.
    CidsExhausted,
    /// The server name is not a valid DNS name.
    InvalidServerName,
    /// The remote address is unusable (port zero or unspecified address).
    InvalidRemoteAddress,
    /// The endpoint does not support the configured QUIC version.
    UnsupportedVersion,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EndpointStopping => "endpoint cannot create further connections",
            Self::CidsExhausted => "connection-ID space exhausted",
            Self::InvalidServerName => "invalid server name",
            Self::InvalidRemoteAddress => "invalid remote address",
            Self::UnsupportedVersion => "unsupported QUIC version",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ConnectError {}

/// Failure to accept or refuse a pending incoming connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcceptError {
    /// The handle is unknown or the incoming connection was already consumed.
    UnknownIncoming,
    /// The server rejected the connection; any protocol response (for
    /// example `CONNECTION_REFUSED`) is queued and emitted by
    /// [`crate::Endpoint::poll_transmit`].
    Rejected,
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnknownIncoming => "unknown or already consumed incoming connection",
            Self::Rejected => "server rejected the incoming connection",
        };
        f.write_str(message)
    }
}

impl std::error::Error for AcceptError {}

/// Stream operation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamError {
    /// The connection handle is unknown.
    UnknownConnection,
    /// The connection is closed or draining.
    Closed,
    /// Flow control currently prevents the write; retry after transmit
    /// polling and peer credit updates.
    Blocked,
    /// The peer’s stream concurrency limit is reached.
    StreamLimitReached,
    /// The operation is illegal for the stream’s direction or initiator.
    WrongDirection,
    /// The stream was never opened, or is already finished or reset.
    StreamClosed,
    /// The peer asked us to stop sending.
    StoppedByPeer {
        /// Application error code carried by `STOP_SENDING`.
        error_code: u64,
    },
    /// The peer reset the sending direction.
    ResetByPeer {
        /// Application error code carried by `RESET_STREAM`.
        error_code: u64,
    },
    /// The caller passed an empty read buffer.
    EmptyBuffer,
    /// The application error code does not fit a QUIC varint.
    ErrorCodeOutOfRange,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownConnection => f.write_str("unknown connection"),
            Self::Closed => f.write_str("connection is closed"),
            Self::Blocked => f.write_str("stream flow control blocked"),
            Self::StreamLimitReached => f.write_str("stream concurrency limit reached"),
            Self::WrongDirection => f.write_str("operation is invalid for this stream direction"),
            Self::StreamClosed => f.write_str("stream is closed"),
            Self::StoppedByPeer { error_code } => {
                write!(f, "peer stopped the stream with code {error_code}")
            }
            Self::ResetByPeer { error_code } => {
                write!(f, "peer reset the stream with code {error_code}")
            }
            Self::EmptyBuffer => f.write_str("read buffer is empty"),
            Self::ErrorCodeOutOfRange => {
                f.write_str("application error code exceeds a QUIC varint")
            }
        }
    }
}

impl std::error::Error for StreamError {}

/// DATAGRAM operation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DatagramError {
    /// The connection handle is unknown.
    UnknownConnection,
    /// The connection is closed or draining.
    Closed,
    /// DATAGRAM support is disabled locally.
    Disabled,
    /// The peer did not advertise DATAGRAM support.
    UnsupportedByPeer,
    /// The payload exceeds the negotiated or path limit; nothing is
    /// truncated.
    TooLarge {
        /// Largest payload the connection can currently accept.
        max_len: usize,
    },
    /// The send buffer is full; retry after transmit polling.
    WouldBlock,
    /// The received datagram does not fit the caller buffer; it is discarded
    /// rather than truncated.
    BufferTooSmall {
        /// Size of the discarded datagram.
        datagram_len: usize,
    },
}

impl fmt::Display for DatagramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownConnection => f.write_str("unknown connection"),
            Self::Closed => f.write_str("connection is closed"),
            Self::Disabled => f.write_str("DATAGRAM support is disabled locally"),
            Self::UnsupportedByPeer => f.write_str("peer does not support DATAGRAM"),
            Self::TooLarge { max_len } => write!(f, "datagram exceeds the {max_len}-byte limit"),
            Self::WouldBlock => f.write_str("datagram send buffer is full"),
            Self::BufferTooSmall { datagram_len } => {
                write!(
                    f,
                    "receive buffer too small for the {datagram_len}-byte datagram"
                )
            }
        }
    }
}

impl std::error::Error for DatagramError {}

/// Connection close failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseError {
    /// The connection handle is unknown.
    UnknownConnection,
    /// The application error code does not fit a QUIC varint.
    ErrorCodeOutOfRange,
}

impl fmt::Display for CloseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnknownConnection => "unknown connection",
            Self::ErrorCodeOutOfRange => "application error code exceeds a QUIC varint",
        };
        f.write_str(message)
    }
}

impl std::error::Error for CloseError {}

/// Metrics snapshot failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetricsError {
    /// The connection handle is unknown.
    UnknownConnection,
}

impl fmt::Display for MetricsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown connection")
    }
}

impl std::error::Error for MetricsError {}

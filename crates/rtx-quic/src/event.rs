//! Application-facing events emitted by [`crate::Endpoint::poll_event`].

use crate::ConnectionId;
use crate::stream::StreamEvent;

/// One ordered facade event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Connection (or pending incoming connection) the event belongs to.
    pub connection: ConnectionId,
    /// Event payload.
    pub kind: EventKind,
}

/// Event payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventKind {
    /// A new incoming connection is waiting for accept or refuse.
    Incoming,
    /// The TLS 1.3 handshake completed on this connection.
    HandshakeComplete(HandshakeInfo),
    /// The handshake failed before completion.
    HandshakeFailed(HandshakeFailure),
    /// A stream event.
    Stream(StreamEvent),
    /// One or more DATAGRAMs are queued for
    /// [`crate::Endpoint::poll_datagram`].
    DatagramReceived,
    /// The connection closed locally, remotely, or by timeout.
    Closed(CloseReason),
}

/// Data captured at the moment the handshake completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeInfo {
    /// Negotiated ALPN protocol, if any.
    pub alpn: Option<Vec<u8>>,
    /// Peer transport parameters in the canonical encoding produced by
    /// `quinn-proto`’s `TransportParameters::write`.
    pub peer_transport_parameters: PeerTransportParameters,
    /// Whether the peer advertised QUIC DATAGRAM support.
    pub datagram_supported: bool,
}

/// Peer transport parameters as encoded by `quinn-proto`.
///
/// `quinn-proto` decodes and validates the parameters but keeps every field
/// `pub(crate)`; the facade therefore carries the canonical re-encoding
/// produced by the upstream public `TransportParameters::write` method
/// instead of inventing a private decoder. Callers that need a field parse
/// these bytes; the DATAGRAM support flag is exposed separately as
/// [`HandshakeInfo::datagram_supported`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTransportParameters {
    encoded: Vec<u8>,
}

impl PeerTransportParameters {
    pub(crate) const fn empty() -> Self {
        Self {
            encoded: Vec::new(),
        }
    }

    pub(crate) fn from_encoded(encoded: Vec<u8>) -> Self {
        Self { encoded }
    }

    /// The encoded transport parameters (may be empty when the peer supplied
    /// none).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

/// Why a handshake failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandshakeFailure {
    /// A TLS certificate alert (bad/unsupported/revoked/expired/unknown
    /// certificate, unknown CA, access denied, decode/decrypt error).
    Certificate,
    /// No ALPN protocol was agreed (`no_application_protocol`).
    Alpn,
    /// The peer’s transport parameters were invalid
    /// (`TRANSPORT_PARAMETER_ERROR`).
    TransportParameter,
    /// The handshake or idle timer expired.
    Timeout,
    /// The peer closed the connection during the handshake (for example a
    /// server `CONNECTION_REFUSED`).
    PeerClosed,
    /// The local application closed the connection during the handshake.
    LocalClose,
    /// Any other transport or version error.
    Protocol,
}

/// Where a close originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseOrigin {
    /// The local application called [`crate::Endpoint::close`].
    Local,
    /// The peer closed the connection.
    Remote,
}

/// Why a connection closed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// An application close (`CONNECTION_CLOSE` with application error
    /// code).
    Application {
        /// Local or remote origin.
        origin: CloseOrigin,
        /// Application error code.
        error_code: u64,
        /// Application reason bytes.
        reason: Vec<u8>,
    },
    /// A transport-level close with a QUIC transport error code.
    Transport {
        /// QUIC transport error code.
        error_code: u64,
    },
    /// The idle timeout expired.
    TimedOut,
    /// The peer is unable to continue (for example a stateless reset).
    Reset,
    /// The peer does not support any offered QUIC version.
    VersionMismatch,
}

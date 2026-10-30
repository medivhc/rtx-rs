//! Error taxonomy for the DTLS 1.2 handshake and DTLS-SRTP export.
//!
//! Every handshake failure is terminal: the state machine moves to
//! `HandshakeState::Failed`, drops its ephemeral key handle and zeroizes its
//! key-schedule buffers. No variant is produced by a panic path; all decoders
//! validate lengths before indexing.

use rtx_crypto::CryptoError;

use crate::error::RecordError;

/// A failure in the minimal DTLS 1.2 handshake profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// The record layer rejected a frame or an AEAD operation.
    Record(RecordError),
    /// A crypto provider call failed.
    Crypto(CryptoError),
    /// Retransmission timers are zero or the initial interval exceeds the cap.
    InvalidConfig,
    /// A client configuration did not provide the peer's Ed25519 public key.
    MissingPeerPublicKey,
    /// A server configuration did not provide a signing-key handle.
    MissingSigningKey,
    /// The `ClientHello` or `ServerHello` version is not DTLS 1.2 `{254, 253}`.
    UnsupportedVersion,
    /// The peer does not offer the single profile this crate implements.
    NoCommonAlgorithm,
    /// A handshake message type outside the minimal profile was received.
    UnsupportedMessage(u8),
    /// A handshake header or body was truncated or internally inconsistent.
    MalformedMessage,
    /// A handshake message exceeds [`crate::MAX_HANDSHAKE_MESSAGE_LEN`].
    MessageTooLong,
    /// A fragmented handshake message was received; reassembly is out of scope.
    FragmentedMessage,
    /// The DTLS `message_seq` is ahead of the expected value.
    UnexpectedMessageSequence {
        /// Sequence number the state machine expected next.
        expected: u16,
        /// Sequence number carried by the received message.
        received: u16,
    },
    /// A well-formed message is not accepted in the current state.
    UnexpectedMessage,
    /// A record content type outside the handshake profile was received.
    UnexpectedRecord,
    /// A `ChangeCipherSpec` record arrived in the wrong state or epoch.
    UnexpectedChangeCipherSpec,
    /// The peer sent an alert; the handshake aborts.
    PeerAlert,
    /// The peer's `ServerKeyExchange` signature did not verify.
    InvalidSignature,
    /// ECDHE produced an all-zero shared secret or rejected the peer key.
    ZeroSharedSecret,
    /// Finished `verify_data` did not match the local computation.
    FinishedMismatch,
    /// The fixed transcript buffer cannot hold another handshake message.
    TranscriptTooLong,
    /// More outbound messages were queued than the fixed flight can hold.
    FlightFull,
    /// A protected outbound record was queued before its key existed.
    KeyMaterialUnavailable,
    /// The DTLS-SRTP exporter failed.
    SrtpExport(SrtpExportError),
    /// Retransmission budget exhausted before the peer completed its flight.
    Timeout,
    /// The machine already failed; no further input is accepted.
    Failed,
}

impl From<RecordError> for HandshakeError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

impl From<CryptoError> for HandshakeError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<SrtpExportError> for HandshakeError {
    fn from(error: SrtpExportError) -> Self {
        Self::SrtpExport(error)
    }
}

/// Failure of the RFC 5764 DTLS-SRTP exporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpExportError {
    /// The requested SRTP protection profile is not implemented.
    UnsupportedProfile(u16),
    /// The underlying HMAC/PRF provider failed.
    Crypto(CryptoError),
}

impl From<CryptoError> for SrtpExportError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    // DTLS-HS-ERR-001 — every variant is constructible, distinct and printable.
    #[test]
    fn handshake_error_variants_are_distinct_and_printable() {
        let variants = [
            HandshakeError::Record(RecordError::UnexpectedEnd),
            HandshakeError::Crypto(CryptoError::Unsupported),
            HandshakeError::InvalidConfig,
            HandshakeError::MissingPeerPublicKey,
            HandshakeError::MissingSigningKey,
            HandshakeError::UnsupportedVersion,
            HandshakeError::NoCommonAlgorithm,
            HandshakeError::UnsupportedMessage(1),
            HandshakeError::MalformedMessage,
            HandshakeError::MessageTooLong,
            HandshakeError::FragmentedMessage,
            HandshakeError::UnexpectedMessageSequence {
                expected: 2,
                received: 3,
            },
            HandshakeError::UnexpectedMessage,
            HandshakeError::UnexpectedRecord,
            HandshakeError::UnexpectedChangeCipherSpec,
            HandshakeError::PeerAlert,
            HandshakeError::InvalidSignature,
            HandshakeError::ZeroSharedSecret,
            HandshakeError::FinishedMismatch,
            HandshakeError::TranscriptTooLong,
            HandshakeError::FlightFull,
            HandshakeError::KeyMaterialUnavailable,
            HandshakeError::SrtpExport(SrtpExportError::UnsupportedProfile(9)),
            HandshakeError::Timeout,
            HandshakeError::Failed,
        ];
        for (index, left) in variants.iter().enumerate() {
            assert_ne!(format!("{left:?}"), "");
            for (other, right) in variants.iter().enumerate() {
                if index != other {
                    assert_ne!(left, right);
                }
            }
        }
        let copied = variants[0]; // Copy
        assert_eq!(copied, HandshakeError::Record(RecordError::UnexpectedEnd));
    }

    // DTLS-HS-ERR-002 — both conversions preserve the wrapped error.
    #[test]
    fn error_conversions_preserve_the_cause() {
        assert_eq!(
            HandshakeError::from(RecordError::Replay),
            HandshakeError::Record(RecordError::Replay)
        );
        assert_eq!(
            HandshakeError::from(CryptoError::InvalidSignature),
            HandshakeError::Crypto(CryptoError::InvalidSignature)
        );
        assert_eq!(
            HandshakeError::from(SrtpExportError::UnsupportedProfile(2)),
            HandshakeError::SrtpExport(SrtpExportError::UnsupportedProfile(2))
        );
        assert_eq!(
            SrtpExportError::from(CryptoError::BackendFailure),
            SrtpExportError::Crypto(CryptoError::BackendFailure)
        );
    }
}

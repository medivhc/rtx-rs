//! Error taxonomy for the DTLS 1.2 record layer.
//!
//! Every decoder failure is reported as a distinct variant so a caller can
//! tell a malformed record from a replay, a stale epoch or an authentication
//! failure without inspecting bytes. No variant is ever constructed by a
//! panic path: the record layer validates before it writes or indexes.

use rtx_crypto::CryptoError;

/// A failure in DTLS 1.2 record framing, replay detection or record
/// protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// The input ends before a complete header, or before the fragment the
    /// header promised.
    UnexpectedEnd,
    /// The length field and the available bytes disagree: a strict decode was
    /// handed trailing bytes, or an explicit nonce does not match the header.
    LengthMismatch,
    /// The declared fragment exceeds the DTLS 1.2 record limit.
    RecordTooLong,
    /// A protected record is shorter than its explicit nonce plus AEAD tag.
    CiphertextTooShort,
    /// The record version is not DTLS 1.2 `{254, 253}`.
    ///
    /// DTLS 1.0 (`{254, 255}`) and DTLS 1.3 (`{254, 252}`) are deliberately
    /// rejected: this crate freezes the DTLS 1.2 contract only.
    UnsupportedVersion,
    /// The content type is not one of the four types defined by RFC 6347.
    InvalidContentType,
    /// The 8-byte explicit nonce does not equal `epoch || sequence_number`.
    InvalidExplicitNonce,
    /// An epoch older than the installed read epoch was received.
    StaleEpoch,
    /// An epoch newer than the installed read epoch was received.
    UnexpectedEpoch,
    /// The sequence number was already accepted inside the replay window.
    Replay,
    /// The sequence number fell out of the 64-record replay window.
    TooOld,
    /// The key length does not match the AEAD algorithm (16 or 32 bytes).
    InvalidKeyLength,
    /// The fixed IV (RFC 5288 salt) is not exactly 4 bytes.
    InvalidFixedIvLength,
    /// The caller-owned output buffer cannot hold the result.
    OutputTooSmall,
    /// The AEAD tag did not authenticate the record.
    AuthenticationFailed,
    /// The machine's fixed event queue is full.
    EventQueueFull,
    /// The 48-bit record sequence number of an epoch is exhausted.
    SequenceExhausted,
    /// The crypto provider failed for a reason the record layer does not
    /// classify further.
    Crypto(CryptoError),
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    // DTLS-ERR-001 — every variant is constructible, distinct and `Debug`.
    #[test]
    fn record_error_variants_are_distinct_and_printable() {
        let variants = [
            RecordError::UnexpectedEnd,
            RecordError::LengthMismatch,
            RecordError::RecordTooLong,
            RecordError::CiphertextTooShort,
            RecordError::UnsupportedVersion,
            RecordError::InvalidContentType,
            RecordError::InvalidExplicitNonce,
            RecordError::StaleEpoch,
            RecordError::UnexpectedEpoch,
            RecordError::Replay,
            RecordError::TooOld,
            RecordError::InvalidKeyLength,
            RecordError::InvalidFixedIvLength,
            RecordError::OutputTooSmall,
            RecordError::AuthenticationFailed,
            RecordError::EventQueueFull,
            RecordError::SequenceExhausted,
            RecordError::Crypto(CryptoError::Unsupported),
            RecordError::Crypto(CryptoError::BackendFailure),
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
        assert_eq!(copied, RecordError::UnexpectedEnd);
    }
}

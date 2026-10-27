//! Typed failures for `SRTP`/`SRTCP` protection.
//!
//! Every variant is explicit: there is no fallback profile, no "decrypt anyway"
//! path after an authentication failure, and replayed and too-old packets are
//! distinguishable so a caller can account for drops separately.

use rtx_crypto::CryptoError;

/// Failure returned by [`crate::SenderContext::protect`],
/// [`crate::ReceiverContext::unprotect`], [`crate::SrtcpSenderContext::protect`]
/// and [`crate::SrtcpReceiverContext::unprotect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The requested protection profile is not
    /// [`crate::PROFILE_AES128_CM_HMAC_SHA1_80`].
    UnsupportedProfile(u16),
    /// The packet `SSRC` does not match the `SSRC` this context owns.
    WrongSsrc {
        /// `SSRC` the context was created for.
        expected: u32,
        /// `SSRC` found in the packet.
        found: u32,
    },
    /// The packet is shorter than its fixed header or its `CSRC`/extension
    /// structure is truncated or inconsistent.
    MalformedPacket,
    /// The caller-provided output slice cannot hold the result.
    ///
    /// Nothing was written before this error was returned.
    OutputTooSmall,
    /// The HMAC-SHA1-80 tag did not authenticate the packet.
    ///
    /// Nothing was written to the caller's output buffer.
    AuthenticationFailed,
    /// The packet index was already accepted: a duplicate or a replay.
    Replay,
    /// The packet index is older than the 64-index replay window.
    TooOld,
    /// The encrypted region would need more than 2^16 AES blocks, the `RFC
    /// 3711` per-packet keystream limit.
    PacketTooLarge,
    /// The sender has already used all 2^32 rollover counter values; a further
    /// wrap from sequence number 65535 to 0 would reuse a keystream index.
    RocExhausted,
    /// The sender was asked to protect the same sequence number twice. Sending
    /// it again would reuse the keystream and index.
    DuplicateSequence,
    /// The SRTCP sender has already used all 2^31 indices available under one
    /// master key (`RFC 3711` sections 3.4 and 9.2). Another packet would
    /// wrap the 31-bit SRTCP index and reuse a keystream.
    SrtcpIndexExhausted,
    /// The crypto provider rejected the operation.
    Crypto(CryptoError),
}

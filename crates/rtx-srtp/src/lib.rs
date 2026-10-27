#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! `SRTP` media protection for a single `SSRC` ([RFC 3711]).
//!
//! This crate protects `RTP` packets with the `SRTP_AES128_CM_HMAC_SHA1_80`
//! profile (0x0001): AES-128 counter mode for confidentiality and
//! HMAC-SHA1 truncated to 80 bits for integrity. It is `no_std`, sans-IO and
//! allocation-free: contexts never open sockets, never read a clock, and every
//! output goes to a caller-owned slice.
//!
//! # Scope
//!
//! * **One context, one `SSRC`.** A [`SenderContext`] or [`ReceiverContext`]
//!   rejects packets carrying a different `SSRC` with [`Error::WrongSsrc`].
//!   Multiplexing several streams is the caller's job, one context each.
//! * **One profile.** [`PROFILE_AES128_CM_HMAC_SHA1_80`] is the only accepted
//!   profile. Every other value fails construction with
//!   [`Error::UnsupportedProfile`]; there is no silent fallback, truncation or
//!   profile negotiation here.
//! * **Caller-supplied session material.** The caller passes a 16-byte session
//!   key and a 14-byte session salt. `RFC 3711` section 4.3 key derivation
//!   (`kdf`) and `SRTCP` are follow-up work, not implemented in this crate.
//!   Because no `kdf` runs yet, the single 16-byte key is used both as the
//!   AES-128 cipher key and as the HMAC-SHA1 key. That is an interim
//!   limitation, not the `RFC` key schedule.
//! * **No interoperability claim.** The construction follows the `RFC 3711`
//!   wire rules below, and its AES-CM keystream is pinned to the published
//!   Appendix B.2 vectors, but this crate does not assert interoperability
//!   with stock `libsrtp` or `OpenSSL`. In particular the missing `kdf` means
//!   `DTLS-SRTP` master keys exported by the `rtx-dtls` crate are not usable
//!   here yet.
//!
//! # Protection layout
//!
//! An `RTP` packet starts with a 12-byte fixed header (version, padding flag,
//! extension flag, `CSRC` count, payload type, sequence number, timestamp and
//! `SSRC`). The `CSRC` list and, when the `X` bit is set, the extension block
//! follow it. This crate treats that whole suffix as the encrypted region:
//!
//! ```text
//! +----------------------+-----------------------------------------------+
//! | 12-byte fixed header | encrypted region                              |
//! | cleartext            | CSRC list || extension || payload || padding  |
//! +----------------------+-----------------------------------------------+
//! | authentication tag (10 bytes, HMAC-SHA1-80)                           |
//! +-----------------------------------------------------------------------+
//! ```
//!
//! The fixed header is copied verbatim. Every octet after it, including the
//! `CSRC` list, the header extension block, the media payload and any `RTP`
//! padding octets, is combined with the AES-CM keystream. The HMAC-SHA1-80 tag
//! authenticates the complete protected packet (cleartext fixed header plus
//! encrypted region) followed by the 32-bit rollover counter (`RFC 3711`
//! section 4.2, `M = Authenticated Portion || ROC`).
//!
//! **Layout determination.** The encrypted region is exactly "everything after
//! the 12-byte fixed header": `CSRC`, header extension, payload and padding.
//! `RFC 3711` instead encrypts only the media payload and leaves `CSRC` and
//! extension bytes in the clear. Consequence: this crate is bidirectionally
//! non-interoperable with every `RFC 3711` implementation, including `libsrtp`
//! and `OpenSSL`; the layout divergence must be resolved before R3-2 wires in
//! real `DTLS-SRTP`.
//!
//! # AES-CM
//!
//! `RFC 3711` section 4.1.1 defines the 128-bit initial counter block as
//!
//! ```text
//! IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
//! ```
//!
//! where `k_s` is the 14-byte session salt, `SSRC` is the 32-bit stream
//! identifier and `i = ROC * 2^16 + SEQ` is the 48-bit packet index. In the
//! 128-bit big-endian block the salt occupies bytes 0..14, the `SSRC` bytes
//! 4..8, the 48-bit index bytes 8..14, and bytes 14..16 are the block counter.
//! Block `j` uses `IV + j` and a single packet may consume at most 2^16 blocks
//! ([`Error::PacketTooLarge`] otherwise).
//!
//! # Receiver order
//!
//! [`ReceiverContext::unprotect`] matches the packet's `SSRC`, authenticates
//! it over the packet plus the guessed `ROC`, then checks the replay window
//! and decrypts. A tag failure leaves the caller's output buffer untouched.
//! The replay window is 64 indices wide: duplicates return [`Error::Replay`],
//! indices older than the window return [`Error::TooOld`]. The receiver
//! derives the missing `ROC` bits with the `RFC 3711` Appendix A algorithm and
//! updates `s_l`/`ROC` only after successful authentication and decryption.
//!
//! # Sender `ROC`
//!
//! [`SenderContext`] starts at `ROC = 0`. Any sequence number below the
//! previous one is a wrap and increments the rollover counter, including a gap
//! such as 65534 -> 0. Repeating the previous sequence number returns
//! [`Error::DuplicateSequence`], and `ROC` exhaustion returns
//! [`Error::RocExhausted`] instead of silently reusing an index.
//!
//! # Secrets
//!
//! [`SenderContext`] and [`ReceiverContext`] store the session key and salt in
//! a private value whose `Drop` zeroizes both. `Debug` implementations redact
//! the key material. The caller still owns its copies of the arrays it passed
//! to the constructor.
//!
//! # Test vectors
//!
//! The AES-CM keystream is checked against the published `RFC 3711` Appendix
//! B.2 vectors (session key `2B7E...4F3C`, salt `F0F1...FCFD`, counters
//! `0000`-`0002` and `FEFF`-`FF01`). No vector was adjusted to fit the
//! implementation.
//!
//! B.2 only covers `SSRC = 0` and `index = 0`, which cannot catch a misplaced
//! `SSRC`/index in the IV. A second hardcoded vector therefore uses
//! `SSRC = 0x12345678` and index `0x0000ABCD1234`; `RFC 3711` publishes no
//! non-zero-`SSRC` keystream vector, so its expected blocks were computed
//! independently with `OpenSSL` 3.0.13 AES-128-ECB from the section 4.1.1
//! formula. The same procedure reproduces B.2 block 0.
//!
//! [RFC 3711]: https://www.rfc-editor.org/rfc/rfc3711

mod cipher;
mod error;
mod packet;
mod receiver;
mod replay;
mod sender;

pub use error::Error;
pub use receiver::ReceiverContext;
pub use sender::SenderContext;

/// `RFC 3711` protection profile `SRTP_AES128_CM_HMAC_SHA1_80`.
pub const PROFILE_AES128_CM_HMAC_SHA1_80: u16 = 0x0001;
/// Session key length for [`PROFILE_AES128_CM_HMAC_SHA1_80`], in bytes.
pub const SESSION_KEY_LEN: usize = 16;
/// Session salt length for [`PROFILE_AES128_CM_HMAC_SHA1_80`], in bytes.
pub const SESSION_SALT_LEN: usize = 14;
/// Authentication tag length for [`PROFILE_AES128_CM_HMAC_SHA1_80`], in bytes.
pub const AUTH_TAG_LEN: usize = 10;
/// Number of packet indices the replay window tracks.
pub const REPLAY_WINDOW_SIZE: u64 = 64;
/// Length of the cleartext `RTP` fixed header, in bytes.
pub const FIXED_HEADER_LEN: usize = 12;

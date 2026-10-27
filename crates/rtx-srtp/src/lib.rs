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
//! * **Two constructor paths.** [`SenderContext::new`] and
//!   [`ReceiverContext::new`] take *session* material: a 16-byte session
//!   encryption key and a 14-byte session salt. That key also becomes the
//!   HMAC-SHA1 authentication key, zero-extended to the profile's 20 bytes;
//!   because HMAC zero-pads short keys to the block size, the tag is
//!   byte-identical to the previous 16-byte HMAC key. These constructors do
//!   **not** accept `DTLS-SRTP` master material. [`SenderContext::from_master`]
//!   and [`ReceiverContext::from_master`] take a `RFC 5764` master key and
//!   master salt, run the `RFC 3711` section 4.3 derivation once, and then
//!   build the context.
//! * **`kdf` is implemented; `SRTCP` is not.** [`derive_session_keys`]
//!   provides the default AES-CM PRF with `key_derivation_rate` zero. There is
//!   no per-packet rekeying (`key_derivation_rate > 0`), no `SRTCP` (R3-3) and
//!   no multi-`SSRC` multiplexing layer: one context still protects one
//!   `SSRC`.
//! * **No interoperability claim.** The construction follows the `RFC 3711`
//!   wire rules below, its AES-CM keystream is pinned to the published
//!   Appendix B.2 vectors, and its derivation is pinned to the published
//!   Appendix B.3 vectors. The integration suite additionally checks the
//!   section 4.3 derivation and the protection path byte for byte against
//!   `libsrtp` 2.5.0 for fixed master keying material. That is a
//!   derivation/protection differential, not an end-to-end interoperability
//!   claim with stock `libsrtp` or `OpenSSL`.
//!
//! # Key derivation
//!
//! [`derive_session_keys`] implements `RFC 3711` section 4.3 for
//! `SRTP_AES128_CM_HMAC_SHA1_80`. With the default `key_derivation_rate = 0`
//! the derivation runs exactly once, at the start of the session
//! (section 4.3.1). For each label the PRF input is
//!
//! ```text
//! x = (<label> || r) XOR master_salt     (right-aligned; r = index DIV kdr = 0)
//! ```
//!
//! and the AES-CM input block is `x * 2^16` (section 4.3.3). Label `0x00`
//! yields the 16-byte session encryption key `k_e`, label `0x01` the 20-byte
//! session authentication key `k_a`, and label `0x02` the 14-byte session salt
//! `k_s` (section 4.3.1; lengths from sections 5.1-5.3).
//!
//! # Direction mapping
//!
//! `RFC 5764` section 4.2 exports four *master* values. [`map_directions`]
//! selects a send/receive pair without deriving anything:
//!
//! | local role      | send           | receive         |
//! |-----------------|----------------|-----------------|
//! | [`Role::Client`]| `client_write` | `server_write`  |
//! | [`Role::Server`]| `server_write` | `client_write`  |
//!
//! [`Role`] mirrors the `rtx-dtls` handshake role but is an independent type:
//! `rtx-srtp` does not depend on `rtx-dtls` in production code
//! (`ARCHITECTURE.md` section 6). The application converts the handshake role
//! and passes the selected master key/salt to `from_master`.
//!
//! # Protection layout
//!
//! An `RTP` packet starts with a 12-byte fixed header (version, padding flag,
//! extension flag, `CSRC` count, payload type, sequence number, timestamp and
//! `SSRC`), followed by the `CSRC` list and, when the `X` bit is set, the
//! header extension block. Only the media payload is encrypted
//! (`RFC 3711` section 3.1):
//!
//! ```text
//! +----------------------+-------------+----------------+------------------------+
//! | 12-byte fixed header | CSRC list   | extension      | payload + padding      |
//! | cleartext            | cleartext   | cleartext      | AES-CM encrypted       |
//! +----------------------+-------------+----------------+------------------------+
//! | authentication tag (10 bytes, HMAC-SHA1-80)                                  |
//! +------------------------------------------------------------------------------+
//! ```
//!
//! The fixed header, the `CSRC` list and the header extension block are copied
//! verbatim and stay in the clear; the encrypted region starts at the end of
//! the full `RTP` header and runs to the end of the packet, covering the media
//! payload and any `RTP` padding octets. The HMAC-SHA1-80 tag authenticates the
//! complete protected packet (cleartext header plus encrypted payload)
//! followed by the 32-bit rollover counter (`RFC 3711` section 4.2,
//! `M = Authenticated Portion || ROC`).
//!
//! **Layout determination.** The R3-1 private layout, which encrypted every
//! octet after the 12-byte fixed header, was superseded by the R3-1b change
//! order: the layout above is the `RFC 3711` section 3.1 layout.
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
//! [`SessionKeys`], [`SenderContext`] and [`ReceiverContext`] store the session
//! encryption key, authentication key and salt in private values whose `Drop`
//! zeroizes every array. `Debug` implementations redact the material.
//! [`DirectionalMasterKeys`] does the same for the two master pairs. The
//! callers still own the copies of the arrays they pass to a constructor.
//!
//! # Test vectors
//!
//! The AES-CM keystream is checked against the published `RFC 3711` Appendix
//! B.2 vectors (session key `2B7E...4F3C`, salt `F0F1...FCFD`, counters
//! `0000`-`0002` and `FEFF`-`FF01`). The derivation is checked against the
//! published Appendix B.3 vectors (master key `E1F9...4139`, master salt
//! `0EC6...ABE6`, cipher key `C61E...A087`, cipher salt `30CB...9AE1`, auth
//! key `CEBE...AACF`). No vector was adjusted to fit the implementation.
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
mod direction;
mod error;
mod kdf;
mod packet;
mod receiver;
mod replay;
mod sender;

pub use direction::{DirectionalMasterKeys, Role, map_directions};
pub use error::Error;
pub use kdf::{SessionKeys, derive_session_keys};
pub use receiver::ReceiverContext;
pub use sender::SenderContext;

/// `RFC 3711` protection profile `SRTP_AES128_CM_HMAC_SHA1_80`.
pub const PROFILE_AES128_CM_HMAC_SHA1_80: u16 = 0x0001;
/// Session encryption key length for
/// [`PROFILE_AES128_CM_HMAC_SHA1_80`], in bytes.
pub const SESSION_KEY_LEN: usize = 16;
/// Session authentication key length for
/// [`PROFILE_AES128_CM_HMAC_SHA1_80`], in bytes (full-length HMAC-SHA1 key).
pub const SESSION_AUTH_KEY_LEN: usize = 20;
/// Session salt length for [`PROFILE_AES128_CM_HMAC_SHA1_80`], in bytes.
pub const SESSION_SALT_LEN: usize = 14;
/// Authentication tag length for [`PROFILE_AES128_CM_HMAC_SHA1_80`], in bytes.
pub const AUTH_TAG_LEN: usize = 10;
/// Number of packet indices the replay window tracks.
pub const REPLAY_WINDOW_SIZE: u64 = 64;
/// Length of the cleartext `RTP` fixed header, in bytes.
pub const FIXED_HEADER_LEN: usize = 12;
/// AES block length, in bytes.
pub(crate) const AES_BLOCK_LEN: usize = 16;

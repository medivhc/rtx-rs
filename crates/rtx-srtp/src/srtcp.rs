//! Secure RTCP (`SRTCP`) for one `SSRC` (`RFC 3711` section 3.4).
//!
//! `SRTCP` wraps a compound `RTCP` packet with the `SRTP_AES128_CM_HMAC_SHA1_80`
//! transforms: AES-128 counter mode for confidentiality and HMAC-SHA1
//! truncated to 80 bits for integrity. Like the `SRTP` half of this crate it
//! is `no_std`, sans-IO and allocation-free; every output goes to a
//! caller-owned slice.
//!
//! # Wire format
//!
//! Section 3.4 appends three mandatory fields to the equivalent compound
//! `RTCP` packet: the E-flag, the 31-bit SRTCP index and the authentication
//! tag. There is no MKI under this profile, so the added fields are exactly
//! 14 octets (four for the E-flag/index word plus ten for the tag), which is
//! the lower bound section 3.4 states for the pre-defined transforms.
//!
//! ```text
//! octet 0      8                              n          n+4        n+14
//! +------------+------------------------------+-----------+----------+
//! | RTCP header| rest of the compound packet  | E | index | auth tag |
//! | + SSRC     | (encrypted in place)         | 1 | 31 bit| 10 bytes |
//! +------------+------------------------------+-----------+----------+
//!              \_______ Encrypted Portion ______/
//!              \_________________________________________________/
//!                    Authenticated Portion (tag covers all of it)
//! ```
//!
//! **Encrypted Portion.** Section 3.4 defines it as "the encryption
//! (Section 4.1) of the RTCP payload of the equivalent compound RTCP packet,
//! from the first RTCP packet, i.e., from the ninth (9) octet to the end of
//! the compound packet". `SRTCP` therefore encrypts every octet from offset 8
//! to the end of the compound packet, including the headers of any following
//! sub-packets; the first 8 octets (4-byte RTCP header plus the sender
//! `SSRC`) stay in the clear and are copied verbatim.
//!
//! **Authenticated Portion.** Section 3.4 defines it as "the entire
//! equivalent (eventually compound) RTCP packet, the E flag, and the SRTCP
//! index (after any encryption has been applied to the payload)". The tag
//! starts after that portion and is not covered by itself. Section 4.2 adds
//! that "in the case of SRTCP, M SHALL consist of the Authenticated Portion
//! ... only", so unlike `SRTP` no rollover counter is appended.
//!
//! # E-flag and index
//!
//! The E-flag and the SRTCP index share one 32-bit word: the flag is the most
//! significant bit and the index the remaining 31 bits (Figure 2 of section
//! 3.4). The flag is `1` when the packet was encrypted and `0` when it was
//! sent in the clear.
//!
//! The index encoding rules are quoted verbatim from section 3.4: the index
//! "MUST be set to zero before the first SRTCP packet is sent, and MUST be
//! incremented by one, modulo 2^31, after each SRTCP packet is sent." The
//! first packet protected here therefore carries index 0, then 1, and so on.
//! Section 9.2 limits one master key to 2^31 `SRTCP` packets, so a context
//! that would wrap the index returns [`Error::SrtcpIndexExhausted`] instead
//! of reusing a keystream.
//!
//! This crate always encrypts, so it emits `E = 1`. A receiver accepts
//! `E = 0` as section 3.4 requires: "in case the E-flag is 0, the payload is
//! simply left unmodified", while the tag still authenticates the packet.
//!
//! **Implementation note.** `libsrtp` 2.5.0 increments its RTCP counter before
//! using it, so its first protected packet carries index 1 rather than 0. That
//! is a divergence from the section 3.4 wording above, not a wire-format
//! difference: the index is explicit, so both values interoperate. This crate
//! follows the RFC text. The differential vector in `tests/srtcp.rs` compares
//! our *second* packet (index 1) with `libsrtp`'s first and matches it byte for
//! byte.
//!
//! # Key derivation and constructors
//!
//! [`SrtcpSenderContext::new`] and [`SrtcpReceiverContext::new`] take direct
//! *session* material: a 16-byte encryption key, a 20-byte authentication key
//! and a 14-byte salt. They perform no derivation and do **not** accept
//! `DTLS-SRTP` master material.
//!
//! [`SrtcpSenderContext::from_master`] and [`SrtcpReceiverContext::from_master`]
//! take a 16-byte master key and a 14-byte master salt and run
//! [`crate::derive_srtcp_session_keys`] once, which applies `RFC 3711` section
//! 4.3.2 labels `0x03`/`0x04`/`0x05` — not the `SRTP` labels
//! `0x00`/`0x01`/`0x02`. The caller selects the send or receive direction with
//! [`crate::map_directions`] before calling; the same `RFC 5764` section 4.2
//! mapping is used for `SRTCP` and `SRTP`.
//!
//! # SSRC
//!
//! One context protects one `SSRC`, and a packet carrying another one is
//! rejected with [`Error::WrongSsrc`]. Section 4.1.1 is explicit for `SRTCP`:
//! "the SSRC of the first header of the compound packet MUST be used". The
//! first 8 octets of the compound packet are cleartext, so the receiver can
//! check the `SSRC` before authentication.
//!
//! # Replay
//!
//! Section 3.4 applies the section 3.3.2 replay rules "but using the SRTCP
//! index as the index i and a separate Replay List that is specific to
//! SRTCP". This module keeps a [`ReplayWindow`] instance separate from any
//! `SRTP` window. Section 3.3.2 requires the window to be at least 64 indices
//! and otherwise leaves the size to the implementation; this crate uses the
//! same [`crate::REPLAY_WINDOW_SIZE`] of 64 as the `SRTP` receiver, which is
//! the required minimum. A duplicate index returns [`Error::Replay`] and an
//! index below the window returns [`Error::TooOld`].
//!
//! Appendix A's rollover-counter estimation does not apply to `SRTCP`:
//! section 3.4 states that "the receiver does not need to 'estimate' the
//! index, as it is explicitly signaled in the packet". The replay check and
//! the AES-CM IV both use the index read from the wire.
//!
//! The receiver authenticates first and moves the replay window only after
//! authentication and decryption succeed, so a forged packet cannot consume
//! an index. A tag failure returns [`Error::AuthenticationFailed`] and never
//! writes to the caller's output buffer.

use rtx_crypto::{Aes128BlockProvider, HmacProvider};
use zeroize::Zeroize;

use crate::cipher;
use crate::error::Error;
use crate::kdf::{self, SrtcpSessionKeys};
use crate::replay::ReplayWindow;
use crate::{
    PROFILE_AES128_CM_HMAC_SHA1_80, SESSION_AUTH_KEY_LEN, SESSION_KEY_LEN, SESSION_SALT_LEN,
    SRTCP_INDEX_LEN, SRTCP_OVERHEAD,
};

/// Length of the cleartext RTCP prefix: the 4-byte first header plus `SSRC`.
const RTCP_PREFIX_LEN: usize = 8;
/// Largest SRTCP index: the index field is 31 bits wide.
const SRTCP_INDEX_MAX: u32 = 0x7FFF_FFFF;
/// `E` occupies the most significant bit of the index word.
const E_FLAG: u32 = 0x8000_0000;
/// Only RTCP version 2 is defined by `RFC 3550`.
const RTCP_VERSION: u8 = 2;
/// RTCP sender report packet type (`RFC 3550` section 6.4.1).
const RTCP_SR: u8 = 200;
/// RTCP receiver report packet type (`RFC 3550` section 6.4.2).
const RTCP_RR: u8 = 201;

/// SRTCP sender context protecting compound RTCP packets for one `SSRC`.
///
/// The context owns the next SRTCP index. It never reads a clock and never
/// allocates.
pub struct SrtcpSenderContext<P> {
    provider: P,
    keys: SrtcpSessionKeys,
    ssrc: u32,
    /// Number of packets already protected; the next index while it is at
    /// most [`SRTCP_INDEX_MAX`].
    next_index: u64,
}

impl<P> SrtcpSenderContext<P> {
    /// Creates a sender from directly supplied *session* material.
    ///
    /// `encryption_key` is the 16-byte AES-CM SRTCP session encryption key,
    /// `authentication_key` the 20-byte HMAC-SHA1 SRTCP session authentication
    /// key, and `salt` the 14-byte SRTCP session salt. This is **not** the
    /// `RFC 3711` section 4.3 key schedule: for `DTLS-SRTP` master keying
    /// material use [`SrtcpSenderContext::from_master`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedProfile`] for any `profile` other than
    /// [`PROFILE_AES128_CM_HMAC_SHA1_80`]. The key and salt lengths are fixed
    /// by their array types.
    pub fn new(
        provider: P,
        profile: u16,
        encryption_key: [u8; SESSION_KEY_LEN],
        authentication_key: [u8; SESSION_AUTH_KEY_LEN],
        salt: [u8; SESSION_SALT_LEN],
        ssrc: u32,
    ) -> Result<Self, Error> {
        if profile != PROFILE_AES128_CM_HMAC_SHA1_80 {
            return Err(Error::UnsupportedProfile(profile));
        }
        Ok(Self::with_keys(
            provider,
            SrtcpSessionKeys::new(encryption_key, authentication_key, salt),
            ssrc,
        ))
    }

    /// Creates a sender from `RFC 5764` master keying material.
    ///
    /// Runs the `RFC 3711` section 4.3.2 derivation once
    /// (`key_derivation_rate = 0`) to obtain the SRTCP session encryption key,
    /// authentication key and salt, then behaves exactly like
    /// [`SrtcpSenderContext::new`]. The master key and salt are consumed and
    /// zeroized; the caller's copies are unaffected.
    ///
    /// The caller selects the send-direction master pair with
    /// [`crate::map_directions`] before calling this constructor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedProfile`] for any `profile` other than
    /// [`PROFILE_AES128_CM_HMAC_SHA1_80`] (before deriving anything), and
    /// [`Error::Crypto`] when the AES-CM PRF provider fails.
    pub fn from_master(
        provider: P,
        profile: u16,
        mut master_key: [u8; SESSION_KEY_LEN],
        mut master_salt: [u8; SESSION_SALT_LEN],
        ssrc: u32,
    ) -> Result<Self, Error>
    where
        P: Aes128BlockProvider,
    {
        if profile != PROFILE_AES128_CM_HMAC_SHA1_80 {
            master_key.zeroize();
            master_salt.zeroize();
            return Err(Error::UnsupportedProfile(profile));
        }
        let keys = kdf::derive_srtcp_session_keys(&provider, &master_key, &master_salt);
        master_key.zeroize();
        master_salt.zeroize();
        Ok(Self::with_keys(provider, keys?, ssrc))
    }

    fn with_keys(provider: P, keys: SrtcpSessionKeys, ssrc: u32) -> Self {
        Self {
            provider,
            keys,
            ssrc,
            next_index: 0,
        }
    }

    /// `SSRC` this context protects.
    #[must_use]
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }
}

impl<P: Aes128BlockProvider + HmacProvider> SrtcpSenderContext<P> {
    /// Protects one compound RTCP packet into `output`, returning the
    /// protected length.
    ///
    /// The first 8 octets (the first RTCP header and its `SSRC`) are copied
    /// verbatim and stay in the clear; every following octet of the compound
    /// packet is AES-CM encrypted (`RFC 3711` section 3.4). The E-flag/index
    /// word and the HMAC-SHA1-80 tag are appended, so the result is
    /// `rtcp.len() + 14` bytes.
    ///
    /// The first packet carries SRTCP index 0 and each later packet one more,
    /// as section 3.4 requires. The index is part of the authenticated
    /// portion, so the receiver can detect any change to it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedPacket`] when `rtcp` is shorter than the
    /// 8-octet RTCP prefix, is not RTCP version 2, or its first packet is
    /// neither a sender nor a receiver report (section 3.4 requires a
    /// compound packet starting with one of those), [`Error::WrongSsrc`] when
    /// the first header carries another `SSRC`, [`Error::OutputTooSmall`] when
    /// `output` cannot hold `rtcp.len() + 14` bytes (without writing),
    /// [`Error::SrtcpIndexExhausted`] after 2^31 packets under one key,
    /// [`Error::PacketTooLarge`] beyond the 2^16-block keystream limit, and
    /// [`Error::Crypto`] when the provider fails.
    pub fn protect(&mut self, rtcp: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let ssrc = parse_prefix(rtcp)?;
        if ssrc != self.ssrc {
            return Err(Error::WrongSsrc {
                expected: self.ssrc,
                found: ssrc,
            });
        }
        if self.next_index > u64::from(SRTCP_INDEX_MAX) {
            return Err(Error::SrtcpIndexExhausted);
        }
        let index = u32::try_from(self.next_index).map_err(|_| Error::SrtcpIndexExhausted)?;

        let cleartext_length = rtcp.len();
        let needed = cleartext_length + SRTCP_OVERHEAD;
        if output.len() < needed {
            return Err(Error::OutputTooSmall);
        }

        output[..cleartext_length].copy_from_slice(rtcp);
        cipher::apply_keystream(
            &self.provider,
            self.keys.session_keys(),
            self.ssrc,
            u64::from(index),
            &mut output[RTCP_PREFIX_LEN..cleartext_length],
        )?;

        // Section 3.4: the E-flag is the most significant bit and the index
        // occupies the other 31 bits of one 32-bit word.
        let trailer = E_FLAG | index;
        output[cleartext_length..cleartext_length + SRTCP_INDEX_LEN]
            .copy_from_slice(&trailer.to_be_bytes());
        let authenticated = cleartext_length + SRTCP_INDEX_LEN;
        let tag = cipher::compute_srtcp_tag(
            &self.provider,
            self.keys.session_keys(),
            &output[..authenticated],
        )?;
        output[authenticated..needed].copy_from_slice(&tag);

        self.next_index += 1;
        Ok(needed)
    }
}

impl<P> core::fmt::Debug for SrtcpSenderContext<P> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SrtcpSenderContext")
            .field("ssrc", &self.ssrc)
            .field("next_index", &self.next_index)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

/// SRTCP receiver context authenticating and decrypting compound RTCP packets
/// for one `SSRC`.
///
/// The context owns a replay window fed by explicit SRTCP indices. It never
/// reads a clock and never allocates.
pub struct SrtcpReceiverContext<P> {
    provider: P,
    keys: SrtcpSessionKeys,
    ssrc: u32,
    replay: ReplayWindow,
}

impl<P> SrtcpReceiverContext<P> {
    /// Creates a receiver from directly supplied *session* material.
    ///
    /// `encryption_key` is the 16-byte AES-CM SRTCP session encryption key,
    /// `authentication_key` the 20-byte HMAC-SHA1 SRTCP session authentication
    /// key, and `salt` the 14-byte SRTCP session salt. This is **not** the
    /// `RFC 3711` section 4.3 key schedule: for `DTLS-SRTP` master keying
    /// material use [`SrtcpReceiverContext::from_master`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedProfile`] for any `profile` other than
    /// [`PROFILE_AES128_CM_HMAC_SHA1_80`]. The key and salt lengths are fixed
    /// by their array types.
    pub fn new(
        provider: P,
        profile: u16,
        encryption_key: [u8; SESSION_KEY_LEN],
        authentication_key: [u8; SESSION_AUTH_KEY_LEN],
        salt: [u8; SESSION_SALT_LEN],
        ssrc: u32,
    ) -> Result<Self, Error> {
        if profile != PROFILE_AES128_CM_HMAC_SHA1_80 {
            return Err(Error::UnsupportedProfile(profile));
        }
        Ok(Self::with_keys(
            provider,
            SrtcpSessionKeys::new(encryption_key, authentication_key, salt),
            ssrc,
        ))
    }

    /// Creates a receiver from `RFC 5764` master keying material.
    ///
    /// Runs the `RFC 3711` section 4.3.2 derivation once
    /// (`key_derivation_rate = 0`) to obtain the SRTCP session encryption key,
    /// authentication key and salt, then behaves exactly like
    /// [`SrtcpReceiverContext::new`]. The master key and salt are consumed and
    /// zeroized; the caller's copies are unaffected.
    ///
    /// The caller selects the receive-direction master pair with
    /// [`crate::map_directions`] before calling this constructor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedProfile`] for any `profile` other than
    /// [`PROFILE_AES128_CM_HMAC_SHA1_80`] (before deriving anything), and
    /// [`Error::Crypto`] when the AES-CM PRF provider fails.
    pub fn from_master(
        provider: P,
        profile: u16,
        mut master_key: [u8; SESSION_KEY_LEN],
        mut master_salt: [u8; SESSION_SALT_LEN],
        ssrc: u32,
    ) -> Result<Self, Error>
    where
        P: Aes128BlockProvider,
    {
        if profile != PROFILE_AES128_CM_HMAC_SHA1_80 {
            master_key.zeroize();
            master_salt.zeroize();
            return Err(Error::UnsupportedProfile(profile));
        }
        let keys = kdf::derive_srtcp_session_keys(&provider, &master_key, &master_salt);
        master_key.zeroize();
        master_salt.zeroize();
        Ok(Self::with_keys(provider, keys?, ssrc))
    }

    fn with_keys(provider: P, keys: SrtcpSessionKeys, ssrc: u32) -> Self {
        Self {
            provider,
            keys,
            ssrc,
            replay: ReplayWindow::new(),
        }
    }

    /// `SSRC` this context receives.
    #[must_use]
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }
}

impl<P: Aes128BlockProvider + HmacProvider> SrtcpReceiverContext<P> {
    /// Authenticates, checks the replay window and decrypts one SRTCP packet
    /// into `output`, returning the cleartext length.
    ///
    /// The first RTCP header and its `SSRC` are matched first. The tag is then
    /// verified over the complete RTCP packet plus the E-flag/index word
    /// (`RFC 3711` sections 3.4 and 4.2): on [`Error::AuthenticationFailed`]
    /// the caller's output buffer is untouched. The replay window is checked
    /// next, so a duplicate returns [`Error::Replay`] and an index below the
    /// window returns [`Error::TooOld`], both without writing. Only then is
    /// the packet copied into `output` and, when `E = 1`, octets 8..end are
    /// AES-CM decrypted with the SRTCP index as `i` (section 4.1.1). An
    /// `E = 0` packet is authenticated but copied unmodified, as section 3.4
    /// specifies.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedPacket`] for a packet shorter than 22 bytes
    /// (8-octet RTCP prefix plus 14 octets of SRTCP fields), a non-version-2
    /// RTCP header, or a first packet that is neither a sender nor a receiver
    /// report; [`Error::WrongSsrc`] for another stream,
    /// [`Error::AuthenticationFailed`], [`Error::Replay`], [`Error::TooOld`],
    /// [`Error::OutputTooSmall`] when `output` cannot hold the cleartext
    /// packet (without writing), [`Error::PacketTooLarge`] beyond the
    /// 2^16-block keystream limit, and [`Error::Crypto`] when the provider
    /// fails.
    pub fn unprotect(&mut self, srtcp: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let total = srtcp.len();
        if total < RTCP_PREFIX_LEN + SRTCP_OVERHEAD {
            return Err(Error::MalformedPacket);
        }
        let cleartext_length = total - SRTCP_OVERHEAD;
        let ssrc = parse_prefix(srtcp)?;
        if ssrc != self.ssrc {
            return Err(Error::WrongSsrc {
                expected: self.ssrc,
                found: ssrc,
            });
        }

        let trailer_at = cleartext_length;
        let trailer = u32::from_be_bytes([
            srtcp[trailer_at],
            srtcp[trailer_at + 1],
            srtcp[trailer_at + 2],
            srtcp[trailer_at + 3],
        ]);
        let encrypted = trailer & E_FLAG != 0;
        let index = trailer & SRTCP_INDEX_MAX;

        let authenticated = cleartext_length + SRTCP_INDEX_LEN;
        let expected = cipher::compute_srtcp_tag(
            &self.provider,
            self.keys.session_keys(),
            &srtcp[..authenticated],
        )?;
        if !cipher::tags_equal(&expected, &srtcp[authenticated..]) {
            return Err(Error::AuthenticationFailed);
        }

        let admission = self.replay.check(u64::from(index))?;

        if output.len() < cleartext_length {
            return Err(Error::OutputTooSmall);
        }
        output[..cleartext_length].copy_from_slice(&srtcp[..cleartext_length]);
        if encrypted {
            cipher::apply_keystream(
                &self.provider,
                self.keys.session_keys(),
                self.ssrc,
                u64::from(index),
                &mut output[RTCP_PREFIX_LEN..cleartext_length],
            )?;
        }

        self.replay.accept(admission);
        Ok(cleartext_length)
    }
}

impl<P> core::fmt::Debug for SrtcpReceiverContext<P> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SrtcpReceiverContext")
            .field("ssrc", &self.ssrc)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

/// Reads the cleartext prefix of a compound RTCP packet.
///
/// The `SSRC` comes from the first RTCP header, as `RFC 3711` section 4.1.1
/// requires for `SRTCP`. Section 3.4 also requires the first sub-packet to be
/// a sender or receiver report.
fn parse_prefix(rtcp: &[u8]) -> Result<u32, Error> {
    let prefix = rtcp.get(..RTCP_PREFIX_LEN).ok_or(Error::MalformedPacket)?;
    if prefix[0] >> 6 != RTCP_VERSION {
        return Err(Error::MalformedPacket);
    }
    if prefix[1] != RTCP_SR && prefix[1] != RTCP_RR {
        return Err(Error::MalformedPacket);
    }
    Ok(u32::from_be_bytes([
        prefix[4], prefix[5], prefix[6], prefix[7],
    ]))
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use rtx_crypto_rustcrypto::RustCryptoProvider;

    const SSRC: u32 = 0xDEAD_BEEF;
    const ENCRYPTION_KEY: [u8; SESSION_KEY_LEN] = [0x11; SESSION_KEY_LEN];
    const AUTHENTICATION_KEY: [u8; SESSION_AUTH_KEY_LEN] = [0x22; SESSION_AUTH_KEY_LEN];
    const SALT: [u8; SESSION_SALT_LEN] = [0x33; SESSION_SALT_LEN];

    /// A minimal valid first RTCP packet: sender report header plus `SSRC`,
    /// followed by sender-info fields that make the compound packet larger
    /// than the encrypted prefix.
    fn rtcp(ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x80;
        packet[1] = RTCP_SR;
        packet[2..4].copy_from_slice(&6_u16.to_be_bytes());
        packet[4..8].copy_from_slice(&ssrc.to_be_bytes());
        packet[8..12].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
        packet[12..16].copy_from_slice(&0x0506_0708_u32.to_be_bytes());
        packet[16..20].copy_from_slice(&0x090A_0B0C_u32.to_be_bytes());
        packet[20..24].copy_from_slice(&11_u32.to_be_bytes());
        packet[24..28].copy_from_slice(&22_u32.to_be_bytes());
        packet
    }

    fn sender() -> SrtcpSenderContext<RustCryptoProvider> {
        SrtcpSenderContext::new(
            RustCryptoProvider::new(),
            PROFILE_AES128_CM_HMAC_SHA1_80,
            ENCRYPTION_KEY,
            AUTHENTICATION_KEY,
            SALT,
            SSRC,
        )
        .expect("supported profile")
    }

    fn receiver() -> SrtcpReceiverContext<RustCryptoProvider> {
        SrtcpReceiverContext::new(
            RustCryptoProvider::new(),
            PROFILE_AES128_CM_HMAC_SHA1_80,
            ENCRYPTION_KEY,
            AUTHENTICATION_KEY,
            SALT,
            SSRC,
        )
        .expect("supported profile")
    }

    fn protect(context: &mut SrtcpSenderContext<RustCryptoProvider>, rtcp: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; rtcp.len() + SRTCP_OVERHEAD];
        let written = context.protect(rtcp, &mut output).expect("protect");
        assert_eq!(written, rtcp.len() + SRTCP_OVERHEAD);
        output
    }

    fn unprotect(context: &mut SrtcpReceiverContext<RustCryptoProvider>, srtcp: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; srtcp.len() - SRTCP_OVERHEAD];
        let written = context.unprotect(srtcp, &mut output).expect("unprotect");
        assert_eq!(written, output.len());
        output
    }

    fn index_of_packet(srtcp: &[u8]) -> u32 {
        let at = srtcp.len() - SRTCP_OVERHEAD;
        u32::from_be_bytes([srtcp[at], srtcp[at + 1], srtcp[at + 2], srtcp[at + 3]])
            & SRTCP_INDEX_MAX
    }

    // SRTP-SRTCP-001 — the layout follows RFC 3711 section 3.4: the first
    // eight octets stay cleartext, octets 8..end are encrypted, the trailer
    // is E=1 with index 0, and the round trip restores every byte.
    #[test]
    fn roundtrip_keeps_prefix_clear_and_encrypts_the_rest() {
        let original = rtcp(SSRC);
        let mut sender = sender();
        let protected = protect(&mut sender, &original);

        assert_eq!(protected.len(), original.len() + SRTCP_OVERHEAD);
        assert_eq!(&protected[..RTCP_PREFIX_LEN], &original[..RTCP_PREFIX_LEN]);
        assert_ne!(
            &protected[RTCP_PREFIX_LEN..original.len()],
            &original[RTCP_PREFIX_LEN..],
            "octets 8..end must be encrypted"
        );
        assert_eq!(
            &protected[original.len()..original.len() + SRTCP_INDEX_LEN],
            &E_FLAG.to_be_bytes(),
            "first packet is E=1, index 0"
        );

        let mut receiver = receiver();
        assert_eq!(unprotect(&mut receiver, &protected), original);
    }

    // SRTP-SRTCP-002 — section 3.4: index 0 before the first packet, then one
    // more for each packet sent.
    #[test]
    fn index_starts_at_zero_and_increments_by_one() {
        let original = rtcp(SSRC);
        let mut sender = sender();
        let first = protect(&mut sender, &original);
        let second = protect(&mut sender, &original);
        assert_eq!(index_of_packet(&first), 0);
        assert_eq!(index_of_packet(&second), 1);
        assert_eq!(
            &second[second.len() - SRTCP_OVERHEAD..][..SRTCP_INDEX_LEN],
            &(E_FLAG | 1).to_be_bytes()
        );
    }

    // SRTP-SRTCP-003 — a tag failure returns AuthenticationFailed and does
    // not touch the caller's output buffer, for a tampered tag, ciphertext,
    // or authenticated trailer.
    #[test]
    fn tampering_is_rejected_without_touching_output() {
        let original = rtcp(SSRC);
        let mut sender = sender();
        let protected = protect(&mut sender, &original);
        let trailer_at = protected.len() - SRTCP_OVERHEAD;
        let cases = [
            ("tag", protected.len() - 1),
            ("ciphertext", RTCP_PREFIX_LEN),
            ("index", trailer_at + SRTCP_INDEX_LEN - 1),
        ];
        for (name, position) in cases {
            let mut tampered = protected.clone();
            tampered[position] ^= 0x01;
            let mut receiver = receiver();
            let mut output = vec![0xA5_u8; original.len()];
            assert_eq!(
                receiver.unprotect(&tampered, &mut output),
                Err(Error::AuthenticationFailed),
                "tampered {name}"
            );
            assert!(
                output.iter().all(|&byte| byte == 0xA5),
                "tampered {name} must not write the output buffer"
            );
            assert_eq!(
                receiver.ssrc(),
                SSRC,
                "a failed packet must not disturb the context"
            );
        }
    }

    // SRTP-SRTCP-004 — the same authenticated packet cannot be accepted twice
    // (section 3.4 applies the section 3.3.2 replay rules).
    #[test]
    fn replayed_packet_is_rejected() {
        let original = rtcp(SSRC);
        let mut sender = sender();
        let protected = protect(&mut sender, &original);

        let mut receiver = receiver();
        assert_eq!(unprotect(&mut receiver, &protected), original);

        let mut output = vec![0x5A_u8; original.len()];
        assert_eq!(
            receiver.unprotect(&protected, &mut output),
            Err(Error::Replay)
        );
        assert!(output.iter().all(|&byte| byte == 0x5A));
    }

    // SRTP-SRTCP-005 — an index below the 64-wide window is TooOld.
    #[test]
    fn index_below_the_window_is_too_old() {
        let original = rtcp(SSRC);
        let mut sender = sender();
        let packets: Vec<Vec<u8>> = (0..=64).map(|_| protect(&mut sender, &original)).collect();

        let mut receiver = receiver();
        assert_eq!(unprotect(&mut receiver, &packets[64]), original);
        let mut output = vec![0xEE_u8; original.len()];
        assert_eq!(
            receiver.unprotect(&packets[0], &mut output),
            Err(Error::TooOld)
        );
        assert!(output.iter().all(|&byte| byte == 0xEE));
    }

    // SRTP-SRTCP-006 — E=0 packets authenticate but are copied unmodified
    // (section 3.4: "in case the E-flag is 0, the payload is simply left
    // unmodified").
    #[test]
    fn unencrypted_packets_are_authenticated_but_not_decrypted() {
        let original = rtcp(SSRC);
        let index = 7_u32;
        let mut packet = original.clone();
        packet.extend_from_slice(&index.to_be_bytes());
        let keys = SrtcpSessionKeys::new(ENCRYPTION_KEY, AUTHENTICATION_KEY, SALT);
        let tag =
            cipher::compute_srtcp_tag(&RustCryptoProvider::new(), keys.session_keys(), &packet)
                .expect("tag");
        packet.extend_from_slice(&tag);

        let mut receiver = receiver();
        let mut output = vec![0u8; original.len()];
        assert_eq!(receiver.unprotect(&packet, &mut output), Ok(original.len()));
        assert_eq!(output, original);
    }

    // SRTP-SRTCP-007 — the context SSRC is enforced on both sides (section
    // 4.1.1 uses the SSRC of the first compound header).
    #[test]
    fn wrong_ssrc_is_rejected_in_both_directions() {
        let original = rtcp(SSRC);
        let mut wrong_sender = SrtcpSenderContext::new(
            RustCryptoProvider::new(),
            PROFILE_AES128_CM_HMAC_SHA1_80,
            ENCRYPTION_KEY,
            AUTHENTICATION_KEY,
            SALT,
            SSRC + 1,
        )
        .expect("sender");
        let mut output = vec![0u8; original.len() + SRTCP_OVERHEAD];
        assert_eq!(
            wrong_sender.protect(&original, &mut output),
            Err(Error::WrongSsrc {
                expected: SSRC + 1,
                found: SSRC,
            })
        );

        let mut sender = sender();
        let protected = protect(&mut sender, &original);
        let mut wrong_receiver = SrtcpReceiverContext::new(
            RustCryptoProvider::new(),
            PROFILE_AES128_CM_HMAC_SHA1_80,
            ENCRYPTION_KEY,
            AUTHENTICATION_KEY,
            SALT,
            SSRC + 1,
        )
        .expect("receiver");
        let mut plaintext = vec![0u8; original.len()];
        assert_eq!(
            wrong_receiver.unprotect(&protected, &mut plaintext),
            Err(Error::WrongSsrc {
                expected: SSRC + 1,
                found: SSRC,
            })
        );
    }

    // SRTP-SRTCP-008 — the RTCP prefix must be version 2 and start with an
    // SR or RR (RFC 3711 section 3.4 / RFC 3550 section 6.1).
    #[test]
    fn malformed_rtcp_prefix_is_rejected() {
        for mutate in [
            |packet: &mut Vec<u8>| packet[0] = 0x40,
            |packet: &mut Vec<u8>| packet[1] = 203,
        ] {
            let mut packet = rtcp(SSRC);
            mutate(&mut packet);
            let mut sender = sender();
            let mut output = vec![0u8; packet.len() + SRTCP_OVERHEAD];
            assert_eq!(
                sender.protect(&packet, &mut output),
                Err(Error::MalformedPacket)
            );
        }

        let mut sender = sender();
        let mut output = vec![0u8; 7 + SRTCP_OVERHEAD];
        assert_eq!(
            sender.protect(&[0u8; 7], &mut output),
            Err(Error::MalformedPacket)
        );

        let mut receiver = receiver();
        let mut output = vec![0u8; 8];
        assert_eq!(
            receiver.unprotect(&[0u8; RTCP_PREFIX_LEN + SRTCP_OVERHEAD - 1], &mut output),
            Err(Error::MalformedPacket)
        );

        let mut protected = protect(&mut sender, &rtcp(SSRC));
        protected[0] = 0x40;
        assert_eq!(
            receiver.unprotect(&protected, &mut output),
            Err(Error::MalformedPacket)
        );
    }

    // SRTP-SRTCP-009 — only profile 0x0001 is accepted by both constructors.
    #[test]
    fn unsupported_profile_is_explicit() {
        let profile = PROFILE_AES128_CM_HMAC_SHA1_80 + 1;
        assert_eq!(
            SrtcpSenderContext::new(
                RustCryptoProvider::new(),
                profile,
                ENCRYPTION_KEY,
                AUTHENTICATION_KEY,
                SALT,
                SSRC
            )
            .err(),
            Some(Error::UnsupportedProfile(profile))
        );
        assert_eq!(
            SrtcpReceiverContext::new(
                RustCryptoProvider::new(),
                profile,
                ENCRYPTION_KEY,
                AUTHENTICATION_KEY,
                SALT,
                SSRC
            )
            .err(),
            Some(Error::UnsupportedProfile(profile))
        );
        assert_eq!(
            SrtcpSenderContext::from_master(
                RustCryptoProvider::new(),
                profile,
                ENCRYPTION_KEY,
                SALT,
                SSRC
            )
            .err(),
            Some(Error::UnsupportedProfile(profile))
        );
        assert_eq!(
            SrtcpReceiverContext::from_master(
                RustCryptoProvider::new(),
                profile,
                ENCRYPTION_KEY,
                SALT,
                SSRC
            )
            .err(),
            Some(Error::UnsupportedProfile(profile))
        );
    }

    // SRTP-SRTCP-010 — output sizing is validated before any write.
    #[test]
    fn output_too_small_never_writes() {
        let original = rtcp(SSRC);
        let mut sender = sender();
        let mut short = vec![0xA5_u8; original.len() + SRTCP_OVERHEAD - 1];
        assert_eq!(
            sender.protect(&original, &mut short),
            Err(Error::OutputTooSmall)
        );
        assert!(short.iter().all(|&byte| byte == 0xA5));

        let protected = protect(&mut sender, &original);
        let mut receiver = receiver();
        let mut short = vec![0xA5_u8; original.len() - 1];
        assert_eq!(
            receiver.unprotect(&protected, &mut short),
            Err(Error::OutputTooSmall)
        );
        assert!(short.iter().all(|&byte| byte == 0xA5));
    }

    // SRTP-SRTCP-011 — section 9.2 caps one master key at 2^31 SRTCP packets;
    // index exhaustion is explicit and leaves the output untouched.
    #[test]
    fn index_exhaustion_is_explicit() {
        let original = rtcp(SSRC);
        let mut sender = sender();
        sender.next_index = u64::from(SRTCP_INDEX_MAX);
        let last = protect(&mut sender, &original);
        assert_eq!(index_of_packet(&last), SRTCP_INDEX_MAX);

        let mut output = vec![0xA5_u8; original.len() + SRTCP_OVERHEAD];
        assert_eq!(
            sender.protect(&original, &mut output),
            Err(Error::SrtcpIndexExhausted)
        );
        assert!(output.iter().all(|&byte| byte == 0xA5));
    }

    // SRTP-SRTCP-012 — from_master derives the section 4.3.2 session values;
    // a context built from those values with `new` produces identical bytes.
    #[test]
    fn from_master_matches_new_with_the_derived_session_material() {
        const MASTER_KEY: [u8; SESSION_KEY_LEN] = [0x44; SESSION_KEY_LEN];
        const MASTER_SALT: [u8; SESSION_SALT_LEN] = [0x55; SESSION_SALT_LEN];
        let derived =
            kdf::derive_srtcp_session_keys(&RustCryptoProvider::new(), &MASTER_KEY, &MASTER_SALT)
                .expect("derive");

        let mut from_master = SrtcpSenderContext::from_master(
            RustCryptoProvider::new(),
            PROFILE_AES128_CM_HMAC_SHA1_80,
            MASTER_KEY,
            MASTER_SALT,
            SSRC,
        )
        .expect("from master");
        let mut direct = SrtcpSenderContext::new(
            RustCryptoProvider::new(),
            PROFILE_AES128_CM_HMAC_SHA1_80,
            *derived.encryption_key(),
            *derived.authentication_key(),
            *derived.salt(),
            SSRC,
        )
        .expect("direct");

        let original = rtcp(SSRC);
        assert_eq!(
            protect(&mut from_master, &original),
            protect(&mut direct, &original)
        );
    }

    // SRTP-SRTCP-013 — Debug never reveals the session material.
    #[test]
    fn debug_redacts_session_material() {
        let sender_text = format!("{:?}", sender());
        assert!(sender_text.contains("SrtcpSenderContext"));
        assert!(sender_text.contains("<redacted>"));
        let receiver_text = format!("{:?}", receiver());
        assert!(receiver_text.contains("SrtcpReceiverContext"));
        assert!(receiver_text.contains("<redacted>"));
    }
}

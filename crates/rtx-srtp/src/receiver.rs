//! Receiver-side `SRTP` context for one `SSRC`.

use rtx_crypto::{Aes128BlockProvider, HmacProvider};

use crate::cipher::{self, SessionKeys};
use crate::error::Error;
use crate::packet;
use crate::replay::ReplayWindow;
use crate::sender::index_of;
use crate::{
    AUTH_TAG_LEN, FIXED_HEADER_LEN, PROFILE_AES128_CM_HMAC_SHA1_80, SESSION_KEY_LEN,
    SESSION_SALT_LEN,
};

/// Receiver context authenticating and decrypting `SRTP` packets for one
/// `SSRC`.
///
/// The context owns the rollover counter, the highest authenticated sequence
/// number (`s_l`) and a 64-index replay window. It never reads a clock and
/// never allocates.
///
/// The receiver starts at `ROC = 0`. Joining a stream that is already running
/// with a non-zero `ROC` needs out-of-band state, which this bounded context
/// does not take as a constructor input yet.
pub struct ReceiverContext<P> {
    provider: P,
    keys: SessionKeys,
    ssrc: u32,
    roc: u32,
    highest_sequence: Option<u16>,
    replay: ReplayWindow,
}

impl<P> ReceiverContext<P> {
    /// Creates a receiver for `ssrc` starting at `ROC = 0`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedProfile`] for any `profile` other than
    /// [`PROFILE_AES128_CM_HMAC_SHA1_80`]. The key and salt lengths are fixed
    /// by their array types.
    pub fn new(
        provider: P,
        profile: u16,
        key: [u8; SESSION_KEY_LEN],
        salt: [u8; SESSION_SALT_LEN],
        ssrc: u32,
    ) -> Result<Self, Error> {
        if profile != PROFILE_AES128_CM_HMAC_SHA1_80 {
            return Err(Error::UnsupportedProfile(profile));
        }
        Ok(Self {
            provider,
            keys: SessionKeys::new(key, salt),
            ssrc,
            roc: 0,
            highest_sequence: None,
            replay: ReplayWindow::new(),
        })
    }

    /// `SSRC` this context receives.
    #[must_use]
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Current rollover counter.
    #[must_use]
    pub const fn rollover_counter(&self) -> u32 {
        self.roc
    }
}

impl<P: Aes128BlockProvider + HmacProvider> ReceiverContext<P> {
    /// Authenticates and decrypts one `SRTP` packet into `output`.
    ///
    /// The tag is verified first: on [`Error::AuthenticationFailed`] the
    /// caller's output buffer is untouched. The replay window is checked next,
    /// so a duplicate returns [`Error::Replay`] and an index below the window
    /// returns [`Error::TooOld`], both without writing. Only then is the packet
    /// copied into `output` and decrypted.
    ///
    /// The `ROC` is estimated with the `RFC 3711` Appendix A algorithm from the
    /// context's `ROC` and `s_l`; `s_l`/`ROC` are updated only after the packet
    /// authenticates and decrypts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedPacket`] for a packet shorter than 22 bytes
    /// (12-byte fixed header plus 10-byte tag) or an invalid `RTP` header,
    /// [`Error::WrongSsrc`] for another stream, [`Error::AuthenticationFailed`],
    /// [`Error::Replay`], [`Error::TooOld`], [`Error::OutputTooSmall`] when
    /// `output` cannot hold the cleartext packet, and [`Error::Crypto`] when
    /// the provider fails.
    pub fn unprotect(&mut self, srtp: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let total = srtp.len();
        if total < FIXED_HEADER_LEN + AUTH_TAG_LEN {
            return Err(Error::MalformedPacket);
        }
        let plaintext_length = total - AUTH_TAG_LEN;
        let (sequence, ssrc) = packet::fixed_header(srtp)?;
        if ssrc != self.ssrc {
            return Err(Error::WrongSsrc {
                expected: self.ssrc,
                found: ssrc,
            });
        }
        let (roc, index) = self.guess_index(sequence);

        let expected = cipher::compute_tag(&self.provider, &self.keys, &srtp[..plaintext_length])?;
        if !cipher::tags_equal(&expected, &srtp[plaintext_length..]) {
            return Err(Error::AuthenticationFailed);
        }

        let admission = self.replay.check(index)?;

        if output.len() < plaintext_length {
            return Err(Error::OutputTooSmall);
        }
        output[..plaintext_length].copy_from_slice(&srtp[..plaintext_length]);
        cipher::apply_keystream(
            &self.provider,
            &self.keys,
            self.ssrc,
            index,
            &mut output[FIXED_HEADER_LEN..plaintext_length],
        )?;

        // The `CSRC` list and extension block were encrypted too, so their
        // structure can only be validated after decryption. A tag-valid packet
        // with a broken header is still not deliverable.
        packet::parse(&output[..plaintext_length])?;

        self.replay.accept(admission);
        self.update(sequence, roc);
        Ok(plaintext_length)
    }

    /// Estimates the rollover counter for `sequence` (`RFC 3711` Appendix A).
    fn guess_index(&self, sequence: u16) -> (u32, u64) {
        let Some(highest) = self.highest_sequence else {
            return (self.roc, index_of(self.roc, sequence));
        };
        let highest = i32::from(highest);
        let sequence_value = i32::from(sequence);
        let roc = if highest < 32_768 {
            if sequence_value - highest > 32_768 {
                self.roc.wrapping_sub(1)
            } else {
                self.roc
            }
        } else if highest - 32_768 > sequence_value {
            self.roc.wrapping_add(1)
        } else {
            self.roc
        };
        (roc, index_of(roc, sequence))
    }

    /// Applies the `RFC 3711` section 3.3.1 `s_l`/`ROC` update for `roc`.
    fn update(&mut self, sequence: u16, roc: u32) {
        if roc == self.roc {
            if self
                .highest_sequence
                .is_none_or(|highest| sequence > highest)
            {
                self.highest_sequence = Some(sequence);
            }
        } else if roc == self.roc.wrapping_add(1) {
            self.roc = roc;
            self.highest_sequence = Some(sequence);
        }
        // `roc == self.roc - 1` marks a late packet from the previous ROC: it
        // is deliverable but does not move the window or `s_l`.
    }
}

impl<P> core::fmt::Debug for ReceiverContext<P> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ReceiverContext")
            .field("ssrc", &self.ssrc)
            .field("rollover_counter", &self.roc)
            .field("highest_sequence", &self.highest_sequence)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use rtx_crypto_rustcrypto::RustCryptoProvider;

    const SSRC: u32 = 0x1234_5678;

    fn context() -> ReceiverContext<RustCryptoProvider> {
        ReceiverContext::new(
            RustCryptoProvider::new(),
            PROFILE_AES128_CM_HMAC_SHA1_80,
            [0x11; SESSION_KEY_LEN],
            [0x22; SESSION_SALT_LEN],
            SSRC,
        )
        .expect("supported profile")
    }

    // SRTP-RECV-001 — Appendix A picks ROC-1, ROC or ROC+1.
    #[test]
    fn index_guess_follows_appendix_a() {
        let mut context = context();
        assert_eq!(context.guess_index(100), (0, 100));

        context.highest_sequence = Some(5);
        context.roc = 0;
        assert_eq!(context.guess_index(6), (0, 6));
        assert_eq!(
            context.guess_index(65535),
            (u32::MAX, index_of(u32::MAX, 65535))
        );

        context.highest_sequence = Some(40_000);
        context.roc = 7;
        assert_eq!(context.guess_index(8_000), (7, index_of(7, 8_000)));
        assert_eq!(context.guess_index(7_000), (8, index_of(8, 7_000)));
    }

    // SRTP-RECV-002 — s_l/ROC updates match RFC 3711 section 3.3.1.
    #[test]
    fn state_updates_follow_rfc3711() {
        let mut context = context();
        context.update(10, 0);
        assert_eq!(context.highest_sequence, Some(10));

        context.update(9, 0);
        assert_eq!(context.highest_sequence, Some(10));

        context.update(11, 0);
        assert_eq!(context.highest_sequence, Some(11));

        context.update(0, 1);
        assert_eq!(context.roc, 1);
        assert_eq!(context.highest_sequence, Some(0));

        // A late packet from ROC-1 does not move either value.
        context.update(65_535, 0);
        assert_eq!(context.roc, 1);
        assert_eq!(context.highest_sequence, Some(0));
    }
}

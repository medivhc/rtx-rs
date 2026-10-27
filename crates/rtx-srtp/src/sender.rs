//! Sender-side `SRTP` context for one `SSRC`.

use rtx_crypto::{Aes128BlockProvider, HmacProvider};

use crate::cipher::{self, SessionKeys};
use crate::error::Error;
use crate::packet;
use crate::{AUTH_TAG_LEN, PROFILE_AES128_CM_HMAC_SHA1_80, SESSION_KEY_LEN, SESSION_SALT_LEN};

/// Sender context protecting `RTP` packets for one `SSRC`.
///
/// The context owns the rollover counter and the sequence number of the last
/// protected packet. It never reads a clock and never allocates.
pub struct SenderContext<P> {
    provider: P,
    keys: SessionKeys,
    ssrc: u32,
    roc: u32,
    last_sequence: Option<u16>,
}

impl<P> SenderContext<P> {
    /// Creates a sender for `ssrc`.
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
            last_sequence: None,
        })
    }

    /// `SSRC` this context protects.
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

impl<P: Aes128BlockProvider + HmacProvider> SenderContext<P> {
    /// Protects one `RTP` packet into `output`, returning the protected length.
    ///
    /// The full `RTP` header — the 12-byte fixed header, the `CSRC` list and
    /// the header extension block — is copied unchanged and left in the clear;
    /// only the media payload, including any `RTP` padding octets, is AES-CM
    /// encrypted, starting at the end of the full header (`RFC 3711`
    /// section 3.1). The HMAC-SHA1-80 tag is computed over the complete
    /// protected packet followed by the 32-bit `ROC` (`RFC 3711` section 4.2)
    /// and appended, so the result is `rtp.len() + 10` bytes.
    ///
    /// The caller must invoke `protect` in send order. A sequence number below
    /// the previous one is treated as a wrap and increments the rollover
    /// counter, including gaps such as 65534 -> 0. Repeating the previous
    /// sequence number returns [`Error::DuplicateSequence`], because it would
    /// reuse a keystream index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedPacket`] when `rtp` is not a complete `RTP`
    /// packet with a valid `CSRC`/extension layout, [`Error::WrongSsrc`] when
    /// it carries another `SSRC`, [`Error::DuplicateSequence`] when the
    /// sequence number did not advance, [`Error::OutputTooSmall`] when
    /// `output` cannot hold `rtp.len() + 10` bytes (without writing),
    /// [`Error::PacketTooLarge`] beyond the 2^16-block keystream limit,
    /// [`Error::RocExhausted`] when advancing the rollover counter would
    /// overflow, and [`Error::Crypto`] when the provider fails.
    pub fn protect(&mut self, rtp: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let header = packet::parse(rtp)?;
        if header.ssrc != self.ssrc {
            return Err(Error::WrongSsrc {
                expected: self.ssrc,
                found: header.ssrc,
            });
        }

        let (roc, index) = self.next_index(header.sequence_number)?;
        let needed = rtp.len() + AUTH_TAG_LEN;
        if output.len() < needed {
            return Err(Error::OutputTooSmall);
        }

        // `RFC 3711` section 3.1: the encrypted region is the payload plus any
        // padding, so it starts at the end of the full `RTP` header (fixed
        // header, `CSRC` list and extension block are all cleartext).
        let enc_start = header.encoded_len();
        let cleartext_length = rtp.len();
        output[..cleartext_length].copy_from_slice(rtp);
        cipher::apply_keystream(
            &self.provider,
            &self.keys,
            self.ssrc,
            index,
            &mut output[enc_start..cleartext_length],
        )?;
        let tag =
            cipher::compute_tag(&self.provider, &self.keys, &output[..cleartext_length], roc)?;
        output[cleartext_length..needed].copy_from_slice(&tag);

        self.roc = roc;
        self.last_sequence = Some(header.sequence_number);
        Ok(needed)
    }

    /// Returns the `ROC` the packet will use and its 48-bit index.
    ///
    /// A sequence regression is a wrap: 65535 -> 0 has no gap, while
    /// 65534 -> 0 skips a value but still starts the next `ROC`. Equality is
    /// a duplicate sequence number and cannot be protected twice.
    fn next_index(&self, sequence: u16) -> Result<(u32, u64), Error> {
        let Some(last_sequence) = self.last_sequence else {
            return Ok((self.roc, index_of(self.roc, sequence)));
        };
        if sequence == last_sequence {
            return Err(Error::DuplicateSequence);
        }
        let roc = if sequence < last_sequence {
            self.roc.checked_add(1).ok_or(Error::RocExhausted)?
        } else {
            self.roc
        };
        Ok((roc, index_of(roc, sequence)))
    }
}

impl<P> core::fmt::Debug for SenderContext<P> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SenderContext")
            .field("ssrc", &self.ssrc)
            .field("rollover_counter", &self.roc)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

/// Combines the rollover counter and sequence number into a 48-bit index.
pub(crate) fn index_of(roc: u32, sequence: u16) -> u64 {
    (u64::from(roc) << 16) | u64::from(sequence)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::FIXED_HEADER_LEN;
    use rtx_crypto_rustcrypto::RustCryptoProvider;

    const SSRC: u32 = 0x1234_5678;

    fn context() -> SenderContext<RustCryptoProvider> {
        SenderContext::new(
            RustCryptoProvider::new(),
            PROFILE_AES128_CM_HMAC_SHA1_80,
            [0x11; SESSION_KEY_LEN],
            [0x22; SESSION_SALT_LEN],
            SSRC,
        )
        .expect("supported profile")
    }

    fn bare_rtp(sequence: u16) -> [u8; FIXED_HEADER_LEN] {
        let mut packet = [0u8; FIXED_HEADER_LEN];
        packet[0] = 0x80;
        packet[1] = 96;
        packet[2..4].copy_from_slice(&sequence.to_be_bytes());
        packet[8..12].copy_from_slice(&SSRC.to_be_bytes());
        packet
    }

    // SRTP-SEND-001 — the ROC cannot wrap past 2^32; that would reuse an index.
    #[test]
    fn rollover_counter_exhaustion_is_explicit() {
        let mut context = context();
        context.roc = u32::MAX;
        context.last_sequence = Some(u16::MAX);

        let mut output = [0u8; FIXED_HEADER_LEN + AUTH_TAG_LEN];
        assert_eq!(
            context.protect(&bare_rtp(0), &mut output),
            Err(Error::RocExhausted)
        );
        // A failed call must not advance the counter or the sequence state.
        assert_eq!(context.rollover_counter(), u32::MAX);
    }

    // SRTP-SEND-002 — clean wrap 65535 -> 0 increments the ROC exactly once.
    #[test]
    fn sequence_wrap_advances_rollover_counter() {
        let mut context = context();
        context.last_sequence = Some(u16::MAX);
        let (roc, index) = context.next_index(0).expect("advance");
        assert_eq!(roc, 1);
        assert_eq!(index, 0x0001_0000);

        // `next_index` is read-only; model the state `protect` commits after a
        // successful packet.
        context.roc = 1;
        context.last_sequence = Some(0);
        let (roc, index) = context.next_index(1).expect("no second advance");
        assert_eq!(roc, 1);
        assert_eq!(index, 0x0001_0001);
    }

    // SRTP-SEND-003 — a gap across the wrap is still a wrap.
    #[test]
    fn gap_wrap_from_65534_to_zero_advances_rollover_counter() {
        let mut context = context();
        context.last_sequence = Some(65_534);
        let (roc, index) = context.next_index(0).expect("advance");
        assert_eq!(roc, 1);
        assert_eq!(index, 0x0001_0000);
    }

    // SRTP-SEND-004 — 0 -> 65535 -> 0 wraps exactly once.
    #[test]
    fn zero_to_max_to_zero_wraps_once() {
        let mut context = context();
        context.last_sequence = Some(0);
        let (roc, index) = context.next_index(u16::MAX).expect("forward jump");
        assert_eq!((roc, index), (0, 0x0000_FFFF));

        context.last_sequence = Some(u16::MAX);
        let (roc, index) = context.next_index(0).expect("wrap");
        assert_eq!((roc, index), (1, 0x0001_0000));
    }

    // SRTP-SEND-005 — the same sequence number cannot be protected twice.
    #[test]
    fn duplicate_sequence_is_rejected() {
        let mut sender = context();
        sender.last_sequence = Some(7);
        assert_eq!(sender.next_index(7), Err(Error::DuplicateSequence));

        let mut fresh = context();
        let mut first = [0u8; FIXED_HEADER_LEN + AUTH_TAG_LEN];
        fresh
            .protect(&bare_rtp(7), &mut first)
            .expect("first packet");

        let mut second = [0u8; FIXED_HEADER_LEN + AUTH_TAG_LEN];
        assert_eq!(
            fresh.protect(&bare_rtp(7), &mut second),
            Err(Error::DuplicateSequence)
        );
        assert!(second.iter().all(|&byte| byte == 0));
    }

    // SRTP-SEND-006 — the index layout is ROC << 16 | SEQ.
    #[test]
    fn index_layout_is_roc_then_sequence() {
        assert_eq!(index_of(0, 0), 0);
        assert_eq!(index_of(0, 65535), 65535);
        assert_eq!(index_of(1, 0), 65_536);
        assert_eq!(index_of(0xFFFF_FFFF, 65535), 0xFFFF_FFFF_FFFF);
    }
}

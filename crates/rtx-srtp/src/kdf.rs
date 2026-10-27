//! `RFC 3711` section 4.3 session-key derivation.
//!
//! The derivation turns one master key and master salt into the three session
//! values used by `SRTP_AES128_CM_HMAC_SHA1_80`: the 16-byte encryption key
//! `k_e`, the 20-byte authentication key `k_a` and the 14-byte session salt
//! `k_s`.
//!
//! # Construction
//!
//! `RFC 3711` section 4.3.1 defines, for `<label>` an 8-bit constant,
//! `key_derivation_rate` and the 48-bit packet index:
//!
//! ```text
//! r       = index DIV key_derivation_rate     (a DIV 0 = 0)
//! key_id  = <label> || r                      (8 + 48 = 56 bits)
//! x       = key_id XOR master_salt            (right-aligned, LSBs agree)
//! key     = PRF_n(k_master, x)                 (n left-most bits)
//! ```
//!
//! and section 4.3.3 defines the default PRF as AES-CM under the master key
//! with the 128-bit IV `x * 2^16`, truncated to the first `n` bits.
//!
//! This crate implements the default rate `key_derivation_rate = 0`, for which
//! section 4.3.1 states that "the application of the key derivation SHALL take
//! place exactly once": `r` is zero, so `key_id` is `<label>` in its most
//! significant octet followed by 48 zero bits. Right-aligning that 56-bit
//! value against the 112-bit master salt puts the label in salt octet 7 and
//! the zero `r` in octets 8..14; multiplying by `2^16` then places the 112-bit
//! `x` in octets 0..14 of the 16-byte AES-CM input block, with octets 14..16
//! zero for the block counter. Concretely, the initial AES-CM block for a
//! label is the master salt with `label` combined by XOR into octet 7.
//!
//! The labels and lengths come from section 4.3.1 (labels) and sections 5.1,
//! 5.2 and 5.3 (default lengths): `k_e` is label `0x00` with `n_e = 128`,
//! `k_a` is label `0x01` with `n_a = 160`, and `k_s` is label `0x02` with
//! `n_s = 112`. The Appendix B.3 vectors in this module pin the construction
//! against the published derivation output, including the authentication key.
//!
//! # SRTCP labels
//!
//! `RFC 3711` section 4.3.2 keeps the same master key and master salt for
//! `SRTCP` but changes the labels: "use `<label>` = 0x03 for the SRTCP
//! encryption key, `<label>` = 0x04 for the SRTCP authentication key, and,
//! `<label>` = 0x05 for the SRTCP salting key". It also replaces the `SRTP`
//! index with the 32-bit quantity `0 || SRTCP index`. With the default
//! `key_derivation_rate = 0` the 48-bit `r` stays zero, so the PRF input has
//! the same shape as for `SRTP` and only the label octet differs.
//!
//! The `SRTP` labels `0x00`/`0x01`/`0x02` MUST NOT be reused for `SRTCP`:
//! section 3.2.1 states that the master key may be shared but the session
//! keys MUST NOT, and section 4.3.1 requires every label to be unique for
//! each type of key. Reusing the `SRTP` labels would derive the same
//! encryption, authentication and salt values for both protocols.
//! [`derive_srtcp_session_keys`] therefore derives under `0x03`/`0x04`/`0x05`
//! only.

use rtx_crypto::Aes128BlockProvider;
use zeroize::Zeroize;

use crate::error::Error;
use crate::{AES_BLOCK_LEN, SESSION_AUTH_KEY_LEN, SESSION_KEY_LEN, SESSION_SALT_LEN};

/// `RFC 3711` section 4.3.1 label for the SRTP encryption key (`k_e`).
const LABEL_ENCRYPTION: u8 = 0x00;
/// `RFC 3711` section 4.3.1 label for the SRTP authentication key (`k_a`).
const LABEL_AUTHENTICATION: u8 = 0x01;
/// `RFC 3711` section 4.3.1 label for the SRTP salting key (`k_s`).
const LABEL_SALT: u8 = 0x02;
/// `RFC 3711` section 4.3.2 label for the SRTCP encryption key.
const LABEL_SRTCP_ENCRYPTION: u8 = 0x03;
/// `RFC 3711` section 4.3.2 label for the SRTCP authentication key.
const LABEL_SRTCP_AUTHENTICATION: u8 = 0x04;
/// `RFC 3711` section 4.3.2 label for the SRTCP salting key.
const LABEL_SRTCP_SALT: u8 = 0x05;

/// Octet of the PRF input `x` that carries `<label> || r`.
///
/// `key_id` is 56 bits (`8`-bit label plus the 48-bit `r`), right-aligned
/// against the 112-bit master salt, so the label lands in salt octet 7. The
/// multiply-by-`2^16` of section 4.3.3 keeps that octet index unchanged.
const LABEL_OCTET: usize = 7;

/// Session key material owned by one context.
///
/// The three values are the derived session encryption key, the full-length
/// HMAC-SHA1 session authentication key and the session salt. `Drop` zeroizes
/// every array and `Debug` redacts them.
pub struct SessionKeys {
    encryption_key: [u8; SESSION_KEY_LEN],
    authentication_key: [u8; SESSION_AUTH_KEY_LEN],
    salt: [u8; SESSION_SALT_LEN],
}

impl SessionKeys {
    pub(crate) const fn new(
        encryption_key: [u8; SESSION_KEY_LEN],
        authentication_key: [u8; SESSION_AUTH_KEY_LEN],
        salt: [u8; SESSION_SALT_LEN],
    ) -> Self {
        Self {
            encryption_key,
            authentication_key,
            salt,
        }
    }

    /// Builds directly supplied session material for [`crate::SenderContext::new`]
    /// and [`crate::ReceiverContext::new`].
    ///
    /// The pre-derivation API accepts one 16-byte session key. It becomes the
    /// AES-CM key and is zero-extended to 20 bytes for HMAC-SHA1. HMAC pads a
    /// key shorter than the 64-byte block with zeros, so this mapping is
    /// byte-identical to the previous `HMAC(key = 16-byte session key)`
    /// behaviour while giving the tag path a full-length `k_a`.
    ///
    /// This is *not* `RFC 3711` section 4.3 output; use [`derive_session_keys`]
    /// or the `from_master` context constructors for `DTLS-SRTP` master
    /// material.
    pub(crate) const fn from_shared_key(
        key: [u8; SESSION_KEY_LEN],
        salt: [u8; SESSION_SALT_LEN],
    ) -> Self {
        let mut authentication_key = [0u8; SESSION_AUTH_KEY_LEN];
        let mut index = 0;
        while index < SESSION_KEY_LEN {
            authentication_key[index] = key[index];
            index += 1;
        }
        Self {
            encryption_key: key,
            authentication_key,
            salt,
        }
    }

    /// AES-CM session encryption key (`k_e`).
    #[must_use]
    pub const fn encryption_key(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.encryption_key
    }

    /// Full-length HMAC-SHA1 session authentication key (`k_a`).
    #[must_use]
    pub const fn authentication_key(&self) -> &[u8; SESSION_AUTH_KEY_LEN] {
        &self.authentication_key
    }

    /// AES-CM session salt (`k_s`).
    #[must_use]
    pub const fn salt(&self) -> &[u8; SESSION_SALT_LEN] {
        &self.salt
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.encryption_key.zeroize();
        self.authentication_key.zeroize();
        self.salt.zeroize();
    }
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SessionKeys")
            .field("encryption_key", &"<redacted>")
            .field("authentication_key", &"<redacted>")
            .field("salt", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// SRTCP session key material owned by one context (`RFC 3711` section 4.3.2).
///
/// The three values have the same roles and lengths as [`SessionKeys`] —
/// 16-byte encryption key, 20-byte authentication key, 14-byte salt — but are
/// derived under the SRTCP labels `0x03`/`0x04`/`0x05`. The type is distinct
/// so `SRTP` session material cannot be passed to an SRTCP context by
/// accident, which section 3.2.1 forbids ("the session key(s) MUST NOT be so
/// shared").
///
/// It wraps [`SessionKeys`], so the single `Drop` implementation zeroizes all
/// three arrays and `Debug` never prints them. The wrapper's own `Debug`
/// renders only `<redacted>`.
pub struct SrtcpSessionKeys {
    keys: SessionKeys,
}

impl SrtcpSessionKeys {
    pub(crate) const fn new(
        encryption_key: [u8; SESSION_KEY_LEN],
        authentication_key: [u8; SESSION_AUTH_KEY_LEN],
        salt: [u8; SESSION_SALT_LEN],
    ) -> Self {
        Self {
            keys: SessionKeys::new(encryption_key, authentication_key, salt),
        }
    }

    /// AES-CM SRTCP session encryption key (`k_e`).
    #[must_use]
    pub const fn encryption_key(&self) -> &[u8; SESSION_KEY_LEN] {
        self.keys.encryption_key()
    }

    /// Full-length HMAC-SHA1 SRTCP session authentication key (`k_a`).
    #[must_use]
    pub const fn authentication_key(&self) -> &[u8; SESSION_AUTH_KEY_LEN] {
        self.keys.authentication_key()
    }

    /// AES-CM SRTCP session salt (`k_s`).
    #[must_use]
    pub const fn salt(&self) -> &[u8; SESSION_SALT_LEN] {
        self.keys.salt()
    }

    /// The wrapped `SRTP`-shaped session values, for the shared cipher helpers.
    pub(crate) const fn session_keys(&self) -> &SessionKeys {
        &self.keys
    }
}

impl core::fmt::Debug for SrtcpSessionKeys {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SrtcpSessionKeys")
            .field("encryption_key", &"<redacted>")
            .field("authentication_key", &"<redacted>")
            .field("salt", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Derives the `SRTP_AES128_CM_HMAC_SHA1_80` session keys from master material
/// (`RFC 3711` section 4.3 with the default `key_derivation_rate` of zero).
///
/// One derivation is performed; there is no per-packet rekeying. The returned
/// value owns copies of the three session values and zeroizes them on drop.
///
/// # Errors
///
/// Returns [`Error::Crypto`] when the AES-CM PRF provider fails. No partially
/// derived material is returned, and the temporary buffers are zeroized on
/// both success and failure.
pub fn derive_session_keys<P: Aes128BlockProvider>(
    provider: &P,
    master_key: &[u8; SESSION_KEY_LEN],
    master_salt: &[u8; SESSION_SALT_LEN],
) -> Result<SessionKeys, Error> {
    derive(
        provider,
        master_key,
        master_salt,
        [LABEL_ENCRYPTION, LABEL_AUTHENTICATION, LABEL_SALT],
    )
}

/// Derives the SRTCP session keys from master material (`RFC 3711` section
/// 4.3.2 with the default `key_derivation_rate` of zero).
///
/// The construction is exactly [`derive_session_keys`] but under the SRTCP
/// labels: `0x03` for the encryption key, `0x04` for the authentication key
/// and `0x05` for the salt (section 4.3.2). The master key and master salt may
/// be the same ones used for `SRTP`, but the derived session values are
/// deliberately different (section 3.2.1).
///
/// One derivation is performed; there is no per-packet rekeying. The returned
/// value owns copies of the three session values and zeroizes them on drop.
///
/// # Errors
///
/// Returns [`Error::Crypto`] when the AES-CM PRF provider fails. No partially
/// derived material is returned, and the temporary buffers are zeroized on
/// both success and failure.
pub fn derive_srtcp_session_keys<P: Aes128BlockProvider>(
    provider: &P,
    master_key: &[u8; SESSION_KEY_LEN],
    master_salt: &[u8; SESSION_SALT_LEN],
) -> Result<SrtcpSessionKeys, Error> {
    let keys = derive(
        provider,
        master_key,
        master_salt,
        [
            LABEL_SRTCP_ENCRYPTION,
            LABEL_SRTCP_AUTHENTICATION,
            LABEL_SRTCP_SALT,
        ],
    )?;
    Ok(SrtcpSessionKeys { keys })
}

/// Runs the section 4.3.1 derivation once for the three labels in
/// `[encryption, authentication, salt]` order.
fn derive<P: Aes128BlockProvider>(
    provider: &P,
    master_key: &[u8; SESSION_KEY_LEN],
    master_salt: &[u8; SESSION_SALT_LEN],
    labels: [u8; 3],
) -> Result<SessionKeys, Error> {
    let mut encryption_key = [0u8; SESSION_KEY_LEN];
    let mut authentication_key = [0u8; SESSION_AUTH_KEY_LEN];
    let mut salt = [0u8; SESSION_SALT_LEN];

    let outcome = prf(
        provider,
        master_key,
        master_salt,
        labels[0],
        &mut encryption_key,
    )
    .and_then(|()| {
        prf(
            provider,
            master_key,
            master_salt,
            labels[1],
            &mut authentication_key,
        )
    })
    .and_then(|()| prf(provider, master_key, master_salt, labels[2], &mut salt));

    if let Err(error) = outcome {
        encryption_key.zeroize();
        authentication_key.zeroize();
        salt.zeroize();
        return Err(error);
    }

    let keys = SessionKeys::new(encryption_key, authentication_key, salt);
    encryption_key.zeroize();
    authentication_key.zeroize();
    salt.zeroize();
    Ok(keys)
}

/// Fills `output` with `PRF_len(k_master, x)` for `label` (`RFC 3711`
/// sections 4.3.1 and 4.3.3).
///
/// `x` is the master salt with `<label> || r` combined by XOR, right-aligned;
/// with `key_derivation_rate` zero, `r` is zero and only the label octet
/// changes.
/// The AES-CM input block is `x * 2^16`, i.e. the 14 salt octets followed by
/// the two-octet block counter. Block `j` encrypts `IV + j` and its keystream
/// is the left-most `n` bits of the concatenation, exactly as section 4.3.3
/// specifies.
fn prf<P: Aes128BlockProvider>(
    provider: &P,
    master_key: &[u8; SESSION_KEY_LEN],
    master_salt: &[u8; SESSION_SALT_LEN],
    label: u8,
    output: &mut [u8],
) -> Result<(), Error> {
    // `x * 2^16`: the 112-bit salt occupies octets 0..14, the 16-bit block
    // counter octets 14..16.
    let mut counter_block = [0u8; AES_BLOCK_LEN];
    counter_block[..SESSION_SALT_LEN].copy_from_slice(master_salt);
    counter_block[LABEL_OCTET] ^= label;

    let mut outcome = Ok(());
    for (counter, chunk) in (0_u16..).zip(output.chunks_mut(AES_BLOCK_LEN)) {
        counter_block[SESSION_SALT_LEN..].copy_from_slice(&counter.to_be_bytes());
        let mut keystream = counter_block;
        if let Err(error) = provider.encrypt_aes128_block(master_key, &mut keystream) {
            outcome = Err(Error::Crypto(error));
            break;
        }
        chunk.copy_from_slice(&keystream[..chunk.len()]);
        keystream.zeroize();
    }
    counter_block.zeroize();
    outcome
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use rtx_crypto::CryptoError;
    use rtx_crypto_rustcrypto::RustCryptoProvider;

    /// RFC 3711 Appendix B.3 master key.
    const MASTER_KEY: [u8; SESSION_KEY_LEN] = [
        0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41,
        0x39,
    ];
    /// RFC 3711 Appendix B.3 master salt.
    const MASTER_SALT: [u8; SESSION_SALT_LEN] = [
        0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
    ];

    fn hex<const N: usize>(input: &str) -> [u8; N] {
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&input[offset..offset + 2], 16).expect("hex");
        }
        output
    }

    fn keys() -> SessionKeys {
        derive_session_keys(&RustCryptoProvider::new(), &MASTER_KEY, &MASTER_SALT).expect("derive")
    }

    // SRTP-KDF-001 — the three session values match RFC 3711 Appendix B.3
    // verbatim: cipher key C61E..., cipher salt 30CB... and the first 20
    // octets of the 94-octet auth key CEBE...6D38.
    #[test]
    fn rfc3711_appendix_b3_key_derivation_matches_published_vectors() {
        let keys = keys();
        assert_eq!(
            keys.encryption_key(),
            &hex::<SESSION_KEY_LEN>("C61E7A93744F39EE10734AFE3FF7A087")
        );
        assert_eq!(
            keys.salt(),
            &hex::<SESSION_SALT_LEN>("30CBBC08863D8C85D49DB34A9AE1")
        );
        assert_eq!(
            keys.authentication_key(),
            &hex::<SESSION_AUTH_KEY_LEN>("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA48F0A0ACF")
        );
    }

    // SRTP-KDF-002 — the authentication key spans two AES-CM blocks; the
    // first 20 octets are the first 20 of 32 keystream octets, not a second
    // derivation. Appendix B.3 publishes 94 octets, of which these are the
    // first 20.
    #[test]
    fn authentication_key_uses_two_counter_blocks() {
        let keys = keys();
        let first = hex::<AES_BLOCK_LEN>("CEBE321F6FF7716B6FD4AB49AF256A15");
        let second = hex::<AES_BLOCK_LEN>("6D38BAA48F0A0ACF3C34E2359E6CDBCE");
        assert_eq!(&keys.authentication_key()[..AES_BLOCK_LEN], &first);
        assert_eq!(
            &keys.authentication_key()[AES_BLOCK_LEN..],
            &second[..SESSION_AUTH_KEY_LEN - AES_BLOCK_LEN]
        );
    }

    // SRTP-KDF-003 — derivation is deterministic and label-separated.
    #[test]
    fn derivation_is_deterministic_and_labels_are_separated() {
        let first = keys();
        let second = keys();
        assert_eq!(first.encryption_key(), second.encryption_key());
        assert_eq!(first.authentication_key(), second.authentication_key());
        assert_eq!(first.salt(), second.salt());
        assert_ne!(
            &first.encryption_key()[..],
            &first.authentication_key()[..SESSION_KEY_LEN]
        );
    }

    // SRTP-KDF-004 — the Debug view and the owner never expose material.
    #[test]
    fn session_keys_debug_redacts_all_three_fields() {
        let rendered = format!("{:?}", keys());
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("c61e"));
        assert!(!rendered.contains("cebe"));
        assert!(!rendered.contains("30cb"));
    }

    // SRTP-KDF-005 — direct session material zero-extends the 16-byte key to
    // the 20-byte HMAC key (bytes 16..20 are zero).
    #[test]
    fn shared_key_is_zero_extended_to_the_authentication_key() {
        let key = [0x11_u8; SESSION_KEY_LEN];
        let keys = SessionKeys::from_shared_key(key, [0x22_u8; SESSION_SALT_LEN]);
        assert_eq!(keys.encryption_key(), &key);
        assert_eq!(keys.salt(), &[0x22_u8; SESSION_SALT_LEN]);
        assert_eq!(&keys.authentication_key()[..SESSION_KEY_LEN], &key);
        assert_eq!(
            &keys.authentication_key()[SESSION_KEY_LEN..],
            &[0_u8; SESSION_AUTH_KEY_LEN - SESSION_KEY_LEN]
        );
    }

    /// AES provider that always fails.
    #[derive(Debug)]
    struct FailingAes;

    impl Aes128BlockProvider for FailingAes {
        fn encrypt_aes128_block(
            &self,
            _key: &[u8; 16],
            _block: &mut [u8; 16],
        ) -> Result<(), CryptoError> {
            Err(CryptoError::Unsupported)
        }
    }

    // SRTP-KDF-006 — a provider failure is reported and no partial key set is
    // returned.
    #[test]
    fn provider_failure_is_reported() {
        assert_eq!(
            derive_session_keys(&FailingAes, &MASTER_KEY, &MASTER_SALT).err(),
            Some(Error::Crypto(CryptoError::Unsupported))
        );
    }

    // SRTP-KDF-007 — SRTCP uses RFC 3711 section 4.3.2 labels 0x03/0x04/0x05.
    // RFC 3711 publishes no SRTCP derivation vector, so the expected values
    // were computed independently with OpenSSL 3.0.13 AES-128-ECB from the
    // section 4.3.3 formula: the master salt with the label XORed into octet
    // 7, followed by the 16-bit block counter 0x0000/0x0001, encrypted under
    // the Appendix B.3 master key. The same procedure reproduces the
    // published Appendix B.3 SRTP values under labels 0x00/0x01/0x02.
    #[test]
    fn srtcp_derivation_uses_the_srtcp_labels() {
        let keys = derive_srtcp_session_keys(&RustCryptoProvider::new(), &MASTER_KEY, &MASTER_SALT)
            .expect("derive");
        assert_eq!(
            keys.encryption_key(),
            &hex::<SESSION_KEY_LEN>("4C1AA45A81F73D61C800BBB00FBB1EAA")
        );
        assert_eq!(
            keys.authentication_key(),
            &hex::<SESSION_AUTH_KEY_LEN>("8D54534FEB49AE8E7993A6BD0B844FC323A93DFD")
        );
        assert_eq!(
            keys.salt(),
            &hex::<SESSION_SALT_LEN>("9581C7AD87B3E530BF3E4454A8B381")
        );
    }

    // SRTP-KDF-008 — SRTCP and SRTP session values are disjoint even under
    // the same master key and salt (RFC 3711 section 3.2.1: the session keys
    // MUST NOT be shared).
    #[test]
    fn srtcp_and_srtp_session_values_are_disjoint() {
        let media = keys();
        let control =
            derive_srtcp_session_keys(&RustCryptoProvider::new(), &MASTER_KEY, &MASTER_SALT)
                .expect("derive");
        assert_ne!(media.encryption_key(), control.encryption_key());
        assert_ne!(media.authentication_key(), control.authentication_key());
        assert_ne!(media.salt(), control.salt());
    }

    // SRTP-KDF-009 — the SRTCP Debug view never exposes material.
    #[test]
    fn srtcp_session_keys_debug_redacts_all_three_fields() {
        let rendered = format!(
            "{:?}",
            derive_srtcp_session_keys(&RustCryptoProvider::new(), &MASTER_KEY, &MASTER_SALT)
                .expect("derive")
        );
        assert!(rendered.contains("SrtcpSessionKeys"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("4c1a"));
        assert!(!rendered.contains("8d54"));
        assert!(!rendered.contains("9581"));
    }

    // SRTP-KDF-010 — the SRTCP derivation reports a provider failure too.
    #[test]
    fn srtcp_provider_failure_is_reported() {
        assert_eq!(
            derive_srtcp_session_keys(&FailingAes, &MASTER_KEY, &MASTER_SALT).err(),
            Some(Error::Crypto(CryptoError::Unsupported))
        );
    }
}

//! Robustness: truncation, garbage, lying header fields, provider failures and
//! the per-packet keystream limit.

mod common;

use common::{KEY, Lcg, SALT, SSRC, protect, receiver, rtp, sender};
use rtx_crypto::{Aes128BlockProvider, CryptoError, HashAlgorithm, HmacProvider};
use rtx_crypto_rustcrypto::RustCryptoProvider;
use rtx_srtp::{
    AUTH_TAG_LEN, Error, PROFILE_AES128_CM_HMAC_SHA1_80, ReceiverContext, SESSION_KEY_LEN,
    SESSION_SALT_LEN, SenderContext,
};

const MAX_REGION_LEN: usize = (1 << 16) * 16;

/// AES that always fails; HMAC is a successful zero-length lie, never reached
/// on the sender path because AES runs first.
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

impl HmacProvider for FailingAes {
    fn hmac(
        &self,
        _algorithm: HashAlgorithm,
        _key: &[u8],
        _input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        output.fill(0);
        Ok(20)
    }
}

/// HMAC that always fails, with a working AES implementation.
#[derive(Debug)]
struct FailingHmac;

impl Aes128BlockProvider for FailingHmac {
    fn encrypt_aes128_block(
        &self,
        key: &[u8; 16],
        block: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        RustCryptoProvider::new().encrypt_aes128_block(key, block)
    }
}

impl HmacProvider for FailingHmac {
    fn hmac(
        &self,
        _algorithm: HashAlgorithm,
        _key: &[u8],
        _input: &[u8],
        _output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// HMAC that writes 19 bytes and claims success.
#[derive(Debug)]
struct LyingHmac;

impl Aes128BlockProvider for LyingHmac {
    fn encrypt_aes128_block(
        &self,
        key: &[u8; 16],
        block: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        RustCryptoProvider::new().encrypt_aes128_block(key, block)
    }
}

impl HmacProvider for LyingHmac {
    fn hmac(
        &self,
        _algorithm: HashAlgorithm,
        _key: &[u8],
        _input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        output.fill(0x5A);
        Ok(19)
    }

    fn hmac_parts(
        &self,
        _algorithm: HashAlgorithm,
        _key: &[u8],
        _parts: &[&[u8]],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        output.fill(0x5A);
        Ok(19)
    }
}

/// Working HMAC with an AES implementation that always fails.
#[derive(Debug)]
struct AesFailsGoodHmac;

impl Aes128BlockProvider for AesFailsGoodHmac {
    fn encrypt_aes128_block(
        &self,
        _key: &[u8; 16],
        _block: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

impl HmacProvider for AesFailsGoodHmac {
    fn hmac(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        RustCryptoProvider::new().hmac(algorithm, key, input, output)
    }

    fn hmac_parts(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        parts: &[&[u8]],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        RustCryptoProvider::new().hmac_parts(algorithm, key, parts, output)
    }
}

fn protected_packet() -> Vec<u8> {
    let original = rtp(SSRC, 12, false, true);
    let mut sender = sender();
    protect(&mut sender, &original)
}

// SRTP-ROB-001 — every prefix of a valid packet is handled without panicking.
#[test]
fn every_truncation_is_safe() {
    let full = rtp(SSRC, 9, true, true);
    for length in 0..=full.len() {
        let mut sender = sender();
        let mut sender_output = vec![0u8; full.len() + AUTH_TAG_LEN + 8];
        let _ = sender.protect(&full[..length], &mut sender_output);

        let mut receiver = receiver();
        let mut receiver_output = vec![0u8; full.len() + 8];
        assert!(
            receiver
                .unprotect(&full[..length], &mut receiver_output)
                .is_err(),
            "length {length} unexpectedly decrypted"
        );
    }
}

// SRTP-ROB-002 — deterministic garbage of every length up to 200 bytes.
#[test]
fn deterministic_garbage_is_safe() {
    let mut lcg = Lcg::new(0x0DDB_1A5E_5BAD_5EED);
    for length in 0..=200 {
        let bytes = lcg.bytes(length);
        let mut sender = sender();
        let mut sender_output = vec![0u8; length + AUTH_TAG_LEN + 8];
        let _ = sender.protect(&bytes, &mut sender_output);

        let mut receiver = receiver();
        let mut receiver_output = vec![0u8; length + 8];
        assert!(
            receiver.unprotect(&bytes, &mut receiver_output).is_err(),
            "garbage length {length} unexpectedly decrypted"
        );
    }
}

// SRTP-ROB-003 — lying CSRC counts, extension lengths and versions fail with a
// typed error rather than an index panic.
#[test]
fn lying_header_fields_are_rejected() {
    let mut sender = sender();
    let mut output = vec![0u8; 4096];

    // CC = 15 with no CSRC bytes following.
    let mut short_csrc = vec![0u8; 12];
    short_csrc[0] = 0x8F;
    assert_eq!(
        sender.protect(&short_csrc, &mut output),
        Err(Error::MalformedPacket)
    );

    // Extension length claims 65535 words beyond the packet.
    let mut long_extension = vec![0u8; 20];
    long_extension[0] = 0x90;
    long_extension[12..16].copy_from_slice(&[0xBE, 0xDE, 0xFF, 0xFF]);
    assert_eq!(
        sender.protect(&long_extension, &mut output),
        Err(Error::MalformedPacket)
    );

    // RTP version 1.
    let mut bad_version = vec![0u8; 12];
    bad_version[0] = 0x40;
    assert_eq!(
        sender.protect(&bad_version, &mut output),
        Err(Error::MalformedPacket)
    );
}

// SRTP-ROB-004 — more than 2^16 keystream blocks is rejected before writing.
#[test]
fn packet_beyond_keystream_limit_is_rejected() {
    let mut huge = vec![0u8; 12 + MAX_REGION_LEN + 1];
    huge[0] = 0x80;
    huge[1] = 96;
    huge[8..12].copy_from_slice(&SSRC.to_be_bytes());
    let mut output = vec![0u8; huge.len() + AUTH_TAG_LEN];

    let mut sender = sender();
    assert_eq!(
        sender.protect(&huge, &mut output),
        Err(Error::PacketTooLarge)
    );
}

// SRTP-ROB-005 — provider failures on the sender path are explicit.
#[test]
fn sender_provider_failures_are_explicit() {
    let original = rtp(SSRC, 12, false, false);
    let mut output = vec![0u8; original.len() + AUTH_TAG_LEN];

    let mut sender =
        SenderContext::new(FailingAes, PROFILE_AES128_CM_HMAC_SHA1_80, KEY, SALT, SSRC)
            .expect("profile");
    assert_eq!(
        sender.protect(&original, &mut output),
        Err(Error::Crypto(CryptoError::Unsupported))
    );

    let mut sender =
        SenderContext::new(FailingHmac, PROFILE_AES128_CM_HMAC_SHA1_80, KEY, SALT, SSRC)
            .expect("profile");
    assert_eq!(
        sender.protect(&original, &mut output),
        Err(Error::Crypto(CryptoError::Unsupported))
    );

    let mut sender = SenderContext::new(LyingHmac, PROFILE_AES128_CM_HMAC_SHA1_80, KEY, SALT, SSRC)
        .expect("profile");
    assert_eq!(
        sender.protect(&original, &mut output),
        Err(Error::Crypto(CryptoError::BackendFailure))
    );
}

// SRTP-ROB-006 — provider failures on the receiver path are explicit both
// before authentication and during decryption.
#[test]
fn receiver_provider_failures_are_explicit() {
    let protected = protected_packet();
    let plaintext_length = protected.len() - AUTH_TAG_LEN;
    let mut output = vec![0u8; plaintext_length];

    let mut receiver =
        ReceiverContext::new(FailingHmac, PROFILE_AES128_CM_HMAC_SHA1_80, KEY, SALT, SSRC)
            .expect("profile");
    assert_eq!(
        receiver.unprotect(&protected, &mut output),
        Err(Error::Crypto(CryptoError::Unsupported))
    );

    let mut receiver =
        ReceiverContext::new(LyingHmac, PROFILE_AES128_CM_HMAC_SHA1_80, KEY, SALT, SSRC)
            .expect("profile");
    assert_eq!(
        receiver.unprotect(&protected, &mut output),
        Err(Error::Crypto(CryptoError::BackendFailure))
    );

    let mut receiver = ReceiverContext::new(
        AesFailsGoodHmac,
        PROFILE_AES128_CM_HMAC_SHA1_80,
        KEY,
        SALT,
        SSRC,
    )
    .expect("profile");
    assert_eq!(
        receiver.unprotect(&protected, &mut output),
        Err(Error::Crypto(CryptoError::Unsupported))
    );
}

// SRTP-ROB-007 — a tag-valid packet whose cleartext extension header is
// inconsistent is rejected when the header is parsed after authentication, and
// the replay state does not advance.
#[test]
fn tag_valid_packet_with_broken_extension_is_rejected() {
    let original = rtp(SSRC, 11, false, true);
    let mut sender = sender();
    let mut protected = protect(&mut sender, &original);

    // The extension length sits at 12 (fixed) + 8 (two CSRC) + 2 (profile) =
    // 22..24 and holds 0x0001 in the clear (RFC 3711 §3.1). Flip it to 0x00FF
    // words, which cannot fit the packet.
    let length_byte = 12 + 8 + 3;
    protected[length_byte] ^= original[length_byte] ^ 0xFF;

    // Re-authenticate the tampered packet with the real session key so the tag
    // check passes and the header check after authentication is reached. The
    // first packet uses ROC = 0, and the tag covers packet || ROC.
    let plaintext_length = protected.len() - AUTH_TAG_LEN;
    let roc = 0_u32.to_be_bytes();
    let mut mac = [0u8; 20];
    RustCryptoProvider::new()
        .hmac_parts(
            HashAlgorithm::Sha1,
            &KEY,
            &[&protected[..plaintext_length], &roc],
            &mut mac,
        )
        .expect("HMAC");
    protected[plaintext_length..].copy_from_slice(&mac[..AUTH_TAG_LEN]);

    let mut receiver = receiver();
    let mut output = vec![0u8; plaintext_length];
    assert_eq!(
        receiver.unprotect(&protected, &mut output),
        Err(Error::MalformedPacket)
    );
    assert_eq!(receiver.rollover_counter(), 0);
}

// SRTP-ROB-008 — a tag-valid packet with an impossible key/salt length is
// unreachable by construction (the arrays are fixed), so the constructor is
// the only place profile validation can fail. Keep that path pinned.
#[test]
fn constructor_validates_profile_before_any_crypto() {
    for profile in [0x0002_u16, 0xFFFF] {
        assert_eq!(
            SenderContext::<RustCryptoProvider>::new(
                RustCryptoProvider::new(),
                profile,
                [0u8; SESSION_KEY_LEN],
                [0u8; SESSION_SALT_LEN],
                SSRC,
            )
            .err(),
            Some(Error::UnsupportedProfile(profile))
        );
        assert_eq!(
            ReceiverContext::<RustCryptoProvider>::new(
                RustCryptoProvider::new(),
                profile,
                [0u8; SESSION_KEY_LEN],
                [0u8; SESSION_SALT_LEN],
                SSRC,
            )
            .err(),
            Some(Error::UnsupportedProfile(profile))
        );
    }
}

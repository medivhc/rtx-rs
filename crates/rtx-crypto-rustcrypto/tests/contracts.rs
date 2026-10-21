//! Contract conformance for the RustCrypto-backed provider.
//!
//! [`published_vectors`](published_vectors.rs) proves the backend agrees with
//! the standards. This file proves it honours the *trait contracts* the
//! workspace depends on — the properties a protocol crate relies on but cannot
//! observe from a wire vector:
//!
//! 1. a rejected call leaves the caller's buffer byte-identical,
//! 2. size validation happens before any write,
//! 3. the declined suites say so explicitly rather than returning garbage,
//! 4. the provider is usable through the trait objects the DTLS engine holds.
//!
//! The reference backend in `rtx-crypto`'s own suite already pins these
//! contracts. Running them against the real backend as well is what catches a
//! provider that satisfies its traits but violates their intent.

#![allow(clippy::missing_panics_doc)]

use rtx_crypto::{
    AeadAlgorithm, AeadProvider, CryptoError, HashAlgorithm, HashProvider, HmacProvider,
    KeyExchangeAlgorithm, KeyExchangeProvider, SignatureAlgorithm, SignatureProvider,
};
use rtx_crypto_rustcrypto::{RustCryptoProvider, TAG_LEN, digest_len};

fn provider() -> RustCryptoProvider {
    RustCryptoProvider::new()
}

/// An AES-128-GCM key and nonce of the right size, for tests that are not
/// about key length.
fn key() -> [u8; 16] {
    [0x11; 16]
}
fn nonce() -> [u8; 12] {
    [0x22; 12]
}

// ---------------------------------------------------------------------------
// OutputTooSmall must not write anything
// ---------------------------------------------------------------------------

/// Every operation validates its output length before touching the buffer, so
/// an undersized buffer is left exactly as the caller passed it in.
#[test]
fn undersized_output_is_rejected_without_writing() {
    let p = provider();

    for algorithm in [
        HashAlgorithm::Sha1,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
    ] {
        let need = digest_len(algorithm);

        // One byte short of the digest.
        let mut short = vec![0xAAu8; need - 1];
        let snapshot = short.clone();
        assert_eq!(
            p.digest(algorithm, b"payload", &mut short),
            Err(CryptoError::OutputTooSmall)
        );
        assert_eq!(short, snapshot, "digest wrote into a rejected buffer");

        // An empty buffer is also rejected, and also untouched.
        let mut empty: Vec<u8> = Vec::new();
        assert_eq!(
            p.digest(algorithm, b"payload", &mut empty),
            Err(CryptoError::OutputTooSmall)
        );

        // The same for HMAC.
        let mut short = vec![0xAAu8; need - 1];
        let snapshot = short.clone();
        assert_eq!(
            p.hmac(algorithm, b"key", b"payload", &mut short),
            Err(CryptoError::OutputTooSmall)
        );
        assert_eq!(short, snapshot, "hmac wrote into a rejected buffer");
    }
}

/// An exactly-sized digest buffer succeeds; one byte more is fine too, because
/// the trait returns the length rather than requiring an exact fit.
#[test]
fn digest_accepts_exact_and_oversized_buffers() {
    let p = provider();
    let mut exact = vec![0u8; 32];
    assert_eq!(p.digest(HashAlgorithm::Sha256, b"abc", &mut exact), Ok(32));

    let mut roomy = vec![0xFFu8; 64];
    assert_eq!(p.digest(HashAlgorithm::Sha256, b"abc", &mut roomy), Ok(32));
    assert_eq!(
        &roomy[..32],
        &exact[..],
        "oversized buffer must receive the same digest"
    );
    assert_eq!(&roomy[32..], &[0xFFu8; 32], "tail must be left alone");
}

/// An AEAD buffer too small for plaintext + tag is rejected before the
/// keystream touches it.
#[test]
fn seal_rejects_undersized_buffer_without_writing() {
    let p = provider();
    let mut buffer = vec![0xAAu8; 4];
    let snapshot = buffer.clone();
    assert_eq!(
        p.seal_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key(),
            &nonce(),
            b"",
            &mut buffer,
            4
        ),
        Err(CryptoError::OutputTooSmall)
    );
    assert_eq!(buffer, snapshot);

    // A `plaintext_len` that would overflow `+ TAG_LEN` is caught too.
    let mut buffer = vec![0xAAu8; 8];
    let snapshot = buffer.clone();
    assert_eq!(
        p.seal_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key(),
            &nonce(),
            b"",
            &mut buffer,
            usize::MAX
        ),
        Err(CryptoError::OutputTooSmall)
    );
    assert_eq!(buffer, snapshot);
}

/// Opening a buffer shorter than the tag cannot be authenticated.
#[test]
fn open_rejects_buffer_shorter_than_tag() {
    let p = provider();
    let mut buffer = vec![0xAAu8; TAG_LEN - 1];
    let snapshot = buffer.clone();
    assert_eq!(
        p.open_in_place(AeadAlgorithm::Aes128Gcm, &key(), &nonce(), b"", &mut buffer),
        Err(CryptoError::OutputTooSmall)
    );
    assert_eq!(buffer, snapshot);
}

// ---------------------------------------------------------------------------
// Key and nonce validation
// ---------------------------------------------------------------------------

/// GCM fixes the nonce at 96 bits. A wrong-length nonce must be reported, not
/// truncated to fit — a silently shortened nonce is a catastrophic nonce-reuse
/// bug.
#[test]
fn wrong_length_nonce_is_rejected_not_truncated() {
    let p = provider();
    let mut buffer = vec![0u8; 4 + TAG_LEN];

    for bad_len in [0usize, 8, 11, 13, 16] {
        let bad = vec![0u8; bad_len];
        let snapshot = buffer.clone();
        assert_eq!(
            p.seal_in_place(AeadAlgorithm::Aes128Gcm, &key(), &bad, b"", &mut buffer, 4),
            Err(CryptoError::InvalidNonce),
            "seal accepted a {bad_len}-byte nonce"
        );
        assert_eq!(buffer, snapshot);

        assert_eq!(
            p.open_in_place(AeadAlgorithm::Aes128Gcm, &key(), &bad, b"", &mut buffer),
            Err(CryptoError::InvalidNonce),
            "open accepted a {bad_len}-byte nonce"
        );
    }

    // A 12-byte nonce is the only accepted length.
    assert!(
        p.seal_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key(),
            &nonce(),
            b"",
            &mut buffer,
            4
        )
        .is_ok()
    );
}

/// A key whose length does not match the cipher is rejected as `InvalidKey`,
/// and the payload is left untouched.
#[test]
fn wrong_length_key_is_rejected() {
    let p = provider();
    for bad_len in [0usize, 8, 15, 17, 24, 31, 33] {
        let bad = vec![0u8; bad_len];
        let mut buffer = vec![0xAAu8; 4 + TAG_LEN];
        let snapshot = buffer.clone();
        assert_eq!(
            p.seal_in_place(
                AeadAlgorithm::Aes128Gcm,
                &bad,
                &nonce(),
                b"",
                &mut buffer,
                4
            ),
            Err(CryptoError::InvalidKey),
            "AES-128 accepted a {bad_len}-byte key"
        );
        assert_eq!(buffer, snapshot);
    }

    // AES-256 needs 32 bytes; a 16-byte key must not be padded up.
    let mut buffer = vec![0xAAu8; 4 + TAG_LEN];
    assert_eq!(
        p.seal_in_place(
            AeadAlgorithm::Aes256Gcm,
            &[0u8; 16],
            &nonce(),
            b"",
            &mut buffer,
            4
        ),
        Err(CryptoError::InvalidKey)
    );
}

// ---------------------------------------------------------------------------
// AEAD round-trip properties
// ---------------------------------------------------------------------------

/// Empty plaintext is legal in GCM and still authenticates: the tag covers
/// the nonce, the empty ciphertext and the AAD.
#[test]
fn empty_plaintext_round_trips() {
    let p = provider();
    let mut buffer = vec![0u8; TAG_LEN];
    let written = p
        .seal_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key(),
            &nonce(),
            b"aad",
            &mut buffer,
            0,
        )
        .expect("seal empty");
    assert_eq!(written, TAG_LEN);

    let opened = p
        .open_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key(),
            &nonce(),
            b"aad",
            &mut buffer,
        )
        .expect("open empty");
    assert_eq!(opened, 0);
}

/// A different nonce must produce a different ciphertext for the same
/// plaintext — the property that makes nonce reuse catastrophic if violated.
#[test]
fn distinct_nonces_produce_distinct_ciphertexts() {
    let p = provider();
    let plaintext = b"the same plaintext every time";

    let mut seen: Vec<Vec<u8>> = Vec::new();
    for counter in 0u8..8 {
        let mut iv = nonce();
        iv[11] = counter;
        let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
        p.seal_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key(),
            &iv,
            b"",
            &mut buffer,
            plaintext.len(),
        )
        .expect("seal");
        assert!(
            !seen.contains(&buffer),
            "nonce {counter} reused a ciphertext: GCM nonce reuse"
        );
        seen.push(buffer);
    }
}

/// Every byte of the plaintext is authenticated: changing the length, the
/// content or the AAD must all fail.
#[test]
fn tamper_detection_covers_length_content_and_aad() {
    let p = provider();
    let plaintext = b"authenticating this";
    let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
    sealed[..plaintext.len()].copy_from_slice(plaintext);
    p.seal_in_place(
        AeadAlgorithm::Aes128Gcm,
        &key(),
        &nonce(),
        b"header",
        &mut sealed,
        plaintext.len(),
    )
    .expect("seal");

    // Unmodified, it opens.
    let mut good = sealed.clone();
    assert_eq!(
        p.open_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key(),
            &nonce(),
            b"header",
            &mut good
        ),
        Ok(plaintext.len())
    );

    // Content tampered.
    let mut bad = sealed.clone();
    bad[0] ^= 0xff;
    assert_eq!(
        p.open_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key(),
            &nonce(),
            b"header",
            &mut bad
        ),
        Err(CryptoError::AuthenticationFailed)
    );

    // Tag tampered.
    let mut bad = sealed.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert_eq!(
        p.open_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key(),
            &nonce(),
            b"header",
            &mut bad
        ),
        Err(CryptoError::AuthenticationFailed)
    );

    // Truncated ciphertext: the remaining tag no longer authenticates.
    let mut bad = sealed[..sealed.len() - TAG_LEN - 1].to_vec();
    assert!(matches!(
        p.open_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key(),
            &nonce(),
            b"header",
            &mut bad
        ),
        Err(CryptoError::AuthenticationFailed)
    ));

    // A different AAD must fail even though the ciphertext is intact.
    let mut bad = sealed.clone();
    assert_eq!(
        p.open_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key(),
            &nonce(),
            b"HEADER",
            &mut bad
        ),
        Err(CryptoError::AuthenticationFailed)
    );

    // A different key must fail too.
    let mut bad = sealed.clone();
    assert_eq!(
        p.open_in_place(
            AeadAlgorithm::Aes128Gcm,
            &[0x99; 16],
            &nonce(),
            b"header",
            &mut bad
        ),
        Err(CryptoError::AuthenticationFailed)
    );
}

// ---------------------------------------------------------------------------
// Declined suites
// ---------------------------------------------------------------------------

/// Ed25519 and ECDH are deliberately not implemented. They must report
/// `Unsupported` on every entry point rather than emitting a placeholder: a
/// silently-wrong DTLS handshake is worse than a refused one.
#[test]
fn declined_suites_report_unsupported() {
    let p = provider();
    let key = rtx_crypto_rustcrypto::SigningKey::for_tests();
    let mut signature = [0u8; 64];
    let mut public = [0u8; 32];
    let mut secret = [0u8; 32];

    for algorithm in [
        SignatureAlgorithm::Ed25519,
        SignatureAlgorithm::EcdsaP256Sha256,
    ] {
        let before = signature;
        assert_eq!(
            p.sign(algorithm, &key, b"msg", &mut signature),
            Err(CryptoError::Unsupported)
        );
        assert_eq!(signature, before, "sign wrote into a declined buffer");

        assert_eq!(
            p.verify(algorithm, &public, b"msg", &signature),
            Err(CryptoError::Unsupported)
        );
    }

    let exchange = rtx_crypto_rustcrypto::ExchangeKey::for_tests();
    for algorithm in [
        KeyExchangeAlgorithm::X25519,
        KeyExchangeAlgorithm::P256,
        KeyExchangeAlgorithm::P384,
    ] {
        let before = public;
        assert_eq!(
            p.generate_key(algorithm, &mut public).map(|_| ()),
            Err(CryptoError::Unsupported)
        );
        assert_eq!(public, before, "generate_key wrote into a declined buffer");

        let before = secret;
        assert_eq!(
            p.agree(algorithm, &exchange, &public, &mut secret),
            Err(CryptoError::Unsupported)
        );
        assert_eq!(secret, before, "agree wrote into a declined buffer");
    }
}

// ---------------------------------------------------------------------------
// Object safety
// ---------------------------------------------------------------------------

/// The DTLS engine holds providers behind trait objects. If a trait were not
/// object-safe the engine could not be generic over providers, so this
/// compiles only while the object-safe subset stays usable that way.
#[test]
fn provider_is_usable_behind_trait_objects() {
    /// The provider is zero-sized, so a `&'static` reference is free — which
    /// is what lets the DTLS engine park one in read-only memory.
    static PROVIDER: RustCryptoProvider = RustCryptoProvider::new();

    let p = provider();

    let hasher: &dyn HashProvider = &p;
    let mac: &dyn HmacProvider = &p;
    let aead: &dyn AeadProvider = &p;

    let mut digest = [0u8; 32];
    hasher
        .digest(HashAlgorithm::Sha256, b"abc", &mut digest)
        .expect("digest through dyn");

    let mut tag = [0u8; 32];
    mac.hmac(HashAlgorithm::Sha256, b"k", b"abc", &mut tag)
        .expect("hmac through dyn");

    let mut buffer = vec![0u8; 4 + TAG_LEN];
    aead.seal_in_place(
        AeadAlgorithm::Aes128Gcm,
        &key(),
        &nonce(),
        b"",
        &mut buffer,
        4,
    )
    .expect("seal through dyn");

    // The static instance behaves exactly like the local one.
    let mut digest2 = [0u8; 32];
    PROVIDER
        .digest(HashAlgorithm::Sha256, b"abc", &mut digest2)
        .expect("static provider");
    assert_eq!(digest, digest2);
}

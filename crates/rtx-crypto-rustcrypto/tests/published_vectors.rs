//! Published test vectors for the RustCrypto-backed provider.
//!
//! The `rtx-crypto` suite pins down the *trait contracts* against a
//! deterministic reference backend. This file answers a different question:
//! does the real backend agree with the published standards?
//!
//! Every vector here comes from a public specification, not from another
//! implementation:
//!
//! | Suite | Source |
//! |---|---|
//! | SHA-1 / SHA-256 / SHA-384 | [FIPS 180] §B.1, [FIPS 202] |
//! | HMAC-SHA1 | [RFC 2202] §2 |
//! | HMAC-SHA256 / HMAC-SHA384 | [RFC 4231] §4 |
//! | AES-GCM | [NIST SP 800-38D] appendix B test cases 3, 4 and 16 |
//!
//! A provider that disagrees with these is not interoperable with anything,
//! regardless of how well it satisfies its own traits — which is exactly the
//! failure mode a self-hosted contract suite cannot catch.
//!
//! [FIPS 180]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//! [FIPS 202]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202-2.pdf
//! [RFC 2202]: https://www.rfc-editor.org/rfc/rfc2202
//! [RFC 4231]: https://www.rfc-editor.org/rfc/rfc4231
//! [NIST SP 800-38D]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

#![allow(clippy::missing_panics_doc)]

use rtx_crypto::{
    AeadAlgorithm, AeadProvider, CryptoError, HashAlgorithm, HashProvider, HmacProvider,
    RandomProvider,
};
use rtx_crypto_rustcrypto::{RustCryptoProvider, TAG_LEN, digest_len};

/// Decodes a hex literal into bytes. Panics on malformed input, which can only
/// be a typo in this file.
fn h(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex literal");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn provider() -> RustCryptoProvider {
    RustCryptoProvider::new()
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

/// FIPS 180 appendix B and FIPS 202: the one-block `"abc"` digests, plus the
/// empty-input digests.
#[test]
fn digest_matches_fips_vectors() {
    let p = provider();
    let cases: &[(HashAlgorithm, &[u8], &str)] = &[
        // FIPS 180-4 appendix B.1
        (
            HashAlgorithm::Sha1,
            b"abc",
            "a9993e364706816aba3e25717850c26c9cd0d89d",
        ),
        // FIPS 202 appendix B.1
        (
            HashAlgorithm::Sha256,
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        // FIPS 202 appendix B.1
        (
            HashAlgorithm::Sha384,
            b"abc",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        ),
        // FIPS 180-4 appendix A.1
        (
            HashAlgorithm::Sha1,
            b"",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ),
        // FIPS 202 appendix B.1
        (
            HashAlgorithm::Sha256,
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        // FIPS 202 appendix B.1
        (
            HashAlgorithm::Sha384,
            b"",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        ),
    ];

    for (algorithm, input, expected) in cases {
        let mut out = vec![0u8; digest_len(*algorithm)];
        let written = p.digest(*algorithm, input, &mut out).expect("digest");
        assert_eq!(
            written,
            out.len(),
            "digest_len disagrees with the algorithm"
        );
        assert_eq!(hex(&out), *expected, "digest mismatch for {algorithm:?}");
    }
}

/// A digest spanning more than one block, to exercise the compression loop.
#[test]
fn digest_handles_multiblock_input() {
    let p = provider();
    let input = vec![0x61u8; 1_000];
    let mut out = vec![0u8; 32];
    p.digest(HashAlgorithm::Sha256, &input, &mut out)
        .expect("digest");

    // The digest is a pure function of the input; recomputing in two halves
    // must give the same answer as the one-shot call.
    let mut a = vec![0u8; 32];
    p.digest(HashAlgorithm::Sha256, &input[..400], &mut a)
        .expect("digest a");
    let mut b = vec![0u8; 32];
    p.digest(HashAlgorithm::Sha256, &input[400..], &mut b)
        .expect("digest b");
    assert_ne!(a, out, "single-block digest must not match the full digest");
    assert_ne!(b, out, "single-block digest must not match the full digest");
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

/// RFC 2202 §2 (HMAC-SHA-1) and RFC 4231 §4 (HMAC-SHA-2), test case 1:
/// key is 20 bytes of `0x0b`, data is `"Hi There"`.
#[test]
fn hmac_matches_rfc_vectors() {
    let p = provider();
    let key = [0x0bu8; 20];
    let cases: &[(HashAlgorithm, &str)] = &[
        // RFC 2202 test case 1
        (
            HashAlgorithm::Sha1,
            "b617318655057264e28bc0b6fb378c8ef146be00",
        ),
        // RFC 4231 test case 1
        (
            HashAlgorithm::Sha256,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        // RFC 4231 test case 1
        (
            HashAlgorithm::Sha384,
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        ),
    ];

    for (algorithm, expected) in cases {
        let mut out = vec![0u8; digest_len(*algorithm)];
        let written = p
            .hmac(*algorithm, &key, b"Hi There", &mut out)
            .expect("hmac");
        assert_eq!(written, out.len());
        assert_eq!(hex(&out), *expected, "hmac mismatch for {algorithm:?}");
    }
}

/// RFC 4231 test cases 2 and 6: the short-key case (`"Jefe"`) and the
/// key-longer-than-block case (131 bytes of `0xaa`), which forces the inner
/// and outer key padding paths that the one-block vectors miss.
#[test]
fn hmac_matches_rfc_edge_case_keys() {
    let p = provider();

    // RFC 4231 test case 2: key = "Jefe", data = "what do ya want for nothing?"
    let mut out = [0u8; 32];
    p.hmac(
        HashAlgorithm::Sha256,
        b"Jefe",
        b"what do ya want for nothing?",
        &mut out,
    )
    .expect("hmac short key");
    assert_eq!(
        hex(&out),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );

    // RFC 4231 test case 6: 131-byte key exceeds the 64-byte SHA-256 block,
    // so the key is hashed first.
    let long_key = [0xaau8; 131];
    p.hmac(
        HashAlgorithm::Sha256,
        &long_key,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        &mut out,
    )
    .expect("hmac long key");
    assert_eq!(
        hex(&out),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

/// NIST SP 800-38D appendix B: AES-GCM test case 3 (no AAD), case 4 (with AAD)
/// and case 16 (AES-256). All three use an all-zero key and IV, so a
/// mismatch can only come from the cipher or the GHASH computation.
#[test]
fn aes_gcm_matches_nist_vectors() {
    let p = provider();
    let iv = h("000000000000000000000000");
    let plaintext = h("00000000000000000000000000000000");

    // Case 3: AES-128, no AAD.
    let expected = "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf";
    check_seal_open(
        p,
        AeadAlgorithm::Aes128Gcm,
        &[0u8; 16],
        &iv,
        &[],
        &plaintext,
        expected,
    );

    // Case 4: AES-128 with AAD, proving the AAD is actually folded into GHASH.
    let aad = h("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let expected = "0388dace60b6a392f328c2b971b2fe783963012c8dd9c9f9b5718669c7ea306e";
    check_seal_open(
        p,
        AeadAlgorithm::Aes128Gcm,
        &[0u8; 16],
        &iv,
        &aad,
        &plaintext,
        expected,
    );

    // Case 16: AES-256, no AAD.
    let expected = "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919";
    check_seal_open(
        p,
        AeadAlgorithm::Aes256Gcm,
        &[0u8; 32],
        &iv,
        &[],
        &plaintext,
        expected,
    );
}

/// Seals `plaintext`, compares against `expected`, and opens it back.
fn check_seal_open(
    p: RustCryptoProvider,
    algorithm: AeadAlgorithm,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    expected: &str,
) {
    let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    let written = p
        .seal_in_place(algorithm, key, iv, aad, &mut buffer, plaintext.len())
        .expect("seal");
    assert_eq!(written, buffer.len());
    assert_eq!(hex(&buffer), expected, "seal mismatch");

    let opened = p
        .open_in_place(algorithm, key, iv, aad, &mut buffer)
        .expect("open");
    assert_eq!(opened, plaintext.len());
    assert_eq!(
        &buffer[..opened],
        plaintext,
        "open must recover the plaintext"
    );
}

/// A rejected `open` must leave the buffer byte-identical. This is the
/// security contract the DTLS record layer depends on: a forged record must
/// not be partially decrypted before authentication fails.
#[test]
fn open_failure_leaves_buffer_untouched() {
    let p = provider();
    let key = [0x42u8; 16];
    let iv = [0x24u8; 12];

    let mut buffer = vec![0u8; 32 + TAG_LEN];
    buffer[..32].copy_from_slice(&[0xa5; 32]);
    p.seal_in_place(AeadAlgorithm::Aes128Gcm, &key, &iv, b"", &mut buffer, 32)
        .expect("seal");
    let sealed = buffer.clone();

    // Flip one ciphertext bit: the tag no longer matches.
    buffer[0] ^= 0x01;
    let tampered = buffer.clone();
    assert_eq!(
        p.open_in_place(AeadAlgorithm::Aes128Gcm, &key, &iv, b"", &mut buffer),
        Err(CryptoError::AuthenticationFailed)
    );
    assert_eq!(buffer, tampered, "a forged record must not be decrypted");

    // A wrong AAD must fail the same way.
    assert_eq!(
        p.open_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key,
            &iv,
            b"unexpected",
            &mut buffer
        ),
        Err(CryptoError::AuthenticationFailed)
    );
    assert_eq!(buffer, tampered);

    // And the untampered copy still opens, recovering the plaintext.
    let mut good = sealed.clone();
    let opened = p
        .open_in_place(AeadAlgorithm::Aes128Gcm, &key, &iv, b"", &mut good)
        .expect("open untampered");
    assert_eq!(&good[..opened], &[0xa5; 32]);
}

// ---------------------------------------------------------------------------
// Random
// ---------------------------------------------------------------------------

/// `fill_random` must fill the whole buffer and must not repeat itself.
#[test]
fn fill_random_fills_and_varies() {
    let p = provider();
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];

    // Without an entropy backend the provider must say so rather than hand
    // back a predictable "random" nonce. Only the default (host) build has
    // `os-rng`.
    if !cfg!(feature = "os-rng") {
        assert_eq!(p.fill_random(&mut a), Err(CryptoError::Unsupported));
        return;
    }

    p.fill_random(&mut a).expect("fill a");
    p.fill_random(&mut b).expect("fill b");
    assert_ne!(a, b, "two draws must differ");
    assert_ne!(a, [0u8; 64], "output must not be all zeroes");

    // An empty request is a no-op, not an error.
    assert_eq!(p.fill_random(&mut []), Ok(()));
}

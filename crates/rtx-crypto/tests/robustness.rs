//! L4 — robustness: malformed, truncated and hostile inputs.
//!
//! The invariant under test is not merely "does not panic" but the stronger
//! contract stated in `rtx_crypto`: **a rejected operation leaves the
//! caller's buffer byte-identical**. A provider that decrypts before it
//! authenticates, or that writes a partial tag, is a security bug even if no
//! assertion fires.

mod common;

use common::{
    AEAD_SUPPORTED, HASH_SUPPORTED, KEX_SUPPORTED, Lcg, MAX_DIGEST_LEN, PUB_LEN, RefCrypto,
    RefSigningKey, SECRET_LEN, SHA256_LEN, SIG_LEN, SIG_SUPPORTED, TAG_LEN, assert_error,
    generate_pair,
};
use rtx_crypto::{
    AeadProvider, CryptoError, HashProvider, HmacProvider, KeyExchangeProvider, SignatureProvider,
};

// ---------------------------------------------------------------------------
// Buffer discipline
// ---------------------------------------------------------------------------

// L4-BUF-001 — seal 空间不足时缓冲逐字节不变。
#[test]
fn rejected_seal_leaves_buffer_untouched() {
    let crypto = RefCrypto::new();
    let mut rng = Lcg::new(0xBAD_C0DE);
    for plaintext_len in [0usize, 1, 7, 16, 31, 64] {
        let mut buffer = rng.bytes(plaintext_len + TAG_LEN);
        let snapshot = buffer.clone();
        // 少一个字节的 tag 空间。
        let target = &mut buffer[..plaintext_len + TAG_LEN - 1];
        assert_error(
            crypto.seal_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &[0x22; 12],
                b"aad",
                target,
                plaintext_len,
            ),
            CryptoError::OutputTooSmall,
            "one byte of tag space missing",
        );
        assert_eq!(buffer, snapshot, "plaintext {plaintext_len} was modified");
    }
}

// L4-BUF-002 — plaintext_len 超出缓冲时返回 OutputTooSmall 且不写任何字节。
#[test]
fn oversized_plaintext_len_is_rejected_without_writes() {
    let crypto = RefCrypto::new();
    let mut buffer = [0x5Au8; 32];
    let snapshot = buffer;
    assert_error(
        crypto.seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"",
            &mut buffer,
            33,
        ),
        CryptoError::OutputTooSmall,
        "plaintext longer than buffer",
    );
    assert_eq!(buffer, snapshot);
}

// L4-BUF-003 — plaintext_len + tag 溢出 usize 时不 panic。
#[test]
fn plaintext_len_overflow_is_reported_not_wrapped() {
    let crypto = RefCrypto::new();
    let mut buffer = [0u8; 16];
    let snapshot = buffer;
    assert_error(
        crypto.seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"",
            &mut buffer,
            usize::MAX,
        ),
        CryptoError::OutputTooSmall,
        "usize overflow must saturate into an error",
    );
    assert_eq!(buffer, snapshot);
}

// L4-BUF-004 — 认证失败后缓冲逐字节不变（先认证后解密）。
#[test]
fn rejected_open_leaves_ciphertext_untouched() {
    let crypto = RefCrypto::new();
    let plaintext = b"do-not-touch";
    let mut rng = Lcg::new(0xF00D);
    let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"aad",
            &mut buffer,
            plaintext.len(),
        )
        .expect("seal");
    let sealed = buffer.clone();

    // 逐位翻转 tag 区，认证必须失败且密文保持密文。
    for index in plaintext.len()..sealed.len() {
        let mut corrupted = sealed.clone();
        corrupted[index] ^= 0x80;
        assert_error(
            crypto.open_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &[0x22; 12],
                b"aad",
                &mut corrupted,
            ),
            CryptoError::AuthenticationFailed,
            "flipped tag byte",
        );
        assert_eq!(&corrupted[..plaintext.len()], &sealed[..plaintext.len()]);
    }
    let _ = rng.next_u64();
}

// L4-BUF-005 — 逐位翻转密文区同样被拒绝且明文区不被"部分解密"。
#[test]
fn every_ciphertext_bit_flip_is_rejected() {
    let crypto = RefCrypto::new();
    let plaintext = b"abcdefgh";
    let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"",
            &mut buffer,
            plaintext.len(),
        )
        .expect("seal");
    let sealed = buffer.clone();

    for index in 0..plaintext.len() {
        for bit in 0..8 {
            let mut corrupted = sealed.clone();
            corrupted[index] ^= 1 << bit;
            let before = corrupted.clone();
            assert_error(
                crypto.open_in_place(
                    AEAD_SUPPORTED,
                    &[0x11; 32],
                    &[0x22; 12],
                    b"",
                    &mut corrupted,
                ),
                CryptoError::AuthenticationFailed,
                &format!("bit {bit} of byte {index}"),
            );
            assert_eq!(corrupted, before, "buffer modified on failure");
        }
    }
}

// L4-BUF-006 — digest / hmac 输出不足时不写入任何字节。
#[test]
fn digest_and_hmac_leave_output_untouched_on_failure() {
    let crypto = RefCrypto::new();
    for size in 0..SHA256_LEN {
        let mut digest_out = vec![0xC3u8; size];
        let digest_snapshot = digest_out.clone();
        assert_error(
            crypto.digest(HASH_SUPPORTED, b"m", &mut digest_out),
            CryptoError::OutputTooSmall,
            "digest output too small",
        );
        assert_eq!(digest_out, digest_snapshot);

        let mut mac_out = vec![0xC3u8; size];
        let mac_snapshot = mac_out.clone();
        assert_error(
            crypto.hmac(HASH_SUPPORTED, b"k", b"m", &mut mac_out),
            CryptoError::OutputTooSmall,
            "mac output too small",
        );
        assert_eq!(mac_out, mac_snapshot);
    }
}

// L4-BUF-007 — 签名输出不足时不写入任何字节。
#[test]
fn sign_leaves_output_untouched_on_failure() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(0x1234_5678);
    for size in [0usize, 1, 32, SIG_LEN - 1] {
        let mut out = vec![0x77u8; size];
        let snapshot = out.clone();
        assert_error(
            crypto.sign(SIG_SUPPORTED, &key, b"m", &mut out),
            CryptoError::OutputTooSmall,
            &format!("signature output of {size} bytes"),
        );
        assert_eq!(out, snapshot);
    }
}

// L4-BUF-008 — sign 输出不足优先于算法检查之外无副作用：先算法后尺寸。
#[test]
fn unsupported_algorithm_takes_precedence_over_buffer_size() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(1);
    let mut out = [0u8; 4];
    assert_error(
        crypto.sign(
            rtx_crypto::SignatureAlgorithm::Ed25519,
            &key,
            b"m",
            &mut out,
        ),
        CryptoError::OutputTooSmall,
        "modelled algorithm with short output",
    );
    assert_error(
        crypto.sign(
            rtx_crypto::SignatureAlgorithm::EcdsaP256Sha256,
            &key,
            b"m",
            &mut [0u8; SIG_LEN],
        ),
        CryptoError::Unsupported,
        "unmodelled algorithm with ample output",
    );
}

// ---------------------------------------------------------------------------
// Malformed key material
// ---------------------------------------------------------------------------

// L4-KEY-001 — 任意长度的对端公钥都不得 panic：要么 InvalidKey，要么成功。
#[test]
fn arbitrary_peer_public_key_lengths_are_handled() {
    let crypto = RefCrypto::new();
    let client = generate_pair(&crypto);
    let mut rng = Lcg::new(0x1234_ABCD);
    for len in 0..80usize {
        let peer = rng.bytes(len);
        let mut secret = [0u8; SECRET_LEN];
        let snapshot = secret;
        match crypto.agree(KEX_SUPPORTED, &client.private, &peer, &mut secret) {
            Ok(written) => assert_eq!(written, SECRET_LEN, "len {len} accepted"),
            Err(error) => {
                assert_eq!(error, CryptoError::InvalidKey, "len {len}");
                assert_eq!(secret, snapshot, "len {len} wrote on failure");
            }
        }
    }
}

// L4-KEY-002 — 全零 / 全一公钥都是格式合法的输入（不因此被拒）。
#[test]
fn degenerate_but_well_formed_public_keys_are_accepted() {
    let crypto = RefCrypto::new();
    let client = generate_pair(&crypto);
    for filler in [0x00u8, 0xFF, 0x01] {
        let peer = [filler; PUB_LEN];
        let mut secret = [0u8; SECRET_LEN];
        crypto
            .agree(KEX_SUPPORTED, &client.private, &peer, &mut secret)
            .unwrap_or_else(|error| panic!("filler {filler:#x}: {error:?}"));
    }
}

// L4-KEY-003 — 公钥生成输出不足时缓冲不变。
#[test]
fn key_generation_short_output_is_rejected_cleanly() {
    let crypto = RefCrypto::new();
    for size in 0..PUB_LEN {
        let mut out = vec![0x9Eu8; size];
        let snapshot = out.clone();
        assert_error(
            crypto.generate_key(KEX_SUPPORTED, &mut out),
            CryptoError::OutputTooSmall,
            "short public key output",
        );
        assert_eq!(out, snapshot);
    }
}

// L4-KEY-004 — agree 输出不足时 secret 缓冲不变。
#[test]
fn agree_short_output_is_rejected_cleanly() {
    let crypto = RefCrypto::new();
    let pair = generate_pair(&crypto);
    for size in 0..SECRET_LEN {
        let mut out = vec![0x3Du8; size];
        let snapshot = out.clone();
        assert_error(
            crypto.agree(KEX_SUPPORTED, &pair.private, &pair.public, &mut out),
            CryptoError::OutputTooSmall,
            "short secret output",
        );
        assert_eq!(out, snapshot);
    }
}

// L4-KEY-005 — 畸形公钥验证返回 InvalidKey 而非 InvalidSignature。
#[test]
fn malformed_public_key_maps_to_invalid_key() {
    let crypto = RefCrypto::new();
    let signature = [0u8; SIG_LEN];
    assert_error(
        crypto.verify(SIG_SUPPORTED, b"", b"m", &signature),
        CryptoError::InvalidKey,
        "empty public key",
    );
    assert_error(
        crypto.verify(SIG_SUPPORTED, &[0x01; 4], b"m", &signature),
        CryptoError::InvalidKey,
        "short public key",
    );
}

// ---------------------------------------------------------------------------
// Truncated records
// ---------------------------------------------------------------------------

// L4-TRUNC-001 — 短于 tag 的密文被拒绝，缓冲不变。
#[test]
fn ciphertext_shorter_than_tag_is_rejected() {
    let crypto = RefCrypto::new();
    for len in 0..TAG_LEN {
        let mut buffer = vec![0x42u8; len];
        let snapshot = buffer.clone();
        assert_error(
            crypto.open_in_place(AEAD_SUPPORTED, &[0x11; 32], &[0x22; 12], b"", &mut buffer),
            CryptoError::OutputTooSmall,
            &format!("record of {len} bytes"),
        );
        assert_eq!(buffer, snapshot);
    }
}

// L4-TRUNC-002 — 恰好 tag 长度但内容随机的记录认证失败而非崩溃。
#[test]
fn tag_sized_random_record_fails_authentication() {
    let crypto = RefCrypto::new();
    let mut rng = Lcg::new(0x7A6E);
    for _ in 0..64 {
        let mut buffer = rng.bytes(TAG_LEN);
        let snapshot = buffer.clone();
        assert_error(
            crypto.open_in_place(AEAD_SUPPORTED, &[0x11; 32], &[0x22; 12], b"", &mut buffer),
            CryptoError::AuthenticationFailed,
            "random tag-sized record",
        );
        assert_eq!(buffer, snapshot);
    }
}

// L4-TRUNC-003 — 随机字节流不会 panic。
#[test]
fn random_byte_streams_never_panic() {
    let crypto = RefCrypto::new();
    let mut rng = Lcg::new(0xDEAD_BEEF);
    for _ in 0..512 {
        let len = rng.below(96);
        let mut buffer = rng.bytes(len);
        let _ = crypto.open_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"aad",
            &mut buffer,
        );
        let plaintext_len = rng.below(len + 1);
        let _ = crypto.seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"aad",
            &mut buffer,
            plaintext_len,
        );
        let slice_len = rng.below(MAX_DIGEST_LEN);
        let mut out = [0u8; MAX_DIGEST_LEN];
        let _ = crypto.digest(HASH_SUPPORTED, &buffer, &mut out[..slice_len]);
    }
}

// L4-TRUNC-004 — 非 8 的倍数 nonce / key / aad 长度被正常处理。
#[test]
fn odd_length_key_nonce_and_aad_are_accepted() {
    let crypto = RefCrypto::new();
    let mut rng = Lcg::new(0x0DDB_A110);
    for round in 0..64usize {
        let _ = round;
        let key_len = 1 + rng.below(40);
        let nonce_len = rng.below(16);
        let aad_len = rng.below(48);
        let key = rng.bytes(key_len);
        let nonce = rng.bytes(nonce_len);
        let aad = rng.bytes(aad_len);
        let plaintext_len = 1 + rng.below(40);
        let plaintext = rng.bytes(plaintext_len);

        let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
        buffer[..plaintext.len()].copy_from_slice(&plaintext);
        crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &key,
                &nonce,
                &aad,
                &mut buffer,
                plaintext.len(),
            )
            .unwrap_or_else(|error| panic!("round {round}: {error:?}"));
        let opened = crypto
            .open_in_place(AEAD_SUPPORTED, &key, &nonce, &aad, &mut buffer)
            .unwrap_or_else(|error| panic!("round {round}: {error:?}"));
        assert_eq!(opened, plaintext.len());
        assert_eq!(&buffer[..plaintext.len()], &plaintext);
    }
}

// L4-TRUNC-005 — 空的 key / nonce / aad 组合仍走完整协议而非短路。
#[test]
fn empty_key_nonce_and_aad_still_authenticate() {
    let crypto = RefCrypto::new();
    let plaintext = b"empty material";
    let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    crypto
        .seal_in_place(AEAD_SUPPORTED, b"", b"", b"", &mut buffer, plaintext.len())
        .expect("seal with empty material");
    let opened = crypto
        .open_in_place(AEAD_SUPPORTED, b"", b"", b"", &mut buffer)
        .expect("open with empty material");
    assert_eq!(opened, plaintext.len());
}

// ---------------------------------------------------------------------------
// Signature robustness
// ---------------------------------------------------------------------------

// L4-SIG-001 — 任意长度签名都不会 panic：非标称长度即 InvalidSignature。
#[test]
fn arbitrary_signature_lengths_are_rejected() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(0xFEED_FACE);
    let public = key.public_key();
    let mut rng = Lcg::new(0x51515);
    for len in 0..(SIG_LEN + 8) {
        let signature = rng.bytes(len);
        match crypto.verify(SIG_SUPPORTED, &public, b"m", &signature) {
            Ok(()) => assert_eq!(len, SIG_LEN, "only exact length may verify"),
            Err(error) => assert_eq!(error, CryptoError::InvalidSignature),
        }
    }
}

// L4-SIG-002 — 空消息与长消息都可签名验证。
#[test]
fn signature_handles_empty_and_long_messages() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(9);
    let public = key.public_key();
    let mut signature = [0u8; SIG_LEN];

    crypto
        .sign(SIG_SUPPORTED, &key, b"", &mut signature)
        .expect("sign empty");
    crypto
        .verify(SIG_SUPPORTED, &public, b"", &signature)
        .expect("verify empty");

    let long = vec![0xABu8; 100_000];
    crypto
        .sign(SIG_SUPPORTED, &key, &long, &mut signature)
        .expect("sign long");
    crypto
        .verify(SIG_SUPPORTED, &public, &long, &signature)
        .expect("verify long");
}

// L4-SIG-003 — 换一个公钥（他人身份）验证失败。
#[test]
fn signature_from_another_identity_is_rejected() {
    let crypto = RefCrypto::new();
    let alice = RefSigningKey(1);
    let mallory = RefSigningKey(2);
    let mut signature = [0u8; SIG_LEN];
    crypto
        .sign(SIG_SUPPORTED, &mallory, b"m", &mut signature)
        .expect("mallory signs");
    assert_error(
        crypto.verify(SIG_SUPPORTED, &alice.public_key(), b"m", &signature),
        CryptoError::InvalidSignature,
        "identity substitution",
    );
}

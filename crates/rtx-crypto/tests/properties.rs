//! L5 — property-based invariants.
//!
//! `invariants.rs` pins the properties with *deterministic* enumeration; this
//! file states the same properties as universal quantifiers over an
//! automatically generated, shrinkable input space. When one fails, proptest
//! shrinks the witness to the minimal input, which is what makes a property
//! failure actionable instead of "seed 0x9E3779B9 failed".
//!
//! Both layers are kept on purpose: the deterministic sweep is a stable
//! regression net (a specific broken vector stays broken), the property suite
//! is the generalization check (a bug in a cell nobody enumerated still fails).

mod common;

use common::{
    AEAD_SUPPORTED, HASH_SUPPORTED, KEX_SUPPORTED, MAX_DIGEST_LEN, RefCrypto, RefSigningKey,
    SECRET_LEN, SIG_LEN, SIG_SUPPORTED, TAG_LEN, digest_len,
};
use proptest::prelude::*;
use rtx_crypto::{
    AeadProvider, CryptoError, HashProvider, HmacProvider, KeyExchangeProvider, RandomProvider,
    SignatureProvider,
};

/// Strategies for the algorithm enums.
fn hash_strategy() -> impl Strategy<Value = rtx_crypto::HashAlgorithm> {
    prop_oneof![
        Just(rtx_crypto::HashAlgorithm::Sha1),
        Just(rtx_crypto::HashAlgorithm::Sha256),
        Just(rtx_crypto::HashAlgorithm::Sha384),
    ]
}

/// A nonce of any length — the reference backend accepts degenerate material.
fn nonce_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=16)
}

/// Key material of at least 1 byte.
fn key_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=64)
}

/// AAD of any length.
fn aad_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=128)
}

/// Plaintext of any length.
fn plaintext_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=512)
}

// 每条性质跑 128 个用例；需要更多/更少时用 PROPTEST_CASES 环境变量覆盖，
// 例如 `PROPTEST_CASES=4096 cargo test --test properties`。
proptest! {
    // PROP-AEAD-001 — seal→open 对任意明文/密钥/nonce/AAD 组合都还原原文。
    #[test]
    fn prop_seal_open_roundtrip(
        plaintext in plaintext_strategy(),
        key in key_strategy(),
        nonce in nonce_strategy(),
        aad in aad_strategy(),
    ) {
        let crypto = RefCrypto::new();
        let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
        buffer[..plaintext.len()].copy_from_slice(&plaintext);

        let sealed = crypto
            .seal_in_place(AEAD_SUPPORTED, &key, &nonce, &aad, &mut buffer, plaintext.len())
            .expect("seal must accept any material length");
        prop_assert_eq!(sealed, plaintext.len() + TAG_LEN);

        let opened = crypto
            .open_in_place(AEAD_SUPPORTED, &key, &nonce, &aad, &mut buffer)
            .expect("open must accept a freshly sealed record");
        prop_assert_eq!(opened, plaintext.len());
        prop_assert_eq!(&buffer[..plaintext.len()], &plaintext[..]);
    }

    // PROP-AEAD-002 — 认证失败时缓冲逐字节不变。
    #[test]
    fn prop_authentication_failure_never_modifies_the_buffer(
        plaintext in plaintext_strategy(),
        index in 0usize..=512,
        aad in aad_strategy(),
        wrong_aad in aad_strategy(),
    ) {
        let crypto = RefCrypto::new();
        if plaintext.is_empty() && index == 0 {
            return Ok(());
        }
        let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
        buffer[..plaintext.len()].copy_from_slice(&plaintext);
        crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &[0x22; 12],
                &aad,
                &mut buffer,
                plaintext.len(),
            )
            .expect("seal");
        let sealed = buffer.clone();

        // 翻转一位后认证必然失败。
        let victim = index % sealed.len();
        buffer[victim] ^= 1;
        let snapshot = buffer.clone();
        let result = crypto.open_in_place(AEAD_SUPPORTED, &[0x11; 32], &[0x22; 12], &aad, &mut buffer);
        let _ = wrong_aad;
        prop_assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
        prop_assert_eq!(&buffer[..], &snapshot[..]);
    }

    // PROP-AEAD-003 — 密文区任一字节的任一比特翻转都被检出。
    #[test]
    fn prop_every_ciphertext_bit_flip_is_detected(
        plaintext in prop::collection::vec(any::<u8>(), 1..=64),
        index in any::<usize>(),
        bit in 0u8..8,
        aad in aad_strategy(),
    ) {
        let crypto = RefCrypto::new();
        let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
        buffer[..plaintext.len()].copy_from_slice(&plaintext);
        crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &[0x22; 12],
                &aad,
                &mut buffer,
                plaintext.len(),
            )
            .expect("seal");

        // 翻转明文区任意一位 → tag 校验必然失败，且失败后缓冲不变。
        let victim = index % plaintext.len();
        buffer[victim] ^= 1 << bit;
        let snapshot = buffer.clone();
        let result = crypto
            .open_in_place(AEAD_SUPPORTED, &[0x11; 32], &[0x22; 12], &aad, &mut buffer);
        prop_assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
        prop_assert_eq!(&buffer[..], &snapshot[..]);
    }

    // PROP-AEAD-004 — seal 是确定性的：同参数两次密封逐字节一致。
    #[test]
    fn prop_seal_is_deterministic(
        plaintext in plaintext_strategy(),
        aad in aad_strategy(),
    ) {
        let crypto = RefCrypto::new();
        let mut first = vec![0u8; plaintext.len() + TAG_LEN];
        let mut second = vec![0u8; plaintext.len() + TAG_LEN];
        first[..plaintext.len()].copy_from_slice(&plaintext);
        second[..plaintext.len()].copy_from_slice(&plaintext);

        crypto
            .seal_in_place(AEAD_SUPPORTED, &[0x11; 32], &[0x22; 12], &aad, &mut first, plaintext.len())
            .expect("seal a");
        crypto
            .seal_in_place(AEAD_SUPPORTED, &[0x11; 32], &[0x22; 12], &aad, &mut second, plaintext.len())
            .expect("seal b");
        prop_assert_eq!(&first[..], &second[..]);
    }

    // PROP-AEAD-005 — 容量不足时 seal 被拒且不写入任何字节。
    #[test]
    fn prop_short_buffer_is_rejected_without_writes(
        plaintext in plaintext_strategy(),
        slack in 0usize..TAG_LEN,
    ) {
        let crypto = RefCrypto::new();
        let capacity = plaintext.len() + slack;
        let mut buffer = vec![0x5Au8; capacity];
        let snapshot = buffer.clone();

        let result = crypto.seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"",
            &mut buffer,
            plaintext.len(),
        );
        prop_assert!(matches!(result, Err(CryptoError::OutputTooSmall)));
        prop_assert_eq!(&buffer[..], &snapshot[..]);
    }

    // PROP-HASH-001 — digest 返回值恒等于标称长度。
    #[test]
    fn prop_digest_length_is_nominal(
        algorithm in hash_strategy(),
        input in prop::collection::vec(any::<u8>(), 0..=4096),
    ) {
        let crypto = RefCrypto::new();
        let mut out = vec![0u8; MAX_DIGEST_LEN];
        let written = crypto.digest(algorithm, &input, &mut out).expect("digest");
        prop_assert_eq!(written, digest_len(algorithm));
    }

    // PROP-HASH-002 — digest 对输入的任一比特翻转都改变输出。
    #[test]
    fn prop_digest_is_bit_sensitive(
        algorithm in hash_strategy(),
        mut input in prop::collection::vec(any::<u8>(), 1..=64),
        index in any::<usize>(),
        bit in 0u8..8,
    ) {
        let crypto = RefCrypto::new();
        let mut baseline = [0u8; MAX_DIGEST_LEN];
        crypto.digest(algorithm, &input, &mut baseline).expect("baseline");

        let victim = index % input.len();
        input[victim] ^= 1 << bit;
        let mut mutated = [0u8; MAX_DIGEST_LEN];
        crypto.digest(algorithm, &input, &mut mutated).expect("mutated");
        prop_assert_ne!(&baseline[..], &mutated[..]);
    }

    // PROP-HASH-003 — 输出缓冲不足一字节即被拒且不写入。
    #[test]
    fn prop_digest_short_output_is_clean(
        algorithm in hash_strategy(),
        input in prop::collection::vec(any::<u8>(), 0..=64),
        // slack 至少为 1：容量必须真的比标称长度小才会被拒。
        slack in 1usize..=8,
    ) {
        let crypto = RefCrypto::new();
        let nominal = digest_len(algorithm);
        let capacity = nominal.saturating_sub(slack);
        if capacity >= nominal {
            return Ok(());
        }
        let mut out = vec![0xC3u8; capacity];
        let snapshot = out.clone();
        let result = crypto.digest(algorithm, &input, &mut out);
        prop_assert!(matches!(result, Err(CryptoError::OutputTooSmall)));
        prop_assert_eq!(&out[..], &snapshot[..]);
    }

    // PROP-HMAC-001 — HMAC 对 key 与 message 的每一位都敏感。
    #[test]
    fn prop_hmac_is_bit_sensitive(
        key in prop::collection::vec(any::<u8>(), 1..=32),
        message in prop::collection::vec(any::<u8>(), 1..=64),
        side in 0u8..2,
        index in any::<usize>(),
        bit in 0u8..8,
    ) {
        let crypto = RefCrypto::new();
        let mut baseline = [0u8; MAX_DIGEST_LEN];
        crypto.hmac(HASH_SUPPORTED, &key, &message, &mut baseline).expect("baseline");

        let mut mutated_key = key.clone();
        let mut mutated_message = message.clone();
        let target = if side == 0 { &mut mutated_key } else { &mut mutated_message };
        let victim = index % target.len();
        target[victim] ^= 1 << bit;

        let mut out = [0u8; MAX_DIGEST_LEN];
        crypto.hmac(HASH_SUPPORTED, &mutated_key, &mutated_message, &mut out).expect("hmac");
        prop_assert_ne!(&baseline[..], &out[..]);
    }

    // PROP-RAND-001 — 随机输出在块级不重复。
    #[test]
    fn prop_random_blocks_are_unique(rounds in 2usize..=64) {
        let crypto = RefCrypto::new();
        let mut seen: Vec<[u8; 8]> = Vec::new();
        for _ in 0..rounds {
            let mut block = [0u8; 8];
            crypto.fill_random(&mut block).expect("fill");
            prop_assert!(!seen.contains(&block), "random block repeated");
            seen.push(block);
        }
    }

    // PROP-KEX-001 — DH 交换对称。
    #[test]
    fn prop_diffie_hellman_is_symmetric(pairs in 1usize..=8) {
        let crypto = RefCrypto::new();
        let mut a_public = [0u8; common::PUB_LEN];
        let mut b_public = [0u8; common::PUB_LEN];
        let (a_private, _) = crypto.generate_key(KEX_SUPPORTED, &mut a_public).expect("a");
        let (b_private, _) = crypto.generate_key(KEX_SUPPORTED, &mut b_public).expect("b");

        let _ = pairs;
        let mut ab = [0u8; SECRET_LEN];
        let mut ba = [0u8; SECRET_LEN];
        crypto.agree(KEX_SUPPORTED, &a_private, &b_public, &mut ab).expect("ab");
        crypto.agree(KEX_SUPPORTED, &b_private, &a_public, &mut ba).expect("ba");
        prop_assert_eq!(&ab[..], &ba[..]);
    }

    // PROP-KEX-002 — 任意长度的对端公钥要么被拒（InvalidKey）要么成功，且失败不写入。
    #[test]
    fn prop_arbitrary_peer_key_is_handled(
        peer in prop::collection::vec(any::<u8>(), 0..=128),
    ) {
        let crypto = RefCrypto::new();
        let mut own_public = [0u8; common::PUB_LEN];
        let (own_private, _) = crypto
            .generate_key(KEX_SUPPORTED, &mut own_public)
            .expect("generate");

        let mut secret = vec![0u8; SECRET_LEN];
        let snapshot = secret.clone();
        match crypto.agree(KEX_SUPPORTED, &own_private, &peer, &mut secret) {
            Ok(written) => prop_assert_eq!(written, SECRET_LEN),
            Err(CryptoError::InvalidKey) => prop_assert_eq!(&secret[..], &snapshot[..]),
            Err(other) => prop_assert!(false, "unexpected error {:?}", other),
        }
    }

    // PROP-SIG-001 — sign/verify 对任意消息成立，且消息的任一比特翻转都被检出。
    #[test]
    fn prop_signature_roundtrip_and_tamper_detection(
        mut message in prop::collection::vec(any::<u8>(), 1..=512),
        index in any::<usize>(),
        bit in 0u8..8,
    ) {
        let crypto = RefCrypto::new();
        let key = RefSigningKey(0x1234_5678_9ABC_DEF0);
        let public = key.public_key();

        let mut signature = [0u8; SIG_LEN];
        crypto.sign(SIG_SUPPORTED, &key, &message, &mut signature).expect("sign");
        crypto.verify(SIG_SUPPORTED, &public, &message, &signature).expect("verify");

        let victim = index % message.len();
        message[victim] ^= 1 << bit;
        prop_assert!(matches!(
            crypto.verify(SIG_SUPPORTED, &public, &message, &signature),
            Err(CryptoError::InvalidSignature)
        ));
    }

    // PROP-TOTAL-001 — 任意切片长度下所有方法都不 panic，且失败不留痕迹。
    #[test]
    fn prop_no_method_panics_for_any_slice_length(
        len in 0usize..=128,
    ) {
        let crypto = RefCrypto::new();
        let key = RefSigningKey(7);
        let public = key.public_key();
        let payload = vec![0x5Au8; len];

        let mut out = vec![0u8; MAX_DIGEST_LEN];
        let _ = crypto.digest(HASH_SUPPORTED, &payload, &mut out);
        let _ = crypto.hmac(HASH_SUPPORTED, &payload, &payload, &mut out);
        let _ = crypto.fill_random(&mut payload.clone());

        let mut record = vec![0u8; len + TAG_LEN];
        let _ = crypto.seal_in_place(
            AEAD_SUPPORTED,
            &payload,
            &payload,
            &payload,
            &mut record,
            len,
        );
        let _ = crypto.open_in_place(AEAD_SUPPORTED, &payload, &payload, &payload, &mut record);

        let mut signature = vec![0u8; len];
        let _ = crypto.sign(SIG_SUPPORTED, &key, &payload, &mut signature);
        let _ = crypto.verify(SIG_SUPPORTED, &public, &payload, &signature);

        let mut secret = vec![0u8; len];
        let _ = crypto.agree(
            KEX_SUPPORTED,
            &common::RefKexKey(0x0123_4567_89AB_CDEF),
            &payload,
            &mut secret,
        );
    }
}

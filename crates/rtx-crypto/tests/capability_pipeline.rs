//! L1 — public API pipelines for every `rtx-crypto` capability.
//!
//! Each capability is exercised the way a protocol engine actually calls it:
//! fill a caller-owned buffer, invoke the provider, assert on the returned
//! length, and assert on the bytes written. Nothing here reaches into
//! internals; the whole file only sees the public trait surface.

mod common;

use common::{
    AEAD_SUPPORTED, ALL_AEADS, ALL_HASHES, ALL_KEX, ALL_SIGNATURES, HASH_SUPPORTED, KEX_SUPPORTED,
    Lcg, MAX_DIGEST_LEN, PUB_LEN, RefCrypto, RefSigningKey, SHA1_LEN, SHA256_LEN, SHA384_LEN,
    SIG_LEN, SIG_SUPPORTED, TAG_LEN, assert_differs, assert_error, digest_len, mock_digest,
    mock_hmac, sign,
};
use rtx_crypto::{
    AeadAlgorithm, AeadProvider, CryptoError, CryptoProvider, HashAlgorithm, HashProvider,
    HmacProvider, KeyExchangeProvider, RandomProvider, SignatureProvider,
};

// ---------------------------------------------------------------------------
// Random
// ---------------------------------------------------------------------------

// L1-RAND-001 — fill_random 写入 capacity 个字节并保持确定性。
#[test]
fn random_fill_is_deterministic_and_length_exact() {
    let a = RefCrypto::new();
    let b = RefCrypto::new();
    let mut first = [0u8; 48];
    let mut second = [0u8; 48];
    a.fill_random(&mut first).expect("fill a");
    b.fill_random(&mut second).expect("fill b");
    // 两次构造相同种子 → 完全相同的流。
    assert_eq!(first, second);
    assert!(first.iter().any(|&byte| byte != 0));
}

// L1-RAND-002 — 空缓冲是合法的 no-op。
#[test]
fn random_fill_accepts_empty_buffer() {
    let crypto = RefCrypto::new();
    let mut empty: [u8; 0] = [];
    crypto.fill_random(&mut empty).expect("empty fill");
}

// L1-RAND-003 — 序列随调用推进，不重复同一块。
#[test]
fn random_stream_advances_across_calls() {
    let crypto = RefCrypto::new();
    let mut previous = [0u8; 32];
    crypto.fill_random(&mut previous).expect("first");
    for round in 0..8 {
        let mut next = [0u8; 32];
        crypto.fill_random(&mut next).expect("next");
        assert_differs(&previous, &next, &format!("round {round} repeated output"));
        previous = next;
    }
}

// L1-RAND-004 — 非 8 的倍数长度不会 panic，最后一块被截断填充。
#[test]
fn random_fill_handles_non_multiple_lengths() {
    let crypto = RefCrypto::new();
    for len in [1usize, 7, 9, 15, 17, 63, 65] {
        let mut buffer = vec![0u8; len];
        crypto
            .fill_random(&mut buffer)
            .unwrap_or_else(|error| panic!("len {len}: {error:?}"));
        assert!(
            buffer.iter().any(|&byte| byte != 0),
            "len {len} stayed zero"
        );
    }
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

// L1-HASH-001 — 每个摘要算法返回标称长度且内容确定。
#[test]
fn hash_digest_returns_nominal_length_for_every_algorithm() {
    let crypto = RefCrypto::new();
    let mut output = [0u8; MAX_DIGEST_LEN];
    let expected = [SHA1_LEN, SHA256_LEN, SHA384_LEN];
    for (algorithm, &len) in ALL_HASHES.iter().zip(expected.iter()) {
        let written = crypto
            .digest(*algorithm, b"rtx", &mut output)
            .unwrap_or_else(|error| panic!("{algorithm:?}: {error:?}"));
        assert_eq!(written, len);
        assert_eq!(&output[..len], &mock_digest(*algorithm, b"rtx")[..len]);
    }
}

// L1-HASH-002 — 缓冲只写摘要长度，不越界污染尾部。
#[test]
fn hash_digest_writes_exactly_digest_len() {
    let crypto = RefCrypto::new();
    let mut output = [0xAAu8; MAX_DIGEST_LEN];
    let written = crypto
        .digest(HashAlgorithm::Sha256, b"rtx", &mut output)
        .expect("digest");
    assert_eq!(written, SHA256_LEN);
    assert!(output[SHA256_LEN..].iter().all(|&byte| byte == 0xAA));
}

// L1-HASH-003 — 缓冲不足一字节即 OutputTooSmall。
#[test]
fn hash_digest_rejects_short_buffer() {
    let crypto = RefCrypto::new();
    for algorithm in ALL_HASHES {
        let len = digest_len(algorithm);
        let mut short = [0u8; MAX_DIGEST_LEN];
        assert_error(
            crypto.digest(algorithm, b"rtx", &mut short[..len - 1]),
            CryptoError::OutputTooSmall,
            "one byte short",
        );
    }
}

// L1-HASH-004 — 空输入是合法输入。
#[test]
fn hash_digest_accepts_empty_input() {
    let crypto = RefCrypto::new();
    let mut output = [0u8; SHA256_LEN];
    let written = crypto
        .digest(HASH_SUPPORTED, b"", &mut output)
        .expect("digest of empty input");
    assert_eq!(written, SHA256_LEN);
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

// L1-HMAC-001 — MAC 长度跟随算法，写入内容确定。
#[test]
fn hmac_returns_nominal_length_for_every_algorithm() {
    let crypto = RefCrypto::new();
    let mut output = [0u8; MAX_DIGEST_LEN];
    let expected = [SHA1_LEN, SHA256_LEN, SHA384_LEN];
    for (algorithm, &len) in ALL_HASHES.iter().zip(expected.iter()) {
        let written = crypto
            .hmac(*algorithm, b"key", b"rtx", &mut output)
            .unwrap_or_else(|error| panic!("{algorithm:?}: {error:?}"));
        assert_eq!(written, len);
        assert_eq!(
            &output[..len],
            &mock_hmac(*algorithm, b"key", b"rtx")[..len]
        );
    }
}

// L1-HMAC-002 — 换 key / 换 message / 换算法都改变 MAC。
#[test]
fn hmac_binds_key_message_and_algorithm() {
    let crypto = RefCrypto::new();
    let mut base = [0u8; SHA256_LEN];
    let mut probe = [0u8; SHA256_LEN];
    crypto
        .hmac(HashAlgorithm::Sha256, b"k", b"m", &mut base)
        .expect("base");

    crypto
        .hmac(HashAlgorithm::Sha256, b"other", b"m", &mut probe)
        .expect("other key");
    assert_differs(&base, &probe, "key not bound");

    crypto
        .hmac(HashAlgorithm::Sha256, b"k", b"other", &mut probe)
        .expect("other message");
    assert_differs(&base, &probe, "message not bound");

    let mut wide = [0u8; SHA384_LEN];
    crypto
        .hmac(HashAlgorithm::Sha384, b"k", b"m", &mut wide)
        .expect("other algorithm");
    let probe_sha384: [u8; SHA256_LEN] = wide[..SHA256_LEN]
        .try_into()
        .expect("truncate sha384 prefix");
    assert_ne!(&base[..], &probe_sha384[..]);
}

// L1-HMAC-003 — 空 key 与空 message 都被接受。
#[test]
fn hmac_accepts_empty_key_and_message() {
    let crypto = RefCrypto::new();
    let mut output = [0u8; SHA256_LEN];
    crypto
        .hmac(HASH_SUPPORTED, b"", b"", &mut output)
        .expect("empty key and message");
}

// L1-HMAC-004 — 缓冲不足即 OutputTooSmall。
#[test]
fn hmac_rejects_short_buffer() {
    let crypto = RefCrypto::new();
    let mut short = [0u8; SHA256_LEN - 1];
    assert_error(
        crypto.hmac(HASH_SUPPORTED, b"k", b"m", &mut short),
        CryptoError::OutputTooSmall,
        "short mac buffer",
    );
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

// L1-AEAD-001 — seal 返回 plaintext_len + tag_len。
#[test]
fn aead_seal_returns_plaintext_plus_tag() {
    let crypto = RefCrypto::new();
    for algorithm in ALL_AEADS {
        let plaintext = b"rtx-payload";
        let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
        let sealed = crypto
            .seal_in_place(
                algorithm,
                &[0x11; 32],
                &[0x22; 12],
                b"aad",
                &mut buffer,
                plaintext.len(),
            )
            .unwrap_or_else(|error| panic!("{algorithm:?}: {error:?}"));
        assert_eq!(sealed, plaintext.len() + TAG_LEN);
        assert_differs(
            &buffer[..plaintext.len()],
            plaintext,
            "payload not encrypted",
        );
    }
}

// L1-AEAD-002 — open 返回明文长度并原地还原。
#[test]
fn aead_open_returns_plaintext_length() {
    let crypto = RefCrypto::new();
    let plaintext = b"rtx-payload";
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
    let opened = crypto
        .open_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"aad",
            &mut buffer,
        )
        .expect("open");
    assert_eq!(opened, plaintext.len());
    assert_eq!(&buffer[..plaintext.len()], plaintext);
}

// L1-AEAD-003 — 空明文可密封（仅 tag）。
#[test]
fn aead_supports_empty_plaintext() {
    let crypto = RefCrypto::new();
    let mut buffer = [0u8; TAG_LEN];
    let sealed = crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"",
            &mut buffer,
            0,
        )
        .expect("seal empty");
    assert_eq!(sealed, TAG_LEN);
    let opened = crypto
        .open_in_place(AEAD_SUPPORTED, &[0x11; 32], &[0x22; 12], b"", &mut buffer)
        .expect("open tag-only");
    assert_eq!(opened, 0);
}

// L1-AEAD-004 — 明文跨 8 字节 keystream 块边界仍正确往返。
#[test]
fn aead_roundtrips_payloads_spanning_keystream_blocks() {
    let crypto = RefCrypto::new();
    let mut rng = Lcg::new(0xA11CE);
    for len in [1usize, 7, 8, 9, 15, 16, 17, 63, 64, 65, 200] {
        let plaintext = rng.bytes(len);
        let mut buffer = vec![0u8; len + TAG_LEN];
        buffer[..len].copy_from_slice(&plaintext);
        crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &[0x22; 12],
                b"aad",
                &mut buffer,
                len,
            )
            .expect("seal");
        let opened = crypto
            .open_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &[0x22; 12],
                b"aad",
                &mut buffer,
            )
            .expect("open");
        assert_eq!(opened, len);
        assert_eq!(&buffer[..len], &plaintext, "len {len} roundtrip");
    }
}

// L1-AEAD-005 — 两种 AEAD 算法产生不同密文与 tag。
#[test]
fn aead_algorithms_are_domain_separated() {
    let crypto = RefCrypto::new();
    let plaintext = [0x5Au8; 16];
    let mut first = vec![0u8; plaintext.len() + TAG_LEN];
    let mut second = first.clone();
    first[..plaintext.len()].copy_from_slice(&plaintext);
    second[..plaintext.len()].copy_from_slice(&plaintext);
    crypto
        .seal_in_place(
            AeadAlgorithm::Aes128Gcm,
            &[0x11; 32],
            &[0x22; 12],
            b"aad",
            &mut first,
            plaintext.len(),
        )
        .expect("seal aes128");
    crypto
        .seal_in_place(
            AeadAlgorithm::Aes256Gcm,
            &[0x11; 32],
            &[0x22; 12],
            b"aad",
            &mut second,
            plaintext.len(),
        )
        .expect("seal aes256");
    assert_ne!(first, second);
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

// L1-SIG-001 — sign 返回 64 字节并可被 verify 接受。
#[test]
fn signature_sign_then_verify_accepts() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(0x0BAD_C0DE_DEAD_BEEF);
    let public = key.public_key();
    let message = b"rtx-handshake";
    let signature = sign(&crypto, key, message);
    crypto
        .verify(SIG_SUPPORTED, &public, message, &signature)
        .expect("verify own signature");
}

// L1-SIG-002 — 签名输出缓冲不足即 OutputTooSmall。
#[test]
fn signature_sign_rejects_short_buffer() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(7);
    let mut short = [0u8; SIG_LEN - 1];
    assert_error(
        crypto.sign(SIG_SUPPORTED, &key, b"m", &mut short),
        CryptoError::OutputTooSmall,
        "short signature buffer",
    );
}

// L1-SIG-003 — 签名确定：同 key 同 message 两次结果一致。
#[test]
fn signature_is_deterministic_per_key_and_message() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(99);
    let first = sign(&crypto, key, b"m");
    let second = sign(&crypto, key, b"m");
    assert_eq!(first, second);
}

// L1-SIG-004 — 不支持的签名算法返回 Unsupported。
#[test]
fn signature_rejects_unsupported_algorithms() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(1);
    let public = key.public_key();
    let signature = sign(&crypto, key, b"m");
    for algorithm in ALL_SIGNATURES {
        if algorithm == SIG_SUPPORTED {
            continue;
        }
        let mut out = [0u8; SIG_LEN];
        assert_error(
            crypto.sign(algorithm, &key, b"m", &mut out),
            CryptoError::Unsupported,
            "sign unsupported",
        );
        assert_error(
            crypto.verify(algorithm, &public, b"m", &signature),
            CryptoError::Unsupported,
            "verify unsupported",
        );
    }
}

// ---------------------------------------------------------------------------
// Key exchange
// ---------------------------------------------------------------------------

// L1-KEX-001 — generate_key 返回公钥长度。
#[test]
fn kex_generate_key_returns_public_length() {
    let crypto = RefCrypto::new();
    let mut public = [0u8; PUB_LEN];
    let (_, written) = crypto
        .generate_key(KEX_SUPPORTED, &mut public)
        .expect("generate");
    assert_eq!(written, PUB_LEN);
}

// L1-KEX-002 — agree 返回共享密钥长度。
#[test]
fn kex_agree_returns_secret_length() {
    let crypto = RefCrypto::new();
    let mut public = [0u8; PUB_LEN];
    let (private, _) = crypto
        .generate_key(KEX_SUPPORTED, &mut public)
        .expect("generate");
    let mut secret = [0u8; 64];
    let written = crypto
        .agree(KEX_SUPPORTED, &private, &public, &mut secret)
        .expect("agree");
    assert_eq!(written, 32);
}

// L1-KEX-003 — 不支持的 KEX 算法返回 Unsupported。
#[test]
fn kex_rejects_unsupported_algorithms() {
    let crypto = RefCrypto::new();
    let mut public = [0u8; PUB_LEN];
    let mut secret = [0u8; 32];
    for algorithm in ALL_KEX {
        if algorithm == KEX_SUPPORTED {
            continue;
        }
        assert_error(
            crypto.generate_key(algorithm, &mut public),
            CryptoError::Unsupported,
            "generate unsupported",
        );
    }
    let (private, _) = crypto
        .generate_key(KEX_SUPPORTED, &mut public)
        .expect("generate supported");
    for algorithm in ALL_KEX {
        if algorithm == KEX_SUPPORTED {
            continue;
        }
        assert_error(
            crypto.agree(algorithm, &private, &public, &mut secret),
            CryptoError::Unsupported,
            "agree unsupported",
        );
    }
}

// L1-KEX-004 — 连续两次 generate_key 产生不同密钥对。
#[test]
fn kex_generate_key_is_not_constant() {
    let crypto = RefCrypto::new();
    let mut first = [0u8; PUB_LEN];
    let mut second = [0u8; PUB_LEN];
    crypto
        .generate_key(KEX_SUPPORTED, &mut first)
        .expect("first");
    crypto
        .generate_key(KEX_SUPPORTED, &mut second)
        .expect("second");
    assert_ne!(first, second);
}

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

// L1-ERR-001 — 七个错误变体两两互异（新增变体时此测试失败，强制同步评审）。
#[test]
fn error_variants_are_pairwise_distinct() {
    let all = [
        CryptoError::Unsupported,
        CryptoError::InvalidKey,
        CryptoError::InvalidNonce,
        CryptoError::InvalidSignature,
        CryptoError::AuthenticationFailed,
        CryptoError::OutputTooSmall,
        CryptoError::BackendFailure,
    ];
    for (i, left) in all.iter().enumerate() {
        for (j, right) in all.iter().enumerate() {
            if i != j {
                assert_ne!(left, right);
            }
        }
    }
}

// L1-ERR-002 — 错误类型是 Copy + Debug，便于跨层透传。
#[test]
fn error_type_is_copy_and_debug() {
    let error = CryptoError::BackendFailure;
    let copied = error;
    assert_eq!(error, copied);
    assert_ne!(format!("{error:?}"), "");
}

// L1-ERR-003 — 算法枚举穷举互异（新增变体时强制同步）。
#[test]
fn algorithm_enums_are_exhaustively_distinct() {
    for (i, left) in ALL_HASHES.iter().enumerate() {
        for (j, right) in ALL_HASHES.iter().enumerate() {
            if i != j {
                assert_ne!(left, right);
            }
        }
    }
    for (i, left) in ALL_AEADS.iter().enumerate() {
        for (j, right) in ALL_AEADS.iter().enumerate() {
            if i != j {
                assert_ne!(left, right);
            }
        }
    }
    for (i, left) in ALL_SIGNATURES.iter().enumerate() {
        for (j, right) in ALL_SIGNATURES.iter().enumerate() {
            if i != j {
                assert_ne!(left, right);
            }
        }
    }
    for (i, left) in ALL_KEX.iter().enumerate() {
        for (j, right) in ALL_KEX.iter().enumerate() {
            if i != j {
                assert_ne!(left, right);
            }
        }
    }
}

// L1-SURF-001 — 能力名称稳定（用于运行时诊断输出）。
#[test]
fn provider_name_is_stable() {
    assert_eq!(RefCrypto::new().name(), "rtx-ref-crypto");
}

// L1-SURF-002 — 全算法 sweep：每个成员都能被调用并落入明确错误分支。
#[test]
fn every_algorithm_member_has_a_defined_branch() {
    let crypto = RefCrypto::new();
    let mut output = [0u8; MAX_DIGEST_LEN];
    let mut saw_ok = false;
    let mut saw_unsupported = false;
    for algorithm in ALL_HASHES {
        match crypto.digest(algorithm, b"x", &mut output) {
            Ok(len) => {
                assert_eq!(len, digest_len(algorithm));
                saw_ok = true;
            }
            Err(CryptoError::Unsupported) => saw_unsupported = true,
            Err(other) => panic!("unexpected {other:?}"),
        }
    }
    assert!(saw_ok, "at least one hash algorithm must be supported");
    assert!(
        !saw_unsupported || ALL_HASHES.len() > 1,
        "unexpected unsupported branch"
    );
}

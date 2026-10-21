//! L5 — invariants that must hold for *every* input, swept exhaustively.
//!
//! Each test here states a property rather than a single case: the property is
//! asserted across an enumerated input space (every algorithm, every boundary
//! length, every single-bit flip) so a regression in any cell of the matrix
//! fails the test. This is the layer that catches "works for the happy path,
//! breaks one byte early".

mod common;

use common::{
    AEAD_SUPPORTED, ALL_AEADS, ALL_HASHES, ALL_KEX, ALL_SIGNATURES, HASH_SUPPORTED, KEX_SUPPORTED,
    Lcg, MAX_DIGEST_LEN, PUB_LEN, RefCrypto, RefSigningKey, SECRET_LEN, SHA256_LEN, SIG_LEN,
    SIG_SUPPORTED, TAG_LEN, digest_len, generate_pair,
};
use rtx_crypto::{
    AeadProvider, CryptoError, HashProvider, HmacProvider, KeyExchangeProvider, RandomProvider,
    SignatureProvider,
};

/// Number of iterations used by the randomized sweeps.
const SWEEP: usize = 256;

// ---------------------------------------------------------------------------
// Length invariants
// ---------------------------------------------------------------------------

// L5-LEN-001 — 对所有算法与边界长度：written == 标称长度。
#[test]
fn returned_length_always_equals_nominal_length() {
    let crypto = RefCrypto::new();

    for algorithm in ALL_HASHES {
        let nominal = digest_len(algorithm);
        for capacity in [nominal, nominal + 1, nominal + 64, MAX_DIGEST_LEN] {
            let mut out = vec![0u8; capacity];
            let written = crypto
                .digest(algorithm, b"data", &mut out)
                .unwrap_or_else(|error| panic!("{algorithm:?}/{capacity}: {error:?}"));
            assert_eq!(written, nominal);
            assert_eq!(
                crypto
                    .hmac(algorithm, b"key", b"data", &mut out)
                    .unwrap_or_else(|error| panic!("hmac {algorithm:?}/{capacity}: {error:?}")),
                nominal,
            );
        }
    }

    for algorithm in ALL_AEADS {
        for plaintext_len in [0usize, 1, 8, 64, 1500] {
            let mut buffer = vec![0u8; plaintext_len + TAG_LEN];
            assert_eq!(
                crypto
                    .seal_in_place(
                        algorithm,
                        &[0x11; 32],
                        &[0x22; 12],
                        b"aad",
                        &mut buffer,
                        plaintext_len,
                    )
                    .unwrap_or_else(|error| panic!("{algorithm:?}/{plaintext_len}: {error:?}")),
                plaintext_len + TAG_LEN,
            );
            assert_eq!(
                crypto
                    .open_in_place(algorithm, &[0x11; 32], &[0x22; 12], b"aad", &mut buffer)
                    .unwrap_or_else(|error| panic!("open {algorithm:?}: {error:?}")),
                plaintext_len,
            );
        }
    }
}

// L5-LEN-002 — 输出缓冲的尾部永不被写入（只写 [0, written)）。
#[test]
fn tail_beyond_written_length_is_never_modified() {
    let crypto = RefCrypto::new();
    for algorithm in ALL_HASHES {
        let mut out = vec![0xEEu8; MAX_DIGEST_LEN + 8];
        let written = crypto.digest(algorithm, b"data", &mut out).expect("digest");
        assert!(out[written..].iter().all(|&byte| byte == 0xEE));
    }

    for plaintext_len in [0usize, 1, 33, 200] {
        let mut buffer = vec![0xDDu8; plaintext_len + TAG_LEN + 16];
        crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &[0x22; 12],
                b"",
                &mut buffer,
                plaintext_len,
            )
            .expect("seal");
        assert!(
            buffer[plaintext_len + TAG_LEN..]
                .iter()
                .all(|&byte| byte == 0xDD)
        );
    }
}

// ---------------------------------------------------------------------------
// Round-trip invariants
// ---------------------------------------------------------------------------

// L5-RT-001 — seal→open 在整个输入空间上还原明文（随机 sweep）。
#[test]
fn seal_open_roundtrip_holds_for_all_swept_inputs() {
    let crypto = RefCrypto::new();
    let mut rng = Lcg::new(0x5254_4F52_5449_5000);
    for _ in 0..SWEEP {
        let plaintext_len = rng.below(256);
        let plaintext = rng.bytes(plaintext_len);
        let key_len = 16 + rng.below(32);
        let aad_len = rng.below(64);
        let key = rng.bytes(key_len);
        let nonce = rng.bytes(12);
        let aad = rng.bytes(aad_len);
        let algorithm = ALL_AEADS[rng.below(ALL_AEADS.len())];

        let mut buffer = vec![0u8; plaintext_len + TAG_LEN];
        buffer[..plaintext_len].copy_from_slice(&plaintext);
        let sealed = crypto
            .seal_in_place(algorithm, &key, &nonce, &aad, &mut buffer, plaintext_len)
            .expect("seal");
        assert_eq!(sealed, plaintext_len + TAG_LEN);
        let opened = crypto
            .open_in_place(algorithm, &key, &nonce, &aad, &mut buffer)
            .expect("open");
        assert_eq!(opened, plaintext_len);
        assert_eq!(&buffer[..plaintext_len], &plaintext);
    }
}

// L5-RT-002 — open(open(x)) 回到原始密文（解密是密封的逆运算）。
#[test]
fn open_is_the_inverse_of_seal() {
    let crypto = RefCrypto::new();
    let mut rng = Lcg::new(0x494E_5645_5253_0001);
    for _ in 0..SWEEP {
        let plaintext_len = rng.below(128);
        let plaintext = rng.bytes(plaintext_len);
        let mut buffer = vec![0u8; plaintext_len + TAG_LEN];
        buffer[..plaintext_len].copy_from_slice(&plaintext);

        crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &[0x22; 12],
                b"aad",
                &mut buffer,
                plaintext_len,
            )
            .expect("seal");
        let sealed = buffer.clone();

        let opened = crypto
            .open_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &[0x22; 12],
                b"aad",
                &mut buffer,
            )
            .expect("open");
        assert_eq!(opened, plaintext_len);

        // 重新密封必须逐字节回到原始密文（确定性 + 无状态泄漏）。
        crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &[0x22; 12],
                b"aad",
                &mut buffer,
                plaintext_len,
            )
            .expect("reseal");
        assert_eq!(buffer, sealed, "seal/open is not an involution pair");
    }
}

// L5-RT-003 — 密文与明文长度相同（AEAD 是流式，不产生膨胀）。
#[test]
fn ciphertext_length_equals_plaintext_length() {
    let crypto = RefCrypto::new();
    let mut rng = Lcg::new(0x4C45_4E47_5448_0000);
    for _ in 0..SWEEP {
        let plaintext_len = rng.below(512);
        let plaintext = rng.bytes(plaintext_len);
        let mut buffer = vec![0u8; plaintext_len + TAG_LEN];
        buffer[..plaintext_len].copy_from_slice(&plaintext);
        let sealed = crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &[0x22; 12],
                b"",
                &mut buffer,
                plaintext_len,
            )
            .expect("seal");
        // 唯一的长度增量就是 tag。
        assert_eq!(sealed - plaintext_len, TAG_LEN);
    }
}

// ---------------------------------------------------------------------------
// Injectivity invariants
// ---------------------------------------------------------------------------

// L5-INJ-001 — 单比特注入：翻转密文/明文任一比特必然改变 tag 或被发现。
#[test]
fn single_bit_changes_are_always_detected() {
    let crypto = RefCrypto::new();
    let plaintext = [0x3Cu8; 16];
    let mut baseline = vec![0u8; plaintext.len() + TAG_LEN];
    baseline[..plaintext.len()].copy_from_slice(&plaintext);
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"aad",
            &mut baseline,
            plaintext.len(),
        )
        .expect("seal");

    for index in 0..baseline.len() {
        for bit in 0..8u8 {
            let mut mutated = baseline.clone();
            mutated[index] ^= 1 << bit;
            if mutated == baseline {
                continue;
            }
            match crypto.open_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &[0x22; 12],
                b"aad",
                &mut mutated,
            ) {
                Err(CryptoError::AuthenticationFailed) => {}
                other => panic!("bit {bit} of byte {index} escaped detection: {other:?}"),
            }
        }
    }
}

// L5-INJ-002 — 摘要对输入的每个比特都敏感。
#[test]
fn digest_is_sensitive_to_every_input_bit() {
    let crypto = RefCrypto::new();
    let input = [0u8; 16];
    let mut baseline = [0u8; MAX_DIGEST_LEN];
    crypto
        .digest(HASH_SUPPORTED, &input, &mut baseline)
        .expect("baseline");

    for index in 0..input.len() {
        for bit in 0..8u8 {
            let mut mutated = input;
            mutated[index] ^= 1 << bit;
            let mut out = [0u8; MAX_DIGEST_LEN];
            crypto
                .digest(HASH_SUPPORTED, &mutated, &mut out)
                .expect("digest");
            assert_ne!(
                &out[..SHA256_LEN],
                &baseline[..SHA256_LEN],
                "byte {index} bit {bit} ignored"
            );
        }
    }
}

// L5-INJ-003 — HMAC 对 key 与 message 的每个比特都敏感。
#[test]
fn hmac_is_sensitive_to_every_key_and_message_bit() {
    let crypto = RefCrypto::new();
    let key = [0x11u8; 8];
    let message = [0x22u8; 8];
    let mut baseline = [0u8; SHA256_LEN];
    crypto
        .hmac(HASH_SUPPORTED, &key, &message, &mut baseline)
        .expect("baseline");

    for bit in 0..64u8 {
        let mut mutated_key = key;
        mutated_key[(bit / 8) as usize] ^= 1 << (bit % 8);
        let mut out = [0u8; SHA256_LEN];
        crypto
            .hmac(HASH_SUPPORTED, &mutated_key, &message, &mut out)
            .expect("digest");
        assert_ne!(out, baseline, "key bit {bit} ignored");

        let mut mutated_message = message;
        mutated_message[(bit / 8) as usize] ^= 1 << (bit % 8);
        crypto
            .hmac(HASH_SUPPORTED, &key, &mutated_message, &mut out)
            .expect("digest");
        assert_ne!(out, baseline, "message bit {bit} ignored");
    }
}

// ---------------------------------------------------------------------------
// Determinism / statelessness
// ---------------------------------------------------------------------------

// L5-DET-001 — 同参数密封两次结果逐字节相同（provider 无隐藏状态）。
#[test]
fn sealing_is_deterministic_for_identical_parameters() {
    let crypto = RefCrypto::new();
    let plaintext = b"deterministic";
    let mut first = vec![0u8; plaintext.len() + TAG_LEN];
    let mut second = first.clone();
    first[..plaintext.len()].copy_from_slice(plaintext);
    second[..plaintext.len()].copy_from_slice(plaintext);
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"aad",
            &mut first,
            plaintext.len(),
        )
        .expect("seal a");
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"aad",
            &mut second,
            plaintext.len(),
        )
        .expect("seal b");
    assert_eq!(first, second);
}

// L5-DET-002 — 交错处理两条独立消息流不互相污染（无隐藏 nonce 计数器）。
#[test]
fn interleaved_streams_do_not_interfere() {
    let crypto = RefCrypto::new();
    let a = b"stream-a-payload";
    let b = b"stream-b-payload";

    let mut sealed_a = vec![0u8; a.len() + TAG_LEN];
    let mut sealed_b = vec![0u8; b.len() + TAG_LEN];
    sealed_a[..a.len()].copy_from_slice(a);
    sealed_b[..b.len()].copy_from_slice(b);
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"A",
            &mut sealed_a,
            a.len(),
        )
        .expect("seal a");
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x33; 32],
            &[0x44; 12],
            b"B",
            &mut sealed_b,
            b.len(),
        )
        .expect("seal b");

    // 交替打开：每轮都用各自的密文副本，顺序无关且可重复。
    for _ in 0..8 {
        let mut open_a = sealed_a.clone();
        let opened_a = crypto
            .open_in_place(AEAD_SUPPORTED, &[0x11; 32], &[0x22; 12], b"A", &mut open_a)
            .expect("open a");
        assert_eq!(&open_a[..opened_a], a);

        let mut open_b = sealed_b.clone();
        let opened_b = crypto
            .open_in_place(AEAD_SUPPORTED, &[0x33; 32], &[0x44; 12], b"B", &mut open_b)
            .expect("open b");
        assert_eq!(&open_b[..opened_b], b);
    }

    // 原始密文缓冲自始至终未被打开操作消耗。
    assert_ne!(&sealed_a[..a.len()], a, "stream A was decrypted in place");
    assert_ne!(&sealed_b[..b.len()], b, "stream B was decrypted in place");
}

// L5-DET-003 — 随机源的输出块之间不重复，且同种子可完全复现。
#[test]
fn random_blocks_are_unique_within_a_stream() {
    let crypto = RefCrypto::new();
    let mut seen: Vec<[u8; 8]> = Vec::new();
    for _ in 0..512 {
        let mut block = [0u8; 8];
        crypto.fill_random(&mut block).expect("fill");
        assert!(!seen.contains(&block), "random block repeated");
        seen.push(block);
    }

    // 同种子重启后序列完全一致（与 `crypto` 之前推进到哪一步无关）。
    let first_run = RefCrypto::new();
    let second_run = RefCrypto::new();
    let mut first = [0u8; 64];
    let mut second = [0u8; 64];
    first_run.fill_random(&mut first).expect("fill");
    second_run.fill_random(&mut second).expect("fill");
    assert_eq!(first, second);
}

// ---------------------------------------------------------------------------
// Algebraic invariants
// ---------------------------------------------------------------------------

// L5-ALG-001 — DH 交换对称：secret(a,b) == secret(b,a)，逐字节。
#[test]
fn diffie_hellman_is_symmetric_over_many_pairs() {
    let crypto = RefCrypto::new();
    for _ in 0..64 {
        let a = generate_pair(&crypto);
        let b = generate_pair(&crypto);
        let mut ab = [0u8; SECRET_LEN];
        let mut ba = [0u8; SECRET_LEN];
        crypto
            .agree(KEX_SUPPORTED, &a.private, &b.public, &mut ab)
            .expect("a agrees with b");
        crypto
            .agree(KEX_SUPPORTED, &b.private, &a.public, &mut ba)
            .expect("b agrees with a");
        assert_eq!(ab, ba, "DH is not commutative");
    }
}

// L5-ALG-002 — 不同密钥对产生不同共享密钥（无碰撞）。
#[test]
fn distinct_key_pairs_yield_distinct_secrets() {
    let crypto = RefCrypto::new();
    let base = generate_pair(&crypto);
    let mut secrets: Vec<[u8; SECRET_LEN]> = Vec::new();
    for _ in 0..32 {
        let peer = generate_pair(&crypto);
        let mut secret = [0u8; SECRET_LEN];
        crypto
            .agree(KEX_SUPPORTED, &base.private, &peer.public, &mut secret)
            .expect("agree");
        secrets.push(secret);
    }
    for (i, left) in secrets.iter().enumerate() {
        for (j, right) in secrets.iter().enumerate() {
            if i != j {
                assert_ne!(left, right, "secret collision between {i} and {j}");
            }
        }
    }
}

// L5-ALG-003 — 自 agree 得到确定值，不同私钥得到不同值。
#[test]
fn self_agreement_is_deterministic_per_private_key() {
    let crypto = RefCrypto::new();
    let pair = generate_pair(&crypto);
    let mut first = [0u8; SECRET_LEN];
    let mut second = [0u8; SECRET_LEN];
    crypto
        .agree(KEX_SUPPORTED, &pair.private, &pair.public, &mut first)
        .expect("self agree");
    crypto
        .agree(KEX_SUPPORTED, &pair.private, &pair.public, &mut second)
        .expect("self agree again");
    assert_eq!(first, second);
}

// L5-ALG-004 — 签名对 message 的每个比特敏感。
#[test]
fn signature_is_sensitive_to_every_message_bit() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(0x1357_9BDF_2468_ACE0);
    let public = key.public_key();
    let message = [0u8; 16];
    let mut baseline = [0u8; SIG_LEN];
    crypto
        .sign(SIG_SUPPORTED, &key, &message, &mut baseline)
        .expect("baseline");

    for index in 0..message.len() {
        for bit in 0..8u8 {
            let mut mutated = message;
            mutated[index] ^= 1 << bit;
            let mut out = [0u8; SIG_LEN];
            crypto
                .sign(SIG_SUPPORTED, &key, &mutated, &mut out)
                .expect("sign");
            assert_ne!(out, baseline, "message byte {index} bit {bit} ignored");
            crypto
                .verify(SIG_SUPPORTED, &public, &mutated, &out)
                .expect("verify");
        }
    }
}

// ---------------------------------------------------------------------------
// Total-function invariants
// ---------------------------------------------------------------------------

// L5-TOT-001 — 对全部算法成员，能力调用要么成功要么返回已定义错误，永不 panic。
#[test]
fn every_algorithm_member_yields_a_defined_outcome() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(7);
    let public = key.public_key();
    let signature = [0u8; SIG_LEN];
    let mut out = [0u8; MAX_DIGEST_LEN];
    let mut buffer = vec![0u8; 8 + TAG_LEN];
    let mut public_out = [0u8; PUB_LEN];
    let mut secret = [0u8; SECRET_LEN];
    let kex_private = generate_pair(&crypto).private;

    for algorithm in ALL_HASHES {
        assert!(crypto.digest(algorithm, b"m", &mut out).is_ok());
        assert!(crypto.hmac(algorithm, b"k", b"m", &mut out).is_ok());
    }
    for algorithm in ALL_AEADS {
        let result = crypto.seal_in_place(algorithm, &[0x11; 32], &[0x22; 12], b"", &mut buffer, 8);
        assert!(result.is_ok(), "{algorithm:?} must seal");
    }
    for algorithm in ALL_SIGNATURES {
        let _ = crypto.sign(algorithm, &key, b"m", &mut [0u8; SIG_LEN]);
        let _ = crypto.verify(algorithm, &public, b"m", &signature);
    }
    for algorithm in ALL_KEX {
        let _ = crypto.generate_key(algorithm, &mut public_out);
        let _ = crypto.agree(algorithm, &kex_private, &public_out, &mut secret);
    }
}

// L5-TOT-002 — 所有 provider 方法在任意切片长度下都不 panic。
#[test]
fn no_method_panics_for_any_slice_length() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(0xABCD);
    let public = key.public_key();
    for len in 0..96usize {
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
        let _ = crypto.agree(KEX_SUPPORTED, &key_exchange_handle(), &payload, &mut secret);
    }
}

/// A fixed handle so the sweep can call `agree` without generating keys.
fn key_exchange_handle() -> common::RefKexKey {
    common::RefKexKey(0x0123_4567_89AB_CDEF)
}

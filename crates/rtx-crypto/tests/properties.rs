//! L5 — property-based invariants, parameterized over both backends.
//!
//! `invariants.rs` pins the properties with *deterministic* enumeration; this
//! file states the same properties as universal quantifiers over an
//! automatically generated, shrinkable input space. When one fails, proptest
//! shrinks the witness to the minimal input, which is what makes a property
//! failure actionable instead of "seed 0x9E3779B9 failed".
//!
//! Unlike the first version of this file, every capability invariant is run
//! against **both** providers:
//!
//! * [`RefCrypto`] — the deterministic reference backend from `common`, which
//!   pins the trait contracts but models no cryptography; and
//! * [`RustCryptoProvider`] — the real `aes-gcm` / `sha2` / `hmac` backend the
//!   DTLS engine will hold.
//!
//! The deterministic reference sweep is a stable regression net (a specific
//! broken vector stays broken); the property suite is the generalization check
//! (a bug in a cell nobody enumerated still fails). Parameterizing it is what
//! makes that check reach the *real* backend instead of only the model of it,
//! closing the gap recorded in `docs/progress-report.md` §7.
//!
//! Backend-specific policy (exact key/nonce lengths, declined suites, OS
//! entropy) is expressed on [`Backend`] rather than guessed in each property,
//! and every failure message names the backend that broke. The signature and
//! key-exchange suites are declined by the real provider by design, so their
//! positive direction stays on the reference backend while the negative
//! direction (`Unsupported`, buffer untouched) is a property of its own on the
//! real one.

mod common;

use common::{
    AEAD_SUPPORTED, HASH_SUPPORTED, KEX_SUPPORTED, MAX_DIGEST_LEN, PUB_LEN, RefCrypto, RefKexKey,
    RefSigningKey, SECRET_LEN, SIG_LEN, SIG_SUPPORTED, TAG_LEN, digest_len,
};
use proptest::prelude::*;
use rtx_crypto::{
    AeadAlgorithm, AeadProvider, CryptoError, HashAlgorithm, HashProvider, HmacProvider,
    KeyExchangeAlgorithm, KeyExchangeProvider, RandomProvider, SignatureAlgorithm,
    SignatureProvider,
};
use rtx_crypto_rustcrypto::{ExchangeKey, RustCryptoProvider, SigningKey};

// ---------------------------------------------------------------------------
// Backend parameterization
// ---------------------------------------------------------------------------

/// The two providers every shared invariant is exercised against.
///
/// The reference backend accepts degenerate key, nonce and digest lengths on
/// purpose — it models the trait contract, not a cipher. The real backend is
/// stricter, because a silently truncated nonce or padded key is a security
/// bug. Encoding that difference here keeps the properties themselves about
/// the invariant rather than about which provider is being called.
enum Backend {
    /// Deterministic reference backend from `common`.
    Reference(RefCrypto),
    /// RustCrypto-backed provider used by deployments.
    RustCrypto(RustCryptoProvider),
}

impl Backend {
    /// One fresh instance of each backend.
    fn all() -> [Self; 2] {
        [
            Self::Reference(RefCrypto::new()),
            Self::RustCrypto(RustCryptoProvider::new()),
        ]
    }

    /// Name used in failure messages so a shrink names the broken backend.
    const fn name(&self) -> &'static str {
        match self {
            Self::Reference(_) => "reference",
            Self::RustCrypto(_) => "rustcrypto",
        }
    }

    /// Whether this is the real `RustCrypto` provider.
    const fn is_real(&self) -> bool {
        matches!(self, Self::RustCrypto(_))
    }

    fn hash(&self) -> &dyn HashProvider {
        match self {
            Self::Reference(provider) => provider,
            Self::RustCrypto(provider) => provider,
        }
    }

    fn hmac(&self) -> &dyn HmacProvider {
        match self {
            Self::Reference(provider) => provider,
            Self::RustCrypto(provider) => provider,
        }
    }

    fn aead(&self) -> &dyn AeadProvider {
        match self {
            Self::Reference(provider) => provider,
            Self::RustCrypto(provider) => provider,
        }
    }

    fn random(&self) -> &dyn RandomProvider {
        match self {
            Self::Reference(provider) => provider,
            Self::RustCrypto(provider) => provider,
        }
    }

    /// The exact AEAD key length this backend requires, or `None` when any
    /// length is accepted (the reference backend).
    const fn aead_key_len(&self, algorithm: AeadAlgorithm) -> Option<usize> {
        match self {
            Self::Reference(_) => None,
            Self::RustCrypto(_) => Some(aead_key_len(algorithm)),
        }
    }

    /// The exact nonce length this backend requires, or `None` when any
    /// length is accepted (the reference backend).
    const fn aead_nonce_len(&self) -> Option<usize> {
        match self {
            Self::Reference(_) => None,
            Self::RustCrypto(_) => Some(GCM_NONCE_LEN),
        }
    }
}

// ---------------------------------------------------------------------------
// Sizes and helpers
// ---------------------------------------------------------------------------

/// AES-128-GCM key length.
const AES128_KEY_LEN: usize = 16;
/// AES-256-GCM key length.
const AES256_KEY_LEN: usize = 32;
/// GCM nonce length: 96 bits, the only length a real GCM accepts.
const GCM_NONCE_LEN: usize = 12;

/// Key length `algorithm` requires.
const fn aead_key_len(algorithm: AeadAlgorithm) -> usize {
    match algorithm {
        AeadAlgorithm::Aes128Gcm => AES128_KEY_LEN,
        AeadAlgorithm::Aes256Gcm => AES256_KEY_LEN,
    }
}

/// HMAC block size for `algorithm`: the key length above which RFC 2104
/// hashes the key before using it.
const fn hmac_block_len(algorithm: HashAlgorithm) -> usize {
    match algorithm {
        HashAlgorithm::Sha1 | HashAlgorithm::Sha256 => 64,
        HashAlgorithm::Sha384 => 128,
    }
}

/// A record buffer holding `plaintext` followed by `TAG_LEN` bytes of room.
fn record(plaintext: &[u8]) -> Vec<u8> {
    let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    buffer
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Strategies for the algorithm enums.
fn hash_strategy() -> impl Strategy<Value = HashAlgorithm> {
    prop_oneof![
        Just(HashAlgorithm::Sha1),
        Just(HashAlgorithm::Sha256),
        Just(HashAlgorithm::Sha384),
    ]
}

fn aead_strategy() -> impl Strategy<Value = AeadAlgorithm> {
    prop_oneof![
        Just(AeadAlgorithm::Aes128Gcm),
        Just(AeadAlgorithm::Aes256Gcm),
    ]
}

fn signature_strategy() -> impl Strategy<Value = SignatureAlgorithm> {
    prop_oneof![
        Just(SignatureAlgorithm::Ed25519),
        Just(SignatureAlgorithm::EcdsaP256Sha256),
        Just(SignatureAlgorithm::EcdsaP384Sha384),
    ]
}

fn kex_strategy() -> impl Strategy<Value = KeyExchangeAlgorithm> {
    prop_oneof![
        Just(KeyExchangeAlgorithm::X25519),
        Just(KeyExchangeAlgorithm::P256),
        Just(KeyExchangeAlgorithm::P384),
    ]
}

/// A key strictly longer than the algorithm's HMAC block size, so the
/// "hash the key first" branch of RFC 2104 is the one under test.
fn hmac_long_key_strategy() -> impl Strategy<Value = (HashAlgorithm, Vec<u8>)> {
    hash_strategy().prop_flat_map(|algorithm| {
        let block = hmac_block_len(algorithm);
        (
            Just(algorithm),
            prop::collection::vec(any::<u8>(), block + 1..=block * 2),
        )
    })
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

// proptest 的默认用例数即可；需要更多/更少时用 PROPTEST_CASES 环境变量覆盖，
// 例如 `PROPTEST_CASES=4096 cargo test --test properties`。
proptest! {
    // PROP-AEAD-001 — seal→open 对任意明文/密钥/nonce/AAD 组合都还原原文。
    // 参考后端与真实后端都必须通过。
    #[test]
    fn prop_seal_open_roundtrip(
        plaintext in plaintext_strategy(),
        algorithm in aead_strategy(),
        key_material in any::<[u8; AES256_KEY_LEN]>(),
        nonce in any::<[u8; GCM_NONCE_LEN]>(),
        aad in aad_strategy(),
    ) {
        let key = &key_material[..aead_key_len(algorithm)];
        for backend in Backend::all() {
            let mut buffer = record(&plaintext);
            let sealed = backend
                .aead()
                .seal_in_place(algorithm, key, &nonce, &aad, &mut buffer, plaintext.len())
                .unwrap_or_else(|error| {
                    panic!("{}: seal rejected a valid record: {error:?}", backend.name())
                });
            prop_assert_eq!(
                sealed,
                plaintext.len() + TAG_LEN,
                "{}: sealed length",
                backend.name()
            );

            let opened = backend
                .aead()
                .open_in_place(algorithm, key, &nonce, &aad, &mut buffer)
                .unwrap_or_else(|error| {
                    panic!("{}: open rejected a fresh record: {error:?}", backend.name())
                });
            prop_assert_eq!(opened, plaintext.len(), "{}: opened length", backend.name());
            prop_assert_eq!(
                &buffer[..plaintext.len()],
                &plaintext[..],
                "{}: recovered plaintext",
                backend.name()
            );
        }
    }

    // PROP-AEAD-002 — 认证失败时缓冲逐字节不变。
    // 覆盖密文翻转、tag 翻转、错误 AAD 与错误密钥四条路径。
    #[test]
    fn prop_authentication_failure_never_modifies_the_buffer(
        plaintext in plaintext_strategy(),
        algorithm in aead_strategy(),
        key_material in any::<[u8; AES256_KEY_LEN]>(),
        index in any::<usize>(),
        aad in aad_strategy(),
        tamper in 0u8..4,
    ) {
        let nonce = [0x22u8; GCM_NONCE_LEN];
        let key = &key_material[..aead_key_len(algorithm)];
        for backend in Backend::all() {
            let mut buffer = record(&plaintext);
            backend
                .aead()
                .seal_in_place(algorithm, key, &nonce, &aad, &mut buffer, plaintext.len())
                .unwrap_or_else(|error| panic!("{}: seal: {error:?}", backend.name()));

            // Every arm points the open call at material that cannot
            // authenticate this record.
            let mut wrong_key = key.to_vec();
            wrong_key[0] ^= 0xFF;
            let mut wrong_aad = aad.clone();
            wrong_aad.push(0xFF);
            let (open_key, open_aad): (&[u8], &[u8]) = match tamper {
                0 => {
                    let victim = index % buffer.len();
                    buffer[victim] ^= 1;
                    (key, &aad)
                }
                1 => {
                    let victim = buffer.len() - TAG_LEN + index % TAG_LEN;
                    buffer[victim] ^= 1;
                    (key, &aad)
                }
                2 => (key, &wrong_aad),
                _ => (&wrong_key[..], &aad),
            };

            let snapshot = buffer.clone();
            let result = backend
                .aead()
                .open_in_place(algorithm, open_key, &nonce, open_aad, &mut buffer);
            prop_assert!(
                matches!(result, Err(CryptoError::AuthenticationFailed)),
                "{}: tamper mode {tamper} escaped detection: {result:?}",
                backend.name()
            );
            prop_assert_eq!(
                &buffer[..],
                &snapshot[..],
                "{}: tamper mode {} modified the buffer",
                backend.name(),
                tamper
            );
        }
    }

    // PROP-AEAD-003 — 密文区或 tag 区任一字节的任一比特翻转都被检出。
    #[test]
    fn prop_every_sealed_bit_flip_is_detected(
        plaintext in prop::collection::vec(any::<u8>(), 1..=64),
        algorithm in aead_strategy(),
        key_material in any::<[u8; AES256_KEY_LEN]>(),
        index in any::<usize>(),
        bit in 0u8..8,
        aad in aad_strategy(),
    ) {
        let key = &key_material[..aead_key_len(algorithm)];
        let nonce = [0x22u8; GCM_NONCE_LEN];
        for backend in Backend::all() {
            let mut buffer = record(&plaintext);
            backend
                .aead()
                .seal_in_place(algorithm, key, &nonce, &aad, &mut buffer, plaintext.len())
                .unwrap_or_else(|error| panic!("{}: seal: {error:?}", backend.name()));

            let victim = index % buffer.len();
            buffer[victim] ^= 1 << bit;
            let snapshot = buffer.clone();
            let result = backend
                .aead()
                .open_in_place(algorithm, key, &nonce, &aad, &mut buffer);
            prop_assert!(
                matches!(result, Err(CryptoError::AuthenticationFailed)),
                "{}: byte {victim} bit {bit} escaped detection: {result:?}",
                backend.name()
            );
            prop_assert_eq!(
                &buffer[..],
                &snapshot[..],
                "{}: rejected open modified the buffer",
                backend.name()
            );
        }
    }

    // PROP-AEAD-004 — seal 是确定性的：同参数两次密封逐字节一致。
    #[test]
    fn prop_seal_is_deterministic(
        plaintext in plaintext_strategy(),
        algorithm in aead_strategy(),
        key_material in any::<[u8; AES256_KEY_LEN]>(),
        aad in aad_strategy(),
    ) {
        let key = &key_material[..aead_key_len(algorithm)];
        let nonce = [0x22u8; GCM_NONCE_LEN];
        for backend in Backend::all() {
            let mut first = record(&plaintext);
            let mut second = record(&plaintext);
            backend
                .aead()
                .seal_in_place(algorithm, key, &nonce, &aad, &mut first, plaintext.len())
                .unwrap_or_else(|error| panic!("{}: seal a: {error:?}", backend.name()));
            backend
                .aead()
                .seal_in_place(algorithm, key, &nonce, &aad, &mut second, plaintext.len())
                .unwrap_or_else(|error| panic!("{}: seal b: {error:?}", backend.name()));
            prop_assert_eq!(
                &first[..],
                &second[..],
                "{}: seal is not deterministic",
                backend.name()
            );
        }
    }

    // PROP-AEAD-005 — 容量不足时 seal 被拒且不写入任何字节。
    #[test]
    fn prop_short_buffer_is_rejected_without_writes(
        plaintext in plaintext_strategy(),
        algorithm in aead_strategy(),
        key_material in any::<[u8; AES256_KEY_LEN]>(),
        slack in 0usize..TAG_LEN,
    ) {
        let key = &key_material[..aead_key_len(algorithm)];
        for backend in Backend::all() {
            let mut buffer = vec![0x5Au8; plaintext.len() + slack];
            let snapshot = buffer.clone();
            let result = backend.aead().seal_in_place(
                algorithm,
                key,
                &[0x22; GCM_NONCE_LEN],
                b"",
                &mut buffer,
                plaintext.len(),
            );
            prop_assert!(
                matches!(result, Err(CryptoError::OutputTooSmall)),
                "{}: slack {slack} was accepted",
                backend.name()
            );
            prop_assert_eq!(
                &buffer[..],
                &snapshot[..],
                "{}: rejected seal modified the buffer",
                backend.name()
            );
        }
    }

    // PROP-AEAD-006 — 短于 tag 的记录被拒且不写入。
    #[test]
    fn prop_short_record_is_rejected_without_writes(
        capacity in 0usize..TAG_LEN,
        algorithm in aead_strategy(),
    ) {
        let key_material = [0x11u8; AES256_KEY_LEN];
        let key = &key_material[..aead_key_len(algorithm)];
        for backend in Backend::all() {
            let mut buffer = vec![0x6Bu8; capacity];
            let snapshot = buffer.clone();
            let result = backend.aead().open_in_place(
                algorithm,
                key,
                &[0x22; GCM_NONCE_LEN],
                b"",
                &mut buffer,
            );
            prop_assert!(
                matches!(result, Err(CryptoError::OutputTooSmall)),
                "{}: a {capacity}-byte record was not rejected as too short",
                backend.name()
            );
            prop_assert_eq!(
                &buffer[..],
                &snapshot[..],
                "{}: rejected open modified the buffer",
                backend.name()
            );
        }
    }

    // PROP-AEAD-007 — nonce 长度不对必须报错而不是截断。
    // 参考后端接受任意长度（它建模的是契约）；真实后端只接受 96 位，
    // 且必须拒绝而非静默截短——截短的 nonce 会引发 GCM nonce 重用。
    #[test]
    fn prop_wrong_length_nonce_is_rejected_not_truncated(
        plaintext in plaintext_strategy(),
        algorithm in aead_strategy(),
        key_material in any::<[u8; AES256_KEY_LEN]>(),
        nonce in prop::collection::vec(any::<u8>(), 0..=2 * GCM_NONCE_LEN),
        aad in aad_strategy(),
    ) {
        let key = &key_material[..aead_key_len(algorithm)];
        for backend in Backend::all() {
            let mut buffer = record(&plaintext);
            let snapshot = buffer.clone();
            match backend.aead_nonce_len() {
                Some(exact) if nonce.len() != exact => {
                    let seal = backend.aead().seal_in_place(
                        algorithm,
                        key,
                        &nonce,
                        &aad,
                        &mut buffer,
                        plaintext.len(),
                    );
                    prop_assert!(
                        matches!(seal, Err(CryptoError::InvalidNonce)),
                        "{}: seal accepted a {}-byte nonce: {seal:?}",
                        backend.name(),
                        nonce.len()
                    );
                    prop_assert_eq!(
                        &buffer[..],
                        &snapshot[..],
                        "{}: seal rejected the nonce but wrote anyway",
                        backend.name()
                    );

                    let open = backend
                        .aead()
                        .open_in_place(algorithm, key, &nonce, &aad, &mut buffer);
                    prop_assert!(
                        matches!(open, Err(CryptoError::InvalidNonce)),
                        "{}: open accepted a {}-byte nonce: {open:?}",
                        backend.name(),
                        nonce.len()
                    );
                    prop_assert_eq!(
                        &buffer[..],
                        &snapshot[..],
                        "{}: open rejected the nonce but wrote anyway",
                        backend.name()
                    );
                }
                _ => {
                    // Exact length for the real backend, any length for the
                    // reference one: either way the record must round-trip.
                    let sealed = backend
                        .aead()
                        .seal_in_place(
                            algorithm,
                            key,
                            &nonce,
                            &aad,
                            &mut buffer,
                            plaintext.len(),
                        )
                        .unwrap_or_else(|error| {
                            panic!(
                                "{}: seal rejected a {}-byte nonce: {error:?}",
                                backend.name(),
                                nonce.len()
                            )
                        });
                    prop_assert_eq!(
                        sealed,
                        plaintext.len() + TAG_LEN,
                        "{}: sealed length",
                        backend.name()
                    );
                    let opened = backend
                        .aead()
                        .open_in_place(algorithm, key, &nonce, &aad, &mut buffer)
                        .unwrap_or_else(|error| {
                            panic!(
                                "{}: open rejected a {}-byte nonce: {error:?}",
                                backend.name(),
                                nonce.len()
                            )
                        });
                    prop_assert_eq!(opened, plaintext.len(), "{}: opened length", backend.name());
                }
            }
        }
    }

    // PROP-AEAD-008 — 密钥长度不对必须报错而不是补齐/截断。
    #[test]
    fn prop_wrong_length_key_is_rejected(
        plaintext in plaintext_strategy(),
        algorithm in aead_strategy(),
        key_len in 0usize..=2 * AES256_KEY_LEN,
        nonce in any::<[u8; GCM_NONCE_LEN]>(),
    ) {
        let key = vec![0x33u8; key_len];
        for backend in Backend::all() {
            let mut buffer = record(&plaintext);
            let snapshot = buffer.clone();
            match backend.aead_key_len(algorithm) {
                Some(exact) if key_len != exact => {
                    let seal = backend.aead().seal_in_place(
                        algorithm,
                        &key,
                        &nonce,
                        b"",
                        &mut buffer,
                        plaintext.len(),
                    );
                    prop_assert!(
                        matches!(seal, Err(CryptoError::InvalidKey)),
                        "{}: seal accepted a {key_len}-byte key: {seal:?}",
                        backend.name()
                    );
                    prop_assert_eq!(
                        &buffer[..],
                        &snapshot[..],
                        "{}: rejected seal modified the buffer",
                        backend.name()
                    );

                    // Seal a valid record, then try to open it with the same
                    // wrong-length key: the length check must fail before
                    // authentication or decryption.
                    let valid_key = vec![0x44u8; exact];
                    backend
                        .aead()
                        .seal_in_place(
                            algorithm,
                            &valid_key,
                            &nonce,
                            b"",
                            &mut buffer,
                            plaintext.len(),
                        )
                        .unwrap_or_else(|error| {
                            panic!("{}: seal with exact key: {error:?}", backend.name())
                        });
                    let sealed_snapshot = buffer.clone();
                    let open = backend
                        .aead()
                        .open_in_place(algorithm, &key, &nonce, b"", &mut buffer);
                    prop_assert!(
                        matches!(open, Err(CryptoError::InvalidKey)),
                        "{}: open accepted a {key_len}-byte key: {open:?}",
                        backend.name()
                    );
                    prop_assert_eq!(
                        &buffer[..],
                        &sealed_snapshot[..],
                        "{}: rejected open modified the buffer",
                        backend.name()
                    );
                }
                _ => {
                    let sealed = backend
                        .aead()
                        .seal_in_place(algorithm, &key, &nonce, b"", &mut buffer, plaintext.len())
                        .unwrap_or_else(|error| {
                            panic!(
                                "{}: seal rejected a legal {key_len}-byte key: {error:?}",
                                backend.name()
                            )
                        });
                    prop_assert_eq!(
                        sealed,
                        plaintext.len() + TAG_LEN,
                        "{}: sealed length",
                        backend.name()
                    );
                    let opened = backend
                        .aead()
                        .open_in_place(algorithm, &key, &nonce, b"", &mut buffer)
                        .unwrap_or_else(|error| {
                            panic!(
                                "{}: open rejected a legal {key_len}-byte key: {error:?}",
                                backend.name()
                            )
                        });
                    prop_assert_eq!(opened, plaintext.len(), "{}: opened length", backend.name());
                }
            }
        }
    }

    // PROP-AEAD-009 — AES-256 不得悄悄复用 AES-128 的密钥调度：
    // 同一 128 位密钥与它的 256 位扩展必须产生不同密文。
    #[test]
    fn prop_aes256_does_not_reuse_the_aes128_key_schedule(
        key in any::<[u8; AES128_KEY_LEN]>(),
        plaintext in prop::collection::vec(any::<u8>(), 1..=64),
        nonce in any::<[u8; GCM_NONCE_LEN]>(),
        aad in aad_strategy(),
    ) {
        let mut doubled = [0u8; AES256_KEY_LEN];
        doubled[..AES128_KEY_LEN].copy_from_slice(&key);
        doubled[AES128_KEY_LEN..].copy_from_slice(&key);
        for backend in Backend::all() {
            let mut short = record(&plaintext);
            let mut long = record(&plaintext);
            backend
                .aead()
                .seal_in_place(
                    AeadAlgorithm::Aes128Gcm,
                    &key,
                    &nonce,
                    &aad,
                    &mut short,
                    plaintext.len(),
                )
                .unwrap_or_else(|error| panic!("{}: AES-128 seal: {error:?}", backend.name()));
            backend
                .aead()
                .seal_in_place(
                    AeadAlgorithm::Aes256Gcm,
                    &doubled,
                    &nonce,
                    &aad,
                    &mut long,
                    plaintext.len(),
                )
                .unwrap_or_else(|error| panic!("{}: AES-256 seal: {error:?}", backend.name()));
            prop_assert_ne!(
                &short[..],
                &long[..],
                "{}: AES-256 reproduced the AES-128 ciphertext",
                backend.name()
            );
        }
    }

    // PROP-HASH-001 — digest 返回值恒等于标称长度，且不写尾部。
    #[test]
    fn prop_digest_length_is_nominal(
        algorithm in hash_strategy(),
        input in prop::collection::vec(any::<u8>(), 0..=4096),
    ) {
        let nominal = digest_len(algorithm);
        for backend in Backend::all() {
            let mut out = vec![0xEEu8; MAX_DIGEST_LEN + 8];
            let written = backend
                .hash()
                .digest(algorithm, &input, &mut out)
                .unwrap_or_else(|error| panic!("{}: digest: {error:?}", backend.name()));
            prop_assert_eq!(written, nominal, "{}: digest length", backend.name());
            prop_assert!(
                out[written..].iter().all(|&byte| byte == 0xEE),
                "{}: digest wrote past the nominal length",
                backend.name()
            );
        }
    }

    // PROP-HASH-002 — digest 对输入的任一比特翻转都改变输出。
    #[test]
    fn prop_digest_is_bit_sensitive(
        algorithm in hash_strategy(),
        input in prop::collection::vec(any::<u8>(), 1..=64),
        index in any::<usize>(),
        bit in 0u8..8,
    ) {
        let victim = index % input.len();
        let mut mutated = input.clone();
        mutated[victim] ^= 1 << bit;
        for backend in Backend::all() {
            let mut baseline = [0u8; MAX_DIGEST_LEN];
            backend
                .hash()
                .digest(algorithm, &input, &mut baseline)
                .unwrap_or_else(|error| panic!("{}: baseline: {error:?}", backend.name()));
            let mut changed = [0u8; MAX_DIGEST_LEN];
            backend
                .hash()
                .digest(algorithm, &mutated, &mut changed)
                .unwrap_or_else(|error| panic!("{}: mutated: {error:?}", backend.name()));
            prop_assert_ne!(
                &baseline[..],
                &changed[..],
                "{}: input byte {} bit {} was ignored",
                backend.name(),
                victim,
                bit
            );
        }
    }

    // PROP-HASH-003 — 输出缓冲不足一字节即被拒且不写入。
    #[test]
    fn prop_digest_short_output_is_clean(
        algorithm in hash_strategy(),
        input in prop::collection::vec(any::<u8>(), 0..=64),
        // slack 至少为 1：容量必须真的比标称长度小才会被拒。
        slack in 1usize..=8,
    ) {
        let nominal = digest_len(algorithm);
        let capacity = nominal.saturating_sub(slack);
        if capacity >= nominal {
            return Ok(());
        }
        for backend in Backend::all() {
            let mut out = vec![0xC3u8; capacity];
            let snapshot = out.clone();
            let result = backend.hash().digest(algorithm, &input, &mut out);
            prop_assert!(
                matches!(result, Err(CryptoError::OutputTooSmall)),
                "{}: accepted a {capacity}-byte buffer for a {nominal}-byte digest",
                backend.name()
            );
            prop_assert_eq!(
                &out[..],
                &snapshot[..],
                "{}: rejected digest modified the buffer",
                backend.name()
            );
        }
    }

    // PROP-HMAC-001 — HMAC 对 key 与 message 的每一位都敏感。
    #[test]
    fn prop_hmac_is_bit_sensitive(
        key in key_strategy(),
        message in prop::collection::vec(any::<u8>(), 1..=64),
        side in 0u8..2,
        index in any::<usize>(),
        bit in 0u8..8,
    ) {
        let mut mutated_key = key.clone();
        let mut mutated_message = message.clone();
        let target = if side == 0 {
            &mut mutated_key
        } else {
            &mut mutated_message
        };
        let victim = index % target.len();
        target[victim] ^= 1 << bit;

        for backend in Backend::all() {
            let mut baseline = [0u8; MAX_DIGEST_LEN];
            backend
                .hmac()
                .hmac(HASH_SUPPORTED, &key, &message, &mut baseline)
                .unwrap_or_else(|error| panic!("{}: baseline: {error:?}", backend.name()));
            let mut changed = [0u8; MAX_DIGEST_LEN];
            backend
                .hmac()
                .hmac(HASH_SUPPORTED, &mutated_key, &mutated_message, &mut changed)
                .unwrap_or_else(|error| panic!("{}: mutated: {error:?}", backend.name()));
            prop_assert_ne!(
                &baseline[..],
                &changed[..],
                "{}: byte {} bit {} on side {} was ignored",
                backend.name(),
                victim,
                bit,
                side
            );
        }
    }

    // PROP-HMAC-002 — 长密钥走 RFC 2104 的「先哈希密钥」分支，而不是截断。
    #[test]
    fn prop_hmac_hashes_keys_longer_than_the_block(
        (algorithm, key) in hmac_long_key_strategy(),
        message in prop::collection::vec(any::<u8>(), 0..=64),
    ) {
        let block = hmac_block_len(algorithm);
        let nominal = digest_len(algorithm);
        for backend in Backend::all() {
            let mut long = [0u8; MAX_DIGEST_LEN];
            let written = backend
                .hmac()
                .hmac(algorithm, &key, &message, &mut long)
                .unwrap_or_else(|error| panic!("{}: long key: {error:?}", backend.name()));
            prop_assert_eq!(written, nominal, "{}: MAC length", backend.name());

            let mut truncated = [0u8; MAX_DIGEST_LEN];
            backend
                .hmac()
                .hmac(algorithm, &key[..block], &message, &mut truncated)
                .unwrap_or_else(|error| panic!("{}: truncated key: {error:?}", backend.name()));
            prop_assert_ne!(
                &long[..nominal],
                &truncated[..nominal],
                "{}: a {}-byte key produced the MAC of its first {} bytes",
                backend.name(),
                key.len(),
                block
            );

            // RFC 2104: a key longer than the block is replaced by its own
            // digest. The reference backend's mock MAC deliberately does not
            // model that branch, so the equivalence is asserted on the real
            // provider only; the inequality above still holds for both.
            if backend.is_real() {
                let mut hashed_key = [0u8; MAX_DIGEST_LEN];
                let hashed_len = backend
                    .hash()
                    .digest(algorithm, &key, &mut hashed_key)
                    .unwrap_or_else(|error| panic!("{}: hash key: {error:?}", backend.name()));
                let mut expected = [0u8; MAX_DIGEST_LEN];
                backend
                    .hmac()
                    .hmac(
                        algorithm,
                        &hashed_key[..hashed_len],
                        &message,
                        &mut expected,
                    )
                    .unwrap_or_else(|error| {
                        panic!("{}: MAC of hashed key: {error:?}", backend.name())
                    });
                prop_assert_eq!(
                    &long[..nominal],
                    &expected[..nominal],
                    "{}: long key was not hashed per RFC 2104",
                    backend.name()
                );
            }
        }
    }

    // PROP-HMAC-003 — 输出缓冲不足即被拒且不写入。
    #[test]
    fn prop_hmac_short_output_is_clean(
        algorithm in hash_strategy(),
        key in prop::collection::vec(any::<u8>(), 0..=64),
        message in prop::collection::vec(any::<u8>(), 0..=64),
        slack in 1usize..=8,
    ) {
        let nominal = digest_len(algorithm);
        let capacity = nominal.saturating_sub(slack);
        if capacity >= nominal {
            return Ok(());
        }
        for backend in Backend::all() {
            let mut out = vec![0xC4u8; capacity];
            let snapshot = out.clone();
            let result = backend.hmac().hmac(algorithm, &key, &message, &mut out);
            prop_assert!(
                matches!(result, Err(CryptoError::OutputTooSmall)),
                "{}: accepted a {capacity}-byte buffer for a {nominal}-byte MAC",
                backend.name()
            );
            prop_assert_eq!(
                &out[..],
                &snapshot[..],
                "{}: rejected HMAC modified the buffer",
                backend.name()
            );
        }
    }

    // PROP-RAND-001 — 随机输出在块级不重复；无 OS 熵源时必须返回
    // Unsupported 且不写缓冲（裸机路径的契约，不因参数化而放宽）。
    #[test]
    fn prop_random_blocks_are_unique(rounds in 2usize..=16) {
        for backend in Backend::all() {
            prop_assert_eq!(
                backend.random().fill_random(&mut []),
                Ok(()),
                "{}: an empty request must be a no-op",
                backend.name()
            );
            let mut seen: Vec<[u8; 8]> = Vec::new();
            for _ in 0..rounds {
                let mut block = [0xEEu8; 8];
                let before = block;
                match backend.random().fill_random(&mut block) {
                    Ok(()) => {
                        prop_assert!(
                            !seen.contains(&block),
                            "{}: random block repeated",
                            backend.name()
                        );
                        seen.push(block);
                    }
                    Err(CryptoError::Unsupported) => {
                        // Built without `os-rng`: the bare-metal posture is a
                        // loud refusal, never a predictable nonce.
                        prop_assert_eq!(
                            block,
                            before,
                            "{}: Unsupported must leave the buffer untouched",
                            backend.name()
                        );
                        break;
                    }
                    Err(other) => prop_assert!(
                        false,
                        "{}: unexpected entropy error {other:?}",
                        backend.name()
                    ),
                }
            }
        }
    }

    // PROP-KEX-001 — DH 交换对称（参考后端实现该套件）。
    #[test]
    fn prop_diffie_hellman_is_symmetric(pairs in 1usize..=8) {
        let crypto = RefCrypto::new();
        for _ in 0..pairs {
            let mut a_public = [0u8; PUB_LEN];
            let mut b_public = [0u8; PUB_LEN];
            let (a_private, _) = crypto.generate_key(KEX_SUPPORTED, &mut a_public).expect("a");
            let (b_private, _) = crypto.generate_key(KEX_SUPPORTED, &mut b_public).expect("b");

            let mut ab = [0u8; SECRET_LEN];
            let mut ba = [0u8; SECRET_LEN];
            crypto.agree(KEX_SUPPORTED, &a_private, &b_public, &mut ab).expect("ab");
            crypto.agree(KEX_SUPPORTED, &b_private, &a_public, &mut ba).expect("ba");
            prop_assert_eq!(&ab[..], &ba[..]);
        }
    }

    // PROP-KEX-002 — 任意长度的对端公钥要么被拒（InvalidKey）要么成功，且失败不写入。
    #[test]
    fn prop_arbitrary_peer_key_is_handled(
        peer in prop::collection::vec(any::<u8>(), 0..=128),
    ) {
        let crypto = RefCrypto::new();
        let mut own_public = [0u8; PUB_LEN];
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

    // PROP-KEX-003 — 真实后端对密钥交换返回 Unsupported，且从不写缓冲。
    #[test]
    fn prop_declined_key_exchange_reports_unsupported(
        algorithm in kex_strategy(),
        peer in prop::collection::vec(any::<u8>(), 0..=2 * PUB_LEN),
        capacity in 0usize..=2 * SECRET_LEN,
    ) {
        let provider = RustCryptoProvider::new();
        let key = ExchangeKey::for_tests();

        let mut public = vec![0xAAu8; capacity];
        let snapshot = public.clone();
        let result = provider.generate_key(algorithm, &mut public);
        prop_assert!(
            matches!(result, Err(CryptoError::Unsupported)),
            "generate_key({algorithm:?}) returned {result:?}"
        );
        prop_assert_eq!(&public[..], &snapshot[..], "generate_key wrote into a declined buffer");

        let mut secret = vec![0xBBu8; capacity];
        let snapshot = secret.clone();
        let result = provider.agree(algorithm, &key, &peer, &mut secret);
        prop_assert!(
            matches!(result, Err(CryptoError::Unsupported)),
            "agree({algorithm:?}) returned {result:?}"
        );
        prop_assert_eq!(&secret[..], &snapshot[..], "agree wrote into a declined buffer");
    }

    // PROP-SIG-001 — sign/verify 对任意消息成立，且消息的任一比特翻转都被检出。
    #[test]
    fn prop_signature_roundtrip_and_tamper_detection(
        message in prop::collection::vec(any::<u8>(), 1..=512),
        index in any::<usize>(),
        bit in 0u8..8,
    ) {
        let crypto = RefCrypto::new();
        let key = RefSigningKey(0x1234_5678_9ABC_DEF0);
        let public = key.public_key();

        let mut signature = [0u8; SIG_LEN];
        crypto.sign(SIG_SUPPORTED, &key, &message, &mut signature).expect("sign");
        crypto.verify(SIG_SUPPORTED, &public, &message, &signature).expect("verify");

        let mut mutated = message.clone();
        let victim = index % mutated.len();
        mutated[victim] ^= 1 << bit;
        prop_assert!(matches!(
            crypto.verify(SIG_SUPPORTED, &public, &mutated, &signature),
            Err(CryptoError::InvalidSignature)
        ));
    }

    // PROP-SIG-002 — 真实后端对签名套件返回 Unsupported，且从不写缓冲。
    #[test]
    fn prop_declined_signature_reports_unsupported(
        algorithm in signature_strategy(),
        message in prop::collection::vec(any::<u8>(), 0..=512),
        public_key in prop::collection::vec(any::<u8>(), 0..=64),
        capacity in 0usize..=SIG_LEN + 16,
    ) {
        let provider = RustCryptoProvider::new();
        let key = SigningKey::for_tests();

        let mut signature = vec![0xCCu8; capacity];
        let snapshot = signature.clone();
        let result = provider.sign(algorithm, &key, &message, &mut signature);
        prop_assert!(
            matches!(result, Err(CryptoError::Unsupported)),
            "sign({algorithm:?}) returned {result:?}"
        );
        prop_assert_eq!(&signature[..], &snapshot[..], "sign wrote into a declined buffer");

        let result = provider.verify(algorithm, &public_key, &message, &signature);
        prop_assert!(
            matches!(result, Err(CryptoError::Unsupported)),
            "verify({algorithm:?}) returned {result:?}"
        );
    }

    // PROP-TOTAL-001 — 任意切片长度下所有方法都不 panic，且失败不留痕迹。
    #[test]
    fn prop_no_method_panics_for_any_slice_length(len in 0usize..=128) {
        let payload = vec![0x5Au8; len];
        for backend in Backend::all() {
            let mut out = vec![0u8; MAX_DIGEST_LEN];
            let _ = backend.hash().digest(HASH_SUPPORTED, &payload, &mut out);
            let _ = backend.hmac().hmac(HASH_SUPPORTED, &payload, &payload, &mut out);
            let _ = backend.random().fill_random(&mut payload.clone());

            let mut record = vec![0u8; len + TAG_LEN];
            let _ = backend.aead().seal_in_place(
                AEAD_SUPPORTED,
                &payload,
                &payload,
                &payload,
                &mut record,
                len,
            );
            let _ = backend.aead().open_in_place(AEAD_SUPPORTED, &payload, &payload, &payload, &mut record);

            let mut signature = vec![0u8; len];
            let mut secret = vec![0u8; len];
            match &backend {
                Backend::Reference(provider) => {
                    let key = RefSigningKey(7);
                    let _ = provider.sign(SIG_SUPPORTED, &key, &payload, &mut signature);
                    let _ = provider.verify(SIG_SUPPORTED, &key.public_key(), &payload, &signature);
                    let _ = provider.agree(
                        KEX_SUPPORTED,
                        &RefKexKey(0x0123_4567_89AB_CDEF),
                        &payload,
                        &mut secret,
                    );
                }
                Backend::RustCrypto(provider) => {
                    let _ = provider.sign(SIG_SUPPORTED, &SigningKey::for_tests(), &payload, &mut signature);
                    let _ = provider.verify(SIG_SUPPORTED, &payload, &payload, &signature);
                    let _ = provider.agree(KEX_SUPPORTED, &ExchangeKey::for_tests(), &payload, &mut secret);
                }
            }
        }
    }
}

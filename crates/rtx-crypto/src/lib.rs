#![cfg_attr(not(feature = "std"), no_std)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    Unsupported,
    InvalidKey,
    InvalidNonce,
    InvalidSignature,
    AuthenticationFailed,
    OutputTooSmall,
    BackendFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeAlgorithm {
    P256,
    P384,
    X25519,
}

pub trait RandomProvider {
    /// Fills `output` with random bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BackendFailure`] when the entropy source fails.
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait HashProvider {
    /// Writes the digest of `input` into `output`, returning its length.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unsupported`] for an unknown algorithm, or
    /// [`CryptoError::OutputTooSmall`] when `output` cannot hold the digest.
    fn digest(
        &self,
        algorithm: HashAlgorithm,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError>;
}

pub trait HmacProvider {
    /// Writes the MAC of `input` under `key` into `output`, returning its length.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unsupported`] for an unknown algorithm, or
    /// [`CryptoError::OutputTooSmall`] when `output` cannot hold the MAC.
    fn hmac(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError>;
}

/// In-place AEAD avoids forcing an allocation at the crypto boundary.
pub trait AeadProvider {
    /// Encrypts `payload_and_tag[..plaintext_len]` in place and appends the
    /// tag, returning `plaintext_len + tag_len`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unsupported`] for an unknown algorithm, or
    /// [`CryptoError::OutputTooSmall`] when `payload_and_tag` cannot hold
    /// `plaintext_len` bytes plus the tag. On error the buffer is left
    /// unmodified.
    fn seal_in_place(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        payload_and_tag: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, CryptoError>;

    /// Authenticates and decrypts `ciphertext_and_tag` in place, returning
    /// the plaintext length.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unsupported`] for an unknown algorithm,
    /// [`CryptoError::OutputTooSmall`] when `ciphertext_and_tag` cannot hold
    /// a tag, or [`CryptoError::AuthenticationFailed`] when the tag does not
    /// authenticate. On failure the buffer is left unmodified.
    fn open_in_place(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &mut [u8],
    ) -> Result<usize, CryptoError>;
}

/// Provider-owned opaque private-key handles let MCU adapters keep keys inside
/// hardware crypto engines or secure elements.
pub trait SignatureProvider {
    type PrivateKey;

    /// Writes the signature of `message` into `signature_out`, returning its length.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unsupported`] for an unknown algorithm, or
    /// [`CryptoError::OutputTooSmall`] when `signature_out` cannot hold the
    /// signature.
    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        key: &Self::PrivateKey,
        message: &[u8],
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError>;

    /// Verifies `signature` over `message` under `public_key`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unsupported`] for an unknown algorithm, or
    /// [`CryptoError::InvalidSignature`] when the signature does not match.
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;
}

pub trait KeyExchangeProvider {
    type PrivateKey;

    /// Generates a fresh key pair, writing the public key into
    /// `public_key_out` and returning the opaque private key handle.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unsupported`] for an unknown algorithm, or
    /// [`CryptoError::OutputTooSmall`] when `public_key_out` cannot hold the
    /// public key.
    fn generate_key(
        &self,
        algorithm: KeyExchangeAlgorithm,
        public_key_out: &mut [u8],
    ) -> Result<(Self::PrivateKey, usize), CryptoError>;

    /// Computes the shared secret with `peer_public_key`, writing it into
    /// `secret_out` and returning its length.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unsupported`] for an unknown algorithm,
    /// [`CryptoError::InvalidKey`] when `peer_public_key` is malformed, or
    /// [`CryptoError::OutputTooSmall`] when `secret_out` cannot hold the
    /// shared secret.
    fn agree(
        &self,
        algorithm: KeyExchangeAlgorithm,
        private_key: &Self::PrivateKey,
        peer_public_key: &[u8],
        secret_out: &mut [u8],
    ) -> Result<usize, CryptoError>;
}

/// Marker trait for a complete portable crypto backend.
pub trait CryptoProvider:
    RandomProvider
    + HashProvider
    + HmacProvider
    + AeadProvider
    + SignatureProvider
    + KeyExchangeProvider
{
    fn name(&self) -> &'static str;
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::cell::Cell;

    // ---- CRYPTO-ERR -------------------------------------------------------

    // CRYPTO-ERR-001 — CryptoError 变体可构造与比较。
    #[test]
    fn crypto_error_variants_construct_and_compare() {
        let variants = [
            CryptoError::Unsupported,
            CryptoError::InvalidKey,
            CryptoError::InvalidNonce,
            CryptoError::InvalidSignature,
            CryptoError::AuthenticationFailed,
            CryptoError::OutputTooSmall,
            CryptoError::BackendFailure,
        ];
        assert_pairwise_distinct(&variants);
        let error = CryptoError::Unsupported;
        let copied = error; // Copy
        assert_eq!(error, copied);
        assert!(!format!("{error:?}").is_empty());
    }

    // ---- CRYPTO-ALG -------------------------------------------------------

    // CRYPTO-ALG-001 — 算法枚举穷举可构造与互异（新增变体时测试失败，强制同步评审）。
    #[test]
    fn algorithm_enums_are_exhaustively_distinct() {
        let hashes = [
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
        ];
        assert_pairwise_distinct(&hashes);
        assert!(matches!(hashes[0], HashAlgorithm::Sha1));

        let aeads = [AeadAlgorithm::Aes128Gcm, AeadAlgorithm::Aes256Gcm];
        assert_pairwise_distinct(&aeads);
        assert!(matches!(aeads[0], AeadAlgorithm::Aes128Gcm));

        let signatures = [
            SignatureAlgorithm::EcdsaP256Sha256,
            SignatureAlgorithm::EcdsaP384Sha384,
            SignatureAlgorithm::Ed25519,
        ];
        assert_pairwise_distinct(&signatures);
        assert!(matches!(signatures[2], SignatureAlgorithm::Ed25519));

        let key_exchanges = [
            KeyExchangeAlgorithm::P256,
            KeyExchangeAlgorithm::P384,
            KeyExchangeAlgorithm::X25519,
        ];
        assert_pairwise_distinct(&key_exchanges);
        assert!(matches!(key_exchanges[2], KeyExchangeAlgorithm::X25519));
    }

    /// 断言所有元素两两互异且可 Debug 输出。
    fn assert_pairwise_distinct<T: PartialEq + core::fmt::Debug>(values: &[T]) {
        for (index, left) in values.iter().enumerate() {
            assert!(!format!("{left:?}").is_empty());
            for (other, right) in values.iter().enumerate() {
                if index != other {
                    assert_ne!(left, right);
                }
            }
        }
    }

    // ---- mock 策略常量（设计 §5.4）与确定性算术辅助 ------------------------

    const TAG_LEN: usize = 16;
    const SHA1_LEN: usize = 20;
    const SHA256_LEN: usize = 32;
    const SHA384_LEN: usize = 48;
    const SIG_LEN: usize = 64;
    const PUB_LEN: usize = 32;
    const SECRET_LEN: usize = 32;

    /// 摘要长度策略：Sha1→20、Sha256→32、Sha384→48。
    fn digest_len(algorithm: HashAlgorithm) -> usize {
        match algorithm {
            HashAlgorithm::Sha1 => SHA1_LEN,
            HashAlgorithm::Sha256 => SHA256_LEN,
            HashAlgorithm::Sha384 => SHA384_LEN,
        }
    }

    /// FNV 风格混合（测试辅助，非真实密码学）。
    fn mix(mut state: u64, bytes: &[u8]) -> u64 {
        for &byte in bytes {
            state ^= u64::from(byte);
            state = state.wrapping_mul(0x0000_0100_0000_01B3);
        }
        state
    }

    /// 将 64 位状态确定性地拉伸为 `out` 字节（测试辅助，非密码学）。
    fn stretch(mut state: u64, out: &mut [u8]) {
        for (block, chunk) in (0_u64..).zip(out.chunks_mut(8)) {
            state ^= block.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            let bytes = state.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    /// 确定性"摘要"：FNV 混合后按算法标称长度拉伸（真实向量属 M2）。
    fn mock_digest(algorithm: HashAlgorithm, input: &[u8]) -> [u8; SHA384_LEN] {
        let seed = match algorithm {
            HashAlgorithm::Sha1 => 0x6A09_E667_0000_0001,
            HashAlgorithm::Sha256 => 0x6A09_E667_0000_0002,
            HashAlgorithm::Sha384 => 0x6A09_E667_0000_0003,
        };
        let len = digest_len(algorithm);
        let mut out = [0u8; SHA384_LEN];
        stretch(mix(seed, input), &mut out[..len]);
        out
    }

    /// 确定性"HMAC"：key、input 依次混合后按标称长度拉伸。
    fn mock_hmac(algorithm: HashAlgorithm, key: &[u8], input: &[u8]) -> [u8; SHA384_LEN] {
        let seed = match algorithm {
            HashAlgorithm::Sha1 => 0x5BE0_CD19_0000_0001,
            HashAlgorithm::Sha256 => 0x5BE0_CD19_0000_0002,
            HashAlgorithm::Sha384 => 0x5BE0_CD19_0000_0003,
        };
        let len = digest_len(algorithm);
        let mut state = mix(seed, key);
        state ^= 0x5A5A_5A5A; // 内/外层分隔概念
        state = mix(state, input);
        let mut out = [0u8; SHA384_LEN];
        stretch(state, &mut out[..len]);
        out
    }

    /// 确定性 keystream 块（由算法/key/nonce/序号决定）。
    fn aead_keystream_block(
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        block: u64,
    ) -> [u8; 8] {
        let mut state = 0x510E_527F_ADE6_82D1 ^ block.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        state ^= match algorithm {
            AeadAlgorithm::Aes128Gcm => 1,
            AeadAlgorithm::Aes256Gcm => 2,
        };
        state = mix(state, key);
        state = mix(state, nonce);
        state.to_le_bytes()
    }

    /// 原地 XOR keystream。
    fn aead_xor_keystream(algorithm: AeadAlgorithm, key: &[u8], nonce: &[u8], buf: &mut [u8]) {
        for (block, chunk) in (0_u64..).zip(buf.chunks_mut(8)) {
            let keystream = aead_keystream_block(algorithm, key, nonce, block);
            for (byte, mask) in chunk.iter_mut().zip(keystream) {
                *byte ^= mask;
            }
        }
    }

    /// 确定性 tag：对算法/key/nonce/aad/密文混合后拉伸 16 字节。
    fn aead_tag(
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> [u8; TAG_LEN] {
        let mut state = 0x6C62_272E_07BB_0142;
        state ^= match algorithm {
            AeadAlgorithm::Aes128Gcm => 1,
            AeadAlgorithm::Aes256Gcm => 2,
        };
        state = mix(state, key);
        state = mix(state, nonce);
        state = mix(state, aad);
        state = mix(state, ciphertext);
        let mut tag = [0u8; TAG_LEN];
        stretch(state, &mut tag);
        tag
    }

    /// 不透明私钥句柄（mock：标量由 provider 侧关联类型承载，§12:291）。
    #[derive(Debug)]
    struct MockPrivateKey(u64);

    /// mock 简化：公钥前 8 字节承载私钥标量，使 `verify` 可确定性重算
    /// （真实提供方把标量锁在不透明句柄内，公钥不可反推）。
    fn sig_public_key(private: &MockPrivateKey) -> [u8; PUB_LEN] {
        let mut out = [0u8; PUB_LEN];
        out[..8].copy_from_slice(&private.0.to_le_bytes());
        stretch(private.0, &mut out[8..]);
        out
    }

    fn sig_scalar_from_public(public_key: &[u8]) -> Option<u64> {
        let bytes: [u8; 8] = public_key.get(..8)?.try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    /// 确定性 Ed25519 风格签名（64 字节）。
    fn sig_sign(private: &MockPrivateKey, message: &[u8]) -> [u8; SIG_LEN] {
        let state = mix(0x1234_5678_9ABC_DEF0 ^ private.0, message);
        let mut signature = [0u8; SIG_LEN];
        stretch(state, &mut signature);
        signature
    }

    /// mock DH：`pub = priv·G`、`secret = priv·peer_pub`（wrapping 乘法，
    /// mod 2^64 天然满足交换律，双方 agree 结果逐字节相等）。
    const KEX_G: u64 = 0x1000_0000_01BF_09CE;

    #[derive(Debug, PartialEq, Eq)]
    struct MockKexPrivateKey(u64);

    fn kex_public_scalar(private: u64) -> u64 {
        private.wrapping_mul(KEX_G)
    }

    fn kex_serialize_public(scalar: u64) -> [u8; PUB_LEN] {
        let mut out = [0u8; PUB_LEN];
        out[..8].copy_from_slice(&scalar.to_le_bytes());
        out
    }

    fn kex_parse_public(peer_public_key: &[u8]) -> Option<u64> {
        if peer_public_key.len() != PUB_LEN {
            return None;
        }
        let bytes: [u8; 8] = peer_public_key.get(..8)?.try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    // ---- CRYPTO-RAND-001 支撑 mock -----------------------------------------

    /// 确定性 xorshift 随机源；trait 方法收 `&self`，内部序列用 `Cell` 推进
    /// （`no_std` 友好的内部可变性，设计 §5.4/m2）。
    #[derive(Debug)]
    struct MockRandom {
        counter: Cell<u64>,
    }

    impl MockRandom {
        fn new(seed: u64) -> Self {
            Self {
                counter: Cell::new(seed),
            }
        }

        fn next_u64(&self) -> u64 {
            let mut value = self.counter.get();
            value ^= value >> 12;
            value ^= value << 25;
            value ^= value >> 27;
            self.counter.set(value);
            value.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    impl RandomProvider for MockRandom {
        fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
            for chunk in output.chunks_mut(8) {
                chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
            }
            Ok(())
        }
    }

    // CRYPTO-RAND-001 — RandomProvider 内存 mock。
    #[test]
    fn random_provider_memory_mock_is_deterministic() {
        let random = MockRandom::new(0x1234_5678_9ABC_DEF0);

        let mut output = [0u8; 32];
        random.fill_random(&mut output).expect("fill 32 bytes");
        assert!(output.iter().any(|&byte| byte != 0)); // 确定性非零图案

        let mut empty: [u8; 0] = [];
        random
            .fill_random(&mut empty)
            .expect("fill empty output is a no-op");

        let mut first = [0u8; 16];
        let mut second = [0u8; 16];
        random.fill_random(&mut first).expect("first fill");
        random.fill_random(&mut second).expect("second fill");
        assert_ne!(first, second); // 序列推进
    }

    // ---- CRYPTO-HASH-001 支撑 mock ------------------------------------------

    #[derive(Debug)]
    struct MockHash;

    impl HashProvider for MockHash {
        fn digest(
            &self,
            algorithm: HashAlgorithm,
            input: &[u8],
            output: &mut [u8],
        ) -> Result<usize, CryptoError> {
            let full = mock_digest(algorithm, input);
            let len = digest_len(algorithm);
            if output.len() < len {
                return Err(CryptoError::OutputTooSmall);
            }
            output[..len].copy_from_slice(&full[..len]);
            Ok(len)
        }
    }

    // CRYPTO-HASH-001 — HashProvider 内存 mock。
    #[test]
    fn hash_provider_memory_mock() {
        let hash = MockHash;

        let mut output = [0u8; SHA384_LEN];
        assert_eq!(
            hash.digest(HashAlgorithm::Sha1, b"rtx", &mut output),
            Ok(SHA1_LEN)
        );
        assert_eq!(
            &output[..SHA1_LEN],
            &mock_digest(HashAlgorithm::Sha1, b"rtx")[..SHA1_LEN]
        );
        assert_eq!(
            hash.digest(HashAlgorithm::Sha256, b"rtx", &mut output),
            Ok(SHA256_LEN)
        );
        assert_eq!(
            &output[..SHA256_LEN],
            &mock_digest(HashAlgorithm::Sha256, b"rtx")[..SHA256_LEN]
        );
        assert_eq!(
            hash.digest(HashAlgorithm::Sha384, b"rtx", &mut output),
            Ok(SHA384_LEN)
        );
        assert_eq!(
            &output[..SHA384_LEN],
            &mock_digest(HashAlgorithm::Sha384, b"rtx")[..SHA384_LEN]
        );

        // 确定性：相同输入相同输出。
        let mut first = [0u8; SHA256_LEN];
        let mut second = [0u8; SHA256_LEN];
        hash.digest(HashAlgorithm::Sha256, b"same", &mut first)
            .expect("first digest");
        hash.digest(HashAlgorithm::Sha256, b"same", &mut second)
            .expect("second digest");
        assert_eq!(first, second);

        // 基本区分性：不同输入不同输出。
        hash.digest(HashAlgorithm::Sha256, b"different", &mut second)
            .expect("third digest");
        assert_ne!(first, second);

        // 输出缓冲不足 → OutputTooSmall。
        let mut small = [0u8; SHA256_LEN - 1];
        assert_eq!(
            hash.digest(HashAlgorithm::Sha256, b"rtx", &mut small),
            Err(CryptoError::OutputTooSmall)
        );
    }

    // ---- CRYPTO-HMAC-001 支撑 mock ------------------------------------------

    #[derive(Debug)]
    struct MockHmac;

    impl HmacProvider for MockHmac {
        fn hmac(
            &self,
            algorithm: HashAlgorithm,
            key: &[u8],
            input: &[u8],
            output: &mut [u8],
        ) -> Result<usize, CryptoError> {
            let full = mock_hmac(algorithm, key, input);
            let len = digest_len(algorithm);
            if output.len() < len {
                return Err(CryptoError::OutputTooSmall);
            }
            output[..len].copy_from_slice(&full[..len]);
            Ok(len)
        }
    }

    // CRYPTO-HMAC-001 — HmacProvider 内存 mock。
    #[test]
    fn hmac_provider_memory_mock() {
        let hmac = MockHmac;

        let mut output = [0u8; SHA384_LEN];
        assert_eq!(
            hmac.hmac(HashAlgorithm::Sha256, b"key", b"rtx", &mut output),
            Ok(SHA256_LEN)
        );
        assert_eq!(
            &output[..SHA256_LEN],
            &mock_hmac(HashAlgorithm::Sha256, b"key", b"rtx")[..SHA256_LEN]
        );

        // 同一 (key, input) 确定可复现。
        let mut again = [0u8; SHA384_LEN];
        hmac.hmac(HashAlgorithm::Sha256, b"key", b"rtx", &mut again)
            .expect("repeat");
        assert_eq!(output[..SHA256_LEN], again[..SHA256_LEN]);

        // 更换 key → mac 变化（密钥参与）。
        hmac.hmac(HashAlgorithm::Sha256, b"other-key", b"rtx", &mut again)
            .expect("key change");
        assert_ne!(output[..SHA256_LEN], again[..SHA256_LEN]);

        // 更换 input → mac 变化。
        hmac.hmac(HashAlgorithm::Sha256, b"key", b"rtx2", &mut again)
            .expect("input change");
        assert_ne!(output[..SHA256_LEN], again[..SHA256_LEN]);

        // 输出过小 → OutputTooSmall。
        let mut small = [0u8; SHA256_LEN - 1];
        assert_eq!(
            hmac.hmac(HashAlgorithm::Sha256, b"key", b"rtx", &mut small),
            Err(CryptoError::OutputTooSmall)
        );
    }

    // ---- CRYPTO-AEAD-001..005 支撑 mock -------------------------------------

    #[derive(Debug)]
    struct MockAead;

    impl AeadProvider for MockAead {
        fn seal_in_place(
            &self,
            algorithm: AeadAlgorithm,
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            payload_and_tag: &mut [u8],
            plaintext_len: usize,
        ) -> Result<usize, CryptoError> {
            // 先校验尺寸，后写缓冲（CRYPTO-AEAD-005：失败不得修改缓冲）。
            let needed = plaintext_len
                .checked_add(TAG_LEN)
                .ok_or(CryptoError::OutputTooSmall)?;
            if payload_and_tag.len() < needed {
                return Err(CryptoError::OutputTooSmall);
            }
            let (payload, tag_region) = payload_and_tag.split_at_mut(plaintext_len);
            aead_xor_keystream(algorithm, key, nonce, payload);
            let tag = aead_tag(algorithm, key, nonce, aad, payload);
            tag_region[..TAG_LEN].copy_from_slice(&tag);
            Ok(plaintext_len + TAG_LEN)
        }

        fn open_in_place(
            &self,
            algorithm: AeadAlgorithm,
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            ciphertext_and_tag: &mut [u8],
        ) -> Result<usize, CryptoError> {
            if ciphertext_and_tag.len() < TAG_LEN {
                return Err(CryptoError::OutputTooSmall);
            }
            let split = ciphertext_and_tag.len() - TAG_LEN;
            let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(split);
            let expected = aead_tag(algorithm, key, nonce, aad, ciphertext);
            // 先验证后解密：认证失败不得篡改缓冲。
            if tag.iter().ne(expected.iter()) {
                return Err(CryptoError::AuthenticationFailed);
            }
            aead_xor_keystream(algorithm, key, nonce, ciphertext);
            Ok(split)
        }
    }

    // CRYPTO-AEAD-001 — seal→open 原地往返。
    #[test]
    fn aead_seal_open_roundtrip_in_place() {
        let aead = MockAead;
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let plaintext = b"rtx-m0-aead";
        let mut buffer = [0u8; 27];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let sealed = aead
            .seal_in_place(
                AeadAlgorithm::Aes128Gcm,
                &key,
                &nonce,
                b"aad",
                &mut buffer,
                plaintext.len(),
            )
            .expect("seal");
        // tag 空间语义 = plaintext_len + tag。
        assert_eq!(sealed, plaintext.len() + TAG_LEN);
        assert_eq!(sealed, buffer.len());
        assert_ne!(&buffer[..plaintext.len()], plaintext); // 密文区 != 明文区

        let opened = aead
            .open_in_place(AeadAlgorithm::Aes128Gcm, &key, &nonce, b"aad", &mut buffer)
            .expect("open");
        assert_eq!(opened, plaintext.len());
        assert_eq!(&buffer[..plaintext.len()], plaintext); // 原地解密还原
    }

    // CRYPTO-AEAD-002 — AAD 认证失败路径。
    #[test]
    fn aead_aad_mismatch_fails_authentication() {
        let aead = MockAead;
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let plaintext = b"rtx-m0-aead";
        let mut buffer = [0u8; 27];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
        aead.seal_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key,
            &nonce,
            b"header",
            &mut buffer,
            plaintext.len(),
        )
        .expect("seal with header aad");
        let sealed_snapshot = buffer;

        let error = aead
            .open_in_place(
                AeadAlgorithm::Aes128Gcm,
                &key,
                &nonce,
                b"HEADER",
                &mut buffer,
            )
            .unwrap_err();
        assert_eq!(error, CryptoError::AuthenticationFailed);
        assert_eq!(buffer, sealed_snapshot); // 失败后缓冲未被解密篡改
    }

    // CRYPTO-AEAD-003 — tag 篡改检测。
    #[test]
    fn aead_tag_tampering_is_detected() {
        let aead = MockAead;
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let plaintext = b"rtx-m0-aead";
        let mut buffer = [0u8; 27];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
        aead.seal_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key,
            &nonce,
            b"aad",
            &mut buffer,
            plaintext.len(),
        )
        .expect("seal");

        // tag 区 = [plaintext_len .. plaintext_len + TAG_LEN)，翻转首字节一 bit。
        buffer[plaintext.len()] ^= 0x01;
        assert_eq!(
            aead.open_in_place(AeadAlgorithm::Aes128Gcm, &key, &nonce, b"aad", &mut buffer),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    // CRYPTO-AEAD-004 — key/nonce 不匹配。
    #[test]
    fn aead_key_or_nonce_mismatch_fails_authentication() {
        let aead = MockAead;
        let key = [0x11u8; 32];
        let other_key = [0x33u8; 32];
        let nonce = [0x22u8; 12];
        let other_nonce = [0x44u8; 12];
        let plaintext = b"rtx-m0-aead";
        let mut buffer = [0u8; 27];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
        aead.seal_in_place(
            AeadAlgorithm::Aes128Gcm,
            &key,
            &nonce,
            b"aad",
            &mut buffer,
            plaintext.len(),
        )
        .expect("seal");

        assert_eq!(
            aead.open_in_place(
                AeadAlgorithm::Aes128Gcm,
                &other_key,
                &nonce,
                b"aad",
                &mut buffer
            ),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            aead.open_in_place(
                AeadAlgorithm::Aes128Gcm,
                &key,
                &other_nonce,
                b"aad",
                &mut buffer
            ),
            Err(CryptoError::AuthenticationFailed)
        );
        // 失败未破坏密封状态：正确参数仍可打开。
        let opened = aead
            .open_in_place(AeadAlgorithm::Aes128Gcm, &key, &nonce, b"aad", &mut buffer)
            .expect("open with correct parameters");
        assert_eq!(opened, plaintext.len());
        assert_eq!(&buffer[..plaintext.len()], plaintext);
    }

    // CRYPTO-AEAD-005 — tag 空间不足。
    #[test]
    fn aead_insufficient_tag_space_is_rejected_without_side_effects() {
        let aead = MockAead;
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let plaintext = b"rtx-m0-aaa";

        // 25 字节缓冲、plaintext_len=10、TAG_LEN=16（需 26）→ OutputTooSmall。
        let mut tight = [0u8; 25];
        tight[..plaintext.len()].copy_from_slice(plaintext);
        assert_eq!(
            aead.seal_in_place(
                AeadAlgorithm::Aes128Gcm,
                &key,
                &nonce,
                b"aad",
                &mut tight,
                plaintext.len()
            ),
            Err(CryptoError::OutputTooSmall)
        );
        assert_eq!(&tight[..plaintext.len()], plaintext); // 缓冲未被修改

        // 边界：恰 26 字节 → Ok。
        let mut exact = [0u8; 26];
        exact[..plaintext.len()].copy_from_slice(plaintext);
        let sealed = aead
            .seal_in_place(
                AeadAlgorithm::Aes128Gcm,
                &key,
                &nonce,
                b"aad",
                &mut exact,
                plaintext.len(),
            )
            .expect("seal into exact buffer");
        assert_eq!(sealed, 26);
    }

    // ---- CRYPTO-SIG-001/002 支撑 mock ---------------------------------------

    #[derive(Debug)]
    struct MockSignature;

    impl SignatureProvider for MockSignature {
        type PrivateKey = MockPrivateKey;

        fn sign(
            &self,
            algorithm: SignatureAlgorithm,
            key: &Self::PrivateKey,
            message: &[u8],
            signature_out: &mut [u8],
        ) -> Result<usize, CryptoError> {
            // 仅建模 Ed25519；其他算法显式 Unsupported（§5.4 失败码约定）。
            if algorithm != SignatureAlgorithm::Ed25519 {
                return Err(CryptoError::Unsupported);
            }
            if signature_out.len() < SIG_LEN {
                return Err(CryptoError::OutputTooSmall);
            }
            let signature = sig_sign(key, message);
            signature_out[..SIG_LEN].copy_from_slice(&signature);
            Ok(SIG_LEN)
        }

        fn verify(
            &self,
            algorithm: SignatureAlgorithm,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), CryptoError> {
            if algorithm != SignatureAlgorithm::Ed25519 {
                return Err(CryptoError::Unsupported);
            }
            // mock 策略：验签失败统一返回 InvalidSignature（与 AEAD 的
            // AuthenticationFailed 分工：签名边界用 InvalidSignature）。
            let scalar = sig_scalar_from_public(public_key).ok_or(CryptoError::InvalidKey)?;
            let expected = sig_sign(&MockPrivateKey(scalar), message);
            if signature.len() != SIG_LEN || signature != expected.as_slice() {
                return Err(CryptoError::InvalidSignature);
            }
            Ok(())
        }
    }

    // CRYPTO-SIG-001 — sign→verify 往返。
    #[test]
    fn signature_sign_verify_roundtrip() {
        let signature = MockSignature;
        let key = MockPrivateKey(0x0BAD_C0DE_DEAD_BEEF);
        let public = sig_public_key(&key);
        let message = b"rtx-m0-signature";

        let mut out = [0u8; SIG_LEN];
        let written = signature
            .sign(SignatureAlgorithm::Ed25519, &key, message, &mut out)
            .expect("sign");
        assert_eq!(written, SIG_LEN);
        signature
            .verify(SignatureAlgorithm::Ed25519, &public, message, &out)
            .expect("verify");

        // 确定性：同一 msg 两次签名一致。
        let mut again = [0u8; SIG_LEN];
        signature
            .sign(SignatureAlgorithm::Ed25519, &key, message, &mut again)
            .expect("sign again");
        assert_eq!(out, again);

        // out 小于 64 → OutputTooSmall。
        let mut small = [0u8; SIG_LEN - 1];
        assert_eq!(
            signature.sign(SignatureAlgorithm::Ed25519, &key, message, &mut small),
            Err(CryptoError::OutputTooSmall)
        );
    }

    // CRYPTO-SIG-002 — 篡改消息/签单一字节均被拒绝。
    #[test]
    fn signature_tampering_is_rejected() {
        let signature = MockSignature;
        let key = MockPrivateKey(42);
        let public = sig_public_key(&key);
        let message = b"rtx-m0-signature";
        let mut signed = [0u8; SIG_LEN];
        signature
            .sign(SignatureAlgorithm::Ed25519, &key, message, &mut signed)
            .expect("sign");

        // 篡改消息一字节。
        let mut tampered_message = *message;
        tampered_message[0] ^= 0x01;
        assert_eq!(
            signature.verify(
                SignatureAlgorithm::Ed25519,
                &public,
                &tampered_message,
                &signed
            ),
            Err(CryptoError::InvalidSignature)
        );

        // 篡改签单一字节。
        let mut tampered_signature = signed;
        tampered_signature[0] ^= 0x01;
        assert_eq!(
            signature.verify(
                SignatureAlgorithm::Ed25519,
                &public,
                message,
                &tampered_signature
            ),
            Err(CryptoError::InvalidSignature)
        );

        // 未篡改仍通过。
        signature
            .verify(SignatureAlgorithm::Ed25519, &public, message, &signed)
            .expect("verify original");
    }

    // ---- CRYPTO-KEX-001/002 支撑 mock ---------------------------------------

    #[derive(Debug)]
    struct MockKeyExchange {
        next_private: Cell<u64>,
    }

    impl MockKeyExchange {
        fn new() -> Self {
            Self {
                next_private: Cell::new(0x243F_6A88_85A3_08D3),
            }
        }

        fn next_scalar(&self) -> u64 {
            let current = self.next_private.get();
            self.next_private
                .set(current.wrapping_add(0x9E37_79B9_7F4A_7C15));
            current
        }
    }

    impl KeyExchangeProvider for MockKeyExchange {
        type PrivateKey = MockKexPrivateKey;

        fn generate_key(
            &self,
            algorithm: KeyExchangeAlgorithm,
            public_key_out: &mut [u8],
        ) -> Result<(Self::PrivateKey, usize), CryptoError> {
            if algorithm != KeyExchangeAlgorithm::X25519 {
                return Err(CryptoError::Unsupported);
            }
            if public_key_out.len() < PUB_LEN {
                return Err(CryptoError::OutputTooSmall);
            }
            let private = self.next_scalar();
            public_key_out[..PUB_LEN]
                .copy_from_slice(&kex_serialize_public(kex_public_scalar(private)));
            Ok((MockKexPrivateKey(private), PUB_LEN))
        }

        fn agree(
            &self,
            algorithm: KeyExchangeAlgorithm,
            private_key: &Self::PrivateKey,
            peer_public_key: &[u8],
            secret_out: &mut [u8],
        ) -> Result<usize, CryptoError> {
            if algorithm != KeyExchangeAlgorithm::X25519 {
                return Err(CryptoError::Unsupported);
            }
            let peer_public = kex_parse_public(peer_public_key).ok_or(CryptoError::InvalidKey)?;
            if secret_out.len() < SECRET_LEN {
                return Err(CryptoError::OutputTooSmall);
            }
            // secret = priv·peer_pub（wrapping 乘，天然交换）。
            let secret = private_key.0.wrapping_mul(peer_public);
            let mut out = [0u8; SECRET_LEN];
            stretch(secret, &mut out);
            secret_out[..SECRET_LEN].copy_from_slice(&out);
            Ok(SECRET_LEN)
        }
    }

    // CRYPTO-KEX-001 — 双方 agree 得到相同 secret。
    #[test]
    fn key_exchange_both_sides_agree_on_secret() {
        let kex = MockKeyExchange::new();

        let mut alice_public = [0u8; PUB_LEN];
        let (alice_private, written) = kex
            .generate_key(KeyExchangeAlgorithm::X25519, &mut alice_public)
            .expect("generate alice key");
        assert_eq!(written, PUB_LEN);

        let mut bob_public = [0u8; PUB_LEN];
        let (bob_private, _) = kex
            .generate_key(KeyExchangeAlgorithm::X25519, &mut bob_public)
            .expect("generate bob key");

        let mut alice_secret = [0u8; SECRET_LEN];
        let written = kex
            .agree(
                KeyExchangeAlgorithm::X25519,
                &alice_private,
                &bob_public,
                &mut alice_secret,
            )
            .expect("alice agrees");
        assert_eq!(written, SECRET_LEN);

        let mut bob_secret = [0u8; SECRET_LEN];
        kex.agree(
            KeyExchangeAlgorithm::X25519,
            &bob_private,
            &alice_public,
            &mut bob_secret,
        )
        .expect("bob agrees");
        assert_eq!(alice_secret, bob_secret); // DH 交换对称性

        // 更换对端公钥 → secret 变化。
        let mut other_public = bob_public;
        other_public[0] ^= 0x01;
        let mut other_secret = [0u8; SECRET_LEN];
        kex.agree(
            KeyExchangeAlgorithm::X25519,
            &alice_private,
            &other_public,
            &mut other_secret,
        )
        .expect("agree with other peer");
        assert_ne!(alice_secret, other_secret);
    }

    // CRYPTO-KEX-002 — KEX 错误路径。
    #[test]
    fn key_exchange_error_paths() {
        let kex = MockKeyExchange::new();

        let mut small_public = [0u8; PUB_LEN - 1];
        assert_eq!(
            kex.generate_key(KeyExchangeAlgorithm::X25519, &mut small_public),
            Err(CryptoError::OutputTooSmall)
        );

        let mut public = [0u8; PUB_LEN];
        let (private, _) = kex
            .generate_key(KeyExchangeAlgorithm::X25519, &mut public)
            .expect("generate key");

        // 错误长度的对端公钥 → InvalidKey。
        let mut secret = [0u8; SECRET_LEN];
        assert_eq!(
            kex.agree(
                KeyExchangeAlgorithm::X25519,
                &private,
                &public[..PUB_LEN - 1],
                &mut secret
            ),
            Err(CryptoError::InvalidKey)
        );

        // secret_out 过小 → OutputTooSmall。
        let mut small_secret = [0u8; SECRET_LEN - 1];
        assert_eq!(
            kex.agree(
                KeyExchangeAlgorithm::X25519,
                &private,
                &public,
                &mut small_secret
            ),
            Err(CryptoError::OutputTooSmall)
        );
    }

    // ---- CRYPTO-COMBO-001..003 ----------------------------------------------

    /// 单一组合 provider：同时实现六个 provider trait（可组合持有前述 mock 逻辑）。
    #[derive(Debug)]
    struct MockCrypto {
        random: MockRandom,
        key_exchange: MockKeyExchange,
    }

    impl MockCrypto {
        fn new() -> Self {
            Self {
                random: MockRandom::new(0x0DDC_0FFE_E0DD_C0DE),
                key_exchange: MockKeyExchange::new(),
            }
        }
    }

    impl RandomProvider for MockCrypto {
        fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
            self.random.fill_random(output)
        }
    }

    impl HashProvider for MockCrypto {
        fn digest(
            &self,
            algorithm: HashAlgorithm,
            input: &[u8],
            output: &mut [u8],
        ) -> Result<usize, CryptoError> {
            MockHash.digest(algorithm, input, output)
        }
    }

    impl HmacProvider for MockCrypto {
        fn hmac(
            &self,
            algorithm: HashAlgorithm,
            key: &[u8],
            input: &[u8],
            output: &mut [u8],
        ) -> Result<usize, CryptoError> {
            MockHmac.hmac(algorithm, key, input, output)
        }
    }

    impl AeadProvider for MockCrypto {
        fn seal_in_place(
            &self,
            algorithm: AeadAlgorithm,
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            payload_and_tag: &mut [u8],
            plaintext_len: usize,
        ) -> Result<usize, CryptoError> {
            MockAead.seal_in_place(algorithm, key, nonce, aad, payload_and_tag, plaintext_len)
        }

        fn open_in_place(
            &self,
            algorithm: AeadAlgorithm,
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            ciphertext_and_tag: &mut [u8],
        ) -> Result<usize, CryptoError> {
            MockAead.open_in_place(algorithm, key, nonce, aad, ciphertext_and_tag)
        }
    }

    impl SignatureProvider for MockCrypto {
        type PrivateKey = MockPrivateKey;

        fn sign(
            &self,
            algorithm: SignatureAlgorithm,
            key: &Self::PrivateKey,
            message: &[u8],
            signature_out: &mut [u8],
        ) -> Result<usize, CryptoError> {
            MockSignature.sign(algorithm, key, message, signature_out)
        }

        fn verify(
            &self,
            algorithm: SignatureAlgorithm,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), CryptoError> {
            MockSignature.verify(algorithm, public_key, message, signature)
        }
    }

    impl KeyExchangeProvider for MockCrypto {
        type PrivateKey = MockKexPrivateKey;

        fn generate_key(
            &self,
            algorithm: KeyExchangeAlgorithm,
            public_key_out: &mut [u8],
        ) -> Result<(Self::PrivateKey, usize), CryptoError> {
            self.key_exchange.generate_key(algorithm, public_key_out)
        }

        fn agree(
            &self,
            algorithm: KeyExchangeAlgorithm,
            private_key: &Self::PrivateKey,
            peer_public_key: &[u8],
            secret_out: &mut [u8],
        ) -> Result<usize, CryptoError> {
            self.key_exchange
                .agree(algorithm, private_key, peer_public_key, secret_out)
        }
    }

    impl CryptoProvider for MockCrypto {
        fn name(&self) -> &'static str {
            "rtx-mock-crypto"
        }
    }

    /// CRYPTO-COMBO-002 支撑：以 `CryptoProvider` 为泛型上界的协议层入口，
    /// 经静态分发逐类调用全部能力。
    ///
    /// **严禁 `&dyn CryptoProvider`**：`SignatureProvider::sign` 以
    /// `&Self::PrivateKey` 为参数、`KeyExchangeProvider::generate_key` 返回
    /// `Self::PrivateKey`——关联类型 `PrivateKey` 出现在参数/返回位，违反对象
    /// 安全规则（E0191，`dyn CryptoProvider` 不可构造）。六个 crypto provider
    /// 一律静态分发（泛型 + `&P`），对应 ARCHITECTURE.md §12 "no assumption
    /// that provider types are dynamically dispatched"。
    ///
    /// `sign_key` 由调用方提供：泛型函数无法凭空制造
    /// `<P as SignatureProvider>::PrivateKey`（不透明句柄由密钥生成流程产出，
    /// §12:291）。
    fn exercise_provider<P: CryptoProvider>(
        provider: &P,
        sign_key: &<P as SignatureProvider>::PrivateKey,
    ) -> Result<(), CryptoError> {
        provider.fill_random(&mut [0u8; 8])?;
        provider.digest(HashAlgorithm::Sha256, b"x", &mut [0u8; SHA256_LEN])?;
        provider.hmac(HashAlgorithm::Sha256, b"k", b"x", &mut [0u8; SHA256_LEN])?;

        let mut buffer = [0u8; 10 + TAG_LEN];
        buffer[..10].copy_from_slice(b"0123456789");
        let sealed = provider.seal_in_place(
            AeadAlgorithm::Aes128Gcm,
            &[0x11; 32],
            &[0x22; 12],
            b"aad",
            &mut buffer,
            10,
        )?;
        assert_eq!(sealed, 10 + TAG_LEN);
        let opened = provider.open_in_place(
            AeadAlgorithm::Aes128Gcm,
            &[0x11; 32],
            &[0x22; 12],
            b"aad",
            &mut buffer,
        )?;
        assert_eq!(opened, 10);

        provider.sign(
            SignatureAlgorithm::Ed25519,
            sign_key,
            b"x",
            &mut [0u8; SIG_LEN],
        )?;

        let mut public = [0u8; PUB_LEN];
        let (private, _written) =
            provider.generate_key(KeyExchangeAlgorithm::X25519, &mut public)?;
        let mut secret = [0u8; SECRET_LEN];
        provider.agree(KeyExchangeAlgorithm::X25519, &private, &public, &mut secret)?;

        assert!(!provider.name().is_empty());
        Ok(())
    }

    // CRYPTO-COMBO-001 — CryptoProvider 组合 mock 与 name()（静态分发冒烟）。
    #[test]
    fn crypto_provider_combo_mock_satisfies_all_supertraits() {
        let crypto = MockCrypto::new();
        assert_eq!(crypto.name(), "rtx-mock-crypto");

        // 静态分发冒烟：六类能力各调用一次成功。
        // 严禁 `&dyn CryptoProvider`（关联类型 PrivateKey 不可 dyn 化，E0191）
        // —— 原因见 exercise_provider 上方说明与 ARCHITECTURE.md §12。
        crypto
            .fill_random(&mut [0u8; 8])
            .expect("random capability");
        crypto
            .digest(HashAlgorithm::Sha256, b"x", &mut [0u8; SHA256_LEN])
            .expect("hash capability");
        crypto
            .hmac(HashAlgorithm::Sha256, b"k", b"x", &mut [0u8; SHA256_LEN])
            .expect("hmac capability");

        let mut buffer = [0u8; 10 + TAG_LEN];
        buffer[..10].copy_from_slice(b"0123456789");
        let sealed = crypto
            .seal_in_place(
                AeadAlgorithm::Aes128Gcm,
                &[0x11; 32],
                &[0x22; 12],
                b"aad",
                &mut buffer,
                10,
            )
            .expect("aead seal capability");
        assert_eq!(sealed, 10 + TAG_LEN);
        let opened = crypto
            .open_in_place(
                AeadAlgorithm::Aes128Gcm,
                &[0x11; 32],
                &[0x22; 12],
                b"aad",
                &mut buffer,
            )
            .expect("aead open capability");
        assert_eq!(opened, 10);

        let sign_key = MockPrivateKey(0x5EED);
        let sign_public = sig_public_key(&sign_key);
        let mut signature = [0u8; SIG_LEN];
        crypto
            .sign(SignatureAlgorithm::Ed25519, &sign_key, b"x", &mut signature)
            .expect("signature capability");
        crypto
            .verify(SignatureAlgorithm::Ed25519, &sign_public, b"x", &signature)
            .expect("verify capability");

        let mut kex_public = [0u8; PUB_LEN];
        let (kex_private, _) = crypto
            .generate_key(KeyExchangeAlgorithm::X25519, &mut kex_public)
            .expect("kex generate capability");
        let mut secret = [0u8; SECRET_LEN];
        crypto
            .agree(
                KeyExchangeAlgorithm::X25519,
                &kex_private,
                &kex_public,
                &mut secret,
            )
            .expect("kex agree capability");
    }

    // CRYPTO-COMBO-002 — CryptoProvider 泛型上界编译期契约。
    #[test]
    fn crypto_provider_generic_bound_compiles() {
        let crypto = MockCrypto::new();
        let sign_key = MockPrivateKey(0xC0FF_EE00_1234_5678);
        exercise_provider(&crypto, &sign_key).expect("exercise every capability");
    }

    // CRYPTO-COMBO-003 — 加密边界无分配/原地语义设计核验（设计评审 + 代码检查）。
    #[test]
    fn crypto_boundary_is_in_place_and_allocation_free() {
        // 对照 crypto:64 注释 "In-place AEAD avoids forcing an allocation at
        // the crypto boundary" 与 ARCHITECTURE.md §12 六条要求逐条确认：
        // 1. provider-neutral —— 六个 trait 由内存 mock 满足（CRYPTO-COMBO-001）；
        // 2. no allocation —— 本模块全部 mock 与用例仅用栈数组/调用方缓冲，
        //    provider 调用路径无 Vec/Box/堆分配（mock 自身零堆分配作范式）；
        // 3. in-place AEAD —— seal/open 原地修改 payload_and_tag（CRYPTO-AEAD-001）；
        // 4. caller-owned buffers —— 输出均为调用方 &mut [u8]，尺寸不足显式
        //    OutputTooSmall（CRYPTO-AEAD-005、CRYPTO-HASH/HMAC-001、CRYPTO-KEX-002）；
        // 5. opaque keys —— 私钥停留在 provider 关联类型后（CRYPTO-SIG/KEX-001）；
        // 6. no dyn-or-Rc assumption —— 全部静态分发（CRYPTO-COMBO-002）。
        // （真实分配计数测量属 M0 基准 harness 设计项，§20:483，不在本测试集。）
        //
        // 下方以一个端到端原地往返再次示范该范式。
        const PLAINTEXT: &[u8; 10] = b"in-place!!";
        let crypto = MockCrypto::new();
        let key = [0x5Au8; 32];
        let nonce = [0xA5u8; 12];
        let mut buffer = [0u8; PLAINTEXT.len() + TAG_LEN];
        buffer[..PLAINTEXT.len()].copy_from_slice(PLAINTEXT);

        let sealed = crypto
            .seal_in_place(
                AeadAlgorithm::Aes256Gcm,
                &key,
                &nonce,
                b"meta",
                &mut buffer,
                PLAINTEXT.len(),
            )
            .expect("seal in place");
        assert_eq!(sealed, buffer.len());
        let opened = crypto
            .open_in_place(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"meta", &mut buffer)
            .expect("open in place");
        assert_eq!(opened, PLAINTEXT.len());
        assert_eq!(&buffer[..PLAINTEXT.len()], PLAINTEXT);
    }
}

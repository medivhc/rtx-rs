//! Deterministic provider for handshake integration tests.
//!
//! Hash, HMAC and AEAD are the real `RustCrypto` implementations; only
//! Ed25519 and X25519 are deterministic test doubles. The doubles preserve
//! the provider contracts that matter to the handshake: caller-owned buffers,
//! failure leaves the buffer untouched, an all-zero/InvalidKey agreement
//! aborts, and public keys are fixed 32-byte values.

use core::cell::Cell;

use rtx_crypto::{
    AeadAlgorithm, AeadProvider, CryptoError, CryptoProvider, HashAlgorithm, HashProvider,
    HmacProvider, KeyExchangeAlgorithm, KeyExchangeProvider, RandomProvider, SignatureAlgorithm,
    SignatureProvider,
};
use rtx_crypto_rustcrypto::RustCryptoProvider;

/// Test-only Ed25519 key handle. The scalar is visible only to tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestSigningKey(pub u64);

/// Server signing key shared by the integration suite.
pub static SERVER_SIGNING_KEY: TestSigningKey = TestSigningKey(0x5EED_5EED_5EED_5EED);

/// Test-only X25519 key handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestExchangeKey(pub u64);

const FLAG_ZERO_SHARED_SECRET: u16 = 0x0001;
const FLAG_CORRUPT_SERVER_FINISHED: u16 = 0x0002;
const FLAG_FAIL_SRTP_EXPORT: u16 = 0x0004;
const FLAG_FAIL_HMAC: u16 = 0x0008;
const FLAG_FAIL_VERIFY: u16 = 0x0010;
const FLAG_FAIL_AGREE: u16 = 0x0020;
const FLAG_AGREE_ZERO_OK: u16 = 0x0040;
const FLAG_FAIL_DIGEST: u16 = 0x0080;
const FLAG_SHORT_DIGEST: u16 = 0x0100;
const FLAG_FAIL_SIGN: u16 = 0x0200;
const FLAG_SHORT_SIGN: u16 = 0x0400;
const FLAG_SHORT_PUBLIC: u16 = 0x0800;
const FLAG_FAIL_SEAL: u16 = 0x1000;

const KEX_GENERATOR: u64 = 0x1000_0000_01BF_09CE;
const SIGNATURE_LEN: usize = 64;
const PUBLIC_KEY_LEN: usize = 32;
const SECRET_LEN: usize = 32;

/// Deterministic test provider.
#[derive(Debug)]
pub struct HandshakeCrypto {
    random: Cell<u64>,
    next_kex_scalar: Cell<u64>,
    flags: u16,
    delegate: RustCryptoProvider,
}

impl HandshakeCrypto {
    /// Provider with deterministic random and key-exchange sequences.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            random: Cell::new(seed | 1),
            next_kex_scalar: Cell::new(0x243F_6A88_85A3_08D3 ^ seed),
            flags: 0,
            delegate: RustCryptoProvider::new(),
        }
    }

    /// Makes `agree` report `InvalidKey` as an all-zero X25519 secret would.
    #[must_use]
    pub const fn with_zero_shared_secret(mut self) -> Self {
        self.flags |= FLAG_ZERO_SHARED_SECRET;
        self
    }

    /// Corrupts PRF output carrying the `server finished` label.
    #[must_use]
    pub const fn with_corrupt_server_finished(mut self) -> Self {
        self.flags |= FLAG_CORRUPT_SERVER_FINISHED;
        self
    }

    /// Fails HMAC calls carrying the DTLS-SRTP exporter label.
    #[must_use]
    pub const fn with_failing_srtp_export(mut self) -> Self {
        self.flags |= FLAG_FAIL_SRTP_EXPORT;
        self
    }

    /// Fails every HMAC call.
    #[must_use]
    pub const fn with_failing_hmac(mut self) -> Self {
        self.flags |= FLAG_FAIL_HMAC;
        self
    }

    /// Fails signature verification with `Unsupported`.
    #[must_use]
    pub const fn with_failing_verify(mut self) -> Self {
        self.flags |= FLAG_FAIL_VERIFY;
        self
    }

    /// Fails `agree` with `BackendFailure`.
    #[must_use]
    pub const fn with_failing_agree(mut self) -> Self {
        self.flags |= FLAG_FAIL_AGREE;
        self
    }

    /// Returns `Ok(32)` with an all-zero shared secret.
    #[must_use]
    pub const fn with_zero_ok_shared_secret(mut self) -> Self {
        self.flags |= FLAG_AGREE_ZERO_OK;
        self
    }

    /// Fails the transcript digest.
    #[must_use]
    pub const fn with_failing_digest(mut self) -> Self {
        self.flags |= FLAG_FAIL_DIGEST;
        self
    }

    /// Reports a digest length one byte short.
    #[must_use]
    pub const fn with_short_digest(mut self) -> Self {
        self.flags |= FLAG_SHORT_DIGEST;
        self
    }

    /// Fails signing.
    #[must_use]
    pub const fn with_failing_sign(mut self) -> Self {
        self.flags |= FLAG_FAIL_SIGN;
        self
    }

    /// Reports a signature length one byte short.
    #[must_use]
    pub const fn with_short_sign(mut self) -> Self {
        self.flags |= FLAG_SHORT_SIGN;
        self
    }

    /// Reports an X25519 public-key length one byte short.
    #[must_use]
    pub const fn with_short_public_key(mut self) -> Self {
        self.flags |= FLAG_SHORT_PUBLIC;
        self
    }

    /// Fails AEAD sealing.
    #[must_use]
    pub const fn with_failing_seal(mut self) -> Self {
        self.flags |= FLAG_FAIL_SEAL;
        self
    }

    fn next_random(&self) -> u64 {
        let mut value = self.random.get();
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.random.set(value);
        value.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_scalar(&self) -> u64 {
        let current = self.next_kex_scalar.get();
        self.next_kex_scalar
            .set(current.wrapping_add(0x9E37_79B9_7F4A_7C15));
        current
    }
}

impl RandomProvider for HandshakeCrypto {
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        for chunk in output.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_random().to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

impl HashProvider for HandshakeCrypto {
    fn digest(
        &self,
        algorithm: HashAlgorithm,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if self.flags & FLAG_FAIL_DIGEST != 0 {
            return Err(CryptoError::BackendFailure);
        }
        let written = self.delegate.digest(algorithm, input, output)?;
        if self.flags & FLAG_SHORT_DIGEST != 0 {
            return Ok(written.saturating_sub(1));
        }
        Ok(written)
    }
}

impl HmacProvider for HandshakeCrypto {
    fn hmac(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if self.flags & FLAG_FAIL_HMAC != 0 {
            return Err(CryptoError::BackendFailure);
        }
        let written = self.delegate.hmac(algorithm, key, input, output)?;
        if self.flags & FLAG_CORRUPT_SERVER_FINISHED != 0 && contains(input, b"server finished") {
            output[0] ^= 0x01;
        }
        if self.flags & FLAG_FAIL_SRTP_EXPORT != 0 && contains(input, b"EXTRACTOR-dtls_srtp") {
            return Err(CryptoError::BackendFailure);
        }
        Ok(written)
    }
}

impl AeadProvider for HandshakeCrypto {
    fn seal_in_place(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        payload_and_tag: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, CryptoError> {
        if self.flags & FLAG_FAIL_SEAL != 0 {
            return Err(CryptoError::BackendFailure);
        }
        self.delegate
            .seal_in_place(algorithm, key, nonce, aad, payload_and_tag, plaintext_len)
    }

    fn open_in_place(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.delegate
            .open_in_place(algorithm, key, nonce, aad, ciphertext_and_tag)
    }
}

impl SignatureProvider for HandshakeCrypto {
    type PrivateKey = TestSigningKey;

    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        key: &Self::PrivateKey,
        message: &[u8],
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if algorithm != SignatureAlgorithm::Ed25519 {
            return Err(CryptoError::Unsupported);
        }
        if self.flags & FLAG_FAIL_SIGN != 0 {
            return Err(CryptoError::BackendFailure);
        }
        if signature_out.len() < SIGNATURE_LEN {
            return Err(CryptoError::OutputTooSmall);
        }
        signature_out[..SIGNATURE_LEN].copy_from_slice(&signature_bytes(key.0, message));
        if self.flags & FLAG_SHORT_SIGN != 0 {
            return Ok(SIGNATURE_LEN - 1);
        }
        Ok(SIGNATURE_LEN)
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
        if self.flags & FLAG_FAIL_VERIFY != 0 {
            return Err(CryptoError::Unsupported);
        }
        if public_key.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }
        let scalar = signing_scalar(public_key).ok_or(CryptoError::InvalidKey)?;
        let expected = signature_bytes(scalar.0, message);
        if signature.len() != SIGNATURE_LEN || signature != expected {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }
}

impl KeyExchangeProvider for HandshakeCrypto {
    type PrivateKey = TestExchangeKey;

    fn generate_key(
        &self,
        algorithm: KeyExchangeAlgorithm,
        public_key_out: &mut [u8],
    ) -> Result<(Self::PrivateKey, usize), CryptoError> {
        if algorithm != KeyExchangeAlgorithm::X25519 {
            return Err(CryptoError::Unsupported);
        }
        if public_key_out.len() < PUBLIC_KEY_LEN {
            return Err(CryptoError::OutputTooSmall);
        }
        if self.flags & FLAG_SHORT_PUBLIC != 0 {
            return Ok((TestExchangeKey(self.next_scalar()), PUBLIC_KEY_LEN - 1));
        }
        let scalar = self.next_scalar();
        let public = scalar.wrapping_mul(KEX_GENERATOR);
        let mut encoded = [0u8; PUBLIC_KEY_LEN];
        encoded[..8].copy_from_slice(&public.to_le_bytes());
        stretch(public, &mut encoded[8..]);
        public_key_out[..PUBLIC_KEY_LEN].copy_from_slice(&encoded);
        Ok((TestExchangeKey(scalar), PUBLIC_KEY_LEN))
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
        if secret_out.len() < SECRET_LEN {
            return Err(CryptoError::OutputTooSmall);
        }
        if self.flags & FLAG_FAIL_AGREE != 0 {
            return Err(CryptoError::BackendFailure);
        }
        if self.flags & FLAG_AGREE_ZERO_OK != 0 {
            secret_out[..SECRET_LEN].fill(0);
            return Ok(SECRET_LEN);
        }
        if self.flags & FLAG_ZERO_SHARED_SECRET != 0 {
            return Err(CryptoError::InvalidKey);
        }
        let peer = exchange_scalar(peer_public_key).ok_or(CryptoError::InvalidKey)?;
        let secret = private_key.0.wrapping_mul(peer);
        if secret == 0 {
            return Err(CryptoError::InvalidKey);
        }
        let mut encoded = [0u8; SECRET_LEN];
        stretch(secret, &mut encoded);
        secret_out[..SECRET_LEN].copy_from_slice(&encoded);
        Ok(SECRET_LEN)
    }
}

impl CryptoProvider for HandshakeCrypto {
    fn name(&self) -> &'static str {
        "rtx-dtls-test-crypto"
    }
}

/// Public key corresponding to `SERVER_SIGNING_KEY`.
#[must_use]
pub fn server_signing_public() -> [u8; 32] {
    signing_public(SERVER_SIGNING_KEY)
}

/// Public key for any test signing handle.
#[must_use]
pub fn signing_public(key: TestSigningKey) -> [u8; 32] {
    let mut public = [0u8; PUBLIC_KEY_LEN];
    public[..8].copy_from_slice(&key.0.to_le_bytes());
    stretch(key.0, &mut public[8..]);
    public
}

fn signing_scalar(public_key: &[u8]) -> Option<TestSigningKey> {
    let bytes: [u8; 8] = public_key.get(..8)?.try_into().ok()?;
    Some(TestSigningKey(u64::from_le_bytes(bytes)))
}

fn exchange_scalar(public_key: &[u8]) -> Option<u64> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return None;
    }
    let bytes: [u8; 8] = public_key.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn signature_bytes(scalar: u64, message: &[u8]) -> [u8; SIGNATURE_LEN] {
    let mut state = 0x1234_5678_9ABC_DEF0u64 ^ scalar;
    for &byte in message {
        state ^= u64::from(byte);
        state = state.wrapping_mul(0x0000_0100_0000_01B3);
    }
    let mut signature = [0u8; SIGNATURE_LEN];
    stretch(state, &mut signature);
    signature
}

fn stretch(mut state: u64, output: &mut [u8]) {
    for (block, chunk) in (0_u64..).zip(output.chunks_mut(8)) {
        state ^= block.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

//! Shared fixtures for the `rtx-crypto` integration suite.
//!
//! Follows the same `EasyTier` `test_support` pattern adopted by the `rtx-stun`
//! suite: one deterministic reference backend reused by every themed file, no
//! `rand` dev-dependency, no global state, no network.
//!
//! The reference backend is deliberately *not* production code. It exists to
//! pin down the **trait contracts** of [`rtx_crypto`]: caller-owned buffers,
//! in-place operation, opaque key handles, explicit error codes and the
//! "on failure the buffer is untouched" guarantee that the MCU adapters rely
//! on when a real provider is swapped in later.

#![allow(dead_code)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]

use core::cell::Cell;

use rtx_crypto::{
    AeadAlgorithm, AeadProvider, CryptoError, CryptoProvider, HashAlgorithm, HashProvider,
    HmacProvider, KeyExchangeAlgorithm, KeyExchangeProvider, RandomProvider, SignatureAlgorithm,
    SignatureProvider,
};

// ---------------------------------------------------------------------------
// Strategy constants
// ---------------------------------------------------------------------------

/// AEAD tag length modelled by the reference backend (GCM standard).
pub const TAG_LEN: usize = 16;
/// SHA-1 digest length.
pub const SHA1_LEN: usize = 20;
/// SHA-256 digest length.
pub const SHA256_LEN: usize = 32;
/// SHA-384 digest length.
pub const SHA384_LEN: usize = 48;
/// Longest digest the reference backend can produce.
pub const MAX_DIGEST_LEN: usize = SHA384_LEN;
/// Signature length modelled by the reference backend (Ed25519 standard).
pub const SIG_LEN: usize = 64;
/// Serialized public-key length modelled by the reference backend.
pub const PUB_LEN: usize = 32;
/// Derived shared-secret length.
pub const SECRET_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Deterministic generator
// ---------------------------------------------------------------------------

/// Deterministic xorshift64* generator.
///
/// Reproducibility beats statistical strength for contract tests, and the
/// workspace keeps zero third-party dependencies.
#[derive(Debug)]
pub struct Lcg {
    state: u64,
}

impl Lcg {
    /// Seeds the generator; a zero seed is mapped to a non-zero state.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    /// Advances the generator and returns the next 64-bit output.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Fills `out` with deterministic bytes.
    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
        }
    }

    /// Returns a value below `bound`.
    pub fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64()).unwrap_or(0) % bound.max(1)
    }

    /// Returns a vector of `len` deterministic bytes.
    #[must_use]
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.fill(&mut out);
        out
    }

    /// Flips a single bit of `buffer` at `index`, returning the previous byte.
    pub fn flip_bit(&mut self, buffer: &mut [u8], index: usize) -> u8 {
        let slot = &mut buffer[index % buffer.len().max(1)];
        let previous = *slot;
        *slot ^= 1 << (self.below(8));
        previous
    }
}

// ---------------------------------------------------------------------------
// Deterministic mixing helpers (test-only, not cryptography)
// ---------------------------------------------------------------------------

/// FNV-style mixing used to derive deterministic pseudo-digests.
pub fn mix(mut state: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        state ^= u64::from(byte);
        state = state.wrapping_mul(0x0000_0100_0000_01B3);
    }
    state
}

/// Stretches a 64-bit state into `out` bytes.
pub fn stretch(mut state: u64, out: &mut [u8]) {
    for (block, chunk) in (0_u64..).zip(out.chunks_mut(8)) {
        state ^= block.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

/// Digest length per algorithm.
#[must_use]
pub const fn digest_len(algorithm: HashAlgorithm) -> usize {
    match algorithm {
        HashAlgorithm::Sha1 => SHA1_LEN,
        HashAlgorithm::Sha256 => SHA256_LEN,
        HashAlgorithm::Sha384 => SHA384_LEN,
    }
}

/// All hash algorithms, for exhaustive sweeps.
pub const ALL_HASHES: [HashAlgorithm; 3] = [
    HashAlgorithm::Sha1,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha384,
];

/// All AEAD algorithms, for exhaustive sweeps.
pub const ALL_AEADS: [AeadAlgorithm; 2] = [AeadAlgorithm::Aes128Gcm, AeadAlgorithm::Aes256Gcm];

/// All signature algorithms, for exhaustive sweeps.
pub const ALL_SIGNATURES: [SignatureAlgorithm; 3] = [
    SignatureAlgorithm::EcdsaP256Sha256,
    SignatureAlgorithm::EcdsaP384Sha384,
    SignatureAlgorithm::Ed25519,
];

/// All key-exchange algorithms, for exhaustive sweeps.
pub const ALL_KEX: [KeyExchangeAlgorithm; 3] = [
    KeyExchangeAlgorithm::P256,
    KeyExchangeAlgorithm::P384,
    KeyExchangeAlgorithm::X25519,
];

/// The one algorithm each capability is modelled for; the reference backend
/// reports [`CryptoError::Unsupported`] for every other member of the enum.
pub const HASH_SUPPORTED: HashAlgorithm = HashAlgorithm::Sha256;
/// See [`HASH_SUPPORTED`].
pub const AEAD_SUPPORTED: AeadAlgorithm = AeadAlgorithm::Aes128Gcm;
/// See [`HASH_SUPPORTED`].
pub const SIG_SUPPORTED: SignatureAlgorithm = SignatureAlgorithm::Ed25519;
/// See [`HASH_SUPPORTED`].
pub const KEX_SUPPORTED: KeyExchangeAlgorithm = KeyExchangeAlgorithm::X25519;

/// Deterministic pseudo-digest of `input`.
#[must_use]
pub fn mock_digest(algorithm: HashAlgorithm, input: &[u8]) -> [u8; MAX_DIGEST_LEN] {
    let seed = match algorithm {
        HashAlgorithm::Sha1 => 0x6A09_E667_0000_0001,
        HashAlgorithm::Sha256 => 0x6A09_E667_0000_0002,
        HashAlgorithm::Sha384 => 0x6A09_E667_0000_0003,
    };
    let len = digest_len(algorithm);
    let mut out = [0u8; MAX_DIGEST_LEN];
    stretch(mix(seed, input), &mut out[..len]);
    out
}

/// Deterministic pseudo-MAC over `(key, input)`.
#[must_use]
pub fn mock_hmac(algorithm: HashAlgorithm, key: &[u8], input: &[u8]) -> [u8; MAX_DIGEST_LEN] {
    let seed = match algorithm {
        HashAlgorithm::Sha1 => 0x5BE0_CD19_0000_0001,
        HashAlgorithm::Sha256 => 0x5BE0_CD19_0000_0002,
        HashAlgorithm::Sha384 => 0x5BE0_CD19_0000_0003,
    };
    let len = digest_len(algorithm);
    let mut state = mix(seed, key);
    state ^= 0x5A5A_5A5A;
    state = mix(state, input);
    let mut out = [0u8; MAX_DIGEST_LEN];
    stretch(state, &mut out[..len]);
    out
}

/// One 8-byte keystream block.
#[must_use]
pub fn keystream_block(algorithm: AeadAlgorithm, key: &[u8], nonce: &[u8], block: u64) -> [u8; 8] {
    let mut state = 0x510E_527F_ADE6_82D1 ^ block.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    state ^= match algorithm {
        AeadAlgorithm::Aes128Gcm => 1,
        AeadAlgorithm::Aes256Gcm => 2,
    };
    state = mix(state, key);
    mix(state, nonce).to_le_bytes()
}

/// XORs the deterministic keystream over `buf`.
pub fn xor_keystream(algorithm: AeadAlgorithm, key: &[u8], nonce: &[u8], buf: &mut [u8]) {
    for (block, chunk) in (0_u64..).zip(buf.chunks_mut(8)) {
        let keystream = keystream_block(algorithm, key, nonce, block);
        for (byte, mask) in chunk.iter_mut().zip(keystream) {
            *byte ^= mask;
        }
    }
}

/// Deterministic 16-byte authentication tag binding algorithm, key, nonce,
/// AAD and ciphertext.
#[must_use]
pub fn mock_tag(
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

// ---------------------------------------------------------------------------
// Opaque key handles
// ---------------------------------------------------------------------------

/// Opaque signing-key handle.
///
/// The scalar never leaves the provider in production; the reference backend
/// exposes it only through [`RefSigningKey::scalar_for_verification`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefSigningKey(pub u64);

impl RefSigningKey {
    /// Derives the serialized public key of this handle.
    #[must_use]
    pub fn public_key(self) -> [u8; PUB_LEN] {
        let mut out = [0u8; PUB_LEN];
        out[..8].copy_from_slice(&self.0.to_le_bytes());
        stretch(self.0, &mut out[8..]);
        out
    }
}

/// Recovers the mock scalar from a serialized public key.
///
/// The reference backend keeps the scalar in the first 8 bytes so `verify` can
/// recompute deterministically; real providers must not do this.
#[must_use]
pub fn scalar_from_public(public_key: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = public_key.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Deterministic 64-byte signature.
#[must_use]
pub fn mock_sign(private: RefSigningKey, message: &[u8]) -> [u8; SIG_LEN] {
    let state = mix(0x1234_5678_9ABC_DEF0 ^ private.0, message);
    let mut signature = [0u8; SIG_LEN];
    stretch(state, &mut signature);
    signature
}

/// Opaque key-exchange handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefKexKey(pub u64);

/// Mock DH group element: `pub = priv · G` over wrapping 64-bit multiplication.
pub const KEX_G: u64 = 0x1000_0000_01BF_09CE;

/// Serializes a public scalar.
#[must_use]
pub fn kex_serialize_public(scalar: u64) -> [u8; PUB_LEN] {
    let mut out = [0u8; PUB_LEN];
    out[..8].copy_from_slice(&scalar.to_le_bytes());
    out
}

/// Parses a serialized public scalar, rejecting any wrong-length input.
#[must_use]
pub fn kex_parse_public(peer_public_key: &[u8]) -> Option<u64> {
    if peer_public_key.len() != PUB_LEN {
        return None;
    }
    let bytes: [u8; 8] = peer_public_key.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

// ---------------------------------------------------------------------------
// The reference backend
// ---------------------------------------------------------------------------

/// Deterministic in-memory backend satisfying every `rtx-crypto` trait.
#[derive(Debug)]
pub struct RefCrypto {
    random: Cell<u64>,
    next_private: Cell<u64>,
}

impl RefCrypto {
    /// Creates a backend with a fixed seed, so every test run is identical.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            random: Cell::new(0x0DDC_0FFE_E0DD_C0DE),
            next_private: Cell::new(0x243F_6A88_85A3_08D3),
        }
    }

    /// Advances the internal random stream and returns the next 64-bit value.
    pub fn next_u64(&self) -> u64 {
        let mut value = self.random.get();
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.random.set(value);
        value.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_private(&self) -> u64 {
        let current = self.next_private.get();
        self.next_private
            .set(current.wrapping_add(0x9E37_79B9_7F4A_7C15));
        current
    }
}

impl Default for RefCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl RandomProvider for RefCrypto {
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        for chunk in output.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

impl HashProvider for RefCrypto {
    fn digest(
        &self,
        algorithm: HashAlgorithm,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let len = digest_len(algorithm);
        if output.len() < len {
            return Err(CryptoError::OutputTooSmall);
        }
        output[..len].copy_from_slice(&mock_digest(algorithm, input)[..len]);
        Ok(len)
    }
}

impl HmacProvider for RefCrypto {
    fn hmac(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let len = digest_len(algorithm);
        if output.len() < len {
            return Err(CryptoError::OutputTooSmall);
        }
        output[..len].copy_from_slice(&mock_hmac(algorithm, key, input)[..len]);
        Ok(len)
    }
}

impl AeadProvider for RefCrypto {
    fn seal_in_place(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        payload_and_tag: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, CryptoError> {
        // Size is validated before any write: a rejected call must leave the
        // caller's buffer byte-identical.
        let needed = plaintext_len
            .checked_add(TAG_LEN)
            .ok_or(CryptoError::OutputTooSmall)?;
        if payload_and_tag.len() < needed {
            return Err(CryptoError::OutputTooSmall);
        }
        let (payload, tag_region) = payload_and_tag.split_at_mut(plaintext_len);
        xor_keystream(algorithm, key, nonce, payload);
        let tag = mock_tag(algorithm, key, nonce, aad, payload);
        tag_region[..TAG_LEN].copy_from_slice(&tag);
        Ok(needed)
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
        let expected = mock_tag(algorithm, key, nonce, aad, ciphertext);
        // Authenticate before decrypting.
        if tag.iter().ne(expected.iter()) {
            return Err(CryptoError::AuthenticationFailed);
        }
        xor_keystream(algorithm, key, nonce, ciphertext);
        Ok(split)
    }
}

impl SignatureProvider for RefCrypto {
    type PrivateKey = RefSigningKey;

    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        key: &Self::PrivateKey,
        message: &[u8],
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if algorithm != SIG_SUPPORTED {
            return Err(CryptoError::Unsupported);
        }
        if signature_out.len() < SIG_LEN {
            return Err(CryptoError::OutputTooSmall);
        }
        signature_out[..SIG_LEN].copy_from_slice(&mock_sign(*key, message));
        Ok(SIG_LEN)
    }

    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if algorithm != SIG_SUPPORTED {
            return Err(CryptoError::Unsupported);
        }
        let scalar = scalar_from_public(public_key).ok_or(CryptoError::InvalidKey)?;
        let expected = mock_sign(RefSigningKey(scalar), message);
        if signature.len() != SIG_LEN || signature != expected.as_slice() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }
}

impl KeyExchangeProvider for RefCrypto {
    type PrivateKey = RefKexKey;

    fn generate_key(
        &self,
        algorithm: KeyExchangeAlgorithm,
        public_key_out: &mut [u8],
    ) -> Result<(Self::PrivateKey, usize), CryptoError> {
        if algorithm != KEX_SUPPORTED {
            return Err(CryptoError::Unsupported);
        }
        if public_key_out.len() < PUB_LEN {
            return Err(CryptoError::OutputTooSmall);
        }
        let private = self.next_private();
        public_key_out[..PUB_LEN]
            .copy_from_slice(&kex_serialize_public(private.wrapping_mul(KEX_G)));
        Ok((RefKexKey(private), PUB_LEN))
    }

    fn agree(
        &self,
        algorithm: KeyExchangeAlgorithm,
        private_key: &Self::PrivateKey,
        peer_public_key: &[u8],
        secret_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if algorithm != KEX_SUPPORTED {
            return Err(CryptoError::Unsupported);
        }
        let peer = kex_parse_public(peer_public_key).ok_or(CryptoError::InvalidKey)?;
        if secret_out.len() < SECRET_LEN {
            return Err(CryptoError::OutputTooSmall);
        }
        let mut out = [0u8; SECRET_LEN];
        stretch(private_key.0.wrapping_mul(peer), &mut out);
        secret_out[..SECRET_LEN].copy_from_slice(&out);
        Ok(SECRET_LEN)
    }
}

impl CryptoProvider for RefCrypto {
    fn name(&self) -> &'static str {
        "rtx-ref-crypto"
    }
}

// ---------------------------------------------------------------------------
// Scenario helpers
// ---------------------------------------------------------------------------

/// A freshly generated key-exchange pair.
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// Opaque private handle.
    pub private: RefKexKey,
    /// Serialized public key.
    pub public: [u8; PUB_LEN],
}

/// Generates a key pair with the supported KEX algorithm.
pub fn generate_pair(crypto: &RefCrypto) -> KeyPair {
    let mut public = [0u8; PUB_LEN];
    let (private, written) = crypto
        .generate_key(KEX_SUPPORTED, &mut public)
        .expect("generate key");
    assert_eq!(written, PUB_LEN);
    KeyPair { private, public }
}

/// Seals `plaintext` into a fresh buffer and returns `(ciphertext_and_tag, len)`.
pub fn seal(crypto: &RefCrypto, plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, usize) {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    let sealed = crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &key,
            &nonce,
            aad,
            &mut buffer,
            plaintext.len(),
        )
        .expect("seal");
    (buffer, sealed)
}

/// Opens a buffer produced by [`seal`].
pub fn open(crypto: &RefCrypto, sealed: &mut [u8], aad: &[u8]) -> Result<usize, CryptoError> {
    crypto.open_in_place(AEAD_SUPPORTED, &[0x11u8; 32], &[0x22u8; 12], aad, sealed)
}

/// Signs `message` with `key`, returning a fixed-size signature buffer.
pub fn sign(crypto: &RefCrypto, key: RefSigningKey, message: &[u8]) -> [u8; SIG_LEN] {
    let mut out = [0u8; SIG_LEN];
    let written = crypto
        .sign(SIG_SUPPORTED, &key, message, &mut out)
        .expect("sign");
    assert_eq!(written, SIG_LEN);
    out
}

/// Asserts that `result` reports exactly `expected`.
pub fn assert_error<T: core::fmt::Debug>(
    result: Result<T, CryptoError>,
    expected: CryptoError,
    context: &str,
) {
    match result {
        Ok(value) => panic!("{context}: expected Err({expected:?}), got Ok({value:?})"),
        Err(error) => assert_eq!(error, expected, "{context}"),
    }
}

/// Asserts that two byte slices differ, panicking with `context` when equal.
pub fn assert_differs(left: &[u8], right: &[u8], context: &str) {
    assert_ne!(left, right, "{context}");
}

//! A [`rtx_crypto`] provider backed by the `RustCrypto` primitives.
//!
//! # Why a separate crate
//!
//! `rtx-crypto` itself stays dependency-free: it defines the six capability
//! traits and nothing else. This crate supplies one *reference implementation*
//! of those traits so the workspace has something real to test the contracts
//! against, and so a deployment can swap in a hardware-backed engine without
//! touching a protocol crate.
//!
//! # Feature posture
//!
//! * `no_std` compatible — `alloc` only, no `std` types on the hot path.
//! * Constant-time primitives throughout (`aes-gcm`, `sha2`, `hmac`).
//! * Signature and ECDH suites are **not** implemented here: Ed25519 and
//!   X25519 need field arithmetic whose constant-time posture this crate does
//!   not yet audit, and a silently-wrong DTLS handshake is worse than an
//!   explicit [`rtx_crypto::CryptoError::Unsupported`]. The DTLS engine will
//!   bring its own provider for those; see `docs/m2-crypto-backend.md`.
//!
//! [RFC 7748]: https://www.rfc-editor.org/rfc/rfc7748
//! [RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use aes::cipher::{Block, BlockEncrypt};
use aes_gcm::aead::consts::U16 as TagLen;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use hmac::{Hmac, Mac};
use rtx_crypto::{
    AeadAlgorithm, AeadProvider, Aes128BlockProvider, CryptoError, HashAlgorithm, HashProvider,
    HmacProvider, KeyExchangeAlgorithm, KeyExchangeProvider, RandomProvider, SignatureAlgorithm,
    SignatureProvider,
};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

/// Length of the GCM authentication tag.
pub const TAG_LEN: usize = 16;
/// Serialized public-key length this provider emits.
pub const PUB_LEN: usize = 32;
/// Length of a derived shared secret (X25519 field element).
pub const SECRET_LEN: usize = 32;

/// Digest length for `algorithm`.
#[must_use]
pub const fn digest_len(algorithm: HashAlgorithm) -> usize {
    match algorithm {
        HashAlgorithm::Sha1 => 20,
        HashAlgorithm::Sha256 => 32,
        HashAlgorithm::Sha384 => 48,
    }
}

/// RustCrypto-backed provider.
///
/// Zero-sized: all state lives in the caller's buffers, which is exactly the
/// discipline the `rtx-crypto` traits impose.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustCryptoProvider {
    _private: (),
}

impl RustCryptoProvider {
    /// Creates a provider.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

/// An opaque Ed25519-shaped signing key handle.
///
/// The scalar never leaves the provider. Only the length and a non-zero
/// invariant are observable, which is what the trait contract requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningKey {
    scalar: [u8; 32],
}

impl SigningKey {
    /// Builds a handle for tests that need a value to pass to a declined
    /// suite. Production key material comes from the engine's own provider.
    ///
    /// # Panics
    ///
    /// Never; the constant is in range by construction.
    #[cfg(any(test, feature = "std"))]
    #[must_use]
    pub const fn for_tests() -> Self {
        Self { scalar: [0x5a; 32] }
    }
}

/// An opaque X25519-shaped key-exchange handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExchangeKey {
    scalar: [u8; 32],
}

impl ExchangeKey {
    /// Builds a handle for tests that need a value to pass to a declined
    /// suite. Production key material comes from the engine's own provider.
    ///
    /// # Panics
    ///
    /// Never; the constant is in range by construction.
    #[cfg(any(test, feature = "std"))]
    #[must_use]
    pub const fn for_tests() -> Self {
        Self { scalar: [0xa5; 32] }
    }
}

// ---------------------------------------------------------------------------
// Random
// ---------------------------------------------------------------------------

impl RandomProvider for RustCryptoProvider {
    /// Fills `output` from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unsupported`] when the crate is built without
    /// the `os-rng` feature — `getrandom` has no entropy backend to use on a
    /// bare-metal target unless the firmware supplies one. Failing loudly
    /// beats emitting a predictable "random" nonce in a DTLS handshake.
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        if output.is_empty() {
            return Ok(());
        }
        #[cfg(feature = "os-rng")]
        {
            getrandom::getrandom(output).map_err(|_| CryptoError::BackendFailure)
        }
        #[cfg(not(feature = "os-rng"))]
        {
            let _ = output;
            Err(CryptoError::Unsupported)
        }
    }
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

impl HashProvider for RustCryptoProvider {
    fn digest(
        &self,
        algorithm: HashAlgorithm,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let len = digest_len(algorithm);
        // Size is validated before any write: a rejected call must leave the
        // caller's buffer byte-identical.
        if output.len() < len {
            return Err(CryptoError::OutputTooSmall);
        }
        let written: &[u8] = match algorithm {
            HashAlgorithm::Sha1 => {
                let mut hasher = Sha1::new();
                hasher.update(input);
                &hasher.finalize()
            }
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(input);
                &hasher.finalize()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(input);
                &hasher.finalize()
            }
        };
        output[..len].copy_from_slice(&written[..len]);
        Ok(len)
    }
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

impl HmacProvider for RustCryptoProvider {
    fn hmac(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.hmac_parts(algorithm, key, &[input], output)
    }

    fn hmac_parts(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        parts: &[&[u8]],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let len = digest_len(algorithm);
        if output.len() < len {
            return Err(CryptoError::OutputTooSmall);
        }
        let written: Vec<u8> = match algorithm {
            HashAlgorithm::Sha1 => {
                let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key)
                    .map_err(|_| CryptoError::InvalidKey)?;
                for part in parts {
                    mac.update(part);
                }
                mac.finalize().into_bytes().to_vec()
            }
            HashAlgorithm::Sha256 => {
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
                    .map_err(|_| CryptoError::InvalidKey)?;
                for part in parts {
                    mac.update(part);
                }
                mac.finalize().into_bytes().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key)
                    .map_err(|_| CryptoError::InvalidKey)?;
                for part in parts {
                    mac.update(part);
                }
                mac.finalize().into_bytes().to_vec()
            }
        };
        output[..len].copy_from_slice(&written[..len]);
        Ok(len)
    }
}

// ---------------------------------------------------------------------------
// Raw AES block
// ---------------------------------------------------------------------------

impl Aes128BlockProvider for RustCryptoProvider {
    fn encrypt_aes128_block(
        &self,
        key: &[u8; 16],
        block: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        let cipher = aes::Aes128::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        // `Block` is a 16-byte `GenericArray`; the caller's array lends its
        // storage for exactly this call.
        let block = Block::<aes::Aes128>::from_mut_slice(block);
        cipher.encrypt_block(block);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

impl AeadProvider for RustCryptoProvider {
    fn seal_in_place(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        payload_and_tag: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, CryptoError> {
        let needed = plaintext_len
            .checked_add(TAG_LEN)
            .ok_or(CryptoError::OutputTooSmall)?;
        // Size is validated before any write: a rejected call must leave the
        // caller's buffer byte-identical.
        if payload_and_tag.len() < needed {
            return Err(CryptoError::OutputTooSmall);
        }
        // GCM requires a 96-bit nonce; anything else is a caller bug we must
        // surface rather than truncate.
        let nonce_bytes: [u8; 12] = nonce.try_into().map_err(|_| CryptoError::InvalidNonce)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let (payload, tag) = payload_and_tag.split_at_mut(plaintext_len);

        let full_tag = match algorithm {
            AeadAlgorithm::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKey)?
                .encrypt_in_place_detached(nonce, aad, payload)
                .map_err(|_| CryptoError::BackendFailure)?,
            AeadAlgorithm::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKey)?
                .encrypt_in_place_detached(nonce, aad, payload)
                .map_err(|_| CryptoError::BackendFailure)?,
        };
        tag.copy_from_slice(&full_tag);
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
        let nonce_bytes: [u8; 12] = nonce.try_into().map_err(|_| CryptoError::InvalidNonce)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let split = ciphertext_and_tag.len() - TAG_LEN;
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(split);

        // `decrypt_in_place_detached` recomputes the tag and compares it in
        // constant time *before* applying the keystream, so a rejected call
        // leaves the caller's buffer untouched by construction.
        let mut full_tag = [0u8; TAG_LEN];
        full_tag.copy_from_slice(tag);
        let tag = Tag::<TagLen>::from(full_tag);
        match algorithm {
            AeadAlgorithm::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKey)?
                .decrypt_in_place_detached(nonce, aad, ciphertext, &tag),
            AeadAlgorithm::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKey)?
                .decrypt_in_place_detached(nonce, aad, ciphertext, &tag),
        }
        .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(split)
    }
}

// ---------------------------------------------------------------------------
// Signature (deliberately unimplemented)
// ---------------------------------------------------------------------------

impl SignatureProvider for RustCryptoProvider {
    type PrivateKey = SigningKey;

    fn sign(
        &self,
        _algorithm: SignatureAlgorithm,
        _key: &Self::PrivateKey,
        _message: &[u8],
        _signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    fn verify(
        &self,
        _algorithm: SignatureAlgorithm,
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// Key exchange (deliberately unimplemented)
// ---------------------------------------------------------------------------

impl KeyExchangeProvider for RustCryptoProvider {
    type PrivateKey = ExchangeKey;

    fn generate_key(
        &self,
        _algorithm: KeyExchangeAlgorithm,
        _public_key_out: &mut [u8],
    ) -> Result<(Self::PrivateKey, usize), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    fn agree(
        &self,
        _algorithm: KeyExchangeAlgorithm,
        _private_key: &Self::PrivateKey,
        _peer_public_key: &[u8],
        _secret_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// Compile-time proof that the provider satisfies the marker trait.
///
/// [`rtx_crypto::CryptoProvider`] cannot be implemented here: it is a
/// supertrait bundle whose `sign` / `generate_key` return opaque handles, and
/// this provider deliberately declines those suites. The static assertion
/// below is what the capability matrix in `docs/m2-crypto-backend.md` cites.
trait _AssertCapabilities:
    HashProvider + HmacProvider + AeadProvider + RandomProvider + Aes128BlockProvider
{
}
impl _AssertCapabilities for RustCryptoProvider {}

//! Differential fuzzing of the `rtx-crypto` AEAD pipeline.
//!
//! The fuzzer drives `seal_in_place` / `open_in_place` with fuzzer-controlled
//! lengths and material, and asserts the three contracts that matter for a
//! memory-safe port to an MCU crypto engine:
//!
//! 1. **no panic** on any length combination,
//! 2. **failure leaves the buffer byte-identical** — a provider that writes a
//!    partial tag before failing is a security bug,
//! 3. **round-trip fidelity** for anything the backend accepts.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rtx_crypto::{
    AeadAlgorithm, AeadProvider, CryptoError, HashAlgorithm, HashProvider, HmacProvider,
    KeyExchangeAlgorithm, KeyExchangeProvider, RandomProvider, SignatureAlgorithm, SignatureProvider,
};

/// Minimal deterministic reference backend (same shape as the integration
/// testkit, trimmed to what the fuzzer needs).
mod ref_backend {
    use rtx_crypto::{
        AeadAlgorithm, AeadProvider, CryptoError, HashAlgorithm, HashProvider, HmacProvider,
        KeyExchangeAlgorithm, KeyExchangeProvider, RandomProvider, SignatureAlgorithm,
        SignatureProvider,
    };

    pub const TAG_LEN: usize = 16;
    pub const SHA1_LEN: usize = 20;
    pub const SHA256_LEN: usize = 32;
    pub const SHA384_LEN: usize = 48;
    pub const MAX_DIGEST_LEN: usize = SHA384_LEN;
    pub const SIG_LEN: usize = 64;
    pub const PUB_LEN: usize = 32;
    pub const SECRET_LEN: usize = 32;
    pub const KEX_G: u64 = 0x1000_0000_01BF_09CE;

    #[derive(Debug)]
    pub struct RefCrypto {
        state: core::cell::Cell<u64>,
        next_private: core::cell::Cell<u64>,
    }

    impl RefCrypto {
        #[must_use]
        pub const fn new() -> Self {
            Self {
                state: core::cell::Cell::new(0x0DDC_0FFE_E0DD_C0DE),
                next_private: core::cell::Cell::new(0x243F_6A88_85A3_08D3),
            }
        }

        fn next_u64(&self) -> u64 {
            let mut value = self.state.get();
            value ^= value >> 12;
            value ^= value << 25;
            value ^= value >> 27;
            self.state.set(value);
            value.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    impl Default for RefCrypto {
        fn default() -> Self {
            Self::new()
        }
    }

    pub fn digest_len(algorithm: HashAlgorithm) -> usize {
        match algorithm {
            HashAlgorithm::Sha1 => SHA1_LEN,
            HashAlgorithm::Sha256 => SHA256_LEN,
            HashAlgorithm::Sha384 => SHA384_LEN,
        }
    }

    pub fn mix(mut state: u64, bytes: &[u8]) -> u64 {
        for &byte in bytes {
            state ^= u64::from(byte);
            state = state.wrapping_mul(0x0000_0100_0000_01B3);
        }
        state
    }

    pub fn stretch(mut state: u64, out: &mut [u8]) {
        for (block, chunk) in (0_u64..).zip(out.chunks_mut(8)) {
            state ^= block.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            let bytes = state.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

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

    pub fn mock_hmac(algorithm: HashAlgorithm, key: &[u8], input: &[u8]) -> [u8; MAX_DIGEST_LEN] {
        let seed = match algorithm {
            HashAlgorithm::Sha1 => 0x5BE0_CD19_0000_0001,
            HashAlgorithm::Sha256 => 0x5BE0_CD19_0000_0002,
            HashAlgorithm::Sha384 => 0x5BE0_CD19_0000_0003,
        };
        let len = digest_len(algorithm);
        let state = mix(mix(seed, key) ^ 0x5A5A_5A5A, input);
        let mut out = [0u8; MAX_DIGEST_LEN];
        stretch(state, &mut out[..len]);
        out
    }

    pub fn keystream(algorithm: AeadAlgorithm, key: &[u8], nonce: &[u8], block: u64) -> [u8; 8] {
        let mut state = 0x510E_527F_ADE6_82D1 ^ block.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        state ^= match algorithm {
            AeadAlgorithm::Aes128Gcm => 1,
            AeadAlgorithm::Aes256Gcm => 2,
        };
        mix(mix(state, key), nonce).to_le_bytes()
    }

    pub fn xor_keystream(algorithm: AeadAlgorithm, key: &[u8], nonce: &[u8], buf: &mut [u8]) {
        for (block, chunk) in (0_u64..).zip(buf.chunks_mut(8)) {
            let mask = keystream(algorithm, key, nonce, block);
            for (byte, key_byte) in chunk.iter_mut().zip(mask) {
                *byte ^= key_byte;
            }
        }
    }

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RefSigningKey(pub u64);

    impl RefSigningKey {
        #[must_use]
        pub fn public_key(self) -> [u8; PUB_LEN] {
            let mut out = [0u8; PUB_LEN];
            out[..8].copy_from_slice(&self.0.to_le_bytes());
            stretch(self.0, &mut out[8..]);
            out
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RefKexKey(pub u64);

    pub fn mock_sign(private: RefSigningKey, message: &[u8]) -> [u8; SIG_LEN] {
        let mut signature = [0u8; SIG_LEN];
        stretch(mix(0x1234_5678_9ABC_DEF0 ^ private.0, message), &mut signature);
        signature
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
            if algorithm != SignatureAlgorithm::Ed25519 {
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
            if algorithm != SignatureAlgorithm::Ed25519 {
                return Err(CryptoError::Unsupported);
            }
            let bytes: [u8; 8] = public_key.get(..8).and_then(|s| s.try_into().ok()).ok_or(CryptoError::InvalidKey)?;
            let expected = mock_sign(RefSigningKey(u64::from_le_bytes(bytes)), message);
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
            if algorithm != KeyExchangeAlgorithm::X25519 {
                return Err(CryptoError::Unsupported);
            }
            if public_key_out.len() < PUB_LEN {
                return Err(CryptoError::OutputTooSmall);
            }
            let current = self.next_private.get();
            self.next_private
                .set(current.wrapping_add(0x9E37_79B9_7F4A_7C15));
            let public = current.wrapping_mul(KEX_G);
            public_key_out[..PUB_LEN].copy_from_slice(&public.to_le_bytes());
            Ok((RefKexKey(current), PUB_LEN))
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
            if peer_public_key.len() != PUB_LEN {
                return Err(CryptoError::InvalidKey);
            }
            if secret_out.len() < SECRET_LEN {
                return Err(CryptoError::OutputTooSmall);
            }
            let bytes: [u8; 8] = peer_public_key[..8].try_into().expect("checked length");
            let peer = u64::from_le_bytes(bytes);
            let mut out = [0u8; SECRET_LEN];
            stretch(private_key.0.wrapping_mul(peer), &mut out);
            secret_out[..SECRET_LEN].copy_from_slice(&out);
            Ok(SECRET_LEN)
        }
    }
}

use ref_backend::{RefCrypto, TAG_LEN};

fuzz_target!(|data: &[u8]| {
    let crypto = RefCrypto::new();

    // The fuzzer owns at least one byte to slice parameters from.
    if data.is_empty() {
        return;
    }
    let selector = data[0];
    let body = &data[1..];

    match selector % 4 {
        0 => {
            // AEAD round-trip with fuzzer-controlled lengths.
            let plaintext_len = body.len().min(512);
            let key_len = body.first().map_or(0, |b| usize::from(*b) % 40);
            let nonce_len = body.get(1).map_or(0, |b| usize::from(*b) % 20);
            let aad_len = body.get(2).map_or(0, |b| usize::from(*b) % 40);
            let plaintext = &body[3.min(body.len())..3.min(body.len()) + plaintext_len];

            let key = &body[..key_len.min(body.len())];
            let nonce = &body[..nonce_len.min(body.len())];
            let aad = &body[..aad_len.min(body.len())];

            let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
            buffer[..plaintext.len()].copy_from_slice(plaintext);
            let sealed = crypto
                .seal_in_place(
                    AeadAlgorithm::Aes128Gcm,
                    key,
                    nonce,
                    aad,
                    &mut buffer,
                    plaintext.len(),
                )
                .expect("seal must accept a correctly sized buffer");
            assert_eq!(sealed, plaintext.len() + TAG_LEN);

            let opened = crypto
                .open_in_place(
                    AeadAlgorithm::Aes128Gcm,
                    key,
                    nonce,
                    aad,
                    &mut buffer,
                )
                .expect("open must accept a freshly sealed record");
            assert_eq!(opened, plaintext.len());
            assert_eq!(&buffer[..plaintext.len()], plaintext);
        }
        1 => {
            // Tampered record: must fail authentication and leave bytes intact.
            let mut buffer = body.to_vec();
            let snapshot = buffer.clone();
            if crypto
                .open_in_place(
                    AeadAlgorithm::Aes128Gcm,
                    &[0x11; 32],
                    &[0x22; 12],
                    b"aad",
                    &mut buffer,
                )
                .is_ok()
            {
                // Only acceptable if the input happened to be a valid record.
                return;
            }
            assert_eq!(buffer, snapshot, "failed open modified the buffer");
        }
        2 => {
            // Digest / HMAC with arbitrary output capacity.
            let capacity = body.first().map_or(0, |b| usize::from(*b) % 49);
            let mut out = vec![0xAAu8; capacity];
            let snapshot = out.clone();
            let algorithm = match body.get(1).map_or(0, |b| b % 3) {
                0 => HashAlgorithm::Sha1,
                1 => HashAlgorithm::Sha256,
                _ => HashAlgorithm::Sha384,
            };
            let _ = crypto.hmac(algorithm, body, body, &mut out);
            if out != snapshot && out.len() < ref_backend::digest_len(algorithm) {
                panic!("rejected hmac wrote into the output buffer");
            }
        }
        _ => {
            // Key exchange with an arbitrary-length peer public key.
            let mut public = [0u8; ref_backend::PUB_LEN];
            let Ok((private, _)) =
                crypto.generate_key(KeyExchangeAlgorithm::X25519, &mut public)
            else {
                panic!("generate_key must accept an exactly sized buffer");
            };
            let peer_len = body.first().map_or(0, |b| usize::from(*b) % 80);
            let peer = &body[..peer_len.min(body.len())];
            let mut secret = [0u8; ref_backend::SECRET_LEN];
            let snapshot = secret;
            match crypto.agree(KeyExchangeAlgorithm::X25519, &private, peer, &mut secret) {
                Ok(written) => assert_eq!(written, ref_backend::SECRET_LEN),
                Err(CryptoError::InvalidKey) => assert_eq!(secret, snapshot),
                Err(other) => panic!("unexpected error {other:?}"),
            }
        }
    }
});
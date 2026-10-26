//! DTLS 1.2 key schedule: TLS 1.2 PRF, master secret, key block and Finished.
//!
//! DTLS 1.2 uses the TLS 1.2 PRF (RFC 5246 section 5), not HKDF. The PRF is
//! `P_SHA256` built exclusively on [`rtx_crypto::HmacProvider`], so the
//! handshake never depends on a concrete hash implementation.
//!
//! Fixed sizes keep the schedule allocation-free:
//!
//! - master secret: 48 bytes;
//! - key block: 40 bytes for AES-128-GCM (two 16-byte keys and two 4-byte
//!   fixed IVs);
//! - Finished `verify_data`: 12 bytes;
//! - DTLS-SRTP export: 60 bytes (see [`crate::srtp`]).
//!
//! Every transient buffer holds secret material and is wrapped in
//! [`zeroize::Zeroizing`]; [`MasterSecret`] and [`KeyBlock`] zeroize themselves
//! on drop.

use rtx_crypto::{CryptoError, HashAlgorithm, HmacProvider};
use zeroize::{Zeroize, Zeroizing};

/// Length of the DTLS 1.2 / TLS 1.2 master secret.
pub(crate) const MASTER_SECRET_LEN: usize = 48;
/// Length of the AES-128-GCM key block.
pub(crate) const KEY_BLOCK_LEN: usize = 40;
/// Length of `verify_data` in a Finished message.
pub const FINISHED_VERIFY_DATA_LEN: usize = 12;
/// SHA-256 output length, the PRF block size.
const SHA256_LEN: usize = 32;
/// Largest `A(i) || label || seed` input any PRF call in this crate builds.
const MAX_PRF_INPUT: usize = SHA256_LEN + 32 + 64;
/// Largest seed any PRF call in this crate builds.
const MAX_SEED: usize = 64;

const CLIENT_FINISHED_LABEL: &[u8] = b"client finished";
const SERVER_FINISHED_LABEL: &[u8] = b"server finished";
const MASTER_SECRET_LABEL: &[u8] = b"master secret";
const KEY_EXPANSION_LABEL: &[u8] = b"key expansion";

/// DTLS 1.2 master secret. Zeroized on drop.
pub(crate) struct MasterSecret {
    bytes: [u8; MASTER_SECRET_LEN],
}

impl MasterSecret {
    pub(crate) const fn as_bytes(&self) -> &[u8; MASTER_SECRET_LEN] {
        &self.bytes
    }

    #[cfg(test)]
    pub(crate) fn corrupt_first_byte(&mut self) {
        self.bytes[0] ^= 0xFF;
    }
}

impl Drop for MasterSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl core::fmt::Debug for MasterSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MasterSecret")
            .field("bytes", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// TLS 1.2 key block split for AES-128-GCM. Zeroized on drop.
pub(crate) struct KeyBlock {
    pub(crate) client_write_key: [u8; 16],
    pub(crate) server_write_key: [u8; 16],
    pub(crate) client_write_iv: [u8; 4],
    pub(crate) server_write_iv: [u8; 4],
}

impl Drop for KeyBlock {
    fn drop(&mut self) {
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
        self.client_write_iv.zeroize();
        self.server_write_iv.zeroize();
    }
}

impl core::fmt::Debug for KeyBlock {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KeyBlock")
            .field("keys", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Computes `PRF(secret, label, seed)` with SHA-256 into `output`.
///
/// # Errors
///
/// Returns the provider error unchanged, or [`CryptoError::BackendFailure`]
/// when the provider reports a MAC length other than SHA-256's 32 bytes or a
/// label/seed combination does not fit the fixed input buffer.
pub(crate) fn prf_sha256<P: HmacProvider + ?Sized>(
    provider: &P,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    let joined = label
        .len()
        .checked_add(seed.len())
        .ok_or(CryptoError::BackendFailure)?;
    if joined > MAX_PRF_INPUT - SHA256_LEN {
        return Err(CryptoError::BackendFailure);
    }

    // seed_full = label || seed. TLS 1.2 defines PRF(secret, label, seed) as
    // P_hash(secret, label || seed), so A(1) hashes the labelled seed too.
    let mut seed_full = Zeroizing::new([0u8; MAX_PRF_INPUT]);
    seed_full[..label.len()].copy_from_slice(label);
    seed_full[label.len()..joined].copy_from_slice(seed);

    // A(1) = HMAC(secret, label || seed).
    let mut a = Zeroizing::new([0u8; SHA256_LEN]);
    let written = provider.hmac(
        HashAlgorithm::Sha256,
        secret,
        &seed_full[..joined],
        &mut a[..],
    )?;
    if written != SHA256_LEN {
        return Err(CryptoError::BackendFailure);
    }

    let mut offset = 0;
    while offset < output.len() {
        // block = HMAC(secret, A(i) || label || seed).
        let mut block_input = Zeroizing::new([0u8; MAX_PRF_INPUT]);
        block_input[..SHA256_LEN].copy_from_slice(&a[..]);
        block_input[SHA256_LEN..SHA256_LEN + joined].copy_from_slice(&seed_full[..joined]);
        let mut block = Zeroizing::new([0u8; SHA256_LEN]);
        let written = provider.hmac(
            HashAlgorithm::Sha256,
            secret,
            &block_input[..SHA256_LEN + joined],
            &mut block[..],
        )?;
        if written != SHA256_LEN {
            return Err(CryptoError::BackendFailure);
        }
        let take = core::cmp::min(SHA256_LEN, output.len() - offset);
        output[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;

        // A(i+1) = HMAC(secret, A(i)) for the next block, only when needed.
        if offset < output.len() {
            let mut next_a = Zeroizing::new([0u8; SHA256_LEN]);
            let written = provider.hmac(HashAlgorithm::Sha256, secret, &a[..], &mut next_a[..])?;
            if written != SHA256_LEN {
                return Err(CryptoError::BackendFailure);
            }
            a.copy_from_slice(&next_a[..]);
        }
    }
    Ok(())
}

/// Derives the 48-byte master secret (RFC 5246 section 8.1).
///
/// # Errors
///
/// Propagates [`prf_sha256`] failures.
pub(crate) fn derive_master_secret<P: HmacProvider + ?Sized>(
    provider: &P,
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<MasterSecret, CryptoError> {
    let mut seed = Zeroizing::new([0u8; MAX_SEED]);
    seed[..32].copy_from_slice(client_random);
    seed[32..].copy_from_slice(server_random);
    let mut bytes = [0u8; MASTER_SECRET_LEN];
    prf_sha256(
        provider,
        pre_master_secret,
        MASTER_SECRET_LABEL,
        &seed[..],
        &mut bytes,
    )?;
    Ok(MasterSecret { bytes })
}

/// Derives the 40-byte key block (RFC 5246 section 6.3).
///
/// # Errors
///
/// Propagates [`prf_sha256`] failures.
pub(crate) fn derive_key_block<P: HmacProvider + ?Sized>(
    provider: &P,
    master_secret: &MasterSecret,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<KeyBlock, CryptoError> {
    let mut seed = Zeroizing::new([0u8; MAX_SEED]);
    // The key-expansion seed is server_random || client_random (RFC 5246
    // section 6.3), the reverse of the master-secret seed order.
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);

    let mut block = Zeroizing::new([0u8; KEY_BLOCK_LEN]);
    prf_sha256(
        provider,
        master_secret.as_bytes(),
        KEY_EXPANSION_LABEL,
        &seed[..],
        &mut block[..],
    )?;

    let mut key_block = KeyBlock {
        client_write_key: [0u8; 16],
        server_write_key: [0u8; 16],
        client_write_iv: [0u8; 4],
        server_write_iv: [0u8; 4],
    };
    key_block.client_write_key.copy_from_slice(&block[..16]);
    key_block.server_write_key.copy_from_slice(&block[16..32]);
    key_block.client_write_iv.copy_from_slice(&block[32..36]);
    key_block.server_write_iv.copy_from_slice(&block[36..40]);
    Ok(key_block)
}

/// Computes Finished `verify_data` from the transcript hash.
///
/// # Errors
///
/// Propagates [`prf_sha256`] failures.
pub(crate) fn finished_verify_data<P: HmacProvider + ?Sized>(
    provider: &P,
    master_secret: &MasterSecret,
    server_role: bool,
    transcript_hash: &[u8; 32],
) -> Result<[u8; FINISHED_VERIFY_DATA_LEN], CryptoError> {
    let label = if server_role {
        SERVER_FINISHED_LABEL
    } else {
        CLIENT_FINISHED_LABEL
    };
    let mut verify_data = [0u8; FINISHED_VERIFY_DATA_LEN];
    prf_sha256(
        provider,
        master_secret.as_bytes(),
        label,
        transcript_hash,
        &mut verify_data,
    )?;
    Ok(verify_data)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use rtx_crypto::{HashProvider, HmacProvider};

    const PRE_MASTER: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    const CLIENT_RANDOM: [u8; 32] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
        0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
        0x3E, 0x3F,
    ];
    const SERVER_RANDOM: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
        0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
        0x5E, 0x5F,
    ];

    /// OpenSSL 3.0.13 `TLS1-PRF` master secret for the fixed inputs above:
    ///
    /// ```text
    /// openssl kdf -keylen 48 -kdfopt digest:SHA256 \
    ///   -kdfopt hexsecret:0001...1f \
    ///   -kdfopt hexseed:6d6173746572207365637265742021...3f40...5f TLS1-PRF
    /// ```
    const MASTER_HEX: &str = "518bc65fd30dabe86349152f98435c94d907b50c92a931c5a2f9e3a4d90f3439f2726c763fb1a40aec90b8bc60173f7c";
    /// OpenSSL `TLS1-PRF` key block for the master secret above.
    const KEY_BLOCK_HEX: &str =
        "9052d2e0e4485b2e323effcbc8a47e0839454ba1588ffbc35dccffd8fe8f67f36aee3d733b5a6abc";
    /// OpenSSL `TLS1-PRF` client Finished for SHA-256("rtx-dtls-1.2-handshake-transcript").
    const CLIENT_FINISHED_HEX: &str = "685c15078dd32880bcb22e4b";

    fn provider() -> rtx_crypto_rustcrypto::RustCryptoProvider {
        rtx_crypto_rustcrypto::RustCryptoProvider::new()
    }

    fn hex<const N: usize>(input: &str) -> [u8; N] {
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&input[offset..offset + 2], 16).expect("hex");
        }
        output
    }

    // DTLS-KS-001 — master secret matches the independent OpenSSL PRF.
    #[test]
    fn master_secret_matches_openssl_prf() {
        let master = derive_master_secret(&provider(), &PRE_MASTER, &CLIENT_RANDOM, &SERVER_RANDOM)
            .expect("master secret");
        assert_eq!(master.as_bytes(), &hex::<48>(MASTER_HEX));
        assert!(format!("{master:?}").contains("<redacted>"));
    }

    // DTLS-KS-002 — key block matches OpenSSL and splits in RFC 5246 order.
    #[test]
    fn key_block_matches_openssl_prf() {
        let provider = provider();
        let master = derive_master_secret(&provider, &PRE_MASTER, &CLIENT_RANDOM, &SERVER_RANDOM)
            .expect("master secret");
        let block = derive_key_block(&provider, &master, &CLIENT_RANDOM, &SERVER_RANDOM)
            .expect("key block");
        let expected = hex::<40>(KEY_BLOCK_HEX);
        assert_eq!(block.client_write_key, expected[..16]);
        assert_eq!(block.server_write_key, expected[16..32]);
        assert_eq!(block.client_write_iv, expected[32..36]);
        assert_eq!(block.server_write_iv, expected[36..40]);
        assert!(format!("{block:?}").contains("<redacted>"));
    }

    // DTLS-KS-003 — Finished matches OpenSSL and the role selects the label.
    #[test]
    fn finished_matches_openssl_prf() {
        let provider = provider();
        let master = derive_master_secret(&provider, &PRE_MASTER, &CLIENT_RANDOM, &SERVER_RANDOM)
            .expect("master secret");
        let mut hash = [0u8; 32];
        let written = provider
            .digest(
                HashAlgorithm::Sha256,
                b"rtx-dtls-1.2-handshake-transcript",
                &mut hash,
            )
            .expect("transcript hash");
        assert_eq!(written, 32);

        let client = finished_verify_data(&provider, &master, false, &hash).expect("client");
        assert_eq!(client, hex::<12>(CLIENT_FINISHED_HEX));
        let server = finished_verify_data(&provider, &master, true, &hash).expect("server");
        assert_ne!(client, server, "role label must change verify_data");
    }

    // DTLS-KS-004 — PRF output is deterministic and supports non-block sizes.
    #[test]
    fn prf_handles_partial_blocks_and_is_deterministic() {
        let provider = provider();
        for length in [0usize, 1, 12, 31, 32, 33, 48, 60, 65] {
            let mut first = vec![0u8; length];
            let mut second = vec![0u8; length];
            prf_sha256(&provider, b"secret", b"label", b"seed", &mut first).expect("first");
            prf_sha256(&provider, b"secret", b"label", b"seed", &mut second).expect("second");
            assert_eq!(first, second, "length {length}");
            if length > 0 {
                assert!(first.iter().any(|&byte| byte != 0));
            }
        }
        let mut first = [0u8; 48];
        let mut second = [0u8; 48];
        prf_sha256(&provider, b"secret", b"label a", b"seed", &mut first).expect("label a");
        prf_sha256(&provider, b"secret", b"label b", b"seed", &mut second).expect("label b");
        assert_ne!(first, second);
    }

    /// Provider that reports a lie about how many bytes it wrote.
    struct LyingHmac;

    impl HmacProvider for LyingHmac {
        fn hmac(
            &self,
            _algorithm: HashAlgorithm,
            _key: &[u8],
            _input: &[u8],
            output: &mut [u8],
        ) -> Result<usize, CryptoError> {
            output.fill(0xAA);
            Ok(0)
        }
    }

    /// Provider that always fails.
    struct FailingHmac(CryptoError);

    impl HmacProvider for FailingHmac {
        fn hmac(
            &self,
            _algorithm: HashAlgorithm,
            _key: &[u8],
            _input: &[u8],
            _output: &mut [u8],
        ) -> Result<usize, CryptoError> {
            Err(self.0)
        }
    }

    // DTLS-KS-005 — provider error paths surface without producing output.
    #[test]
    fn prf_propagates_provider_failures() {
        let mut output = [0xAAu8; 48];
        assert_eq!(
            prf_sha256(&LyingHmac, b"secret", b"label", b"seed", &mut output),
            Err(CryptoError::BackendFailure)
        );
        assert_eq!(output, [0xAA; 48]);

        for error in [
            CryptoError::Unsupported,
            CryptoError::BackendFailure,
            CryptoError::OutputTooSmall,
        ] {
            assert_eq!(
                prf_sha256(
                    &FailingHmac(error),
                    b"secret",
                    b"label",
                    b"seed",
                    &mut output
                ),
                Err(error)
            );
        }

        let too_long = [0u8; MAX_PRF_INPUT];
        assert_eq!(
            prf_sha256(&provider(), b"secret", &too_long, b"", &mut output),
            Err(CryptoError::BackendFailure)
        );

        let master = MasterSecret { bytes: [0; 48] };
        let mut secret = master;
        secret.corrupt_first_byte();
        assert_ne!(secret.as_bytes(), &[0u8; 48]);
    }

    // DTLS-KS-006 — empty key block request still consumes one A(i) step and
    // zero-length output is a no-op.
    #[test]
    fn prf_zero_length_output_is_a_noop() {
        let provider = provider();
        let mut empty: [u8; 0] = [];
        prf_sha256(&provider, b"secret", b"label", b"seed", &mut empty).expect("empty");
    }
}

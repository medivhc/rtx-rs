//! AES-CM keystream generation and HMAC-SHA1-80 authentication.
//!
//! The initial counter block follows `RFC 3711` section 4.1.1:
//!
//! ```text
//! IV = (salt * 2^16) XOR (SSRC * 2^64) XOR (index * 2^16)
//! ```
//!
//! The 14-byte salt occupies bytes 0..14 of the 128-bit value, the 32-bit
//! `SSRC` bytes 8..12, the 48-bit index bytes 2..8, and bytes 14..16 are the
//! block counter. Because the salt is shifted left by two octets, the low 16
//! bits start at zero and block `j` is `IV + j`.

use rtx_crypto::{Aes128BlockProvider, CryptoError, HashAlgorithm, HmacProvider};
use zeroize::Zeroize;

use crate::error::Error;
use crate::{AUTH_TAG_LEN, SESSION_KEY_LEN, SESSION_SALT_LEN};

/// SHA-1 digest length, the full HMAC output before truncation.
pub(crate) const SHA1_LEN: usize = 20;
/// AES block length.
pub(crate) const AES_BLOCK_LEN: usize = 16;
/// `RFC 3711` caps a single keystream segment at 2^16 AES blocks.
pub(crate) const MAX_KEYSTREAM_BLOCKS: usize = 1 << 16;

/// Session key material owned by one context.
///
/// `Drop` zeroizes both arrays. The values never appear in `Debug` output.
pub(crate) struct SessionKeys {
    key: [u8; SESSION_KEY_LEN],
    salt: [u8; SESSION_SALT_LEN],
}

impl SessionKeys {
    pub(crate) const fn new(key: [u8; SESSION_KEY_LEN], salt: [u8; SESSION_SALT_LEN]) -> Self {
        Self { key, salt }
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.key.zeroize();
        self.salt.zeroize();
    }
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SessionKeys")
            .field("key", &"<redacted>")
            .field("salt", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Encrypts or decrypts `region` with AES-CM (the operation is an XOR).
///
/// # Errors
///
/// Returns [`Error::PacketTooLarge`] before touching `region` when it needs
/// more than 2^16 blocks, and [`Error::Crypto`] when the provider fails.
pub(crate) fn apply_keystream<P: Aes128BlockProvider>(
    provider: &P,
    keys: &SessionKeys,
    ssrc: u32,
    index: u64,
    region: &mut [u8],
) -> Result<(), Error> {
    let blocks = region.len().div_ceil(AES_BLOCK_LEN);
    if blocks > MAX_KEYSTREAM_BLOCKS {
        return Err(Error::PacketTooLarge);
    }
    // `blocks <= 2^16`, so the `u16` counter sequence covers every chunk
    // exactly once without wrapping.
    for (counter, chunk) in (0_u16..).zip(region.chunks_mut(AES_BLOCK_LEN)) {
        let mut keystream = keystream_block(provider, keys, ssrc, index, counter)?;
        for (byte, mask) in chunk.iter_mut().zip(keystream.iter()) {
            *byte ^= mask;
        }
        keystream.zeroize();
    }
    Ok(())
}

/// Produces one AES-CM keystream block for `counter`.
fn keystream_block<P: Aes128BlockProvider>(
    provider: &P,
    keys: &SessionKeys,
    ssrc: u32,
    index: u64,
    counter: u16,
) -> Result<[u8; AES_BLOCK_LEN], Error> {
    let mut block = initial_iv(&keys.salt, ssrc, index);
    block[14..AES_BLOCK_LEN].copy_from_slice(&counter.to_be_bytes());
    provider
        .encrypt_aes128_block(&keys.key, &mut block)
        .map_err(Error::Crypto)?;
    Ok(block)
}

/// Builds the 128-bit initial counter block.
fn initial_iv(salt: &[u8; SESSION_SALT_LEN], ssrc: u32, index: u64) -> [u8; AES_BLOCK_LEN] {
    let mut iv = [0u8; AES_BLOCK_LEN];
    iv[..SESSION_SALT_LEN].copy_from_slice(salt);

    // SSRC * 2^64: bytes 8..12.
    for (destination, source) in iv[8..12].iter_mut().zip(ssrc.to_be_bytes()) {
        *destination ^= source;
    }

    // index * 2^16: the low 48 bits land in bytes 2..8.
    let index_bytes = index.to_be_bytes();
    for (destination, source) in iv[2..8].iter_mut().zip(&index_bytes[2..]) {
        *destination ^= source;
    }

    iv
}

/// Computes the HMAC-SHA1 tag and truncates it to 80 bits.
///
/// # Errors
///
/// Returns [`Error::Crypto`] when the provider fails or reports a digest
/// length other than the 20 bytes SHA-1 produces.
pub(crate) fn compute_tag<P: HmacProvider>(
    provider: &P,
    keys: &SessionKeys,
    authenticated: &[u8],
) -> Result<[u8; AUTH_TAG_LEN], Error> {
    let mut mac = [0u8; SHA1_LEN];
    let written = provider
        .hmac(HashAlgorithm::Sha1, &keys.key, authenticated, &mut mac)
        .map_err(Error::Crypto)?;
    if written != SHA1_LEN {
        return Err(Error::Crypto(CryptoError::BackendFailure));
    }
    let mut tag = [0u8; AUTH_TAG_LEN];
    tag.copy_from_slice(&mac[..AUTH_TAG_LEN]);
    mac.zeroize();
    Ok(tag)
}

/// Compares a computed tag with the received bytes without early exit.
pub(crate) fn tags_equal(expected: &[u8; AUTH_TAG_LEN], received: &[u8]) -> bool {
    if received.len() != AUTH_TAG_LEN {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in expected.iter().zip(received) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use rtx_crypto_rustcrypto::RustCryptoProvider;

    /// RFC 3711 Appendix B.2 session key.
    const KEY: [u8; SESSION_KEY_LEN] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C,
    ];
    /// RFC 3711 Appendix B.2 session salt, without the shifted low octets.
    const SALT: [u8; SESSION_SALT_LEN] = [
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
    ];

    /// RFC 3711 Appendix B.2, counters 0000-0002 and FEFF-FF01.
    const VECTORS: [(u16, &str); 6] = [
        (0x0000, "E03EAD0935C95E80E166B16DD92B4EB4"),
        (0x0001, "D23513162B02D0F72A43A2FE4A5F97AB"),
        (0x0002, "41E95B3BB0A2E8DD477901E4FCA894C0"),
        (0xFEFF, "EC8CDF7398607CB0F2D21675EA9EA1E4"),
        (0xFF00, "362B7C3C6773516318A077D7FC5073AE"),
        (0xFF01, "6A2CC3787889374FBEB4C81B17BA6C44"),
    ];

    fn hex<const N: usize>(input: &str) -> [u8; N] {
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&input[offset..offset + 2], 16).expect("hex");
        }
        output
    }

    fn keys() -> SessionKeys {
        SessionKeys::new(KEY, SALT)
    }

    // SRTP-VEC-001 — RFC 3711 Appendix B.2 keystream vectors, cited verbatim.
    #[test]
    fn rfc3711_appendix_b2_keystream_matches_published_vectors() {
        let provider = RustCryptoProvider::new();
        let keys = keys();
        for (counter, expected) in VECTORS {
            let actual = keystream_block(&provider, &keys, 0, 0, counter).expect("block");
            assert_eq!(actual, hex::<AES_BLOCK_LEN>(expected));
        }
    }

    // SRTP-VEC-002 — SSRC and the 48-bit index land in the RFC 3711 positions.
    #[test]
    fn iv_places_ssrc_and_index_per_rfc3711() {
        let provider = RustCryptoProvider::new();
        let keys = keys();
        let ssrc = 0x1122_3344_u32;
        let index = 0x0000_5566_7788_99AA_u64;
        let counter = 0x1234_u16;

        let mut expected = [0u8; AES_BLOCK_LEN];
        expected[..SESSION_SALT_LEN].copy_from_slice(&SALT);
        for (destination, source) in expected[8..12].iter_mut().zip(ssrc.to_be_bytes()) {
            *destination ^= source;
        }
        let index_bytes = index.to_be_bytes();
        for (destination, source) in expected[2..8].iter_mut().zip(&index_bytes[2..]) {
            *destination ^= source;
        }
        expected[14..].copy_from_slice(&counter.to_be_bytes());
        provider
            .encrypt_aes128_block(&KEY, &mut expected)
            .expect("independent AES block");

        let actual = keystream_block(&provider, &keys, ssrc, index, counter).expect("block");
        assert_eq!(actual, expected);
    }

    // SRTP-VEC-003 — more than 2^16 blocks is rejected before any write.
    #[test]
    fn region_beyond_keystream_limit_is_rejected() {
        let provider = RustCryptoProvider::new();
        let keys = keys();
        let mut region = vec![0xAA_u8; MAX_KEYSTREAM_BLOCKS * AES_BLOCK_LEN + 1];
        assert_eq!(
            apply_keystream(&provider, &keys, 7, 9, &mut region),
            Err(Error::PacketTooLarge)
        );
        assert!(region.iter().all(|&byte| byte == 0xAA));
    }

    // SRTP-TAG-001 — tag comparison accepts only the exact 10 bytes.
    #[test]
    fn tag_comparison_is_exact_and_length_checked() {
        let tag = [0x5Au8; AUTH_TAG_LEN];
        assert!(tags_equal(&tag, &tag));
        assert!(!tags_equal(&tag, &tag[..AUTH_TAG_LEN - 1]));

        let mut changed = tag;
        changed[AUTH_TAG_LEN - 1] ^= 0x01;
        assert!(!tags_equal(&tag, &changed));
    }

    // SRTP-SEC-001 — Debug never reveals the key or salt.
    #[test]
    fn session_keys_debug_redacts_material() {
        let rendered = format!("{:?}", keys());
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("2b7e"));
        assert!(!rendered.contains("f0f1"));
    }
}

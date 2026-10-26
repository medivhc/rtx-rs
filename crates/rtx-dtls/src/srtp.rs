//! DTLS-SRTP key export (RFC 5764 section 4.2).
//!
//! The exporter is the TLS 1.2 PRF with label `EXTRACTOR-dtls_srtp` and seed
//! `client_random || server_random`:
//!
//! ```text
//! keying_material = PRF(master_secret, "EXTRACTOR-dtls_srtp",
//!                       client_random || server_random)[0..60]
//! ```
//!
//! Profile 0x0001 (`SRTP_AES128_CM_HMAC_SHA1_80`) fixes the master key at 16
//! bytes and the master salt at 14 bytes, so the export length is
//! `2 * (16 + 14) = 60` bytes. The layout is client key, server key, client
//! salt, server salt.
//!
//! Export failure is terminal for the handshake: there is no fallback profile,
//! no truncation and no reuse of an older key set. The returned material
//! zeroizes itself on drop.

use rtx_crypto::HmacProvider;
use zeroize::{Zeroize, Zeroizing};

use crate::handshake_error::SrtpExportError;
use crate::keyschedule::prf_sha256;

/// RFC 5764 protection profile `SRTP_AES128_CM_HMAC_SHA1_80`.
pub const SRTP_PROFILE_AES128_CM_HMAC_SHA1_80: u16 = 0x0001;
/// Master key length for [`SRTP_PROFILE_AES128_CM_HMAC_SHA1_80`].
pub const SRTP_MASTER_KEY_LEN: usize = 16;
/// Master salt length for [`SRTP_PROFILE_AES128_CM_HMAC_SHA1_80`].
pub const SRTP_MASTER_SALT_LEN: usize = 14;
/// Total exported keying material: `2 * (key_len + salt_len)`.
pub const SRTP_EXPORT_LEN: usize = 2 * (SRTP_MASTER_KEY_LEN + SRTP_MASTER_SALT_LEN);
/// RFC 5764 exporter label.
pub const DTLS_SRTP_EXPORTER_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp";

/// DTLS-SRTP master keys and salts for both directions.
///
/// The values are secrets: `Debug` redacts them, the type is not `Clone` and
/// `Drop` zeroizes every byte. Use the getters to hand them to an SRTP stack.
pub struct SrtpKeyingMaterial {
    profile: u16,
    client_write_key: [u8; SRTP_MASTER_KEY_LEN],
    server_write_key: [u8; SRTP_MASTER_KEY_LEN],
    client_write_salt: [u8; SRTP_MASTER_SALT_LEN],
    server_write_salt: [u8; SRTP_MASTER_SALT_LEN],
}

impl SrtpKeyingMaterial {
    /// Exports keying material for `profile` (RFC 5764 section 4.2).
    ///
    /// # Errors
    ///
    /// Returns [`SrtpExportError::UnsupportedProfile`] before touching any
    /// secret when `profile` is not
    /// [`SRTP_PROFILE_AES128_CM_HMAC_SHA1_80`], and
    /// [`SrtpExportError::Crypto`] when the PRF provider fails or reports an
    /// unexpected MAC length. On error no material is returned.
    pub fn export<P: HmacProvider + ?Sized>(
        provider: &P,
        profile: u16,
        master_secret: &[u8; 48],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Result<Self, SrtpExportError> {
        if profile != SRTP_PROFILE_AES128_CM_HMAC_SHA1_80 {
            return Err(SrtpExportError::UnsupportedProfile(profile));
        }

        let mut seed = Zeroizing::new([0u8; 64]);
        seed[..32].copy_from_slice(client_random);
        seed[32..].copy_from_slice(server_random);

        let mut material = Zeroizing::new([0u8; SRTP_EXPORT_LEN]);
        prf_sha256(
            provider,
            master_secret,
            DTLS_SRTP_EXPORTER_LABEL,
            &seed[..],
            &mut material[..],
        )
        .map_err(SrtpExportError::Crypto)?;

        let mut result = Self {
            profile,
            client_write_key: [0u8; SRTP_MASTER_KEY_LEN],
            server_write_key: [0u8; SRTP_MASTER_KEY_LEN],
            client_write_salt: [0u8; SRTP_MASTER_SALT_LEN],
            server_write_salt: [0u8; SRTP_MASTER_SALT_LEN],
        };
        result
            .client_write_key
            .copy_from_slice(&material[..SRTP_MASTER_KEY_LEN]);
        result
            .server_write_key
            .copy_from_slice(&material[SRTP_MASTER_KEY_LEN..2 * SRTP_MASTER_KEY_LEN]);
        result.client_write_salt.copy_from_slice(
            &material[2 * SRTP_MASTER_KEY_LEN..2 * SRTP_MASTER_KEY_LEN + SRTP_MASTER_SALT_LEN],
        );
        result
            .server_write_salt
            .copy_from_slice(&material[2 * SRTP_MASTER_KEY_LEN + SRTP_MASTER_SALT_LEN..]);
        Ok(result)
    }

    /// Protection profile this material belongs to.
    #[must_use]
    pub const fn profile(&self) -> u16 {
        self.profile
    }

    /// Client-to-server SRTP master key.
    #[must_use]
    pub const fn client_write_key(&self) -> &[u8; SRTP_MASTER_KEY_LEN] {
        &self.client_write_key
    }

    /// Server-to-client SRTP master key.
    #[must_use]
    pub const fn server_write_key(&self) -> &[u8; SRTP_MASTER_KEY_LEN] {
        &self.server_write_key
    }

    /// Client-to-server SRTP master salt.
    #[must_use]
    pub const fn client_write_salt(&self) -> &[u8; SRTP_MASTER_SALT_LEN] {
        &self.client_write_salt
    }

    /// Server-to-client SRTP master salt.
    #[must_use]
    pub const fn server_write_salt(&self) -> &[u8; SRTP_MASTER_SALT_LEN] {
        &self.server_write_salt
    }
}

impl Drop for SrtpKeyingMaterial {
    fn drop(&mut self) {
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
        self.client_write_salt.zeroize();
        self.server_write_salt.zeroize();
    }
}

impl core::fmt::Debug for SrtpKeyingMaterial {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SrtpKeyingMaterial")
            .field("profile", &self.profile)
            .field("keys", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use rtx_crypto::{CryptoError, HashAlgorithm};

    const MASTER: [u8; 48] = [
        0x51, 0x8B, 0xC6, 0x5F, 0xD3, 0x0D, 0xAB, 0xE8, 0x63, 0x49, 0x15, 0x2F, 0x98, 0x43, 0x5C,
        0x94, 0xD9, 0x07, 0xB5, 0x0C, 0x92, 0xA9, 0x31, 0xC5, 0xA2, 0xF9, 0xE3, 0xA4, 0xD9, 0x0F,
        0x34, 0x39, 0xF2, 0x72, 0x6C, 0x76, 0x3F, 0xB1, 0xA4, 0x0A, 0xEC, 0x90, 0xB8, 0xBC, 0x60,
        0x17, 0x3F, 0x7C,
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

    /// OpenSSL 3.0.13 `TLS1-PRF`, keylen 60, label `EXTRACTOR-dtls_srtp`.
    const EXPORT_HEX: &str = "33b70d6f21c49d3dd1b573fa210e48a0f8800b3d0407960c223d9fd23f3008edea3360b45a198187fae49bae00c5b1698fd9b933013f269f7be4aa94";

    fn hex<const N: usize>(input: &str) -> [u8; N] {
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&input[offset..offset + 2], 16).expect("hex");
        }
        output
    }

    fn provider() -> rtx_crypto_rustcrypto::RustCryptoProvider {
        rtx_crypto_rustcrypto::RustCryptoProvider::new()
    }

    // DTLS-SRTP-001 — export matches the independent OpenSSL PRF byte for byte.
    #[test]
    fn export_matches_openssl_prf() {
        let material = SrtpKeyingMaterial::export(
            &provider(),
            SRTP_PROFILE_AES128_CM_HMAC_SHA1_80,
            &MASTER,
            &CLIENT_RANDOM,
            &SERVER_RANDOM,
        )
        .expect("export");
        let expected = hex::<60>(EXPORT_HEX);
        assert_eq!(material.profile(), SRTP_PROFILE_AES128_CM_HMAC_SHA1_80);
        assert_eq!(material.client_write_key(), &expected[..16]);
        assert_eq!(material.server_write_key(), &expected[16..32]);
        assert_eq!(material.client_write_salt(), &expected[32..46]);
        assert_eq!(material.server_write_salt(), &expected[46..60]);
        assert_eq!(SRTP_EXPORT_LEN, 60);
        assert!(format!("{material:?}").contains("<redacted>"));
    }

    /// HMAC provider that reports success but the wrong length.
    struct ShortHmac;

    impl HmacProvider for ShortHmac {
        fn hmac(
            &self,
            _algorithm: HashAlgorithm,
            _key: &[u8],
            _input: &[u8],
            output: &mut [u8],
        ) -> Result<usize, CryptoError> {
            output.fill(0x5A);
            Ok(output.len() - 1)
        }
    }

    /// HMAC provider that fails.
    struct FailingHmac;

    impl HmacProvider for FailingHmac {
        fn hmac(
            &self,
            _algorithm: HashAlgorithm,
            _key: &[u8],
            _input: &[u8],
            _output: &mut [u8],
        ) -> Result<usize, CryptoError> {
            Err(CryptoError::Unsupported)
        }
    }

    // DTLS-SRTP-002 — failures are explicit and never return material.
    #[test]
    fn export_failure_paths() {
        assert_eq!(
            SrtpKeyingMaterial::export(
                &provider(),
                SRTP_PROFILE_AES128_CM_HMAC_SHA1_80 + 1,
                &MASTER,
                &CLIENT_RANDOM,
                &SERVER_RANDOM
            )
            .err(),
            Some(SrtpExportError::UnsupportedProfile(2))
        );
        assert_eq!(
            SrtpKeyingMaterial::export(
                &ShortHmac,
                SRTP_PROFILE_AES128_CM_HMAC_SHA1_80,
                &MASTER,
                &CLIENT_RANDOM,
                &SERVER_RANDOM
            )
            .err(),
            Some(SrtpExportError::Crypto(CryptoError::BackendFailure))
        );
        assert_eq!(
            SrtpKeyingMaterial::export(
                &FailingHmac,
                SRTP_PROFILE_AES128_CM_HMAC_SHA1_80,
                &MASTER,
                &CLIENT_RANDOM,
                &SERVER_RANDOM
            )
            .err(),
            Some(SrtpExportError::Crypto(CryptoError::Unsupported))
        );
    }
}

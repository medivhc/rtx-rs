//! AEAD record protection for DTLS 1.2 (RFC 6347 section 4.1.2.1, RFC 5288).
//!
//! A protected record on the wire is
//!
//! ```text
//! header (13 bytes) || explicit_nonce (8) || ciphertext (n) || tag (16)
//! ```
//!
//! The explicit nonce is `epoch || sequence_number`, exactly the 64 bits the
//! DTLS header already carries (RFC 5288 section 3). The AEAD nonce is the
//! 4-byte fixed IV (the "salt" from the key block) followed by the explicit
//! nonce, which yields the 12-byte AES-GCM nonce of RFC 5116 section 5.1:
//!
//! ```text
//! nonce = fixed_iv (4) || epoch (2) || sequence_number (6)
//! ```
//!
//! The additional authenticated data follows RFC 5246 section 6.2.3.3 with
//! the DTLS 64-bit sequence number, so it is **not** in wire-header order:
//!
//! ```text
//! additional_data = epoch || sequence_number (8)
//!                || type (1) || version (2) || plaintext_length (2)
//! ```
//!
//! Nonce and sequence management stay in this crate: [`RecordCipher`] derives
//! the nonce from the header fields and [`crate::RecordEncoder`] owns the
//! outbound sequence number. The [`rtx_crypto::AeadProvider`] never sees or
//! generates nonces on its own.

use rtx_crypto::{AeadAlgorithm, AeadProvider, CryptoError};

use crate::error::RecordError;
use crate::record::{
    AEAD_EXPLICIT_NONCE_LEN, AEAD_OVERHEAD, AEAD_TAG_LEN, ContentType, DTLS12_VERSION,
    MAX_PLAINTEXT_LEN, RECORD_HEADER_LEN, Record, RecordHeader, SequenceNumber,
};

/// Length of the per-record nonce (96-bit AES-GCM nonce).
pub const AEAD_NONCE_LEN: usize = 12;
/// Length of the fixed IV ("salt") taken from the key block.
pub const FIXED_IV_LEN: usize = 4;
/// Longest key any supported AEAD algorithm uses.
const MAX_KEY_LEN: usize = 32;

/// Record protection state for one epoch: algorithm, key and fixed IV.
///
/// The key and IV are held in fixed-size storage so the record layer never
/// allocates. `Debug` redacts both.
pub struct RecordCipher {
    algorithm: AeadAlgorithm,
    key: [u8; MAX_KEY_LEN],
    fixed_iv: [u8; FIXED_IV_LEN],
}

impl RecordCipher {
    /// Builds record protection from a raw key and fixed IV.
    ///
    /// `key` must be 16 bytes for AES-128-GCM or 32 for AES-256-GCM;
    /// `fixed_iv` must be exactly 4 bytes (the RFC 5288 salt).
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::InvalidKeyLength`] when `key.len()` does not
    /// match `algorithm`, and [`RecordError::InvalidFixedIvLength`] unless
    /// `fixed_iv` is 4 bytes.
    pub fn new(algorithm: AeadAlgorithm, key: &[u8], fixed_iv: &[u8]) -> Result<Self, RecordError> {
        let expected = match algorithm {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::Aes256Gcm => MAX_KEY_LEN,
        };
        if key.len() != expected {
            return Err(RecordError::InvalidKeyLength);
        }
        if fixed_iv.len() != FIXED_IV_LEN {
            return Err(RecordError::InvalidFixedIvLength);
        }
        let mut key_bytes = [0u8; MAX_KEY_LEN];
        key_bytes[..key.len()].copy_from_slice(key);
        let mut iv_bytes = [0u8; FIXED_IV_LEN];
        iv_bytes.copy_from_slice(fixed_iv);
        Ok(Self {
            algorithm,
            key: key_bytes,
            fixed_iv: iv_bytes,
        })
    }

    /// AEAD algorithm this cipher uses.
    #[must_use]
    pub const fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }

    /// Derives the 12-byte AEAD nonce for `epoch` and `sequence_number`.
    #[must_use]
    pub fn nonce(&self, epoch: u16, sequence_number: SequenceNumber) -> [u8; AEAD_NONCE_LEN] {
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        nonce[..FIXED_IV_LEN].copy_from_slice(&self.fixed_iv);
        nonce[FIXED_IV_LEN..FIXED_IV_LEN + 2].copy_from_slice(&epoch.to_be_bytes());
        nonce[FIXED_IV_LEN + 2..].copy_from_slice(&sequence_number.to_be_bytes());
        nonce
    }

    /// Returns the 8-byte explicit nonce carried inside a protected record.
    #[must_use]
    pub const fn explicit_nonce(
        epoch: u16,
        sequence_number: SequenceNumber,
    ) -> [u8; AEAD_EXPLICIT_NONCE_LEN] {
        let epoch = epoch.to_be_bytes();
        let sequence = sequence_number.to_be_bytes();
        [
            epoch[0],
            epoch[1],
            sequence[0],
            sequence[1],
            sequence[2],
            sequence[3],
            sequence[4],
            sequence[5],
        ]
    }

    /// Writes a complete protected record into `output`, returning its length.
    ///
    /// The caller owns `output`; nothing is allocated and no `Vec` is
    /// returned. `output` must hold
    /// `RECORD_HEADER_LEN + AEAD_OVERHEAD + plaintext.len()` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::RecordTooLong`] when `plaintext` exceeds 2^14,
    /// [`RecordError::OutputTooSmall`] when `output` is too short, and the
    /// provider error mapped through [`RecordError::Crypto`] when sealing
    /// fails. All structural and size checks happen before the first write.
    pub fn seal<P: AeadProvider + ?Sized>(
        &self,
        provider: &P,
        content_type: ContentType,
        epoch: u16,
        sequence_number: SequenceNumber,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, RecordError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(RecordError::RecordTooLong);
        }
        let fragment_len = plaintext
            .len()
            .checked_add(AEAD_OVERHEAD)
            .ok_or(RecordError::RecordTooLong)?;
        let total = RECORD_HEADER_LEN + fragment_len;
        if output.len() < total {
            return Err(RecordError::OutputTooSmall);
        }
        let header = RecordHeader {
            content_type,
            epoch,
            sequence_number,
            fragment_len,
        };
        let nonce = self.nonce(epoch, sequence_number);
        let aad = associated_data(content_type, epoch, sequence_number, plaintext.len())?;

        header.encode(&mut output[..RECORD_HEADER_LEN])?;
        let explicit_end = RECORD_HEADER_LEN + AEAD_EXPLICIT_NONCE_LEN;
        output[RECORD_HEADER_LEN..explicit_end]
            .copy_from_slice(&Self::explicit_nonce(epoch, sequence_number));
        let ciphertext_start = explicit_end;
        let ciphertext_end = ciphertext_start + plaintext.len() + AEAD_TAG_LEN;
        output[ciphertext_start..ciphertext_start + plaintext.len()].copy_from_slice(plaintext);
        let sealed = provider
            .seal_in_place(
                self.algorithm,
                self.key(),
                &nonce,
                &aad,
                &mut output[ciphertext_start..ciphertext_end],
                plaintext.len(),
            )
            .map_err(map_crypto)?;
        if sealed != plaintext.len() + AEAD_TAG_LEN {
            return Err(RecordError::Crypto(CryptoError::BackendFailure));
        }
        Ok(total)
    }

    /// Authenticates a protected record and writes its plaintext into
    /// `output`, returning the plaintext length.
    ///
    /// `output` is the caller-owned buffer. It must hold at least
    /// `record.fragment.len() - AEAD_EXPLICIT_NONCE_LEN` bytes, because the
    /// ciphertext plus tag is copied there before being decrypted in place.
    /// Every structural check runs before that copy. This convenience method
    /// is intended for machine-style callers; use
    /// [`RecordCipher::open_in_place`] when the caller buffer must stay
    /// byte-identical on every failure.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::CiphertextTooShort`] when the fragment cannot
    /// hold a nonce and a tag, [`RecordError::InvalidExplicitNonce`] when the
    /// explicit nonce disagrees with the header,
    /// [`RecordError::RecordTooLong`] when the plaintext would exceed 2^14,
    /// [`RecordError::OutputTooSmall`] when `output` is too short, and every
    /// error of [`RecordCipher::open_in_place`].
    pub fn open<P: AeadProvider + ?Sized>(
        &self,
        provider: &P,
        record: &Record<'_>,
        output: &mut [u8],
    ) -> Result<usize, RecordError> {
        let header = record.header;
        if header.fragment_len != record.fragment.len() {
            return Err(RecordError::LengthMismatch);
        }
        if header.fragment_len < AEAD_OVERHEAD {
            return Err(RecordError::CiphertextTooShort);
        }
        let Some((explicit_nonce, ciphertext_and_tag)) =
            record.fragment.split_at_checked(AEAD_EXPLICIT_NONCE_LEN)
        else {
            return Err(RecordError::CiphertextTooShort);
        };
        if explicit_nonce != Self::explicit_nonce(header.epoch, header.sequence_number).as_slice() {
            return Err(RecordError::InvalidExplicitNonce);
        }
        if ciphertext_and_tag.len() - AEAD_TAG_LEN > MAX_PLAINTEXT_LEN {
            return Err(RecordError::RecordTooLong);
        }
        if output.len() < ciphertext_and_tag.len() {
            return Err(RecordError::OutputTooSmall);
        }
        let destination = &mut output[..ciphertext_and_tag.len()];
        destination.copy_from_slice(ciphertext_and_tag);
        self.open_in_place(
            provider,
            header.content_type,
            header.epoch,
            header.sequence_number,
            destination,
        )
    }

    /// Authenticates `ciphertext_and_tag` in place under the record header
    /// context, returning the plaintext length.
    ///
    /// The buffer must already contain the ciphertext followed by the tag.
    /// All size and context checks run before the provider is called, and the
    /// provider contract leaves the buffer byte-identical when authentication
    /// fails, so this is the strict sentinel-buffer entry point.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::CiphertextTooShort`] when the buffer cannot
    /// hold a tag, [`RecordError::RecordTooLong`] when the plaintext would
    /// exceed 2^14, [`RecordError::AuthenticationFailed`] when the tag does
    /// not verify, and the provider error mapped through
    /// [`RecordError::Crypto`].
    pub fn open_in_place<P: AeadProvider + ?Sized>(
        &self,
        provider: &P,
        content_type: ContentType,
        epoch: u16,
        sequence_number: SequenceNumber,
        ciphertext_and_tag: &mut [u8],
    ) -> Result<usize, RecordError> {
        if ciphertext_and_tag.len() < AEAD_TAG_LEN {
            return Err(RecordError::CiphertextTooShort);
        }
        let plaintext_len = ciphertext_and_tag.len() - AEAD_TAG_LEN;
        if plaintext_len > MAX_PLAINTEXT_LEN {
            return Err(RecordError::RecordTooLong);
        }
        let nonce = self.nonce(epoch, sequence_number);
        let aad = associated_data(content_type, epoch, sequence_number, plaintext_len)?;
        let opened = provider
            .open_in_place(self.algorithm, self.key(), &nonce, &aad, ciphertext_and_tag)
            .map_err(map_crypto)?;
        if opened != plaintext_len {
            return Err(RecordError::Crypto(CryptoError::BackendFailure));
        }
        Ok(opened)
    }

    fn key(&self) -> &[u8] {
        match self.algorithm {
            AeadAlgorithm::Aes128Gcm => &self.key[..16],
            AeadAlgorithm::Aes256Gcm => &self.key[..MAX_KEY_LEN],
        }
    }
}

impl core::fmt::Debug for RecordCipher {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RecordCipher")
            .field("algorithm", &self.algorithm)
            .field("key", &"<redacted>")
            .field("fixed_iv", &"<redacted>")
            .finish()
    }
}

/// Builds the AEAD additional data.
///
/// RFC 5246 section 6.2.3.3 defines
/// `seq_num || type || version || length`, with the DTLS 64-bit sequence
/// number (`epoch || sequence_number`) in the `seq_num` slot and the
/// plaintext length in the `length` slot.
fn associated_data(
    content_type: ContentType,
    epoch: u16,
    sequence_number: SequenceNumber,
    plaintext_len: usize,
) -> Result<[u8; RECORD_HEADER_LEN], RecordError> {
    if plaintext_len > MAX_PLAINTEXT_LEN {
        return Err(RecordError::RecordTooLong);
    }
    let plaintext_len = u16::try_from(plaintext_len).map_err(|_| RecordError::RecordTooLong)?;
    let mut aad = [0u8; RECORD_HEADER_LEN];
    aad[..AEAD_EXPLICIT_NONCE_LEN]
        .copy_from_slice(&RecordCipher::explicit_nonce(epoch, sequence_number));
    aad[AEAD_EXPLICIT_NONCE_LEN] = content_type.to_u8();
    aad[AEAD_EXPLICIT_NONCE_LEN + 1..AEAD_EXPLICIT_NONCE_LEN + 3].copy_from_slice(&DTLS12_VERSION);
    aad[AEAD_EXPLICIT_NONCE_LEN + 3..].copy_from_slice(&plaintext_len.to_be_bytes());
    Ok(aad)
}

/// Narrows a provider failure without hiding authentication or buffer errors.
fn map_crypto(error: CryptoError) -> RecordError {
    match error {
        CryptoError::OutputTooSmall => RecordError::OutputTooSmall,
        CryptoError::AuthenticationFailed => RecordError::AuthenticationFailed,
        other => RecordError::Crypto(other),
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::cell::Cell;

    use crate::record::{MAX_FRAGMENT_LEN, RecordHeader};

    const TAG_LEN: usize = AEAD_TAG_LEN;
    const SEQ: SequenceNumber = SequenceNumber::from_be_bytes([0, 0, 0, 0, 0, 9]);
    const KEY_128: [u8; 16] = [0x11; 16];
    const KEY_256: [u8; 32] = [0x22; 32];
    const FIXED_IV: [u8; 4] = [0x0A, 0x0B, 0x0C, 0x0D];

    fn cipher(algorithm: AeadAlgorithm) -> RecordCipher {
        let key: &[u8] = match algorithm {
            AeadAlgorithm::Aes128Gcm => &KEY_128,
            AeadAlgorithm::Aes256Gcm => &KEY_256,
        };
        RecordCipher::new(algorithm, key, &FIXED_IV).expect("cipher")
    }

    /// Deterministic provider that records the nonce and AAD it is handed and
    /// honours the "on failure the buffer is untouched" contract.
    #[derive(Debug, Default)]
    struct TestAead {
        fail: Cell<Option<CryptoError>>,
        calls: Cell<usize>,
        nonce: Cell<[u8; AEAD_NONCE_LEN]>,
        aad: Cell<[u8; RECORD_HEADER_LEN]>,
    }

    impl TestAead {
        fn fail_with(error: CryptoError) -> Self {
            let provider = Self::default();
            provider.fail.set(Some(error));
            provider
        }

        fn observe(&self, nonce: &[u8], aad: &[u8]) -> Result<(), CryptoError> {
            let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
            nonce_bytes.copy_from_slice(nonce);
            self.nonce.set(nonce_bytes);
            let mut aad_bytes = [0u8; RECORD_HEADER_LEN];
            aad_bytes.copy_from_slice(aad);
            self.aad.set(aad_bytes);
            self.calls.set(self.calls.get() + 1);
            match self.fail.get() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    }

    fn mock_tag(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
        let mut state = 0xCBF2_9CE4_8422_2325u64;
        for bytes in [key, nonce, aad, ciphertext] {
            for &byte in bytes {
                state ^= u64::from(byte);
                state = state.wrapping_mul(0x0000_0100_0000_01B3);
            }
        }
        let mut tag = [0u8; TAG_LEN];
        tag[..8].copy_from_slice(&state.to_le_bytes());
        tag[8..].copy_from_slice(&(state.rotate_left(32) ^ 0x9E37_79B9_7F4A_7C15).to_le_bytes());
        tag
    }

    fn xor_keystream(nonce: &[u8], buffer: &mut [u8]) {
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte ^= nonce[index % nonce.len()] ^ 0xA5;
        }
    }

    impl AeadProvider for TestAead {
        fn seal_in_place(
            &self,
            _algorithm: AeadAlgorithm,
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
            self.observe(nonce, aad)?;
            let (payload, tag_region) = payload_and_tag.split_at_mut(plaintext_len);
            xor_keystream(nonce, payload);
            let tag = mock_tag(key, nonce, aad, payload);
            tag_region[..TAG_LEN].copy_from_slice(&tag);
            Ok(needed)
        }

        fn open_in_place(
            &self,
            _algorithm: AeadAlgorithm,
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            ciphertext_and_tag: &mut [u8],
        ) -> Result<usize, CryptoError> {
            if ciphertext_and_tag.len() < TAG_LEN {
                return Err(CryptoError::OutputTooSmall);
            }
            self.observe(nonce, aad)?;
            let split = ciphertext_and_tag.len() - TAG_LEN;
            let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(split);
            if tag != mock_tag(key, nonce, aad, ciphertext) {
                return Err(CryptoError::AuthenticationFailed);
            }
            xor_keystream(nonce, ciphertext);
            Ok(split)
        }
    }

    /// Provider that reports success but returns the wrong written length.
    #[derive(Debug, Default)]
    struct LyingAead;

    impl AeadProvider for LyingAead {
        fn seal_in_place(
            &self,
            _algorithm: AeadAlgorithm,
            _key: &[u8],
            _nonce: &[u8],
            _aad: &[u8],
            _payload_and_tag: &mut [u8],
            _plaintext_len: usize,
        ) -> Result<usize, CryptoError> {
            Ok(0)
        }

        fn open_in_place(
            &self,
            _algorithm: AeadAlgorithm,
            _key: &[u8],
            _nonce: &[u8],
            _aad: &[u8],
            _ciphertext_and_tag: &mut [u8],
        ) -> Result<usize, CryptoError> {
            Ok(0)
        }
    }

    fn sealed(cipher: &RecordCipher, plaintext: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; RECORD_HEADER_LEN + AEAD_OVERHEAD + plaintext.len()];
        let written = cipher
            .seal(
                &TestAead::default(),
                ContentType::ApplicationData,
                1,
                SEQ,
                plaintext,
                &mut output,
            )
            .expect("seal");
        assert_eq!(written, output.len());
        output
    }

    // DTLS-CIPHER-001 — algorithm/key/IV validation.
    #[test]
    fn cipher_rejects_wrong_key_and_fixed_iv_lengths() {
        assert_eq!(
            cipher(AeadAlgorithm::Aes128Gcm).algorithm(),
            AeadAlgorithm::Aes128Gcm
        );
        assert_eq!(
            cipher(AeadAlgorithm::Aes256Gcm).algorithm(),
            AeadAlgorithm::Aes256Gcm
        );

        assert_eq!(
            RecordCipher::new(AeadAlgorithm::Aes128Gcm, &KEY_128[..15], &FIXED_IV).err(),
            Some(RecordError::InvalidKeyLength)
        );
        assert_eq!(
            RecordCipher::new(AeadAlgorithm::Aes128Gcm, &KEY_256, &FIXED_IV).err(),
            Some(RecordError::InvalidKeyLength)
        );
        assert_eq!(
            RecordCipher::new(AeadAlgorithm::Aes256Gcm, &KEY_128, &FIXED_IV).err(),
            Some(RecordError::InvalidKeyLength)
        );
        assert_eq!(
            RecordCipher::new(AeadAlgorithm::Aes256Gcm, &KEY_256[..31], &FIXED_IV).err(),
            Some(RecordError::InvalidKeyLength)
        );
        for iv_len in [0, 3, 5, 12] {
            assert_eq!(
                RecordCipher::new(AeadAlgorithm::Aes128Gcm, &KEY_128, &[0; 12][..iv_len]).err(),
                Some(RecordError::InvalidFixedIvLength),
                "iv length {iv_len}"
            );
        }
    }

    // DTLS-CIPHER-002 — RFC 5116 nonce layout and explicit nonce layout.
    #[test]
    fn nonce_is_fixed_iv_epoch_and_sequence() {
        let cipher = cipher(AeadAlgorithm::Aes128Gcm);
        let epoch = 0x0102;
        let sequence = SequenceNumber::from_u64(0x0000_0304_0506_0708).expect("in range");
        assert_eq!(
            cipher.nonce(epoch, sequence),
            [
                0x0A, 0x0B, 0x0C, 0x0D, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
            ]
        );
        assert_eq!(
            RecordCipher::explicit_nonce(epoch, sequence),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(
            RecordCipher::explicit_nonce(0, SequenceNumber::ZERO),
            [0; AEAD_EXPLICIT_NONCE_LEN]
        );
    }

    // DTLS-CIPHER-003 — sealed layout: header, explicit nonce, ciphertext,
    // tag; AAD uses the plaintext length and the full nonce reaches the
    // provider.
    #[test]
    fn seal_emits_the_rfc_layout_and_correct_aad() {
        let cipher = cipher(AeadAlgorithm::Aes128Gcm);
        let provider = TestAead::default();
        let plaintext = b"dtls-record";
        let mut output = vec![0u8; RECORD_HEADER_LEN + AEAD_OVERHEAD + plaintext.len()];
        let written = cipher
            .seal(
                &provider,
                ContentType::Handshake,
                2,
                SEQ,
                plaintext,
                &mut output,
            )
            .expect("seal");
        assert_eq!(written, output.len());
        assert_eq!(provider.calls.get(), 1);

        let record = Record::decode_protected(&output).expect("decode sealed record");
        assert_eq!(record.header.content_type, ContentType::Handshake);
        assert_eq!(record.header.epoch, 2);
        assert_eq!(record.header.sequence_number, SEQ);
        assert_eq!(record.header.fragment_len, AEAD_OVERHEAD + plaintext.len());
        assert_eq!(
            &record.fragment[..AEAD_EXPLICIT_NONCE_LEN],
            &RecordCipher::explicit_nonce(2, SEQ)
        );
        assert_ne!(
            &record.fragment[AEAD_EXPLICIT_NONCE_LEN..AEAD_EXPLICIT_NONCE_LEN + plaintext.len()],
            plaintext
        );

        assert_eq!(provider.nonce.get(), cipher.nonce(2, SEQ));
        let aad = provider.aad.get();
        // RFC 5246 section 6.2.3.3 order: seq_num, type, version, length.
        assert_eq!(
            aad[..AEAD_EXPLICIT_NONCE_LEN],
            RecordCipher::explicit_nonce(2, SEQ)
        );
        assert_eq!(aad[AEAD_EXPLICIT_NONCE_LEN], ContentType::Handshake.to_u8());
        assert_eq!(
            aad[AEAD_EXPLICIT_NONCE_LEN + 1..AEAD_EXPLICIT_NONCE_LEN + 3],
            DTLS12_VERSION
        );
        assert_eq!(
            aad[AEAD_EXPLICIT_NONCE_LEN + 3..],
            u16::try_from(plaintext.len()).expect("fits").to_be_bytes()
        );
    }

    // DTLS-CIPHER-004 — seal then open roundtrip for both key sizes.
    #[test]
    fn seal_open_roundtrip_for_both_algorithms() {
        let provider = TestAead::default();
        for algorithm in [AeadAlgorithm::Aes128Gcm, AeadAlgorithm::Aes256Gcm] {
            let cipher = cipher(algorithm);
            for plaintext in [&b""[..], &b"x"[..], &b"a longer plaintext fragment"[..]] {
                let wire = sealed(&cipher, plaintext);
                let record = Record::decode_protected(&wire).expect("protected");
                let mut output = vec![0u8; record.fragment.len() - AEAD_EXPLICIT_NONCE_LEN];
                let opened = cipher.open(&provider, &record, &mut output).expect("open");
                assert_eq!(opened, plaintext.len());
                assert_eq!(&output[..opened], plaintext);
            }
        }
    }

    // DTLS-CIPHER-005 — the 2^14 plaintext ceiling is enforced on both sides.
    #[test]
    fn maximum_plaintext_roundtrip() {
        let cipher = cipher(AeadAlgorithm::Aes256Gcm);
        let provider = TestAead::default();
        let plaintext = vec![0x3Cu8; MAX_PLAINTEXT_LEN];
        let wire = sealed(&cipher, &plaintext);
        assert_eq!(wire.len(), RECORD_HEADER_LEN + MAX_FRAGMENT_LEN);
        let record = Record::decode_protected(&wire).expect("max protected");
        let mut output = vec![0u8; MAX_PLAINTEXT_LEN + AEAD_TAG_LEN];
        let opened = cipher.open(&provider, &record, &mut output).expect("open");
        assert_eq!(opened, MAX_PLAINTEXT_LEN);
        assert_eq!(&output[..opened], &plaintext[..]);

        let oversized = vec![0u8; MAX_PLAINTEXT_LEN + 1];
        let mut roomy = vec![0u8; RECORD_HEADER_LEN + AEAD_OVERHEAD + oversized.len()];
        assert_eq!(
            cipher.seal(
                &provider,
                ContentType::ApplicationData,
                1,
                SEQ,
                &oversized,
                &mut roomy
            ),
            Err(RecordError::RecordTooLong)
        );
    }

    // DTLS-CIPHER-006 — seal validates size before writing; provider errors
    // are mapped, and an inconsistent provider length is a backend failure.
    #[test]
    fn seal_error_paths() {
        let cipher = cipher(AeadAlgorithm::Aes128Gcm);
        let provider = TestAead::default();
        let plaintext = b"payload";

        let mut short = [0xAAu8; RECORD_HEADER_LEN + AEAD_OVERHEAD + 3];
        assert_eq!(
            cipher.seal(&provider, ContentType::Alert, 1, SEQ, plaintext, &mut short),
            Err(RecordError::OutputTooSmall)
        );
        assert_eq!(short, [0xAA; RECORD_HEADER_LEN + AEAD_OVERHEAD + 3]);
        assert_eq!(provider.calls.get(), 0);

        for (error, expected) in [
            (
                CryptoError::Unsupported,
                RecordError::Crypto(CryptoError::Unsupported),
            ),
            (CryptoError::OutputTooSmall, RecordError::OutputTooSmall),
            (
                CryptoError::AuthenticationFailed,
                RecordError::AuthenticationFailed,
            ),
            (
                CryptoError::BackendFailure,
                RecordError::Crypto(CryptoError::BackendFailure),
            ),
        ] {
            let provider = TestAead::fail_with(error);
            let mut output = vec![0u8; RECORD_HEADER_LEN + AEAD_OVERHEAD + plaintext.len()];
            assert_eq!(
                cipher.seal(
                    &provider,
                    ContentType::Alert,
                    1,
                    SEQ,
                    plaintext,
                    &mut output
                ),
                Err(expected)
            );
        }

        let mut output = vec![0u8; RECORD_HEADER_LEN + AEAD_OVERHEAD + plaintext.len()];
        assert_eq!(
            cipher.seal(
                &LyingAead,
                ContentType::Alert,
                1,
                SEQ,
                plaintext,
                &mut output
            ),
            Err(RecordError::Crypto(CryptoError::BackendFailure))
        );
    }

    // DTLS-CIPHER-007 — open rejects every malformed protected record before
    // authentication, leaving the output sentinel intact.
    #[test]
    fn open_structural_error_paths() {
        let cipher = cipher(AeadAlgorithm::Aes128Gcm);
        let provider = TestAead::default();
        let wire = sealed(&cipher, b"structural");
        let record = Record::decode_protected(&wire).expect("protected");

        let mut sentinel = [0xAAu8; 64];
        assert_eq!(
            RecordCipher::open(
                &cipher,
                &provider,
                &Record {
                    header: RecordHeader {
                        fragment_len: record.header.fragment_len + 1,
                        ..record.header
                    },
                    fragment: record.fragment,
                },
                &mut sentinel,
            ),
            Err(RecordError::LengthMismatch)
        );
        assert_eq!(sentinel, [0xAA; 64]);

        let short_fragment: &[u8] = &[0u8; AEAD_OVERHEAD - 1];
        let short = RecordHeader {
            content_type: ContentType::ApplicationData,
            epoch: 1,
            sequence_number: SEQ,
            fragment_len: short_fragment.len(),
        };
        assert_eq!(
            RecordCipher::open(
                &cipher,
                &provider,
                &Record {
                    header: short,
                    fragment: short_fragment
                },
                &mut sentinel
            ),
            Err(RecordError::CiphertextTooShort)
        );

        let mut tampered_nonce = wire.clone();
        tampered_nonce[RECORD_HEADER_LEN] ^= 0xFF;
        let tampered = Record::decode_protected(&tampered_nonce).expect("protected");
        assert_eq!(
            cipher.open(&provider, &tampered, &mut sentinel),
            Err(RecordError::InvalidExplicitNonce)
        );
        assert_eq!(sentinel, [0xAA; 64]);
        assert_eq!(provider.calls.get(), 0);

        let mut tiny = [0xAAu8; AEAD_TAG_LEN];
        assert_eq!(
            cipher.open(&provider, &record, &mut tiny),
            Err(RecordError::OutputTooSmall)
        );
        assert_eq!(tiny, [0xAA; AEAD_TAG_LEN]);
    }

    // DTLS-CIPHER-008 — a ciphertext declaring more than 2^14 plaintext is
    // rejected, even when the header itself is within the wire limit.
    #[test]
    fn open_rejects_plaintext_above_the_limit() {
        let cipher = cipher(AeadAlgorithm::Aes256Gcm);
        let provider = TestAead::default();
        let mut fragment = vec![0u8; AEAD_OVERHEAD + MAX_PLAINTEXT_LEN + 1];
        fragment[..AEAD_EXPLICIT_NONCE_LEN].copy_from_slice(&RecordCipher::explicit_nonce(1, SEQ));
        let header = RecordHeader {
            content_type: ContentType::ApplicationData,
            epoch: 1,
            sequence_number: SEQ,
            fragment_len: fragment.len(),
        };
        let mut output = vec![0xAAu8; fragment.len()];
        assert_eq!(
            cipher.open(
                &provider,
                &Record {
                    header,
                    fragment: &fragment
                },
                &mut output
            ),
            Err(RecordError::RecordTooLong)
        );
        assert!(output.iter().all(|&byte| byte == 0xAA));
    }

    // DTLS-CIPHER-009 — authentication failure never exposes plaintext; the
    // output holds the ciphertext copy and nothing past it is touched.
    #[test]
    fn open_authentication_failure_leaves_no_plaintext() {
        let cipher = cipher(AeadAlgorithm::Aes128Gcm);
        let provider = TestAead::default();
        let plaintext = b"secret payload";
        let mut wire = sealed(&cipher, plaintext);
        let ciphertext_len = wire.len() - RECORD_HEADER_LEN - AEAD_EXPLICIT_NONCE_LEN;
        let last = wire.len() - 1;
        wire[last] ^= 0x01; // corrupt the tag
        let tampered_record = Record::decode_protected(&wire).expect("protected");
        let mut output = vec![0xAAu8; ciphertext_len + 8];
        assert_eq!(
            cipher.open(&provider, &tampered_record, &mut output),
            Err(RecordError::AuthenticationFailed)
        );
        assert_eq!(
            &output[..ciphertext_len],
            &tampered_record.fragment[AEAD_EXPLICIT_NONCE_LEN..]
        );
        assert!(output[ciphertext_len..].iter().all(|&byte| byte == 0xAA));
        assert_ne!(&output[..plaintext.len()], &plaintext[..]);
    }

    // DTLS-CIPHER-010 — provider failures on open are mapped; a wrong
    // plaintext length from the provider is a backend failure.
    #[test]
    fn open_provider_error_paths() {
        let cipher = cipher(AeadAlgorithm::Aes128Gcm);
        let wire = sealed(&cipher, b"provider");
        let record = Record::decode_protected(&wire).expect("protected");
        let mut output = vec![0u8; record.fragment.len() - AEAD_EXPLICIT_NONCE_LEN];

        for (error, expected) in [
            (
                CryptoError::Unsupported,
                RecordError::Crypto(CryptoError::Unsupported),
            ),
            (
                CryptoError::AuthenticationFailed,
                RecordError::AuthenticationFailed,
            ),
            (CryptoError::OutputTooSmall, RecordError::OutputTooSmall),
        ] {
            let provider = TestAead::fail_with(error);
            assert_eq!(cipher.open(&provider, &record, &mut output), Err(expected));
        }

        assert_eq!(
            cipher.open(&LyingAead, &record, &mut output),
            Err(RecordError::Crypto(CryptoError::BackendFailure))
        );
    }

    // DTLS-CIPHER-011 — Debug never prints key or IV bytes.
    #[test]
    fn cipher_debug_redacts_secrets() {
        let cipher = cipher(AeadAlgorithm::Aes128Gcm);
        let rendered = format!("{cipher:?}");
        assert!(rendered.contains("RecordCipher"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("11, 11, 11"));
        assert!(!rendered.contains("10, 11, 12"));
    }

    // DTLS-CIPHER-012 — open_in_place is the strict sentinel-buffer entry
    // point: every failure leaves the caller's bytes untouched.
    #[test]
    fn open_in_place_preserves_the_caller_buffer_on_failure() {
        let cipher = cipher(AeadAlgorithm::Aes128Gcm);
        let provider = TestAead::default();

        let mut sentinel = [0xAAu8; 32];
        assert_eq!(
            cipher.open_in_place(&provider, ContentType::Alert, 1, SEQ, &mut sentinel),
            Err(RecordError::AuthenticationFailed)
        );
        assert_eq!(sentinel, [0xAA; 32]);

        let mut tiny = [0xAAu8; AEAD_TAG_LEN - 1];
        assert_eq!(
            cipher.open_in_place(&provider, ContentType::Alert, 1, SEQ, &mut tiny),
            Err(RecordError::CiphertextTooShort)
        );
        assert_eq!(tiny, [0xAA; AEAD_TAG_LEN - 1]);

        let failing = TestAead::fail_with(CryptoError::Unsupported);
        let mut buffer = [0xAAu8; 32];
        assert_eq!(
            cipher.open_in_place(&failing, ContentType::Alert, 1, SEQ, &mut buffer),
            Err(RecordError::Crypto(CryptoError::Unsupported))
        );
        assert_eq!(buffer, [0xAA; 32]);

        // Success path: plaintext replaces the ciphertext in place.
        let plaintext = b"in-place-api";
        let wire = sealed(&cipher, plaintext);
        let record = Record::decode_protected(&wire).expect("protected");
        let mut buffer = vec![0u8; record.fragment.len() - AEAD_EXPLICIT_NONCE_LEN];
        buffer.copy_from_slice(&record.fragment[AEAD_EXPLICIT_NONCE_LEN..]);
        let opened = cipher
            .open_in_place(&provider, ContentType::ApplicationData, 1, SEQ, &mut buffer)
            .expect("open in place");
        assert_eq!(opened, plaintext.len());
        assert_eq!(&buffer[..opened], plaintext);
    }
}

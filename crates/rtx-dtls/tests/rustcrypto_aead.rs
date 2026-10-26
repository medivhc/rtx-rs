//! AEAD record roundtrips against the real `RustCrypto` backend.

mod common;

use common::{cipher, datagram, protected_wire, provider};
use rtx_crypto::AeadAlgorithm;
use rtx_crypto_rustcrypto::RustCryptoProvider;
use rtx_dtls::{
    AEAD_OVERHEAD, MAX_PLAINTEXT_LEN, ProtocolMachine, RECORD_HEADER_LEN, Record, RecordError,
    RecordMachine, SequenceNumber,
};

const EPOCH: u16 = 1;
const ALGORITHMS: [AeadAlgorithm; 2] = [AeadAlgorithm::Aes128Gcm, AeadAlgorithm::Aes256Gcm];

// DTLS-INT-AEAD-001 — real AES-GCM seal/open roundtrip for every size
// boundary, including the empty and maximum plaintext records.
#[test]
fn rustcrypto_seal_open_roundtrip() {
    for algorithm in ALGORITHMS {
        let cipher = cipher(algorithm);
        let provider = provider();
        for plaintext in [
            Vec::new(),
            vec![0x00],
            (0..=255).collect::<Vec<u8>>(),
            vec![0xA5; MAX_PLAINTEXT_LEN],
        ] {
            let mut wire = vec![0u8; RECORD_HEADER_LEN + AEAD_OVERHEAD + plaintext.len()];
            let written = cipher
                .seal(
                    &provider,
                    rtx_dtls::ContentType::ApplicationData,
                    EPOCH,
                    SequenceNumber::from_u64(7).expect("48-bit"),
                    &plaintext,
                    &mut wire,
                )
                .expect("seal");
            assert_eq!(written, wire.len());

            let record = Record::decode_protected(&wire).expect("decode protected");
            assert_eq!(record.header.fragment_len, AEAD_OVERHEAD + plaintext.len());
            let mut output = vec![0u8; record.fragment.len() - 8];
            let opened = cipher.open(&provider, &record, &mut output).expect("open");
            assert_eq!(opened, plaintext.len());
            assert_eq!(&output[..opened], &plaintext[..]);
        }
    }
}

// DTLS-INT-AEAD-002 — the machine consumes records sealed by the real backend
// and hands the plaintext to the handshake layer.
#[test]
fn machine_accepts_rustcrypto_records() {
    let mut machine = RecordMachine::<2048, RustCryptoProvider>::new(provider());
    machine.install_cipher(cipher(AeadAlgorithm::Aes128Gcm), EPOCH);
    for (sequence, content) in [
        (0u64, &b"client hello"[..]),
        (1, b"server hello"),
        (2, b"done"),
    ] {
        let wire = protected_wire(AeadAlgorithm::Aes128Gcm, EPOCH, sequence, content);
        machine
            .handle_input(datagram(1_000 + sequence, &wire))
            .expect("machine accepts sealed record");
        let event = machine.poll_event().expect("event");
        assert_eq!(event.epoch(), EPOCH);
        assert_eq!(event.sequence_number().as_u64(), sequence);
        assert_eq!(event.plaintext(), content);
    }
    assert!(machine.poll_event().is_none());
}

// DTLS-INT-AEAD-003 — a corrupted tag never yields an event and never burns
// the sequence number.
#[test]
fn tampered_tag_is_rejected_and_retry_succeeds() {
    let mut machine = RecordMachine::<2048, RustCryptoProvider>::new(provider());
    machine.install_cipher(cipher(AeadAlgorithm::Aes256Gcm), EPOCH);

    let mut wire = protected_wire(AeadAlgorithm::Aes256Gcm, EPOCH, 0, b"authenticated");
    let last = wire.len() - 1;
    wire[last] ^= 0x80;
    assert_eq!(
        machine.handle_input(datagram(1_000, &wire)),
        Err(RecordError::AuthenticationFailed)
    );
    assert!(machine.poll_event().is_none());

    let good = protected_wire(AeadAlgorithm::Aes256Gcm, EPOCH, 0, b"authenticated");
    machine
        .handle_input(datagram(1_001, &good))
        .expect("retransmission accepted");
    assert_eq!(
        machine.poll_event().expect("event").plaintext(),
        b"authenticated"
    );
}

// DTLS-INT-AEAD-004 — the explicit nonce must equal epoch || sequence.
#[test]
fn tampered_explicit_nonce_is_rejected() {
    let mut machine = RecordMachine::<2048, RustCryptoProvider>::new(provider());
    machine.install_cipher(cipher(AeadAlgorithm::Aes128Gcm), EPOCH);
    let mut wire = protected_wire(AeadAlgorithm::Aes128Gcm, EPOCH, 3, b"bound");
    wire[RECORD_HEADER_LEN + 2] ^= 0x01;
    assert_eq!(
        machine.handle_input(datagram(1_000, &wire)),
        Err(RecordError::InvalidExplicitNonce)
    );
    assert!(machine.poll_event().is_none());
}

// DTLS-INT-AEAD-005 — a different key fails authentication rather than
// returning garbage.
#[test]
fn wrong_key_fails_authentication() {
    let wire = protected_wire(AeadAlgorithm::Aes128Gcm, EPOCH, 0, b"key binding");
    let mut machine = RecordMachine::<2048, RustCryptoProvider>::new(provider());
    let wrong_key = [0x5Au8; 16];
    let wrong_cipher =
        rtx_dtls::RecordCipher::new(AeadAlgorithm::Aes128Gcm, &wrong_key, &common::FIXED_IV)
            .expect("cipher");
    machine.install_cipher(wrong_cipher, EPOCH);
    assert_eq!(
        machine.handle_input(datagram(1_000, &wire)),
        Err(RecordError::AuthenticationFailed)
    );
    assert!(machine.poll_event().is_none());
}

// DTLS-INT-AEAD-006 — the full 2^14 plaintext record is accepted end to end.
#[test]
fn maximum_record_through_the_machine() {
    let mut machine = RecordMachine::<
        { MAX_PLAINTEXT_LEN + rtx_dtls::AEAD_TAG_LEN },
        RustCryptoProvider,
    >::new(provider());
    machine.install_cipher(cipher(AeadAlgorithm::Aes256Gcm), EPOCH);
    let payload = vec![0x5Au8; MAX_PLAINTEXT_LEN];
    let wire = protected_wire(AeadAlgorithm::Aes256Gcm, EPOCH, 0, &payload);
    machine
        .handle_input(datagram(1_000, &wire))
        .expect("maximum record");
    assert_eq!(
        machine.poll_event().expect("event").plaintext(),
        &payload[..]
    );
}

// DTLS-INT-AEAD-007 — the wire bytes match an independent AES-GCM
// computation with the RFC 5246 / RFC 5288 nonce and AAD order. This is the
// test that would catch a self-consistent but wrong AAD layout.
#[test]
fn wire_matches_an_independent_gcm_reference() {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use aes_gcm::{Aes128Gcm, Nonce};

    let epoch = 3u16;
    let sequence = SequenceNumber::from_u64(0x0000_0102_0304_0506).expect("48-bit");
    let plaintext = b"independent reference";
    let content_type = rtx_dtls::ContentType::ApplicationData;

    let mut wire = vec![0u8; RECORD_HEADER_LEN + AEAD_OVERHEAD + plaintext.len()];
    let written = cipher(AeadAlgorithm::Aes128Gcm)
        .seal(
            &provider(),
            content_type,
            epoch,
            sequence,
            plaintext,
            &mut wire,
        )
        .expect("seal");
    assert_eq!(written, wire.len());

    // RFC 5288 nonce: 4-byte salt followed by epoch || sequence.
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(&common::FIXED_IV);
    nonce_bytes[4..6].copy_from_slice(&epoch.to_be_bytes());
    nonce_bytes[6..].copy_from_slice(&sequence.to_be_bytes());

    // RFC 5246 additional data: seq_num || type || version || length.
    let mut aad = [0u8; 13];
    aad[..2].copy_from_slice(&epoch.to_be_bytes());
    aad[2..8].copy_from_slice(&sequence.to_be_bytes());
    aad[8] = content_type.to_u8();
    aad[9..11].copy_from_slice(&[254, 253]);
    aad[11..13].copy_from_slice(&u16::try_from(plaintext.len()).expect("fits").to_be_bytes());

    let gcm = Aes128Gcm::new_from_slice(&common::KEY_128).expect("key");
    let mut expected = plaintext.to_vec();
    let tag = gcm
        .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &aad, &mut expected)
        .expect("reference encryption");

    let ciphertext = &wire[RECORD_HEADER_LEN + 8..RECORD_HEADER_LEN + 8 + plaintext.len()];
    assert_eq!(ciphertext, &expected[..]);
    assert_eq!(&wire[RECORD_HEADER_LEN + 8 + plaintext.len()..], &tag[..]);
    assert_eq!(
        &wire[RECORD_HEADER_LEN..RECORD_HEADER_LEN + 8],
        &nonce_bytes[4..]
    );
}

//! L4 robustness: truncation tables, lying length fields, version/type
//! tables, deterministic random decode storms and machine storms.
//!
//! The property under test is total safety: every input either decodes into a
//! record that re-encodes verbatim, or fails with a specific [`RecordError`].
//! Nothing in between, and never a panic.

mod common;

use common::{Lcg, cipher, datagram, plaintext_wire, protected_wire, provider};
use rtx_crypto::AeadAlgorithm;
use rtx_crypto_rustcrypto::RustCryptoProvider;
use rtx_dtls::{
    ContentType, DTLS12_VERSION, MAX_FRAGMENT_LEN, MAX_PLAINTEXT_LEN, ProtocolMachine,
    RECORD_HEADER_LEN, Record, RecordError, RecordHeader, RecordMachine,
};

fn template_plaintext() -> Vec<u8> {
    plaintext_wire(5, b"dtls-record-robustness")
}

fn template_protected() -> Vec<u8> {
    protected_wire(AeadAlgorithm::Aes128Gcm, 1, 5, b"dtls-record-robustness")
}

// DTLS-ROB-001 — every strict prefix of a valid record is UnexpectedEnd.
#[test]
fn truncation_table_for_plaintext_and_protected_records() {
    for bytes in [template_plaintext(), template_protected()] {
        for len in 0..bytes.len() {
            assert_eq!(
                Record::decode(&bytes[..len]),
                Err(RecordError::UnexpectedEnd),
                "strict truncated to {len}"
            );
            assert_eq!(
                Record::decode_prefix(&bytes[..len]),
                Err(RecordError::UnexpectedEnd),
                "prefix truncated to {len}"
            );
        }
        let (record, consumed) = Record::decode_prefix(&bytes).expect("full decode");
        assert_eq!(consumed, bytes.len());
        let mut reencoded = vec![0u8; record.encoded_len()];
        let written = record.encode(&mut reencoded).expect("re-encode");
        assert_eq!(written, bytes.len());
        assert_eq!(reencoded, bytes);
    }
}

// DTLS-ROB-002 — a length field that disagrees with the datagram is rejected
// with a distinguishable error in both directions.
#[test]
fn lying_length_fields_are_rejected() {
    let bytes = template_plaintext();
    let fragment_len = bytes.len() - RECORD_HEADER_LEN;
    assert!(fragment_len > 1);

    // Declared larger than present -> truncated.
    let mut longer = bytes.clone();
    longer[11..13].copy_from_slice(&u16::try_from(fragment_len + 1).expect("fits").to_be_bytes());
    assert_eq!(Record::decode(&longer), Err(RecordError::UnexpectedEnd));
    assert_eq!(
        Record::decode_prefix(&longer),
        Err(RecordError::UnexpectedEnd)
    );

    // Declared smaller than present -> strict decode reports extra bytes,
    // prefix decode consumes only what was declared.
    let mut shorter = bytes;
    shorter[11..13].copy_from_slice(&u16::try_from(fragment_len - 1).expect("fits").to_be_bytes());
    assert_eq!(Record::decode(&shorter), Err(RecordError::LengthMismatch));
    let (record, consumed) = Record::decode_prefix(&shorter).expect("prefix");
    assert_eq!(consumed, shorter.len() - 1);
    assert_eq!(record.fragment.len(), fragment_len - 1);

    // Declared beyond the RFC 6347 fragment ceiling -> RecordTooLong.
    let mut oversized = vec![0u8; RECORD_HEADER_LEN];
    oversized[0] = ContentType::ApplicationData.to_u8();
    oversized[1..3].copy_from_slice(&DTLS12_VERSION);
    oversized[11..13].copy_from_slice(
        &u16::try_from(MAX_FRAGMENT_LEN + 1)
            .expect("fits")
            .to_be_bytes(),
    );
    assert_eq!(Record::decode(&oversized), Err(RecordError::RecordTooLong));
}

// DTLS-ROB-003 — version and content-type rejection tables.
#[test]
fn version_and_content_type_tables() {
    let bytes = template_plaintext();
    for version in [[254u8, 255u8], [3, 3], [254, 252], [0, 0], [255, 255]] {
        let mut mutated = bytes.clone();
        mutated[1..3].copy_from_slice(&version);
        assert_eq!(
            Record::decode(&mutated),
            Err(RecordError::UnsupportedVersion),
            "version {version:?}"
        );
    }
    for content_type in [0u8, 19, 24, 25, 255] {
        let mut mutated = bytes.clone();
        mutated[0] = content_type;
        assert_eq!(
            Record::decode(&mutated),
            Err(RecordError::InvalidContentType),
            "content type {content_type}"
        );
    }
}

// DTLS-ROB-004 — deterministic random byte storms over every decoder.
#[test]
fn random_bytes_never_panic_in_decoders() {
    let mut generator = Lcg::new(0x0D15_EED5_5EED_1234);
    for round in 0..4096u32 {
        let len = usize::try_from(generator.next_u64() % 320).expect("small");
        let bytes = generator.bytes(len);
        let _ = RecordHeader::decode(&bytes);
        let _ = Record::decode(&bytes);
        let _ = Record::decode_plaintext(&bytes);
        let _ = Record::decode_protected(&bytes);
        if let Ok((record, consumed)) = Record::decode_prefix(&bytes) {
            assert!(consumed <= bytes.len(), "round {round}");
            let mut output = vec![0u8; record.encoded_len()];
            assert!(record.encode(&mut output).is_ok(), "round {round}");
            assert_eq!(output, bytes[..consumed], "round {round}");
        }
    }
}

// DTLS-ROB-005 — random datagrams through a plaintext machine never panic.
#[test]
fn random_datagrams_never_panic_in_plaintext_machine() {
    let mut generator = Lcg::new(0xABCD_1234_5678_9EF0);
    let mut machine = RecordMachine::<256, RustCryptoProvider>::new(provider());
    for _ in 0..2048 {
        let len = usize::try_from(generator.next_u64() % 200).expect("small");
        let bytes = generator.bytes(len);
        let result = machine.handle_input(datagram(1_000, &bytes));
        while machine.poll_event().is_some() {}
        if let Ok(()) = result {
            // Random bytes almost never form a record; success is fine.
        }
    }
}

// DTLS-ROB-006 — bit-flipped valid protected records through a fresh machine.
#[test]
fn mutated_protected_records_never_panic_and_never_leak_plaintext() {
    let mut generator = Lcg::new(0xFEED_FACE_CAFE_BEEF);
    let plaintext: &[u8] = b"never leaked";
    for round in 0..512u32 {
        let mut wire = protected_wire(AeadAlgorithm::Aes128Gcm, 1, 0, plaintext);
        let flips = 1 + generator.next_u64() % 3;
        for _ in 0..flips {
            let index = usize::try_from(generator.next_u64() % wire.len() as u64)
                .expect("bounded by wire length");
            wire[index] ^= 1 << (generator.next_u64() % 8);
        }
        let mut machine = RecordMachine::<256, RustCryptoProvider>::new(provider());
        machine.install_cipher(cipher(AeadAlgorithm::Aes128Gcm), 1);
        let _ = machine.handle_input(datagram(1_000, &wire));
        if let Some(event) = machine.poll_event() {
            // Only an unmodified record can authenticate; if a flip landed on
            // bytes outside the authenticated region this cannot happen, but
            // assert that no corrupted plaintext escapes either way.
            assert_eq!(event.plaintext(), plaintext, "round {round}");
        }
    }
}

// DTLS-ROB-007 — coalesced record walks stop at the first malformed record
// without losing the records accepted before it.
#[test]
fn malformed_tail_keeps_earlier_records() {
    let mut bytes = plaintext_wire(0, b"first");
    bytes.extend_from_slice(&plaintext_wire(1, b"second"));
    let accepted_len = bytes.len();
    bytes.extend_from_slice(&[0x00, 0x01]); // not a record
    let mut machine = RecordMachine::<256, RustCryptoProvider>::new(provider());
    assert_eq!(
        machine.handle_input(datagram(1_000, &bytes)),
        Err(RecordError::UnexpectedEnd)
    );
    assert_eq!(machine.poll_event().expect("first").plaintext(), b"first");
    assert_eq!(machine.poll_event().expect("second").plaintext(), b"second");
    assert!(machine.poll_event().is_none());
    assert_eq!(accepted_len, RECORD_HEADER_LEN * 2 + 5 + 6);
}

// DTLS-ROB-008 — plaintext and protected mode bounds are enforced for random
// accepted records.
#[test]
fn random_valid_records_roundtrip_through_the_machine() {
    let mut generator = Lcg::new(0x1357_9BDF_2468_ACE0);
    let mut machine =
        RecordMachine::<{ MAX_PLAINTEXT_LEN + 1 }, RustCryptoProvider>::new(provider());
    for sequence in 0..64u64 {
        let len = usize::try_from(generator.next_u64() % 1024).expect("small");
        let content = generator.bytes(len);
        let wire = plaintext_wire(sequence, &content);
        machine
            .handle_input(datagram(1_000, &wire))
            .expect("valid random record");
        assert_eq!(
            machine.poll_event().expect("event").plaintext(),
            &content[..]
        );
    }
    assert!(machine.poll_event().is_none());
}

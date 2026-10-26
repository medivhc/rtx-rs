//! OpenSSL 3.0.13 differential vectors.
//!
//! The `ClientHello` bytes below were captured on 2026-10-27 by running a
//! stock OpenSSL DTLS server and client:
//!
//! ```text
//! openssl s_server -dtls1_2 -listen -accept 33447 \
//!   -cert cert.pem -key key.pem \
//!   -use_srtp SRTP_AES128_CM_SHA1_80 -msg -state
//!
//! openssl s_client -dtls1_2 -connect 127.0.0.1:33447 \
//!   -use_srtp SRTP_AES128_CM_SHA1_80 -msg
//! ```
//!
//! OpenSSL puts this first `ClientHello` in a record with version `{254, 255}`
//! (DTLS 1.0 compatibility). R2-1 deliberately rejects that version, so the
//! differential below checks two separate facts:
//!
//! 1. the real OpenSSL handshake message parses and negotiates in this
//!    profile when re-wrapped in a `{254, 253}` record;
//! 2. the original `{254, 255}` record is rejected, which is recorded as a
//!    gap rather than claimed as interoperability.

mod common;

use common::handshake::{HandshakeCrypto, SERVER_SIGNING_KEY};
use rtx_dtls::{
    ContentType, DTLS12_VERSION, HandshakeConfig, HandshakeMachine, HandshakeState, HandshakeType,
    MAX_HANDSHAKE_RECORD_LEN, OfferedAlgorithms, ProtocolMachine, RECORD_HEADER_LEN, Record,
    RecordError, RecordHeader, SRTP_EXPORT_LEN, SRTP_MASTER_KEY_LEN, SRTP_MASTER_SALT_LEN,
    SequenceNumber,
};

/// Complete `ClientHello` handshake message captured from OpenSSL's `-msg`
/// dump: 12-byte DTLS handshake header plus 189-byte body.
const OPENSSL_CLIENT_HELLO_HEX: &str = concat!(
    "010000bd00000000000000bdfefdcab8a58ff90a6262d49f712b0b1e1d66acff102a806093",
    "438d58faa0c47afefb00000038c02cc030009fcca9cca8ccaac02bc02f009ec024c028006b",
    "c023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff0100005b00",
    "0b000403000102000a000c000a001d0017001e0019001800230000000e0005000200010000",
    "16000000170000000d002a0028040305030603080708080809080a080b0804080508060401",
    "05010601030303010302040205020602"
);

fn hex_bytes(input: &str) -> Vec<u8> {
    let mut output = vec![0u8; input.len() / 2];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&input[offset..offset + 2], 16).expect("hex");
    }
    output
}

fn record_with_version(version: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let header = RecordHeader {
        content_type: ContentType::Handshake,
        epoch: 0,
        sequence_number: SequenceNumber::ZERO,
        fragment_len: payload.len(),
    };
    let mut output = vec![0u8; RECORD_HEADER_LEN + payload.len()];
    Record {
        header,
        fragment: payload,
    }
    .encode(&mut output)
    .expect("encode");
    output[1..3].copy_from_slice(&version);
    output
}

// DTLS-HS-OPENSSL-001 — the captured OpenSSL ClientHello parses with every
// profile offer present.
#[test]
fn openssl_client_hello_parses_with_required_offers() {
    let bytes = hex_bytes(OPENSSL_CLIENT_HELLO_HEX);
    assert_eq!(bytes.len(), 201);
    let message = rtx_dtls::decode_handshake_message(&bytes).expect("OpenSSL ClientHello");
    assert_eq!(message.message_type, HandshakeType::ClientHello);
    assert_eq!(message.message_seq, 0);
    assert_eq!(message.body.len(), 189);

    let info = rtx_dtls::parse_client_hello(&message).expect("parse");
    assert_eq!(info.session_id_len, 0);
    assert_eq!(info.cookie_len, 0);
    assert_eq!(info.cipher_suite_count, 28);
    assert_eq!(info.extension_count, 7);
    assert_eq!(info.offers, OfferedAlgorithms::REQUIRED);
    assert!(info.offers.contains(OfferedAlgorithms::CIPHER_SUITE));
    assert!(info.offers.contains(OfferedAlgorithms::X25519));
    assert!(info.offers.contains(OfferedAlgorithms::ED25519));
    assert!(
        info.offers
            .contains(OfferedAlgorithms::SRTP_AES128_CM_HMAC_SHA1_80)
    );
}

// DTLS-HS-OPENSSL-002 — the original record version is rejected by R2-1, and
// the message necessarily succeeds only after re-wrapping in {254, 253}.
#[test]
fn openssl_record_version_is_a_recorded_gap() {
    let payload = hex_bytes(OPENSSL_CLIENT_HELLO_HEX);
    let original = record_with_version([254, 255], &payload);
    assert_eq!(
        Record::decode(&original),
        Err(RecordError::UnsupportedVersion)
    );

    let wrapped = record_with_version(DTLS12_VERSION, &payload);
    let record = Record::decode(&wrapped).expect("DTLS 1.2 record");
    assert_eq!(record.header.epoch, 0);
    assert_eq!(record.fragment, &payload[..]);
}

// DTLS-HS-OPENSSL-003 — a server accepts the re-wrapped OpenSSL ClientHello,
// negotiates the profile and emits its flight.
#[test]
fn openssl_client_hello_negotiates_with_the_server_machine() {
    let payload = hex_bytes(OPENSSL_CLIENT_HELLO_HEX);
    let wrapped = record_with_version(DTLS12_VERSION, &payload);
    let mut server = HandshakeMachine::new(
        HandshakeCrypto::new(0x0D15_EE01),
        HandshakeConfig::server(),
        Some(&SERVER_SIGNING_KEY),
    )
    .expect("server");
    server
        .handle_input(rtx_dtls::Input::Datagram {
            meta: common::meta(1_000),
            payload: &wrapped,
        })
        .expect("OpenSSL ClientHello negotiated");
    assert_eq!(server.state(), HandshakeState::WaitClientKeyExchange);

    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    let mut message_types = Vec::new();
    while let Some(len) = server.poll_transmit(&mut buffer).expect("server flight") {
        let record = Record::decode(&buffer[..len]).expect("record");
        message_types.push(record.fragment[0]);
    }
    assert_eq!(
        message_types,
        [
            HandshakeType::ServerHello.to_u8(),
            HandshakeType::ServerKeyExchange.to_u8(),
            HandshakeType::ServerHelloDone.to_u8()
        ]
    );
}

// DTLS-HS-OPENSSL-004 — the RFC 5764 export length is pinned and matches the
// OpenSSL `TLS1-PRF` vector used in the unit test.
#[test]
fn srtp_export_length_matches_rfc5764() {
    assert_eq!(SRTP_MASTER_KEY_LEN, 16);
    assert_eq!(SRTP_MASTER_SALT_LEN, 14);
    assert_eq!(SRTP_EXPORT_LEN, 2 * (16 + 14));
    assert_eq!(SRTP_EXPORT_LEN, 60);
    assert_eq!(rtx_dtls::DTLS_SRTP_EXPORTER_LABEL, b"EXTRACTOR-dtls_srtp");
}

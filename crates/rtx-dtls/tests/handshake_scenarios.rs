//! DTLS 1.2 handshake scenarios: the minimal profile, retransmission, timer
//! expiry and every required failure path.
//!
//! The provider is deterministic; hash, HMAC and AEAD are the real `RustCrypto`
//! implementations from `common::handshake`.

mod common;

use common::handshake::{HandshakeCrypto, SERVER_SIGNING_KEY, TestSigningKey, signing_public};
use common::{datagram, meta};
use rtx_crypto::CryptoError;
use rtx_dtls::{
    ContentType, DTLS12_VERSION, HandshakeConfig, HandshakeError, HandshakeEvent, HandshakeMachine,
    HandshakeState, HandshakeType, Input, MAX_HANDSHAKE_RECORD_LEN, ProtocolMachine, Record,
    RecordHeader, SequenceNumber, SrtpExportError, SrtpKeyingMaterial, Timestamp,
};

type Machine = HandshakeMachine<HandshakeCrypto>;

fn make_client(provider: HandshakeCrypto) -> Machine {
    HandshakeMachine::new(
        provider,
        HandshakeConfig::client(common::handshake::server_signing_public()),
        None,
    )
    .expect("client machine")
}

fn make_server(provider: HandshakeCrypto) -> Machine {
    HandshakeMachine::new(
        provider,
        HandshakeConfig::server(),
        Some(&SERVER_SIGNING_KEY),
    )
    .expect("server machine")
}

fn plaintext_record(
    content_type: ContentType,
    epoch: u16,
    sequence: u64,
    payload: &[u8],
) -> Vec<u8> {
    let header = RecordHeader {
        content_type,
        epoch,
        sequence_number: SequenceNumber::from_u64(sequence).expect("48-bit"),
        fragment_len: payload.len(),
    };
    let mut output = vec![0u8; rtx_dtls::RECORD_HEADER_LEN + payload.len()];
    Record {
        header,
        fragment: payload,
    }
    .encode(&mut output)
    .expect("encode record");
    output
}

fn handshake_message(message_type: u8, sequence: u16, body: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; rtx_dtls::HANDSHAKE_HEADER_LEN + body.len()];
    output[0] = message_type;
    let length = u32::try_from(body.len()).expect("small");
    output[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
    output[4..6].copy_from_slice(&sequence.to_be_bytes());
    output[9..12].copy_from_slice(&length.to_be_bytes()[1..]);
    output[rtx_dtls::HANDSHAKE_HEADER_LEN..].copy_from_slice(body);
    output
}

/// Drives both machines to completion, returning the first error.
fn drive(client: &mut Machine, server: &mut Machine, now: &mut u64) -> Result<(), HandshakeError> {
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    for _ in 0..32 {
        while let Some(len) = client.poll_transmit(&mut buffer)? {
            server.handle_input(datagram(*now, &buffer[..len]))?;
        }
        while let Some(len) = server.poll_transmit(&mut buffer)? {
            client.handle_input(datagram(*now, &buffer[..len]))?;
        }
        if client.is_established() && server.is_established() {
            return Ok(());
        }
        *now = now.saturating_add(1);
    }
    Err(HandshakeError::Timeout)
}

fn decode_owned(bytes: &[u8]) -> (RecordHeader, Vec<u8>) {
    let record = Record::decode(bytes).expect("single record");
    (record.header, record.fragment.to_vec())
}

fn established_material(machine: &mut Machine) -> ([u8; 16], [u8; 16], [u8; 14], [u8; 14]) {
    match machine.poll_event().expect("established event") {
        HandshakeEvent::Established { keying_material } => material_tuple(&keying_material),
    }
}

fn material_tuple(material: &SrtpKeyingMaterial) -> ([u8; 16], [u8; 16], [u8; 14], [u8; 14]) {
    (
        *material.client_write_key(),
        *material.server_write_key(),
        *material.client_write_salt(),
        *material.server_write_salt(),
    )
}

// DTLS-HS-INT-001 — the minimal handshake establishes both sides and both
// derive the same DTLS-SRTP keying material.
#[test]
fn minimal_handshake_establishes_both_sides() {
    let mut client = make_client(HandshakeCrypto::new(0x1111_2222_3333_4444));
    let mut server = make_server(HandshakeCrypto::new(0x5555_6666_7777_8888));
    let mut now = 1_000u64;
    drive(&mut client, &mut server, &mut now).expect("handshake");

    assert_eq!(client.state(), HandshakeState::Established);
    assert_eq!(server.state(), HandshakeState::Established);
    assert_eq!(client.role(), rtx_dtls::Role::Client);
    assert_eq!(server.role(), rtx_dtls::Role::Server);
    let client_material = established_material(&mut client);
    let server_material = established_material(&mut server);
    assert_eq!(client_material, server_material);
    assert!(client.poll_event().is_none());
    assert!(server.poll_event().is_none());
    assert!(client.next_wakeup().is_none());

    // The server keeps its final flight retransmittable for a bounded budget.
    let wakeup = server.next_wakeup().expect("final flight timer");
    server
        .handle_input(Input::Timeout(wakeup))
        .expect("final flight retransmission accepted");
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    let mut records = 0usize;
    while let Some(len) = server.poll_transmit(&mut buffer).expect("retransmit") {
        client
            .handle_input(datagram(now, &buffer[..len]))
            .expect("established client ignores retransmission");
        records += 1;
    }
    assert_eq!(records, 2, "CCS plus Finished");
}

// DTLS-HS-INT-002 — record retransmission uses a fresh record sequence number
// but keeps the handshake message bytes.
#[test]
fn client_retransmits_with_a_fresh_record_sequence() {
    let mut client = make_client(HandshakeCrypto::new(0x0A0B_0C0D));
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    let first_len = client
        .poll_transmit(&mut buffer)
        .expect("first transmit")
        .expect("ClientHello");
    let (first_header, first_fragment) = decode_owned(&buffer[..first_len]);
    assert_eq!(first_header.epoch, 0);
    assert_eq!(first_header.sequence_number.as_u64(), 0);

    let wakeup = client.next_wakeup().expect("retransmission timer");
    client
        .handle_input(Input::Timeout(wakeup))
        .expect("timeout");
    let second_len = client
        .poll_transmit(&mut buffer)
        .expect("second transmit")
        .expect("ClientHello retransmission");
    let (second_header, second_fragment) = decode_owned(&buffer[..second_len]);
    assert_eq!(second_header.sequence_number.as_u64(), 1);
    assert_eq!(second_fragment, first_fragment);
}

// DTLS-HS-INT-003 — a retransmitted ClientHello makes the server resend its
// flight with new record sequence numbers.
#[test]
fn duplicate_client_hello_resends_the_server_flight() {
    let mut client = make_client(HandshakeCrypto::new(0x1010_2020));
    let mut server = make_server(HandshakeCrypto::new(0x3030_4040));
    let mut now = 5_000u64;
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    let first_len = client
        .poll_transmit(&mut buffer)
        .expect("client hello")
        .expect("record");
    let first_hello = buffer[..first_len].to_vec();
    server
        .handle_input(datagram(now, &first_hello))
        .expect("first hello");

    let mut first_flight = Vec::new();
    while let Some(len) = server.poll_transmit(&mut buffer).expect("server flight") {
        first_flight.push(buffer[..len].to_vec());
    }
    assert_eq!(first_flight.len(), 3, "ServerHello, SKE, ServerHelloDone");

    let wakeup = client.next_wakeup().expect("client timer");
    client
        .handle_input(Input::Timeout(wakeup))
        .expect("client timeout");
    let retry_len = client
        .poll_transmit(&mut buffer)
        .expect("retry")
        .expect("record");
    now = now.saturating_add(wakeup.as_micros());
    server
        .handle_input(datagram(now, &buffer[..retry_len]))
        .expect("duplicate hello");

    for expected in first_flight {
        let len = server
            .poll_transmit(&mut buffer)
            .expect("resend")
            .expect("record");
        let actual = &buffer[..len];
        let expected_record = Record::decode(&expected).expect("first record");
        let actual_record = Record::decode(actual).expect("second record");
        assert_eq!(
            actual_record.header.sequence_number.as_u64(),
            expected_record.header.sequence_number.as_u64() + 3
        );
        assert_eq!(actual_record.fragment, expected_record.fragment);
    }
    assert!(
        server
            .poll_transmit(&mut buffer)
            .expect("drained")
            .is_none()
    );
}

// DTLS-HS-INT-004 — the retransmission budget expires into a terminal timeout.
#[test]
fn retransmission_budget_exhaustion_aborts() {
    let mut config = HandshakeConfig::client(common::handshake::server_signing_public());
    config.initial_retransmit = rtx_core::Duration::from_millis(1);
    config.max_retransmit = rtx_core::Duration::from_millis(1);
    config.max_retransmissions = 1;
    let mut client = HandshakeMachine::new(HandshakeCrypto::new(7), config, None).expect("machine");
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    client
        .poll_transmit(&mut buffer)
        .expect("transmit")
        .expect("hello");

    let first = client.next_wakeup().expect("timer");
    client
        .handle_input(Input::Timeout(first))
        .expect("first retry");
    client
        .poll_transmit(&mut buffer)
        .expect("retransmit")
        .expect("hello");
    let second = client.next_wakeup().expect("second timer");
    assert_eq!(
        client.handle_input(Input::Timeout(second)),
        Err(HandshakeError::Timeout)
    );
    assert_eq!(client.state(), HandshakeState::Failed);
    assert!(client.poll_transmit(&mut buffer).is_err());
}

// DTLS-HS-INT-005 — a wrong provisioned server key is a strict signature
// failure.
#[test]
fn server_key_exchange_signature_failure_aborts() {
    let mut client = HandshakeMachine::new(
        HandshakeCrypto::new(0xAAAA),
        HandshakeConfig::client(signing_public(TestSigningKey(0xBAD))),
        None,
    )
    .expect("client");
    let mut server = make_server(HandshakeCrypto::new(0xBBBB));
    let mut now = 1u64;
    assert_eq!(
        drive(&mut client, &mut server, &mut now),
        Err(HandshakeError::InvalidSignature)
    );
    assert_eq!(client.state(), HandshakeState::Failed);
}

// DTLS-HS-INT-006 — an all-zero/InvalidKey agreement aborts and wipes state.
#[test]
fn zero_shared_secret_aborts() {
    let mut client = make_client(HandshakeCrypto::new(0xCCCC));
    let mut server = make_server(HandshakeCrypto::new(0xDDDD).with_zero_shared_secret());
    let mut now = 1u64;
    assert_eq!(
        drive(&mut client, &mut server, &mut now),
        Err(HandshakeError::ZeroSharedSecret)
    );
    assert_eq!(server.state(), HandshakeState::Failed);
}

// DTLS-HS-INT-007 — Finished verify_data mismatch aborts after successful
// record authentication.
#[test]
fn finished_verify_data_mismatch_aborts() {
    let mut client = make_client(HandshakeCrypto::new(0xEEEE).with_corrupt_server_finished());
    let mut server = make_server(HandshakeCrypto::new(0xFFFF));
    let mut now = 1u64;
    assert_eq!(
        drive(&mut client, &mut server, &mut now),
        Err(HandshakeError::FinishedMismatch)
    );
    assert_eq!(client.state(), HandshakeState::Failed);
}

// DTLS-HS-INT-008 — SRTP export failure aborts and never falls back.
#[test]
fn srtp_export_failure_aborts() {
    let mut client = make_client(HandshakeCrypto::new(0x1234).with_failing_srtp_export());
    let mut server = make_server(HandshakeCrypto::new(0x5678));
    let mut now = 1u64;
    assert_eq!(
        drive(&mut client, &mut server, &mut now),
        Err(HandshakeError::SrtpExport(SrtpExportError::Crypto(
            CryptoError::BackendFailure
        )))
    );
    assert_eq!(client.state(), HandshakeState::Failed);
}

// DTLS-HS-INT-009 — a key-schedule provider failure aborts the handshake.
#[test]
fn key_schedule_provider_failure_aborts() {
    let mut client = make_client(HandshakeCrypto::new(0x9ABC).with_failing_hmac());
    let mut server = make_server(HandshakeCrypto::new(0xDEF0));
    let mut now = 1u64;
    assert_eq!(
        drive(&mut client, &mut server, &mut now),
        Err(HandshakeError::Crypto(CryptoError::BackendFailure))
    );
}

// DTLS-HS-INT-010 — a protected Finished with a corrupted tag is rejected by
// the record layer before verify_data is checked.
#[test]
fn tampered_finished_record_aborts() {
    let mut client = make_client(HandshakeCrypto::new(0x0102));
    let mut server = make_server(HandshakeCrypto::new(0x0304));
    let now = 1u64;
    // Deliver the server flight first.
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    while let Some(len) = client.poll_transmit(&mut buffer).expect("client") {
        server
            .handle_input(datagram(now, &buffer[..len]))
            .expect("hello");
    }
    let mut flight = Vec::new();
    while let Some(len) = server.poll_transmit(&mut buffer).expect("server") {
        flight.push(buffer[..len].to_vec());
    }
    for record in &flight {
        client
            .handle_input(datagram(now, record))
            .expect("server flight");
    }
    // Client flight: CKE, CCS, Finished.
    let mut client_flight = Vec::new();
    while let Some(len) = client.poll_transmit(&mut buffer).expect("client flight") {
        client_flight.push(buffer[..len].to_vec());
    }
    assert_eq!(client_flight.len(), 3);
    // Corrupt the last byte (the GCM tag) of the Finished record.
    let mut tampered = client_flight.pop().expect("finished");
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    for record in &client_flight {
        server
            .handle_input(datagram(now, record))
            .expect("earlier records");
    }
    assert_eq!(
        server.handle_input(datagram(now, &tampered)),
        Err(HandshakeError::Record(
            rtx_dtls::RecordError::AuthenticationFailed
        ))
    );
    assert_eq!(server.state(), HandshakeState::Failed);
}

// DTLS-HS-INT-011 — malformed, unexpected and unsupported messages never panic
// and are rejected with specific errors.
#[test]
fn malformed_and_unexpected_messages_are_rejected() {
    let mut client = make_client(HandshakeCrypto::new(0x1111));
    let unexpected = plaintext_record(
        ContentType::Handshake,
        0,
        0,
        &handshake_message(HandshakeType::ServerHelloDone.to_u8(), 0, &[]),
    );
    assert_eq!(
        client.handle_input(datagram(1_000, &unexpected)),
        Err(HandshakeError::UnexpectedMessage)
    );
    assert_eq!(client.state(), HandshakeState::Failed);
    assert_eq!(
        client.handle_input(datagram(1_001, &unexpected)),
        Err(HandshakeError::Failed)
    );

    let mut server_ccs = make_server(HandshakeCrypto::new(0x2222));
    let ccs = plaintext_record(ContentType::ChangeCipherSpec, 0, 0, &[1]);
    assert_eq!(
        server_ccs.handle_input(datagram(1_000, &ccs)),
        Err(HandshakeError::UnexpectedChangeCipherSpec)
    );

    let mut server_alert = make_server(HandshakeCrypto::new(0x2222));
    let alert = plaintext_record(ContentType::Alert, 0, 0, &[2, 40]);
    assert_eq!(
        server_alert.handle_input(datagram(1_000, &alert)),
        Err(HandshakeError::PeerAlert)
    );

    let mut server_app = make_server(HandshakeCrypto::new(0x2222));
    let app_data = plaintext_record(ContentType::ApplicationData, 0, 0, b"data");
    assert_eq!(
        server_app.handle_input(datagram(1_000, &app_data)),
        Err(HandshakeError::UnexpectedRecord)
    );

    let mut server_fragmented = make_server(HandshakeCrypto::new(0x2222));
    let fragmented = {
        let mut message = handshake_message(HandshakeType::ClientHello.to_u8(), 0, &[]);
        message[6..9].copy_from_slice(&[0, 0, 1]);
        plaintext_record(ContentType::Handshake, 0, 0, &message)
    };
    assert_eq!(
        server_fragmented.handle_input(datagram(1_000, &fragmented)),
        Err(HandshakeError::FragmentedMessage)
    );

    let mut server_unsupported = make_server(HandshakeCrypto::new(0x2222));
    let unsupported =
        plaintext_record(ContentType::Handshake, 0, 0, &handshake_message(99, 0, &[]));
    assert_eq!(
        server_unsupported.handle_input(datagram(1_000, &unsupported)),
        Err(HandshakeError::UnsupportedMessage(99))
    );

    let mut server_sequence = make_server(HandshakeCrypto::new(0x2222));
    let wrong_sequence = plaintext_record(
        ContentType::Handshake,
        0,
        0,
        &handshake_message(HandshakeType::ClientHello.to_u8(), 5, &[]),
    );
    assert_eq!(
        server_sequence.handle_input(datagram(1_000, &wrong_sequence)),
        Err(HandshakeError::UnexpectedMessageSequence {
            expected: 0,
            received: 5
        })
    );

    let mut server_version = make_server(HandshakeCrypto::new(0x2222));
    let mut wrong_version = plaintext_record(
        ContentType::Handshake,
        0,
        0,
        &handshake_message(HandshakeType::ClientHello.to_u8(), 0, &[]),
    );
    wrong_version[1..3].copy_from_slice(&[254, 255]);
    assert_eq!(
        server_version.handle_input(datagram(1_000, &wrong_version)),
        Err(HandshakeError::Record(
            rtx_dtls::RecordError::UnsupportedVersion
        ))
    );

    let mut server_truncated = make_server(HandshakeCrypto::new(0x2222));
    let truncated = plaintext_record(
        ContentType::Handshake,
        0,
        0,
        &handshake_message(HandshakeType::ClientHello.to_u8(), 0, &[0xFE]),
    );
    assert_eq!(
        server_truncated.handle_input(datagram(1_000, &truncated)),
        Err(HandshakeError::MalformedMessage)
    );
}

// DTLS-HS-INT-012 — a replay of the same record is ignored without advancing
// the handshake.
#[test]
fn replayed_client_hello_is_ignored() {
    let mut client = make_client(HandshakeCrypto::new(0x3333));
    let mut server = make_server(HandshakeCrypto::new(0x4444));
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    let len = client
        .poll_transmit(&mut buffer)
        .expect("client")
        .expect("hello");
    let hello = buffer[..len].to_vec();
    server.handle_input(datagram(1_000, &hello)).expect("hello");
    assert_eq!(server.state(), HandshakeState::WaitClientKeyExchange);
    server
        .handle_input(datagram(1_001, &hello))
        .expect("replay ignored");
    assert_eq!(server.state(), HandshakeState::WaitClientKeyExchange);
}

// DTLS-HS-INT-013 — invalid constructor configurations are rejected.
#[test]
fn invalid_configurations_are_rejected() {
    let peer = common::handshake::server_signing_public();

    let mut zero_initial = HandshakeConfig::client(peer);
    zero_initial.initial_retransmit = rtx_core::Duration::ZERO;
    assert_eq!(
        HandshakeMachine::new(HandshakeCrypto::new(1), zero_initial, None).err(),
        Some(HandshakeError::InvalidConfig)
    );

    let mut inverted = HandshakeConfig::client(peer);
    inverted.initial_retransmit = rtx_core::Duration::from_millis(2);
    inverted.max_retransmit = rtx_core::Duration::from_millis(1);
    assert_eq!(
        HandshakeMachine::new(HandshakeCrypto::new(1), inverted, None).err(),
        Some(HandshakeError::InvalidConfig)
    );

    let mut no_peer = HandshakeConfig::client(peer);
    no_peer.peer_public_key = None;
    assert_eq!(
        HandshakeMachine::new(HandshakeCrypto::new(1), no_peer, None).err(),
        Some(HandshakeError::MissingPeerPublicKey)
    );

    assert_eq!(
        HandshakeMachine::new(HandshakeCrypto::new(1), HandshakeConfig::server(), None).err(),
        Some(HandshakeError::MissingSigningKey)
    );
}

// DTLS-HS-INT-014 — short output buffers and a tiny record payload fail
// without panicking or advancing the flight.
#[test]
fn transmit_buffer_and_payload_limits() {
    let mut client = make_client(HandshakeCrypto::new(0x5555));
    let mut tiny = [0u8; 10];
    assert_eq!(
        client.poll_transmit(&mut tiny),
        Err(HandshakeError::Record(
            rtx_dtls::RecordError::OutputTooSmall
        ))
    );
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    assert!(
        client
            .poll_transmit(&mut buffer)
            .expect("transmit")
            .is_some()
    );

    let mut server = make_server(HandshakeCrypto::new(0x6666));
    let huge = vec![0u8; rtx_dtls::MAX_HANDSHAKE_MESSAGE_LEN + 1];
    let record = plaintext_record(ContentType::Handshake, 0, 0, &huge);
    assert_eq!(
        server.handle_input(datagram(1_000, &record)),
        Err(HandshakeError::Record(rtx_dtls::RecordError::RecordTooLong))
    );
}

// DTLS-HS-INT-015 — after establishment the client ignores further datagrams
// and the server ignores application data, without recreating events.
#[test]
fn established_machines_are_quiet() {
    let mut client = make_client(HandshakeCrypto::new(0x7777));
    let mut server = make_server(HandshakeCrypto::new(0x8888));
    let mut now = 1u64;
    drive(&mut client, &mut server, &mut now).expect("handshake");
    let _ = established_material(&mut client);
    let _ = established_material(&mut server);

    let app = plaintext_record(ContentType::ApplicationData, 0, 99, b"ignored");
    client
        .handle_input(datagram(now, &app))
        .expect("client ignores after establishment");
    server
        .handle_input(datagram(now, &app))
        .expect("server ignores after establishment");
    assert!(client.poll_event().is_none());
    assert!(server.poll_event().is_none());
    assert!(!format!("{client:?}").is_empty());
}

// DTLS-HS-INT-016 — a datagram with several records is walked in order.
#[test]
fn coalesced_records_are_accepted_until_the_first_error() {
    let mut client = make_client(HandshakeCrypto::new(0x9999));
    let mut server = make_server(HandshakeCrypto::new(0xAAAA));
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    let len = client
        .poll_transmit(&mut buffer)
        .expect("client")
        .expect("hello");
    let mut datagram_bytes = buffer[..len].to_vec();
    datagram_bytes.extend_from_slice(&[0x00]);
    assert_eq!(
        server.handle_input(Input::Datagram {
            meta: meta(1_000),
            payload: &datagram_bytes,
        }),
        Err(HandshakeError::Record(rtx_dtls::RecordError::UnexpectedEnd))
    );
    // A handshake error is terminal even when an earlier record in the same
    // datagram was accepted.
    assert_eq!(server.state(), HandshakeState::Failed);
}

// DTLS-HS-INT-017 — deterministic random datagrams never panic the machine.
#[test]
fn random_datagrams_never_panic() {
    let mut state = 0xC0DE_1234_5678_9ABCu64;
    let mut next = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        state
    };
    let mut server = make_server(HandshakeCrypto::new(0xAAAA_BBBB));
    for _ in 0..512 {
        let len = usize::try_from(next() % 160).expect("small");
        let mut bytes = vec![0u8; len];
        for byte in &mut bytes {
            *byte = u8::try_from(next() & 0xFF).expect("byte");
        }
        let _ = server.handle_input(datagram(1_000, &bytes));
        if server.state() == HandshakeState::Failed {
            break;
        }
    }
}

// DTLS-HS-INT-018 — the record version is pinned to DTLS 1.2 and the record
// header is exposed unchanged by the handshake layer.
#[test]
fn record_version_is_strict_dtls12() {
    assert_eq!(DTLS12_VERSION, [254, 253]);
    let mut client = make_client(HandshakeCrypto::new(0xBBBB_CCCC));
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    let len = client
        .poll_transmit(&mut buffer)
        .expect("transmit")
        .expect("hello");
    let record = Record::decode(&buffer[..len]).expect("record");
    assert_eq!(record.header.content_type, ContentType::Handshake);
    assert_eq!(record.header.epoch, 0);
    assert_eq!(record.fragment[0], HandshakeType::ClientHello.to_u8());
}

// DTLS-HS-INT-019 — the server rejects a ClientHello without the SRTP
// extension rather than silently skipping key export.
#[test]
fn client_hello_without_use_srtp_is_rejected() {
    let mut client = make_client(HandshakeCrypto::new(0xDDDD_EEEE));
    let mut server = make_server(HandshakeCrypto::new(0xFFFF_1111));
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    let len = client
        .poll_transmit(&mut buffer)
        .expect("transmit")
        .expect("hello");
    let record = Record::decode(&buffer[..len]).expect("record");
    let mut payload = record.fragment.to_vec();
    // The use_srtp extension is the last extension; retype it to 0x000B.
    let extension_start = payload.len() - 9;
    payload[extension_start..extension_start + 2].copy_from_slice(&0x000Bu16.to_be_bytes());
    let replaced = plaintext_record(ContentType::Handshake, 0, 0, &payload);
    assert_eq!(
        server.handle_input(datagram(1_000, &replaced)),
        Err(HandshakeError::NoCommonAlgorithm)
    );
}

/// Delivers `ClientHello` to a server and the whole server flight back to the
/// client, leaving the client in `WaitServerFinished`.
fn deliver_server_flight(client: &mut Machine, server: &mut Machine, now: u64) {
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    while let Some(len) = client.poll_transmit(&mut buffer).expect("client hello") {
        server
            .handle_input(datagram(now, &buffer[..len]))
            .expect("server accepts hello");
    }
    while let Some(len) = server.poll_transmit(&mut buffer).expect("server flight") {
        client
            .handle_input(datagram(now, &buffer[..len]))
            .expect("client accepts server flight");
    }
    assert_eq!(client.state(), HandshakeState::WaitServerFinished);
}

fn client_with_read_cipher(seed: u64) -> Machine {
    let mut client = make_client(HandshakeCrypto::new(seed));
    let mut server = make_server(HandshakeCrypto::new(seed ^ 0xA5A5));
    deliver_server_flight(&mut client, &mut server, 1_000);
    let ccs = plaintext_record(ContentType::ChangeCipherSpec, 0, 100, &[1]);
    client
        .handle_input(datagram(1_001, &ccs))
        .expect("synthetic CCS installs the read cipher");
    client
}

// DTLS-HS-INT-020 — constructor provider failures are explicit.
#[test]
fn constructor_provider_failure_aborts() {
    let result = HandshakeMachine::new(
        HandshakeCrypto::new(0x1234).with_short_public_key(),
        HandshakeConfig::client(common::handshake::server_signing_public()),
        None,
    );
    assert_eq!(
        result.err(),
        Some(HandshakeError::Crypto(CryptoError::BackendFailure))
    );
}

// DTLS-HS-INT-021 — signing failures and lying signature lengths abort.
#[test]
fn signing_failure_aborts() {
    let mut client = make_client(HandshakeCrypto::new(0x1111));
    let mut server = make_server(HandshakeCrypto::new(0x2222).with_failing_sign());
    let mut now = 1u64;
    assert_eq!(
        drive(&mut client, &mut server, &mut now),
        Err(HandshakeError::Crypto(CryptoError::BackendFailure))
    );

    let mut client_b = make_client(HandshakeCrypto::new(0x3333));
    let mut server_b = make_server(HandshakeCrypto::new(0x4444).with_short_sign());
    let mut now_b = 1u64;
    assert_eq!(
        drive(&mut client_b, &mut server_b, &mut now_b),
        Err(HandshakeError::Crypto(CryptoError::BackendFailure))
    );
}

// DTLS-HS-INT-022 — a verify provider failure is not reported as a signature
// mismatch.
#[test]
fn verify_provider_failure_aborts() {
    let mut client = make_client(HandshakeCrypto::new(0x5555).with_failing_verify());
    let mut server = make_server(HandshakeCrypto::new(0x6666));
    let mut now = 1u64;
    assert_eq!(
        drive(&mut client, &mut server, &mut now),
        Err(HandshakeError::Crypto(CryptoError::Unsupported))
    );
}

// DTLS-HS-INT-023 — an `agree` provider failure and a provider that returns a
// zero secret with `Ok` both abort.
#[test]
fn agreement_provider_failure_aborts() {
    let mut client = make_client(HandshakeCrypto::new(0x7777));
    let mut server = make_server(HandshakeCrypto::new(0x8888).with_failing_agree());
    let mut now = 1u64;
    assert_eq!(
        drive(&mut client, &mut server, &mut now),
        Err(HandshakeError::Crypto(CryptoError::BackendFailure))
    );

    let mut client_b = make_client(HandshakeCrypto::new(0x9999));
    let mut server_b = make_server(HandshakeCrypto::new(0xAAAA).with_zero_ok_shared_secret());
    let mut now_b = 1u64;
    assert_eq!(
        drive(&mut client_b, &mut server_b, &mut now_b),
        Err(HandshakeError::ZeroSharedSecret)
    );
}

// DTLS-HS-INT-024 — transcript digest failures and lying digest lengths abort.
#[test]
fn digest_failure_aborts() {
    let mut client = make_client(HandshakeCrypto::new(0xBBBB).with_failing_digest());
    let mut server = make_server(HandshakeCrypto::new(0xCCCC));
    let mut now = 1u64;
    assert_eq!(
        drive(&mut client, &mut server, &mut now),
        Err(HandshakeError::Crypto(CryptoError::BackendFailure))
    );

    let mut client_b = make_client(HandshakeCrypto::new(0xDDDD).with_short_digest());
    let mut server_b = make_server(HandshakeCrypto::new(0xEEEE));
    let mut now_b = 1u64;
    assert_eq!(
        drive(&mut client_b, &mut server_b, &mut now_b),
        Err(HandshakeError::Crypto(CryptoError::BackendFailure))
    );
}

// DTLS-HS-INT-025 — a transmit-time AEAD failure is terminal and wipes state.
#[test]
fn transmit_seal_failure_is_terminal() {
    let mut client = make_client(HandshakeCrypto::new(0xFFFF).with_failing_seal());
    let mut server = make_server(HandshakeCrypto::new(0x1010));
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    // Hello is plaintext; deliver the server flight so the client queues a
    // protected Finished.
    while let Some(len) = client.poll_transmit(&mut buffer).expect("hello") {
        server
            .handle_input(datagram(1_000, &buffer[..len]))
            .expect("server hello");
    }
    while let Some(len) = server.poll_transmit(&mut buffer).expect("server flight") {
        client
            .handle_input(datagram(1_000, &buffer[..len]))
            .expect("server flight");
    }
    // The first two records (CKE and CCS) are still plaintext; the Finished
    // seal fails and `poll_transmit` marks the machine failed.
    let mut error = None;
    loop {
        match client.poll_transmit(&mut buffer) {
            Ok(Some(_len)) => {}
            Ok(None) => break,
            Err(actual) => {
                error = Some(actual);
                break;
            }
        }
    }
    assert_eq!(
        error,
        Some(HandshakeError::Record(rtx_dtls::RecordError::Crypto(
            CryptoError::BackendFailure
        )))
    );
    assert_eq!(client.state(), HandshakeState::Failed);
}

// DTLS-HS-INT-026 — timeouts before a flight and before the deadline are
// no-ops.
#[test]
fn harmless_timeouts_are_noops() {
    let mut fresh = make_server(HandshakeCrypto::new(0x1111));
    fresh
        .handle_input(Input::Timeout(Timestamp::from_micros(50)))
        .expect("no timer");
    assert!(fresh.next_wakeup().is_none());

    let mut client = make_client(HandshakeCrypto::new(0x2222));
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    client
        .poll_transmit(&mut buffer)
        .expect("hello")
        .expect("record");
    let deadline = client.next_wakeup().expect("timer");
    client
        .handle_input(Input::Timeout(Timestamp::from_micros(
            deadline.as_micros().saturating_sub(1),
        )))
        .expect("early timeout");
    assert_eq!(client.next_wakeup(), Some(deadline));
}

// DTLS-HS-INT-027 — empty datagrams are rejected.
#[test]
fn empty_datagram_is_rejected() {
    let mut server = make_server(HandshakeCrypto::new(0x3333));
    assert_eq!(
        server.handle_input(Input::Datagram {
            meta: meta(1_000),
            payload: &[],
        }),
        Err(HandshakeError::Record(rtx_dtls::RecordError::UnexpectedEnd))
    );
    assert_eq!(server.state(), HandshakeState::Failed);
}

// DTLS-HS-INT-028 — epoch and protected-length checks after a CCS.
#[test]
fn epoch_and_protected_record_checks() {
    let mut client = make_client(HandshakeCrypto::new(0x4444));
    let mut server = make_server(HandshakeCrypto::new(0x5555));
    deliver_server_flight(&mut client, &mut server, 1_000);
    let future_epoch = plaintext_record(ContentType::Handshake, 1, 10, &[0u8; 24]);
    assert_eq!(
        client.handle_input(datagram(1_001, &future_epoch)),
        Err(HandshakeError::Record(
            rtx_dtls::RecordError::UnexpectedEpoch
        ))
    );

    let mut client = client_with_read_cipher(0x6666);
    let stale = plaintext_record(ContentType::Handshake, 0, 101, &[]);
    client
        .handle_input(datagram(1_002, &stale))
        .expect("stale epoch ignored");
    assert_eq!(client.state(), HandshakeState::WaitServerFinished);

    let mut client = client_with_read_cipher(0x7777);
    let short = plaintext_record(ContentType::Handshake, 1, 0, &[0u8; 23]);
    assert_eq!(
        client.handle_input(datagram(1_002, &short)),
        Err(HandshakeError::Record(
            rtx_dtls::RecordError::CiphertextTooShort
        ))
    );

    let mut client = client_with_read_cipher(0x8888);
    let oversized = plaintext_record(ContentType::Handshake, 1, 0, &[0u8; 600]);
    assert_eq!(
        client.handle_input(datagram(1_002, &oversized)),
        Err(HandshakeError::Record(
            rtx_dtls::RecordError::OutputTooSmall
        ))
    );
}

// DTLS-HS-INT-029 — a zero retry budget stops the established server's final
// flight timer without failing the handshake.
#[test]
fn established_server_zero_retry_budget() {
    let mut client = make_client(HandshakeCrypto::new(0x9999));
    let mut config = HandshakeConfig::server();
    config.max_retransmissions = 0;
    let mut server = HandshakeMachine::new(
        HandshakeCrypto::new(0xAAAA),
        config,
        Some(&SERVER_SIGNING_KEY),
    )
    .expect("server");
    let mut now = 1u64;
    drive(&mut client, &mut server, &mut now).expect("handshake");
    let deadline = server.next_wakeup().expect("final flight timer");
    server
        .handle_input(Input::Timeout(deadline))
        .expect("retry budget exhausted without error");
    assert!(server.next_wakeup().is_none());
    assert_eq!(server.state(), HandshakeState::Established);
}

// DTLS-HS-INT-030 — after ClientKeyExchange the server keeps its last flight
// retransmittable while the client finishes.
#[test]
fn server_retransmits_while_waiting_for_client_finished() {
    let mut client = make_client(HandshakeCrypto::new(0xBBBB));
    let mut server = make_server(HandshakeCrypto::new(0xCCCC));
    deliver_server_flight(&mut client, &mut server, 1_000);
    let mut buffer = [0u8; MAX_HANDSHAKE_RECORD_LEN];
    let cke_len = client
        .poll_transmit(&mut buffer)
        .expect("client flight")
        .expect("CKE");
    server
        .handle_input(datagram(1_001, &buffer[..cke_len]))
        .expect("CKE");
    assert_eq!(server.state(), HandshakeState::WaitClientFinished);
    let deadline = server.next_wakeup().expect("server flight timer");
    server
        .handle_input(Input::Timeout(deadline))
        .expect("server timeout");
    let mut records = 0usize;
    while let Some(len) = server.poll_transmit(&mut buffer).expect("resend") {
        let record = Record::decode(&buffer[..len]).expect("record");
        assert_eq!(
            record.fragment[0],
            [
                HandshakeType::ServerHello.to_u8(),
                HandshakeType::ServerKeyExchange.to_u8(),
                HandshakeType::ServerHelloDone.to_u8(),
            ][records]
        );
        records += 1;
    }
    assert_eq!(records, 3);
}

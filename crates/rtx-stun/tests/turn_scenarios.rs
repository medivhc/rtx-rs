//! L3 — TURN protocol-scenario integration tests (RFC 5766 / RFC 5389).
//!
//! Allocation, permission, channel and refresh dialogues with the
//! long-term credential dance: the 401 challenge carries REALM and
//! NONCE, the retry signs with MESSAGE-INTEGRITY, and the server answers
//! with relayed addresses and lifetimes.

mod common;

use common::{assert_verbatim, build, mock_mac, tx};
use rtx_core::IpAddr;
use rtx_stun::attributes::{
    ATTR_CHANNEL_NUMBER, ATTR_DATA, ATTR_LIFETIME, ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_REALM,
    ATTR_REQUESTED_TRANSPORT, ATTR_SOFTWARE, ATTR_USERNAME, ATTR_XOR_PEER_ADDRESS,
    ATTR_XOR_RELAYED_ADDRESS, ATTR_XORMAPPED_ADDRESS, AttrType,
};
use rtx_stun::error_code::{ErrorCode, ErrorCodeAttribute};
use rtx_stun::integrity::MessageIntegrity;
use rtx_stun::message::{
    CLASS_ERROR_RESPONSE, CLASS_INDICATION, CLASS_REQUEST, CLASS_SUCCESS_RESPONSE,
    MESSAGE_HEADER_SIZE, METHOD_ALLOCATE, METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION,
    METHOD_REFRESH, METHOD_SEND, Message, MessageClass, MessageType, Method,
};
use rtx_stun::textattrs::TextAttribute;
use rtx_stun::xoraddr::XorMappedAddress;
use rtx_stun::{Decode, check_fingerprint, push_fingerprint};

/// The relayed transport address the fake server hands out.
const RELAYED: (IpAddr, u16) = (IpAddr::V4([203, 0, 113, 9]), 49_190);

/// A peer the client asks permission for.
const PEER: (IpAddr, u16) = (IpAddr::V4([203, 0, 113, 7]), 53_552);

/// Builds a message type for `method` with the given class.
fn response_type(method: Method, class: MessageClass) -> MessageType {
    MessageType::new(method, class)
}

// STUN-TURN-001 — allocate 成功响应：XOR-RELAYED-ADDRESS + LIFETIME + SOFTWARE。
#[test]
fn stun_turn_001_allocation_success() {
    let mut response = [0u8; 128];
    let response_len = build(
        &mut response,
        response_type(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE),
        tx(0x71),
        |writer| {
            XorMappedAddress::new(RELAYED.0, RELAYED.1)
                .push_to(ATTR_XOR_RELAYED_ADDRESS, writer)?;
            writer.push(ATTR_LIFETIME, &600u32.to_be_bytes())?;
            TextAttribute::new(ATTR_SOFTWARE, "rtx-turn 1.0").push_to(writer)
        },
    )
    .expect("response");

    let msg = assert_verbatim(&response[..response_len]);
    assert_eq!(msg.typ.method, METHOD_ALLOCATE);
    assert_eq!(msg.typ.class, CLASS_SUCCESS_RESPONSE);

    let relayed = msg
        .get(ATTR_XOR_RELAYED_ADDRESS)
        .expect("xor-relayed-address");
    let decoded = XorMappedAddress::from_value(relayed.value, msg.transaction_id).expect("unmask");
    assert_eq!(decoded.ip, RELAYED.0);
    assert_eq!(decoded.port, RELAYED.1);

    let lifetime = msg.get(ATTR_LIFETIME).expect("lifetime");
    assert_eq!(lifetime.value, 600u32.to_be_bytes());
}

// STUN-TURN-002 — long-term credential 两步对话：401 challenge → 重签成功。
#[test]
fn stun_turn_002_long_term_credential_dance() {
    // Step 1: unauthenticated allocate is refused with a challenge.
    let mut challenge = [0u8; 128];
    let challenge_len = build(
        &mut challenge,
        response_type(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
        tx(0x72),
        |writer| {
            ErrorCodeAttribute::new(ErrorCode(401), b"Unauthorized").push_to(writer)?;
            TextAttribute::new(ATTR_REALM, "example.org").push_to(writer)?;
            TextAttribute::new(ATTR_NONCE, "nonce-abc-123").push_to(writer)
        },
    )
    .expect("challenge");

    let (challenge_msg, _) =
        Message::decode(&challenge[..challenge_len]).expect("decode challenge");
    let realm = challenge_msg.get(ATTR_REALM).expect("realm");
    let nonce = challenge_msg.get(ATTR_NONCE).expect("nonce");
    assert_eq!(realm.value, b"example.org");
    assert_eq!(nonce.value, b"nonce-abc-123");

    // Step 2: the client retries with the credentials and a signature.
    let mut request = [0u8; 256];
    let request_len = build(
        &mut request,
        MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST),
        challenge_msg.transaction_id,
        |writer| {
            writer.push(ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0])?; // UDP
            TextAttribute::new(ATTR_USERNAME, "alice").push_to(writer)?;
            TextAttribute::new(ATTR_REALM, "example.org").push_to(writer)?;
            TextAttribute::new(ATTR_NONCE, "nonce-abc-123").push_to(writer)?;
            MessageIntegrity::new_raw(b"password", mock_mac).add_to(writer)
        },
    )
    .expect("request");

    let (signed, _) = Message::decode(&request[..request_len]).expect("decode request");
    assert!(signed.contains(ATTR_MESSAGE_INTEGRITY));
    MessageIntegrity::check(&signed, b"password", mock_mac).expect("integrity over allocate");
    assert_eq!(
        signed.get(AttrType(0x0019)).map(|attr| attr.value),
        Some(&[17u8, 0, 0, 0][..]),
        "requested-transport UDP"
    );

    // Step 3: the server grants the allocation.
    let mut granted = [0u8; 128];
    let granted_len = build(
        &mut granted,
        response_type(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE),
        signed.transaction_id,
        |writer| {
            XorMappedAddress::new(RELAYED.0, RELAYED.1)
                .push_to(ATTR_XOR_RELAYED_ADDRESS, writer)?;
            writer.push(ATTR_LIFETIME, &600u32.to_be_bytes())
        },
    )
    .expect("granted");

    let msg = assert_verbatim(&granted[..granted_len]);
    assert_eq!(msg.typ.class, CLASS_SUCCESS_RESPONSE);
    assert!(msg.contains(ATTR_XOR_RELAYED_ADDRESS));
}

// STUN-TURN-003 — CreatePermission：XOR-PEER-ADDRESS + 认证后成功。
#[test]
fn stun_turn_003_create_permission() {
    let mut request = [0u8; 256];
    let request_len = build(
        &mut request,
        MessageType::new(METHOD_CREATE_PERMISSION, CLASS_REQUEST),
        tx(0x73),
        |writer| {
            XorMappedAddress::new(PEER.0, PEER.1).push_to(ATTR_XOR_PEER_ADDRESS, writer)?;
            TextAttribute::new(ATTR_USERNAME, "alice").push_to(writer)?;
            MessageIntegrity::new_raw(b"password", mock_mac).add_to(writer)
        },
    )
    .expect("request");

    let (msg, _) = Message::decode(&request[..request_len]).expect("decode request");
    let peer = msg.get(ATTR_XOR_PEER_ADDRESS).expect("xor-peer-address");
    let decoded = XorMappedAddress::from_value(peer.value, msg.transaction_id).expect("unmask");
    assert_eq!(decoded.ip, PEER.0);
    assert_eq!(decoded.port, PEER.1);
    MessageIntegrity::check(&msg, b"password", mock_mac).expect("integrity over permission");

    // The success response carries nothing but the header.
    let mut response = [0u8; 32];
    let response_len = build(
        &mut response,
        response_type(METHOD_CREATE_PERMISSION, CLASS_SUCCESS_RESPONSE),
        msg.transaction_id,
        |_| Ok(()),
    )
    .expect("response");
    let msg = assert_verbatim(&response[..response_len]);
    assert_eq!(msg.attributes().count(), 0);
}

// STUN-TURN-004 — ChannelBind：CHANNEL-NUMBER 0x4000 + XOR-PEER-ADDRESS。
#[test]
fn stun_turn_004_channel_bind() {
    let mut request = [0u8; 128];
    let request_len = build(
        &mut request,
        MessageType::new(METHOD_CHANNEL_BIND, CLASS_REQUEST),
        tx(0x74),
        |writer| {
            writer.push(ATTR_CHANNEL_NUMBER, &[0x40, 0x00, 0x00, 0x00])?;
            XorMappedAddress::new(PEER.0, PEER.1).push_to(ATTR_XOR_PEER_ADDRESS, writer)
        },
    )
    .expect("request");

    let msg = assert_verbatim(&request[..request_len]);
    let channel = msg.get(ATTR_CHANNEL_NUMBER).expect("channel-number");
    assert_eq!(channel.value, [0x40, 0x00, 0x00, 0x00]);
    let peer = msg.get(ATTR_XOR_PEER_ADDRESS).expect("xor-peer-address");
    let decoded = XorMappedAddress::from_value(peer.value, msg.transaction_id).expect("unmask");
    assert_eq!(decoded.port, PEER.1);
}

// STUN-TURN-005 — Send/Data indication：二进制负载逐字节往返。
#[test]
fn stun_turn_005_send_data_indication() {
    let payload: Vec<u8> = (0..=255u8).collect();
    let mut indication = [0u8; 512];
    let written = build(
        &mut indication,
        MessageType::new(METHOD_SEND, CLASS_INDICATION),
        tx(0x75),
        |writer| writer.push(ATTR_DATA, &payload),
    )
    .expect("indication");
    assert_eq!(written, MESSAGE_HEADER_SIZE + 4 + 256);

    let msg = assert_verbatim(&indication[..written]);
    assert_eq!(msg.typ.class, CLASS_INDICATION);
    let data = msg.get(ATTR_DATA).expect("data attribute");
    assert_eq!(data.length, 256);
    assert_eq!(data.value, &payload[..]);
}

// STUN-TURN-006 — Refresh LIFETIME=0：删除 allocation。
#[test]
fn stun_turn_006_refresh_zero_lifetime() {
    let mut request = [0u8; 128];
    let request_len = build(
        &mut request,
        MessageType::new(METHOD_REFRESH, CLASS_REQUEST),
        tx(0x76),
        |writer| writer.push(ATTR_LIFETIME, &0u32.to_be_bytes()),
    )
    .expect("request");

    let msg = assert_verbatim(&request[..request_len]);
    let lifetime = msg.get(ATTR_LIFETIME).expect("lifetime");
    assert_eq!(lifetime.value, [0, 0, 0, 0]);
}

// STUN-TURN-007 — 437 allocation mismatch 错误往返。
#[test]
fn stun_turn_007_allocation_mismatch() {
    let mut error = [0u8; 128];
    let error_len = build(
        &mut error,
        response_type(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
        tx(0x77),
        |writer| ErrorCodeAttribute::new(ErrorCode(437), b"Allocation Mismatch").push_to(writer),
    )
    .expect("error");

    let msg = assert_verbatim(&error[..error_len]);
    let attr = msg.get(AttrType(0x0009)).expect("error-code");
    let decoded = ErrorCodeAttribute::from_value(attr.value).expect("decode");
    assert_eq!(decoded.code, ErrorCode(437));
    assert_eq!(decoded.reason, b"Allocation Mismatch");
}

// STUN-TURN-008 — stale nonce 轮换：438 带新 REALM/NONCE → 重签成功。
#[test]
fn stun_turn_008_stale_nonce_rotation() {
    let mut challenge = [0u8; 256];
    let challenge_len = build(
        &mut challenge,
        response_type(METHOD_REFRESH, CLASS_ERROR_RESPONSE),
        tx(0x78),
        |writer| {
            ErrorCodeAttribute::new(ErrorCode(438), b"Stale Nonce").push_to(writer)?;
            TextAttribute::new(ATTR_REALM, "example.org").push_to(writer)?;
            TextAttribute::new(ATTR_NONCE, "nonce-rotated-9").push_to(writer)
        },
    )
    .expect("challenge");

    let (challenge_msg, _) = Message::decode(&challenge[..challenge_len]).expect("decode");
    let rotated_nonce = challenge_msg.get(ATTR_NONCE).expect("nonce");
    assert_eq!(rotated_nonce.value, b"nonce-rotated-9");

    // The client resends with the rotated nonce and a fresh signature.
    let mut request = [0u8; 256];
    let request_len = build(
        &mut request,
        MessageType::new(METHOD_REFRESH, CLASS_REQUEST),
        challenge_msg.transaction_id,
        |writer| {
            writer.push(ATTR_LIFETIME, &600u32.to_be_bytes())?;
            TextAttribute::new(ATTR_USERNAME, "alice").push_to(writer)?;
            TextAttribute::new(ATTR_REALM, "example.org").push_to(writer)?;
            TextAttribute::new(ATTR_NONCE, "nonce-rotated-9").push_to(writer)?;
            MessageIntegrity::new_raw(b"password", mock_mac).add_to(writer)
        },
    )
    .expect("request");

    let (msg, _) = Message::decode(&request[..request_len]).expect("decode request");
    MessageIntegrity::check(&msg, b"password", mock_mac).expect("integrity over refresh");
    assert!(msg.contains(ATTR_MESSAGE_INTEGRITY));
}

// STUN-TURN-009 — 441 wrong credentials 错误往返。
#[test]
fn stun_turn_009_wrong_credentials() {
    let mut error = [0u8; 128];
    let error_len = build(
        &mut error,
        response_type(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
        tx(0x79),
        |writer| ErrorCodeAttribute::new(ErrorCode(441), b"Wrong Credentials").push_to(writer),
    )
    .expect("error");

    let msg = assert_verbatim(&error[..error_len]);
    let attr = msg.get(AttrType(0x0009)).expect("error-code");
    let decoded = ErrorCodeAttribute::from_value(attr.value).expect("decode");
    assert_eq!(decoded.code, ErrorCode(441));
    assert_eq!(decoded.reason, b"Wrong Credentials");
}

// STUN-TURN-010 — 完整认证消息：trailer 顺序 INTEGRITY → FINGERPRINT 全栈校验。
#[test]
fn stun_turn_010_full_authentication_stack() {
    let mut message = [0u8; 512];
    let written = build(
        &mut message,
        response_type(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE),
        tx(0x7A),
        |writer| {
            TextAttribute::new(ATTR_USERNAME, "alice").push_to(writer)?;
            TextAttribute::new(ATTR_REALM, "example.org").push_to(writer)?;
            TextAttribute::new(ATTR_NONCE, "nonce-abc-123").push_to(writer)?;
            XorMappedAddress::new(RELAYED.0, RELAYED.1)
                .push_to(ATTR_XOR_RELAYED_ADDRESS, writer)?;
            writer.push(ATTR_LIFETIME, &600u32.to_be_bytes())?;
            MessageIntegrity::new_raw(b"password", mock_mac).add_to(writer)?;
            push_fingerprint(writer)
        },
    )
    .expect("message");

    let msg = assert_verbatim(&message[..written]);

    // Trailer order: MESSAGE-INTEGRITY must precede FINGERPRINT.
    let types: Vec<_> = msg.attributes().map(|attr| attr.typ).collect();
    let integrity_at = types
        .iter()
        .position(|typ| *typ == ATTR_MESSAGE_INTEGRITY)
        .expect("integrity present");
    let fingerprint_at = types
        .iter()
        .position(|typ| *typ == AttrType(0x8028))
        .expect("fingerprint present");
    assert!(
        integrity_at < fingerprint_at,
        "integrity precedes fingerprint"
    );

    MessageIntegrity::check(&msg, b"password", mock_mac).expect("integrity");
    check_fingerprint(&msg).expect("fingerprint");

    // The relayed address still unmasks through the full stack.
    let relayed = msg.get(ATTR_XOR_RELAYED_ADDRESS).expect("relayed");
    let decoded = XorMappedAddress::from_value(relayed.value, msg.transaction_id).expect("unmask");
    assert_eq!(decoded.ip, RELAYED.0);
    assert_eq!(decoded.port, RELAYED.1);
}

// STUN-TURN-011 — 401 线上字节级验证：4 字节码头 + reason，长度字段含补齐。
#[test]
fn stun_turn_011_unauthorized_wire_bytes() {
    let mut error = [0u8; 128];
    let written = build(
        &mut error,
        response_type(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
        tx(0x7B),
        |writer| ErrorCodeAttribute::new(ErrorCode(401), b"Unauthorized").push_to(writer),
    )
    .expect("error");

    // ERROR-CODE value: 00 00 04 01 "Unauthorized" (16 bytes, no padding).
    let value = &error[MESSAGE_HEADER_SIZE + 4..];
    assert_eq!(&value[0..4], &[0x00, 0x00, 0x04, 0x01], "class 4, number 1");
    assert_eq!(&value[4..16], b"Unauthorized");
    assert_eq!(written, MESSAGE_HEADER_SIZE + 4 + 16);
    assert_verbatim(&error[..written]);
}

// STUN-TURN-012 — XOR-PEER-ADDRESS 掩码字节级验证（v4 与 v6）。
#[test]
fn stun_turn_012_xor_peer_address_mask_bytes() {
    // v4: 203.0.113.7:53552 → port 0xD130 ^ 0x2112 = 0xF022.
    let mut request = [0u8; 128];
    let written = build(
        &mut request,
        MessageType::new(METHOD_CREATE_PERMISSION, CLASS_REQUEST),
        tx(0x7C),
        |writer| XorMappedAddress::new(PEER.0, PEER.1).push_to(ATTR_XOR_PEER_ADDRESS, writer),
    )
    .expect("request");

    let value = &request[MESSAGE_HEADER_SIZE + 4..];
    assert_eq!(&value[0..2], &[0x00, 0x01], "ipv4 family");
    assert_eq!(&value[2..4], &[0xF0, 0x22], "masked peer port");
    // 203.0.113.7 = CB 00 71 07, XOR cookie 21 12 A4 42 → EA 12 D5 45.
    assert_eq!(&value[4..8], &[0xEA, 0x12, 0xD5, 0x45], "masked peer ipv4");

    let msg = assert_verbatim(&request[..written]);
    let peer = msg.get(ATTR_XOR_PEER_ADDRESS).expect("peer");
    let decoded = XorMappedAddress::from_value(peer.value, msg.transaction_id).expect("unmask");
    assert_eq!(decoded.ip, PEER.0);
    assert_eq!(decoded.port, PEER.1);
}

// STUN-TURN-013 — REQUESTED-TRANSPORT 非 UDP 协议号往返（TCP = 6）。
#[test]
fn stun_turn_013_requested_transport_tcp() {
    let mut request = [0u8; 128];
    let request_len = build(
        &mut request,
        MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST),
        tx(0x7D),
        |writer| writer.push(AttrType(0x0019), &[6, 0, 0, 0]),
    )
    .expect("request");

    let msg = assert_verbatim(&request[..request_len]);
    let transport = msg.get(AttrType(0x0019)).expect("requested-transport");
    assert_eq!(transport.value, [6, 0, 0, 0]);
}

// STUN-TURN-014 — allocate 失败后的重试不改变 transaction id 语义。
#[test]
fn stun_turn_014_transaction_id_stability_across_retry() {
    let mut error = [0u8; 128];
    let error_len = build(
        &mut error,
        response_type(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
        tx(0x7E),
        |writer| ErrorCodeAttribute::new(ErrorCode(401), b"Unauthorized").push_to(writer),
    )
    .expect("error");
    let (error_msg, _) = Message::decode(&error[..error_len]).expect("decode error");

    let mut retry = [0u8; 128];
    let retry_len = build(
        &mut retry,
        MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST),
        error_msg.transaction_id,
        |writer| writer.push(ATTR_LIFETIME, &600u32.to_be_bytes()),
    )
    .expect("retry");
    let (retry_msg, _) = Message::decode(&retry[..retry_len]).expect("decode retry");

    assert_eq!(retry_msg.transaction_id, tx(0x7E));
    assert_eq!(retry_msg.transaction_id, error_msg.transaction_id);
}

// STUN-TURN-015 — 大数据 DATA indication（1000 字节）往返。
#[test]
fn stun_turn_015_large_data_indication() {
    let payload: Vec<u8> = (0..1000u32).map(|index| (index % 251) as u8).collect();
    let mut indication = vec![0u8; 2048];
    let written = build(
        &mut indication,
        MessageType::new(METHOD_SEND, CLASS_INDICATION),
        tx(0x7F),
        |writer| writer.push(ATTR_DATA, &payload),
    )
    .expect("indication");

    let msg = assert_verbatim(&indication[..written]);
    let data = msg.get(ATTR_DATA).expect("data");
    assert_eq!(data.value, &payload[..]);
    // 1000 bytes is already word-aligned, so no padding is appended.
    assert_eq!(written, MESSAGE_HEADER_SIZE + 4 + 1000);
}

// STUN-TURN-016 — 服务器软件属性在错误响应中同样往返。
#[test]
fn stun_turn_016_software_on_error_response() {
    let mut error = [0u8; 256];
    let error_len = build(
        &mut error,
        response_type(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE),
        tx(0x80),
        |writer| {
            ErrorCodeAttribute::new(ErrorCode(486), b"Allocation Quota Reached").push_to(writer)?;
            TextAttribute::new(ATTR_SOFTWARE, "rtx-turn 1.0").push_to(writer)
        },
    )
    .expect("error");

    let msg = assert_verbatim(&error[..error_len]);
    let software = msg.get(ATTR_SOFTWARE).expect("software");
    assert_eq!(software.value, b"rtx-turn 1.0");
    assert!(!msg.contains(ATTR_XORMAPPED_ADDRESS));
}

//! L3 — ICE protocol-scenario integration tests (RFC 8445 / RFC 5389).
//!
//! Each test replays a realistic connectivity-check dialogue: the
//! controlling agent builds a request, the peer decodes it and answers,
//! and the agent verifies the answer — the same request/response pairing
//! a production ICE agent performs, minus the sockets.

mod common;

use common::{assert_verbatim, build, mock_mac, tx};
use rtx_core::IpAddr;
use rtx_stun::attributes::{
    ATTR_ICE_CONTROLLED, ATTR_ICE_CONTROLLING, ATTR_MESSAGE_INTEGRITY, ATTR_PRIORITY,
    ATTR_SOFTWARE, ATTR_UNKNOWN_ATTRIBUTES, ATTR_USE_CANDIDATE, ATTR_USERNAME,
    ATTR_XORMAPPED_ADDRESS, AttrType,
};
use rtx_stun::error_code::{CODE_ROLE_CONFLICT, CODE_UNKNOWN_ATTRIBUTE, ErrorCodeAttribute};
use rtx_stun::integrity::MessageIntegrity;
use rtx_stun::message::{
    BINDING_ERROR, BINDING_REQUEST, BINDING_SUCCESS, CLASS_ERROR_RESPONSE, CLASS_INDICATION,
    CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, MESSAGE_HEADER_SIZE, METHOD_BINDING, Message,
    MessageType,
};
use rtx_stun::textattrs::TextAttribute;
use rtx_stun::uattrs::UnknownAttributes;
use rtx_stun::xoraddr::XorMappedAddress;
use rtx_stun::{Decode, WireError, check_fingerprint, push_fingerprint};

/// The server-reflexive address the fake responder reports.
const SRFLX: (IpAddr, u16) = (IpAddr::V4([192, 0, 2, 1]), 32_853);

// STUN-ICE-001 — 完整 binding 对话：request → success response，地址解掩码回显。
#[test]
fn stun_ice_001_binding_request_response_pair() {
    // Agent builds a connectivity check with credentials and software.
    let mut request = [0u8; 128];
    let request_len = build(&mut request, BINDING_REQUEST, tx(0xC1), |writer| {
        TextAttribute::new(ATTR_USERNAME, "iceagent:peer").push_to(writer)?;
        TextAttribute::new(ATTR_SOFTWARE, "rtx-rs 0.1.0").push_to(writer)
    })
    .expect("request");

    let (decoded, _) = Message::decode(&request[..request_len]).expect("decode request");
    assert_eq!(decoded.typ.class, CLASS_REQUEST);

    // Peer answers with the XOR-mapped address it observed.
    let mut response = [0u8; 128];
    let response_len = build(
        &mut response,
        BINDING_SUCCESS,
        decoded.transaction_id,
        |writer| {
            XorMappedAddress::new(SRFLX.0, SRFLX.1).push_to(ATTR_XORMAPPED_ADDRESS, writer)?;
            TextAttribute::new(ATTR_SOFTWARE, "peer-stun 1.4").push_to(writer)
        },
    )
    .expect("response");

    // The masked wire bytes are deterministic. XOR-MAPPED-ADDRESS value =
    // family(2) + xport(2) + xipv4(4): port 0x8055 ^ 0x2112 and
    // 192.0.2.1 ^ magic cookie.
    let attr = &response[MESSAGE_HEADER_SIZE..];
    assert_eq!(&attr[4..6], &[0x00, 0x01], "ipv4 family");
    assert_eq!(&attr[6..8], &[0xA1, 0x47], "masked port");
    assert_eq!(&attr[8..12], &[0xE1, 0x12, 0xA6, 0x43], "masked ipv4");

    let msg = assert_verbatim(&response[..response_len]);
    assert_eq!(msg.typ.class, CLASS_SUCCESS_RESPONSE);
    assert_eq!(msg.typ.method, METHOD_BINDING);
    let raw = msg.get(ATTR_XORMAPPED_ADDRESS).expect("xor-mapped-address");
    let observed = XorMappedAddress::from_value(raw.value, msg.transaction_id).expect("unmask");
    assert_eq!(observed.ip, SRFLX.0);
    assert_eq!(observed.port, SRFLX.1);
}

// STUN-ICE-002 — 角色冲突：双方 controlling 时以 487 + reason 拒绝。
#[test]
fn stun_ice_002_role_conflict_error() {
    let tiebreaker = 0x0123_4567_89AB_CDEFu64;
    let mut request = [0u8; 128];
    let request_len = build(&mut request, BINDING_REQUEST, tx(0xC2), |writer| {
        writer.push(ATTR_ICE_CONTROLLING, &tiebreaker.to_be_bytes())?;
        writer.push(ATTR_PRIORITY, &0x6EFF_FFFFu32.to_be_bytes())
    })
    .expect("request");

    let (decoded, _) = Message::decode(&request[..request_len]).expect("decode request");
    assert!(decoded.contains(ATTR_ICE_CONTROLLING));
    assert_eq!(
        decoded.get(ATTR_ICE_CONTROLLING).map(|attr| attr.value),
        Some(&tiebreaker.to_be_bytes()[..])
    );

    // The peer is also controlling, so it refuses with 487.
    let mut error = [0u8; 128];
    let error_len = build(
        &mut error,
        BINDING_ERROR,
        decoded.transaction_id,
        |writer| ErrorCodeAttribute::new(CODE_ROLE_CONFLICT, b"Role Conflict").push_to(writer),
    )
    .expect("error");

    let msg = assert_verbatim(&error[..error_len]);
    assert_eq!(msg.typ.class, CLASS_ERROR_RESPONSE);
    let attr = msg.get(AttrType(0x0009)).expect("error-code");
    let decoded_error = ErrorCodeAttribute::from_value(attr.value).expect("decode");
    assert_eq!(decoded_error.code, CODE_ROLE_CONFLICT);
    assert_eq!(decoded_error.reason, b"Role Conflict");
    assert!(!msg.contains(ATTR_UNKNOWN_ATTRIBUTES));
}

// STUN-ICE-003 — nomination：USE-CANDIDATE + PRIORITY，随后 success。
#[test]
fn stun_ice_003_use_candidate_nomination() {
    // Host candidate priority per RFC 8445 §5.1.2.1:
    // (110 << 24) + (65535 << 8) + (256 - 1) = 0x6EFFFFFF.
    const HOST_PRIORITY: u32 = 0x6EFF_FFFF;

    let mut nominated = [0u8; 128];
    let nominated_len = build(&mut nominated, BINDING_REQUEST, tx(0xC3), |writer| {
        writer.push(ATTR_PRIORITY, &HOST_PRIORITY.to_be_bytes())?;
        writer.push(ATTR_USE_CANDIDATE, &[])
    })
    .expect("nominated request");

    let (decoded, _) = Message::decode(&nominated[..nominated_len]).expect("decode");
    assert_eq!(
        decoded.get(ATTR_PRIORITY).map(|attr| attr.value),
        Some(&HOST_PRIORITY.to_be_bytes()[..])
    );
    let use_candidate = decoded.get(ATTR_USE_CANDIDATE).expect("use-candidate");
    assert_eq!(use_candidate.length, 0, "USE-CANDIDATE carries no value");

    let mut response = [0u8; 128];
    let response_len = build(
        &mut response,
        BINDING_SUCCESS,
        decoded.transaction_id,
        |writer| XorMappedAddress::new(SRFLX.0, SRFLX.1).push_to(ATTR_XORMAPPED_ADDRESS, writer),
    )
    .expect("response");
    let msg = assert_verbatim(&response[..response_len]);
    assert_eq!(msg.typ.class, CLASS_SUCCESS_RESPONSE);
    assert!(!msg.contains(ATTR_USE_CANDIDATE));
}

// STUN-ICE-004 — consent freshness：周期性 indication 无属性，均能解码。
#[test]
fn stun_ice_004_consent_keepalive_indications() {
    for (index, tag) in [0xD1u8, 0xD2, 0xD3].iter().enumerate() {
        let mut indication = [0u8; 32];
        let written = build(
            &mut indication,
            MessageType::new(METHOD_BINDING, CLASS_INDICATION),
            tx(*tag),
            |_| Ok(()),
        )
        .expect("indication");

        let msg = assert_verbatim(&indication[..written]);
        assert_eq!(msg.typ.class, CLASS_INDICATION, "round {index}");
        assert_eq!(msg.length, 0);
        assert_eq!(msg.transaction_id, tx(*tag));
    }
}

// STUN-ICE-005 — 候选收集序列：host / srflx / relay 三个响应逐一往返。
#[test]
fn stun_ice_005_candidate_gathering_sequence() {
    struct Candidate {
        name: &'static str,
        ip: IpAddr,
        port: u16,
        tag: u8,
    }
    let candidates = [
        Candidate {
            name: "host v4",
            ip: IpAddr::V4([10, 0, 0, 7]),
            port: 53_000,
            tag: 0xE1,
        },
        Candidate {
            name: "srflx",
            ip: SRFLX.0,
            port: SRFLX.1,
            tag: 0xE2,
        },
        Candidate {
            name: "relay v6",
            ip: IpAddr::V6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09,
            ]),
            port: 53_532,
            tag: 0xE3,
        },
    ];

    for candidate in candidates {
        let mut response = [0u8; 128];
        let response_len = build(
            &mut response,
            BINDING_SUCCESS,
            tx(candidate.tag),
            |writer| {
                XorMappedAddress::new(candidate.ip, candidate.port)
                    .push_to(ATTR_XORMAPPED_ADDRESS, writer)
            },
        )
        .expect("response");

        let msg = assert_verbatim(&response[..response_len]);
        let raw = msg.get(ATTR_XORMAPPED_ADDRESS).expect("xor-mapped-address");
        let observed = XorMappedAddress::from_value(raw.value, msg.transaction_id).expect("unmask");
        assert_eq!(observed.ip, candidate.ip, "{}", candidate.name);
        assert_eq!(observed.port, candidate.port, "{}", candidate.name);
    }
}

// STUN-ICE-006 — SOFTWARE 版本交换：client 声明 → server 回显自身版本。
#[test]
fn stun_ice_006_software_version_exchange() {
    let mut request = [0u8; 128];
    let request_len = build(&mut request, BINDING_REQUEST, tx(0xC6), |writer| {
        TextAttribute::new(ATTR_SOFTWARE, "rtx-rs 0.1.0").push_to(writer)
    })
    .expect("request");

    let (decoded, _) = Message::decode(&request[..request_len]).expect("decode request");
    let client_software = decoded.get(ATTR_SOFTWARE).expect("client software");
    assert_eq!(
        TextAttribute::from_value(ATTR_SOFTWARE, client_software.value)
            .expect("utf-8 software")
            .text,
        "rtx-rs 0.1.0"
    );

    let mut response = [0u8; 128];
    let response_len = build(
        &mut response,
        BINDING_SUCCESS,
        decoded.transaction_id,
        |writer| TextAttribute::new(ATTR_SOFTWARE, "rtx-peer 2.6.4").push_to(writer),
    )
    .expect("response");

    let msg = assert_verbatim(&response[..response_len]);
    let server_software = msg.get(ATTR_SOFTWARE).expect("server software");
    assert_eq!(
        TextAttribute::from_value(ATTR_SOFTWARE, server_software.value)
            .expect("utf-8 software")
            .text,
        "rtx-peer 2.6.4"
    );
}

// STUN-ICE-007 — USERNAME 上限 513 字节（ICE ufrag 对）往返。
#[test]
fn stun_ice_007_max_length_username() {
    let mut username = String::from("ufragA:");
    username.push_str(&"u".repeat(513 - username.len()));

    let mut request = [0u8; 1024];
    let request_len = build(&mut request, BINDING_REQUEST, tx(0xC7), |writer| {
        TextAttribute::new(ATTR_USERNAME, &username).push_to(writer)
    })
    .expect("request");
    assert_eq!(request_len, MESSAGE_HEADER_SIZE + 4 + 516);

    let msg = assert_verbatim(&request[..request_len]);
    let attr = msg.get(ATTR_USERNAME).expect("username");
    assert_eq!(attr.length, 513);
    assert_eq!(attr.value.len(), 513);
}

// STUN-ICE-008 — 420 Unknown Attribute：UNKNOWN-ATTRIBUTES 列出对方不懂的类型。
#[test]
fn stun_ice_008_unknown_attributes_reply() {
    let unknown = [ATTR_ICE_CONTROLLING];
    let mut error = [0u8; 128];
    let error_len = build(&mut error, BINDING_ERROR, tx(0xC8), |writer| {
        ErrorCodeAttribute::new(CODE_UNKNOWN_ATTRIBUTE, b"Unknown Attribute").push_to(writer)?;
        UnknownAttributes::push_to(writer, &unknown)
    })
    .expect("error");

    let msg = assert_verbatim(&error[..error_len]);
    let attr = msg
        .get(ATTR_UNKNOWN_ATTRIBUTES)
        .expect("unknown-attributes");
    let decoded = UnknownAttributes::from_value(attr.value).expect("decode");
    assert_eq!(decoded.len(), 1);
    let types: Vec<_> = decoded.types().collect();
    assert_eq!(types, unknown);
}

// STUN-ICE-009 — controlled 侧请求：ICE-CONTROLLED + tiebreaker 往返。
#[test]
fn stun_ice_009_controlled_side_request() {
    let tiebreaker = 0xFEDC_BA98_7654_3210u64;
    let mut request = [0u8; 128];
    let request_len = build(&mut request, BINDING_REQUEST, tx(0xC9), |writer| {
        writer.push(ATTR_ICE_CONTROLLED, &tiebreaker.to_be_bytes())?;
        TextAttribute::new(ATTR_USERNAME, "peer:iceagent").push_to(writer)
    })
    .expect("request");

    let msg = assert_verbatim(&request[..request_len]);
    assert!(msg.contains(ATTR_ICE_CONTROLLED));
    assert!(!msg.contains(ATTR_ICE_CONTROLLING));
    assert_eq!(
        msg.get(ATTR_ICE_CONTROLLED).map(|attr| attr.value),
        Some(&tiebreaker.to_be_bytes()[..])
    );
}

// STUN-ICE-010 — 带完整认证栈的 keepalive：USERNAME + INTEGRITY + FINGERPRINT，
// 且任一字节被篡改后两项校验都必须失败。
#[test]
fn stun_ice_010_authenticated_keepalive_with_tamper_detection() {
    let mut keepalive = [0u8; 256];
    let written = build(&mut keepalive, BINDING_REQUEST, tx(0xCA), |writer| {
        TextAttribute::new(ATTR_USERNAME, "iceagent:peer").push_to(writer)?;
        TextAttribute::new(ATTR_SOFTWARE, "rtx-rs 0.1.0").push_to(writer)?;
        MessageIntegrity::new_raw(b"password", mock_mac).add_to(writer)?;
        push_fingerprint(writer)
    })
    .expect("keepalive");

    let msg = assert_verbatim(&keepalive[..written]);
    assert!(msg.contains(ATTR_MESSAGE_INTEGRITY));
    MessageIntegrity::check(&msg, b"password", mock_mac).expect("integrity over keepalive");
    check_fingerprint(&msg).expect("fingerprint over keepalive");

    // Tamper with the SOFTWARE value: both trailer checks must reject it.
    // Layout: header + USERNAME TLV (4 + 16, "iceagent:peer" is 13 bytes
    // padded to 16) + SOFTWARE TLV header + value.
    let username_tlv = 4 + 16;
    let software_value = MESSAGE_HEADER_SIZE + username_tlv + 4;
    let mut tampered = keepalive;
    tampered[software_value] ^= 0xFF;
    let (tampered_msg, _) = Message::decode(&tampered[..written]).expect("still well-formed");
    assert_eq!(
        MessageIntegrity::check(&tampered_msg, b"password", mock_mac).unwrap_err(),
        WireError::InvalidValue
    );
    assert_eq!(
        check_fingerprint(&tampered_msg).unwrap_err(),
        WireError::InvalidValue
    );

    // A wrong key fails integrity but leaves the fingerprint valid.
    assert_eq!(
        MessageIntegrity::check(&msg, b"wrong-key", mock_mac).unwrap_err(),
        WireError::InvalidValue
    );
    check_fingerprint(&msg).expect("fingerprint is key-independent");
}

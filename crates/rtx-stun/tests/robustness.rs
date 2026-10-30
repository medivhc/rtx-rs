//! L4 — robustness integration tests: truncation tables, malformed TLVs
//! and deterministic pseudo-random fuzzing.
//!
//! The property under test is *total safety*: every input either decodes
//! into a well-formed message that re-encodes verbatim, or fails with a
//! specific [`WireError`]. Nothing in between, and never a panic.

mod common;

use common::{Lcg, build, encode_msg, tx};
use rtx_stun::attributes::{ATTR_SOFTWARE, ATTR_USERNAME, AttrType};
use rtx_stun::message::{BINDING_REQUEST, MESSAGE_HEADER_SIZE, Message};
use rtx_stun::{Decode, WireError};

/// A message with two attributes, used as the truncation template.
fn template() -> Vec<u8> {
    let mut buf = [0u8; 128];
    let written = build(&mut buf, BINDING_REQUEST, tx(0x31), |writer| {
        writer.push(ATTR_USERNAME, b"alice:bob")?;
        writer.push(ATTR_SOFTWARE, b"rtx-rs")
    })
    .expect("template");
    buf[..written].to_vec()
}

// STUN-ROB-001 — 截断表：每个前缀长度要么完整解码要么 UnexpectedEnd。
#[test]
fn stun_rob_001_truncation_table() {
    struct Case {
        name: &'static str,
        bytes: Vec<u8>,
    }
    let mut empty = [0u8; 32];
    let empty_len = build(&mut empty, BINDING_REQUEST, tx(0x32), |_| Ok(())).expect("empty");
    let cases = [
        Case {
            name: "empty message",
            bytes: empty[..empty_len].to_vec(),
        },
        Case {
            name: "two attributes",
            bytes: template(),
        },
    ];

    for case in cases {
        let full = case.bytes.len();
        for len in 0..full {
            let result = Message::decode(&case.bytes[..len]);
            assert_eq!(
                result.unwrap_err(),
                WireError::UnexpectedEnd,
                "{} truncated to {len}",
                case.name
            );
        }
        let (msg, consumed) = Message::decode(&case.bytes).expect("full decodes");
        assert_eq!(consumed, full, "{}", case.name);
        assert_eq!(encode_msg(&msg), case.bytes, "{} verbatim", case.name);
    }
}

// STUN-ROB-002 — magic cookie 任一字节被破坏即 InvalidValue。
#[test]
fn stun_rob_002_bad_magic_cookie() {
    let bytes = template();
    for index in 4..8 {
        let mut broken = bytes.clone();
        broken[index] ^= 0x80;
        assert_eq!(
            Message::decode(&broken).unwrap_err(),
            WireError::InvalidValue,
            "cookie byte {index}"
        );
    }
}

// STUN-ROB-003 — 长度字段撒谎：消息级与属性级截断均为 UnexpectedEnd。
#[test]
fn stun_rob_003_lying_length_fields() {
    // (a) The message length field announces 8 attribute bytes but the
    // buffer only holds the 20-byte header.
    let mut header_only = [0u8; 20];
    header_only[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    header_only[2..4].copy_from_slice(&8u16.to_be_bytes());
    header_only[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes());
    header_only[8..20].copy_from_slice(&[0x33; 12]);
    assert_eq!(
        Message::decode(&header_only).unwrap_err(),
        WireError::UnexpectedEnd
    );

    // (b) The region holds a TLV whose value claims 8 bytes but only 4
    // are present (region length 8, TLV needs 12).
    let mut region = [0u8; 28];
    region[2..4].copy_from_slice(&8u16.to_be_bytes()); // message length 8
    region[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes()); // magic cookie
    let tlv = [
        0x80, 0x22, 0x00, 0x08, // SOFTWARE, value length 8
        b'a', b'b', b'c', b'd', // only 4 value bytes, no padding
    ];
    region[MESSAGE_HEADER_SIZE..MESSAGE_HEADER_SIZE + 8].copy_from_slice(&tlv);
    assert_eq!(
        Message::decode(&region).unwrap_err(),
        WireError::UnexpectedEnd
    );
}

// STUN-ROB-004 — 未补齐属性：区域长度不是 4 的倍数时拒绝。
#[test]
fn stun_rob_004_unpadded_attribute_rejected() {
    // Region of 7 bytes: a 3-byte value without its padding byte.
    let mut short = [0u8; 27];
    short[2..4].copy_from_slice(&7u16.to_be_bytes()); // message length 7
    short[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes()); // magic cookie
    let tlv = [
        0x00, 0x06, 0x00, 0x03, // USERNAME, value length 3
        b'a', b'b', b'c', 0x00, // value plus its zero padding octet
    ];
    short[MESSAGE_HEADER_SIZE..MESSAGE_HEADER_SIZE + 7].copy_from_slice(&tlv[..7]);
    assert_eq!(
        Message::decode(&short).unwrap_err(),
        WireError::UnexpectedEnd
    );

    // The same TLV inside an 8-byte region (padding present) decodes.
    let mut padded = [0u8; 28];
    padded[2..4].copy_from_slice(&8u16.to_be_bytes());
    padded[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes());
    padded[MESSAGE_HEADER_SIZE..MESSAGE_HEADER_SIZE + 8].copy_from_slice(&tlv);
    let (msg, consumed) = Message::decode(&padded).expect("padded region decodes");
    assert_eq!(consumed, 28);
    assert_eq!(
        msg.get(ATTR_USERNAME).map(|attr| attr.value),
        Some(&b"abc"[..])
    );
}

// STUN-ROB-005 — LCG 模糊：300 个随机字节块，解码不 panic 且成功即 verbatim。
#[test]
fn stun_rob_005_lcg_byte_blob_fuzz() {
    let mut rng = Lcg::new(0x000B_00B5);
    for iteration in 0..300u32 {
        let len = rng.below(64);
        let mut blob = vec![0u8; len];
        rng.fill(&mut blob);
        // Half the blobs carry a valid cookie so some actually decode.
        if iteration % 2 == 0 && len >= MESSAGE_HEADER_SIZE {
            blob[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes());
            // Keep the announced length inside the blob.
            let region = u16::try_from(len.saturating_sub(MESSAGE_HEADER_SIZE)).unwrap_or(0);
            blob[2..4].copy_from_slice(&region.to_be_bytes());
        }

        if let Ok((msg, consumed)) = Message::decode(&blob) {
            assert!(consumed <= blob.len(), "consumed within input");
            // Decode rejects a non-zero reserved field (RFC 5389 section 6,
            // the two most significant bits of the type), so every message
            // that decodes has a canonical type and must re-encode verbatim.
            assert_eq!(
                blob[0] & 0xc0,
                0,
                "decode accepted reserved type bits, iter {iteration}"
            );
            assert_eq!(
                encode_msg(&msg),
                blob[..consumed],
                "verbatim, iter {iteration}"
            );
        }
    }
}

// STUN-ROB-006 — LCG 构造模糊：随机属性集合构造后必须解码回同等属性。
#[test]
fn stun_rob_006_lcg_constructed_message_fuzz() {
    let mut rng = Lcg::new(0x00C0_FFEE);
    let attr_pool = [
        AttrType(0x0001),
        AttrType(0x0006),
        AttrType(0x0014),
        AttrType(0x8022),
        AttrType(0x0020),
        AttrType(0xFFFF), // comprehension-required unknown
        AttrType(0x8000),
    ];

    for iteration in 0..300u32 {
        let count = rng.below(6);
        let mut buf = [0u8; 512];
        let mut expected: Vec<(u16, Vec<u8>)> = Vec::new();
        let written = build(&mut buf, BINDING_REQUEST, tx(rng.next_u8()), |writer| {
            for _ in 0..count {
                let typ = attr_pool[rng.below(attr_pool.len())];
                let len = rng.below(20);
                let mut value = vec![0u8; len];
                rng.fill(&mut value);
                writer.push(typ, &value)?;
                expected.push((typ.value(), value));
            }
            Ok(())
        })
        .expect("build");

        let bytes = &buf[..written];
        let (msg, consumed) = Message::decode(bytes).expect("decode");
        assert_eq!(consumed, written, "iteration {iteration}");
        let decoded: Vec<(u16, Vec<u8>)> = msg
            .attributes()
            .map(|attr| (attr.typ.value(), attr.value.to_vec()))
            .collect();
        assert_eq!(decoded, expected, "iteration {iteration}");
        assert_eq!(encode_msg(&msg), bytes, "iteration {iteration} verbatim");
    }
}

// STUN-ROB-007 — UNKNOWN-ATTRIBUTES 流式写入 300 个类型码（2 字节 stride）。
#[test]
fn stun_rob_007_many_unknown_attributes() {
    use rtx_stun::uattrs::UnknownAttributes;

    const COUNT: usize = 300;
    let types: Vec<AttrType> = (0..COUNT)
        .map(|index| AttrType(0x0100 + u16::try_from(index).expect("index fits u16")))
        .collect();

    let mut buf = [0u8; 2048];
    let written = build(&mut buf, BINDING_REQUEST, tx(0x41), |writer| {
        // push_with streams the 600-byte value without a scratch buffer;
        // the value is 2 bytes per type, padded to 600 (already aligned).
        writer.push_with(AttrType(0x000A), COUNT * 2, |region| {
            for (index, chunk) in region.chunks_exact_mut(2).enumerate() {
                chunk.copy_from_slice(&types[index].value().to_be_bytes());
            }
        })
    })
    .expect("build");
    assert_eq!(written, MESSAGE_HEADER_SIZE + 4 + COUNT * 2);

    let (msg, consumed) = Message::decode(&buf[..written]).expect("decode");
    assert_eq!(consumed, written);
    let attr = msg.get(AttrType(0x000A)).expect("unknown-attributes");
    let decoded = UnknownAttributes::from_value(attr.value).expect("decode");
    assert_eq!(decoded.len(), COUNT);
    let collected: Vec<_> = decoded.types().collect();
    assert_eq!(collected, types);
    assert_eq!(encode_msg(&msg), &buf[..written], "verbatim");
}

// STUN-ROB-008 — 属性区为空与仅含补齐字节的消息均被拒绝。
#[test]
fn stun_rob_008_zero_length_region_edge() {
    // A message whose only attribute has a zero-length value decodes.
    let mut buf = [0u8; 32];
    let written = build(&mut buf, BINDING_REQUEST, tx(0x42), |writer| {
        writer.push(ATTR_SOFTWARE, &[])
    })
    .expect("build");
    assert_eq!(written, MESSAGE_HEADER_SIZE + 4);

    let msg = common::assert_verbatim(&buf[..written]);
    let attr = msg.get(ATTR_SOFTWARE).expect("software");
    assert_eq!(attr.length, 0);
    assert_eq!(attr.value, []);
}

// STUN-ROB-009 — 重复 trailer：FINGERPRINT 后再推 INTEGRITY 必须被拒绝。
#[test]
fn stun_rob_009_fingerprint_before_integrity_rejected() {
    use rtx_stun::integrity::MessageIntegrity;
    use rtx_stun::push_fingerprint;

    let mut buf = [0u8; 128];
    let err = build(&mut buf, BINDING_REQUEST, tx(0x43), |writer| {
        writer.push(ATTR_USERNAME, b"alice:bob")?;
        push_fingerprint(writer)?;
        MessageIntegrity::new_raw(b"password", common::mock_mac).add_to(writer)
    })
    .expect_err("integrity after fingerprint is refused");
    assert_eq!(err, WireError::InvalidValue);
}

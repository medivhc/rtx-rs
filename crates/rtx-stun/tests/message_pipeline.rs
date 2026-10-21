//! L1 — message-level integration tests (public API only).
//!
//! Each test drives the full pipeline the way a transport would: build
//! with [`MessageWriter`], decode with [`Message`], assert the semantic
//! fields, then re-encode and demand byte-for-byte verbatim output.

mod common;

use common::{Lcg, assert_verbatim, build, encode_msg, mock_mac, padded, tx};
use rtx_stun::attributes::{ATTR_SOFTWARE, ATTR_USERNAME, AttrType};
use rtx_stun::error_code::{ErrorCode, ErrorCodeAttribute};
use rtx_stun::integrity::MessageIntegrity;
use rtx_stun::message::{
    BINDING_ERROR, BINDING_REQUEST, BINDING_SUCCESS, CLASS_ERROR_RESPONSE, CLASS_INDICATION,
    CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, MESSAGE_HEADER_SIZE, METHOD_ALLOCATE, METHOD_BINDING,
    METHOD_CONNECTION_ATTEMPT, METHOD_DATA, Message, MessageType, MessageWriter, is_stun_message,
};
use rtx_stun::textattrs::TextAttribute;
use rtx_stun::{Decode, WireError};

// STUN-IT-001 — 完整管线：writer 构造 → decode → 字段断言 → verbatim 重编码。
#[test]
fn stun_it_001_full_pipeline_round_trip() {
    let mut buf = [0u8; 128];
    let written = build(&mut buf, BINDING_REQUEST, tx(0x5A), |writer| {
        TextAttribute::new(ATTR_USERNAME, "alice:bob").push_to(writer)?;
        TextAttribute::new(ATTR_SOFTWARE, "rtx-rs 0.1.0").push_to(writer)?;
        Ok(())
    })
    .expect("build");

    // USERNAME "alice:bob" (9 -> padded 12) + SOFTWARE (12, aligned): 16+16.
    assert_eq!(written, MESSAGE_HEADER_SIZE + 16 + 16);
    let bytes = &buf[..written];
    let msg = assert_verbatim(bytes);

    assert_eq!(msg.typ.method, METHOD_BINDING);
    assert_eq!(msg.typ.class, CLASS_REQUEST);
    assert_eq!(msg.transaction_id, tx(0x5A));
    assert_eq!(msg.length, 32);
    assert_eq!(
        msg.get(ATTR_USERNAME).map(|attr| attr.value),
        Some(&b"alice:bob"[..])
    );
    assert_eq!(
        msg.get(ATTR_SOFTWARE).map(|attr| attr.value),
        Some(&b"rtx-rs 0.1.0"[..])
    );
}

// STUN-IT-002 — 空属性消息：20 字节头即完整消息。
#[test]
fn stun_it_002_empty_attribute_region() {
    let mut buf = [0u8; 32];
    let written = build(&mut buf, BINDING_REQUEST, tx(0x01), |_| Ok(())).expect("build");
    assert_eq!(written, MESSAGE_HEADER_SIZE);
    assert_eq!(buf[2..4], [0x00, 0x00], "length field must stay zero");

    let msg = assert_verbatim(&buf[..written]);
    assert_eq!(msg.length, 0);
    assert_eq!(msg.attributes().count(), 0);
    assert!(!msg.contains(ATTR_USERNAME));
}

// STUN-IT-003 — writer 状态跟踪：每 push 一个属性后 length/written/字节字段同步。
#[test]
fn stun_it_003_writer_length_tracking() {
    let mut buf = [0u8; 128];
    let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, tx(0x77)).expect("writer");
    assert_eq!(writer.length(), 0);
    assert_eq!(writer.written(), MESSAGE_HEADER_SIZE);
    assert_eq!(writer.as_bytes().len(), MESSAGE_HEADER_SIZE);
    assert_eq!(writer.typ(), BINDING_REQUEST);
    assert_eq!(writer.transaction_id(), tx(0x77));

    // SOFTWARE "abc": 4-byte TLV header + 3 value bytes padded to 4 => 8.
    writer.push(ATTR_SOFTWARE, b"abc").expect("push software");
    assert_eq!(writer.length(), 8);
    assert_eq!(writer.written(), MESSAGE_HEADER_SIZE + 8);
    assert_eq!(writer.as_bytes()[2..4], 8u16.to_be_bytes());

    // USERNAME "a:b": 3 value bytes padded to 4 => another 8.
    writer.push(ATTR_USERNAME, b"a:b").expect("push username");
    assert_eq!(writer.length(), 16);
    assert_eq!(writer.as_bytes()[2..4], 16u16.to_be_bytes());
    assert_eq!(writer.as_bytes().len(), MESSAGE_HEADER_SIZE + 16);

    let bytes = writer.as_bytes().to_vec();
    let msg = assert_verbatim(&bytes);
    assert_eq!(msg.length, 16);
    assert_eq!(msg.attributes().count(), 2);
}

// STUN-IT-004 — is_stun_message 复用判定表（STUN / RTCP / 短包 / 坏 cookie）。
#[test]
fn stun_it_004_dispatch_table() {
    struct Case {
        name: &'static str,
        bytes: Vec<u8>,
        expected: bool,
    }

    let mut stun = [0u8; 24];
    stun[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    stun[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes());
    let cases = [
        Case {
            name: "valid header",
            bytes: stun.to_vec(),
            expected: true,
        },
        Case {
            name: "exactly 20 bytes",
            bytes: stun[..20].to_vec(),
            expected: true,
        },
        Case {
            name: "one byte short",
            bytes: stun[..19].to_vec(),
            expected: false,
        },
        Case {
            name: "empty",
            bytes: Vec::new(),
            expected: false,
        },
        Case {
            name: "rtcp sender report",
            bytes: vec![
                0x80, 0xc8, 0x00, 0x06, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            ],
            expected: false,
        },
        Case {
            name: "wrong magic cookie",
            bytes: {
                let mut bad = stun;
                bad[7] ^= 0xFF;
                bad.to_vec()
            },
            expected: false,
        },
    ];

    for case in cases {
        assert_eq!(
            is_stun_message(&case.bytes),
            case.expected,
            "case {}",
            case.name
        );
    }
}

// STUN-IT-005 — MessageType 编解码：method/class 打包与已知 RFC 5389 值。
#[test]
fn stun_it_005_message_type_packing() {
    let known = [
        (BINDING_REQUEST, 0x0001u16),
        (BINDING_SUCCESS, 0x0101),
        (BINDING_ERROR, 0x0111),
        (MessageType::new(METHOD_BINDING, CLASS_INDICATION), 0x0011),
        (MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST), 0x0003),
        (
            MessageType::new(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE),
            0x0103,
        ),
        (MessageType::new(METHOD_DATA, CLASS_INDICATION), 0x0017),
    ];
    for (typ, value) in known {
        assert_eq!(typ.value(), value, "wire value of {typ:?}");
        let mut decoded = MessageType::default();
        decoded.read_value(value);
        assert_eq!(decoded, typ, "read_value round trip of {typ:?}");
    }
}

// STUN-IT-006 — decode 只消费一个消息，trailing 字节留给调用方。
#[test]
fn stun_it_006_decode_consumes_exactly_one_message() {
    let mut first = [0u8; 64];
    let first_len = build(&mut first, BINDING_REQUEST, tx(0x21), |writer| {
        writer.push(ATTR_SOFTWARE, b"one")
    })
    .expect("first");

    let mut second = [0u8; 64];
    let second_len = build(&mut second, BINDING_REQUEST, tx(0x22), |writer| {
        writer.push(ATTR_SOFTWARE, b"two")
    })
    .expect("second");

    let mut stream = first[..first_len].to_vec();
    stream.extend_from_slice(&second[..second_len]);
    let trailing = stream.len();
    stream.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let (msg, consumed) = Message::decode(&stream).expect("decode first");
    assert_eq!(consumed, first_len);
    assert_eq!(msg.transaction_id, tx(0x21));

    let (msg2, consumed2) = Message::decode(&stream[consumed..]).expect("decode second");
    assert_eq!(consumed2, second_len);
    assert_eq!(msg2.transaction_id, tx(0x22));

    // The trailing junk is not a valid message.
    assert!(Message::decode(&stream[trailing..]).is_err());
}

// STUN-IT-007 — 事务 id 回显：响应必须复用请求的 transaction id。
#[test]
fn stun_it_007_transaction_id_echo() {
    let request_id = tx(0xAB);
    let mut request = [0u8; 64];
    build(&mut request, BINDING_REQUEST, request_id, |_| Ok(())).expect("request");

    let (decoded, _) = Message::decode(&request).expect("decode request");
    let mut response = [0u8; 64];
    build(
        &mut response,
        BINDING_SUCCESS,
        decoded.transaction_id,
        |_| Ok(()),
    )
    .expect("response");

    let (echoed, _) = Message::decode(&response).expect("decode response");
    assert_eq!(echoed.transaction_id, request_id);
    assert_eq!(echoed.typ.class, CLASS_SUCCESS_RESPONSE);
    assert_ne!(echoed.transaction_id, tx(0x00));
}

// STUN-IT-008 — push_with 流式写值：缓冲区不足时状态不受影响。
#[test]
fn stun_it_008_push_with_streaming_and_output_too_small() {
    // A 100-byte value fits a 128-byte buffer (20 + 4 + 100 = 124).
    let mut buf = [0u8; 128];
    let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, tx(0x33)).expect("writer");
    writer
        .push_with(AttrType(0x7000), 100, |region| {
            for (index, byte) in region.iter_mut().enumerate() {
                *byte = u8::try_from(index % 251).expect("index fits u8");
            }
        })
        .expect("push_with");
    assert_eq!(writer.length(), 104);

    // The same push into a 64-byte buffer fails without writing anything.
    let mut small = [0u8; 64];
    let mut writer = MessageWriter::new(&mut small, BINDING_REQUEST, tx(0x33)).expect("writer");
    let err = writer
        .push_with(AttrType(0x7000), 100, |region| region.fill(0))
        .expect_err("output too small");
    assert_eq!(err, WireError::OutputTooSmall);
    assert_eq!(writer.length(), 0, "failed push must not touch the length");
    assert_eq!(writer.written(), MESSAGE_HEADER_SIZE);
    assert_eq!(writer.as_bytes()[2..4], [0, 0], "length field stays zero");
}

// STUN-IT-009 — 十六属性长消息：表驱动编号值，迭代与重编码全量断言。
#[test]
fn stun_it_009_sixteen_attributes_round_trip() {
    const COUNT: usize = 16;
    let mut buf = [0u8; 256];
    let written = build(&mut buf, BINDING_REQUEST, tx(0x44), |writer| {
        for index in 0..COUNT {
            let value = u32::try_from(index).expect("index fits u32");
            let typ = AttrType(0x8000 + u16::try_from(index).expect("index fits u16"));
            writer.push_with(typ, 4, |region| {
                region.copy_from_slice(&value.to_be_bytes());
            })?;
        }
        Ok(())
    })
    .expect("build");

    assert_eq!(written, MESSAGE_HEADER_SIZE + COUNT * 8);
    let msg = assert_verbatim(&buf[..written]);
    let attrs: Vec<_> = msg.attributes().collect();
    assert_eq!(attrs.len(), COUNT);
    for (index, attr) in attrs.iter().enumerate() {
        let expected_typ = AttrType(0x8000 + u16::try_from(index).expect("index fits u16"));
        assert_eq!(attr.typ, expected_typ);
        assert_eq!(attr.length, 4);
        assert_eq!(
            attr.value,
            u32::try_from(index).expect("index fits u32").to_be_bytes()
        );
    }
}

// STUN-IT-010 — 属性迭代顺序等于 push 顺序。
#[test]
fn stun_it_010_attribute_iteration_order() {
    let order = [
        ATTR_USERNAME,
        ATTR_SOFTWARE,
        AttrType(0x0014), // REALM
        AttrType(0x0015), // NONCE
    ];
    let mut buf = [0u8; 128];
    let written = build(&mut buf, BINDING_REQUEST, tx(0x55), |writer| {
        writer.push(ATTR_USERNAME, b"u")?;
        writer.push(ATTR_SOFTWARE, b"s")?;
        writer.push(AttrType(0x0014), b"r")?;
        writer.push(AttrType(0x0015), b"n")?;
        Ok(())
    })
    .expect("build");

    let msg = assert_verbatim(&buf[..written]);
    let decoded: Vec<_> = msg.attributes().map(|attr| attr.typ).collect();
    assert_eq!(decoded, order);
}

// STUN-IT-011 — get/contains 语义：重复属性返回首个。
#[test]
fn stun_it_011_get_returns_first_and_contains() {
    let mut buf = [0u8; 128];
    let written = build(&mut buf, BINDING_REQUEST, tx(0x66), |writer| {
        writer.push(ATTR_SOFTWARE, b"first")?;
        writer.push(ATTR_USERNAME, b"mid")?;
        writer.push(ATTR_SOFTWARE, b"second")?;
        Ok(())
    })
    .expect("build");

    let msg = assert_verbatim(&buf[..written]);
    assert_eq!(
        msg.get(ATTR_SOFTWARE).map(|attr| attr.value),
        Some(&b"first"[..])
    );
    assert!(msg.contains(ATTR_USERNAME));
    assert!(!msg.contains(AttrType(0x8028)));
    assert_eq!(msg.attributes().count(), 3);
}

// STUN-IT-012 — 长度上溢：超长值必然 Overflow，且不污染 writer。
#[test]
fn stun_it_012_length_overflow_rejected() {
    let mut buf = [0u8; 64];
    let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, tx(0x88)).expect("writer");
    let err = writer
        .push_with(AttrType(0x8001), 65_535, |_| {})
        .expect_err("u16 length overflow");
    assert_eq!(err, WireError::Overflow);
    assert_eq!(writer.length(), 0);
    assert_eq!(writer.as_bytes()[2..4], [0, 0]);

    // A 65531-byte value pads to 65532 and the TLV header pushes the
    // total past u16::MAX as well.
    let err = writer
        .push_with(AttrType(0x8001), 65_531, |_| {})
        .expect_err("padded length overflow");
    assert_eq!(err, WireError::Overflow);
}

// STUN-IT-013 — ERROR-CODE 属性跨消息管线：构造 → decode → 默认 reason 表。
#[test]
fn stun_it_013_error_code_pipeline() {
    struct Case {
        code: u16,
        reason: &'static [u8],
    }
    let cases = [
        Case {
            code: 400,
            reason: b"Bad Request",
        },
        Case {
            code: 401,
            reason: b"Unauthorized",
        },
        Case {
            code: 438,
            reason: b"Stale Nonce",
        },
        Case {
            code: 500,
            reason: b"Server Error",
        },
    ];

    for case in cases {
        let mut buf = [0u8; 128];
        let written = build(&mut buf, BINDING_ERROR, tx(0x99), |writer| {
            ErrorCodeAttribute::new(ErrorCode(case.code), case.reason).push_to(writer)
        })
        .expect("build");

        let msg = assert_verbatim(&buf[..written]);
        let attr = msg.get(AttrType(0x0009)).expect("error-code attribute");
        let decoded = ErrorCodeAttribute::from_value(attr.value).expect("decode error code");
        assert_eq!(decoded.code, ErrorCode(case.code));
        assert_eq!(decoded.reason, case.reason);
        assert_eq!(decoded.code.default_reason(), Some(case.reason));
    }
}

// STUN-IT-014 — LCG 模糊：200 个伪随机消息构造后必须解码回同等字段。
#[test]
fn stun_it_014_lcg_message_fuzz() {
    let mut rng = Lcg::new(0x0051_0001);
    let types = [
        ATTR_USERNAME,
        ATTR_SOFTWARE,
        AttrType(0x0014),
        AttrType(0x0015),
    ];
    let classes = [CLASS_REQUEST, CLASS_INDICATION, CLASS_SUCCESS_RESPONSE];

    for iteration in 0..200u32 {
        let method = match iteration % 3 {
            0 => METHOD_BINDING,
            1 => METHOD_ALLOCATE,
            _ => METHOD_DATA,
        };
        let class = classes[rng.below(classes.len())];
        let tag = rng.next_u8();
        let count = rng.below(5);

        let mut buf = [0u8; 512];
        let mut expected: Vec<(AttrType, Vec<u8>)> = Vec::new();
        let written = build(
            &mut buf,
            MessageType::new(method, class),
            tx(tag),
            |writer| {
                for _ in 0..count {
                    let typ = types[rng.below(types.len())];
                    let len = rng.below(24);
                    let mut value = vec![0u8; len];
                    rng.fill(&mut value);
                    // Text attributes reject invalid UTF-8, so stay ASCII.
                    for byte in &mut value {
                        *byte = b'a' + *byte % 26;
                    }
                    writer.push(typ, &value)?;
                    expected.push((typ, value));
                }
                Ok(())
            },
        )
        .expect("build");

        let bytes = &buf[..written];
        let (msg, consumed) = Message::decode(bytes).expect("decode fuzz message");
        assert_eq!(consumed, written);
        assert_eq!(msg.transaction_id, tx(tag));
        assert_eq!(msg.typ.class, class);
        assert_eq!(msg.typ.method, method);

        let decoded: Vec<_> = msg
            .attributes()
            .map(|attr| (attr.typ, attr.value.to_vec()))
            .collect();
        assert_eq!(decoded, expected, "iteration {iteration}");
        assert_eq!(encode_msg(&msg), bytes, "iteration {iteration} verbatim");
    }
}

// STUN-IT-015 — padding 算术契约：padded(len) 与 writer 实际补齐一致。
#[test]
fn stun_it_015_padding_arithmetic() {
    for len in 0..40usize {
        assert_eq!(padded(len), (4 - len % 4) % 4);
    }
    let mut buf = [0u8; 128];
    let written = build(&mut buf, BINDING_REQUEST, tx(0x0E), |writer| {
        writer.push(ATTR_USERNAME, b"abc")
    })
    .expect("build");
    // 4 TLV header + 3 value + 1 zero padding.
    assert_eq!(written, MESSAGE_HEADER_SIZE + 4 + 3 + 1);
    assert_eq!(buf[MESSAGE_HEADER_SIZE + 7], 0, "padding byte must be zero");
    let msg = assert_verbatim(&buf[..written]);
    assert_eq!(msg.length, 8);
}

// STUN-IT-016 — 完整性签名不改变消息语义：signed 消息字段与未签名一致。
#[test]
fn stun_it_016_integrity_preserves_fields() {
    let mut plain = [0u8; 128];
    let plain_len = build(&mut plain, BINDING_REQUEST, tx(0x0F), |writer| {
        writer.push(ATTR_USERNAME, b"alice:bob")?;
        writer.push(ATTR_SOFTWARE, b"rtx-rs")
    })
    .expect("plain");

    let mut signed = [0u8; 128];
    let signed_len = build(&mut signed, BINDING_REQUEST, tx(0x0F), |writer| {
        writer.push(ATTR_USERNAME, b"alice:bob")?;
        writer.push(ATTR_SOFTWARE, b"rtx-rs")?;
        MessageIntegrity::new_raw(b"password", mock_mac).add_to(writer)
    })
    .expect("signed");

    let plain_msg = assert_verbatim(&plain[..plain_len]);
    let signed_msg = assert_verbatim(&signed[..signed_len]);
    assert_eq!(plain_msg.transaction_id, signed_msg.transaction_id);
    assert_eq!(plain_msg.typ, signed_msg.typ);
    assert!(signed_msg.contains(AttrType(0x0008)));
    assert!(!plain_msg.contains(AttrType(0x0008)));
    assert_eq!(
        signed_len,
        plain_len + 4 + 20,
        "integrity TLV is 24 bytes on the wire"
    );
}

// STUN-IT-017 — decode 对超短输入一律 UnexpectedEnd。
#[test]
fn stun_it_017_short_input_rejected() {
    let mut buf = [0u8; 32];
    let written = build(&mut buf, BINDING_REQUEST, tx(0x0A), |_| Ok(())).expect("build");
    for len in 0..written {
        assert_eq!(
            Message::decode(&buf[..len]).unwrap_err(),
            WireError::UnexpectedEnd,
            "len {len}"
        );
    }
    assert!(Message::decode(&[]).is_err());
}

// STUN-IT-018 — class 常量互异且覆盖全部四个 RFC 5389 类别。
#[test]
fn stun_it_018_class_constants_distinct() {
    let classes = [
        CLASS_REQUEST,
        CLASS_INDICATION,
        CLASS_SUCCESS_RESPONSE,
        CLASS_ERROR_RESPONSE,
    ];
    let values: Vec<u8> = classes.iter().map(|class| class.value()).collect();
    assert_eq!(values, vec![0x00, 0x01, 0x02, 0x03]);
}

// STUN-IT-019 — 文本属性上限边界：SOFTWARE 763 字节放行、764 拒绝。
#[test]
fn stun_it_019_text_attribute_ceiling() {
    // 763 is the ceiling; it pads to 764 on the wire.
    let text = "x".repeat(763);
    let mut buf = vec![0u8; 1024];
    let written = build(&mut buf, BINDING_REQUEST, tx(0x0B), |writer| {
        TextAttribute::new(ATTR_SOFTWARE, &text).push_to(writer)
    })
    .expect("763-byte software fits");
    assert_eq!(written, MESSAGE_HEADER_SIZE + 4 + 764);

    let msg = assert_verbatim(&buf[..written]);
    let attr = msg.get(ATTR_SOFTWARE).expect("software");
    assert_eq!(attr.length, 763);
    assert_eq!(attr.value.len(), 763);

    // One byte over the ceiling is rejected before anything is written.
    let over = "x".repeat(764);
    let mut small = [0u8; 64];
    let err = build(&mut small, BINDING_REQUEST, tx(0x0B), |writer| {
        TextAttribute::new(ATTR_SOFTWARE, &over).push_to(writer)
    })
    .expect_err("764-byte software must be refused");
    assert_eq!(err, WireError::InvalidValue);
}

// STUN-IT-020 — method 常量互异（binding/allocate/data/connection-attempt）。
#[test]
fn stun_it_020_method_constants_distinct() {
    let methods = [
        METHOD_BINDING,
        METHOD_ALLOCATE,
        METHOD_DATA,
        METHOD_CONNECTION_ATTEMPT,
    ];
    let values: Vec<_> = methods.iter().map(|method| method.value()).collect();
    assert_eq!(values, vec![0x001, 0x003, 0x007, 0x00c]);
}

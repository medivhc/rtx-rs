//! L4 — robustness: truncation tables, lying length fields,
//! deterministic LCG compound fuzzing and count-mismatch tables.
//!
//! Two decoder layers are exercised separately, because they enforce
//! different contracts:
//!
//! - the [`RtcpPacket`] dispatcher slices exactly one sub-packet by the
//!   `length` field (`consumed = 4 + length * 4`), so a truncated
//!   well-formed packet is rejected with [`WireError::Overflow`];
//! - the inner packet decoders enforce their own region rules
//!   (count-driven block areas, chunk walks, reason offsets).

mod common;

use rtx_rtcp::goodbye::Goodbye;
use rtx_rtcp::nack::Nack;
use rtx_rtcp::packet::RtcpPacket;
use rtx_rtcp::pli::Pli;
use rtx_rtcp::receiver_report::ReceiverReport;
use rtx_rtcp::sdes::SourceDescription;
use rtx_rtcp::sender_report::SenderReport;
use rtx_rtcp::twcc::Twcc;
use rtx_rtcp::{CompoundPacket, Decode, WireError};
use rtx_wire::Encode;

use common::{encode_rtcp, err, nack_pair, report_block, sdes_chunk};

const SENDER: u32 = 0x1111_2222;
const MEDIA: u32 = 0x3333_4444;

/// Leaks a byte vector into a `'static` slice for the zero-copy
/// packet structs.
fn leak(bytes: Vec<u8>) -> &'static [u8] {
    Box::leak(bytes.into_boxed_slice())
}

/// A 52-byte sender report with one reception block.
fn sr_bytes() -> Vec<u8> {
    let block =
        leak(report_block(0x0BAD_C0DE, 200, 1_000, 0x46E1, 273, 0x09F3_6432, 150_137).to_vec());
    encode_rtcp(&RtcpPacket::SenderReport(SenderReport {
        ssrc: SENDER,
        ntp_time: 0x1122_3344_5566_7788,
        rtp_time: 0x0DEE_DBAD,
        packet_count: 1_000,
        octet_count: 250_000,
        report_blocks: block,
        profile_extensions: &[],
    }))
}

/// A 32-byte receiver report with one block.
fn rr_bytes() -> Vec<u8> {
    let block =
        leak(report_block(0x0BAD_C0DE, 200, 1_000, 0x46E1, 273, 0x09F3_6432, 150_137).to_vec());
    encode_rtcp(&RtcpPacket::ReceiverReport(ReceiverReport {
        ssrc: SENDER,
        report_blocks: block,
        profile_extensions: &[],
    }))
}

/// A 24-byte SDES packet with one CNAME chunk.
fn sdes_bytes() -> Vec<u8> {
    let chunk = leak(sdes_chunk(SENDER, &[(1, b"rtx@example")]));
    encode_rtcp(&RtcpPacket::SourceDescription(SourceDescription {
        body: chunk,
    }))
}

/// A 12-byte BYE with one source and a 3-byte reason.
fn bye_bytes() -> Vec<u8> {
    encode_rtcp(&RtcpPacket::Goodbye(Goodbye {
        sources: leak(SENDER.to_be_bytes().to_vec()),
        reason: Some(leak(b"bye".to_vec())),
    }))
}

/// A 16-byte Generic NACK with one pair.
fn nack_bytes() -> Vec<u8> {
    let pairs = leak(nack_pair(1000, 0x21).to_vec());
    encode_rtcp(&RtcpPacket::Nack(Nack {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
        nacks: pairs,
    }))
}

/// A 28-byte run-length TWCC report (small delta, run 4).
fn twcc_bytes() -> Vec<u8> {
    let report = rtx_rtcp::twcc::TwccRunLengthReport {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
        base_sequence_number: 1000,
        reference_time: 0x0012_3456,
        feedback_packet_count: 7,
        symbol: rtx_rtcp::twcc::SymbolTypeTcc::PacketReceivedSmallDelta,
        run_length: 4,
        recv_deltas: &[11, 22, 33, 44],
    };
    let mut buf = [0u8; 64];
    let mut writer = rtx_wire::Writer::new(&mut buf);
    rtx_rtcp::twcc::write_run_length_report(&mut writer, &report).expect("write twcc report");
    let written = writer.offset();
    buf[..written].to_vec()
}

/// A 12-byte PLI.
fn pli_bytes() -> Vec<u8> {
    encode_rtcp(&RtcpPacket::Pli(Pli {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
    }))
}

// RTCP-ROB-001 — 分发器截断表：well-formed 包的任意前缀都被拒，
// 错误类型由“哪一层的检查先失败”决定。
#[test]
fn rtcp_rob_001_dispatcher_truncation_table() {
    let packets = [
        ("SR", sr_bytes()),
        ("RR", rr_bytes()),
        ("SDES", sdes_bytes()),
        ("BYE", bye_bytes()),
        ("NACK", nack_bytes()),
        ("TWCC", twcc_bytes()),
        ("PLI", pli_bytes()),
    ];

    for (name, bytes) in &packets {
        assert_eq!(err(bytes), None, "{name}: the full packet must decode");
        for prefix in 0..bytes.len() {
            let slice = &bytes[..prefix];
            let error = err(slice);
            match prefix {
                // 头部本身不足 4 字节。
                0..=3 => assert_eq!(
                    error,
                    Some(WireError::UnexpectedEnd),
                    "{name}@{prefix}: short header"
                ),
                // 长度字段声称的字节数超过实际输入。
                _ => assert_eq!(
                    error,
                    Some(WireError::Overflow),
                    "{name}@{prefix}: length field claims more than present"
                ),
            }
        }
    }
}

// RTCP-ROB-002 — 内层解码器截断表：绕过分发器的 length 切片，
// 直接锁定各包型的区域规则与错误类型。
#[test]
fn rtcp_rob_002_inner_decoder_truncation_table() {
    let sr = sr_bytes();
    let rr = rr_bytes();
    let sdes = sdes_bytes();
    let bye = bye_bytes();
    let nack = nack_bytes();
    let twcc = twcc_bytes();
    let pli = pli_bytes();

    // SR：固定区 28 字节 + count 驱动的 block 区。
    assert_eq!(
        SenderReport::decode(&sr[..27]),
        Err(WireError::UnexpectedEnd),
        "SR fixed part truncated"
    );
    assert_eq!(
        SenderReport::decode(&sr[..30]),
        Err(WireError::UnexpectedEnd),
        "SR block region truncated"
    );
    // RR：固定区 8 字节 + count 驱动的 block 区。
    assert_eq!(
        ReceiverReport::decode(&rr[..7]),
        Err(WireError::UnexpectedEnd)
    );
    assert_eq!(
        ReceiverReport::decode(&rr[..30]),
        Err(WireError::UnexpectedEnd)
    );
    // SDES：chunk walk 在 SSRC 后即需 item 类型字节。
    assert_eq!(
        SourceDescription::decode(&sdes[..8]),
        Err(WireError::UnexpectedEnd)
    );
    assert_eq!(
        SourceDescription::decode(&sdes[..12]),
        Err(WireError::UnexpectedEnd),
        "item text runs past the chunk"
    );
    // BYE：4 字节对齐要求；8 字节（无 reason）合法。
    assert_eq!(Goodbye::decode(&bye[..5]), Err(WireError::UnexpectedEnd));
    let (short_bye, consumed) = Goodbye::decode(&bye[..8]).expect("bye without reason");
    assert_eq!(consumed, 8);
    assert_eq!(short_bye.reason, None);
    assert_eq!(short_bye.sources, &SENDER.to_be_bytes());
    // NACK：length 驱动的 pair 区。
    assert_eq!(Nack::decode(&nack[..12]), Err(WireError::UnexpectedEnd));
    // PLI / TWCC：length 驱动的固定区。
    assert_eq!(Pli::decode(&pli[..11]), Err(WireError::UnexpectedEnd));
    assert_eq!(Twcc::decode(&twcc[..26]), Err(WireError::UnexpectedEnd));

    // Ok 分支：8 字节 BYE 重新编码后，length 由内容推导为 1 words，
    // 其余字节与原切片一致（内容派生长度，非逐字节复刻）。
    let mut out = vec![0u8; short_bye.encoded_len()];
    let written = short_bye.encode(&mut out).expect("encode short bye");
    assert_eq!(written, 8);
    assert_eq!(&out[..2], &bye[..2], "v/count and packet type survive");
    assert_eq!(&out[2..4], &[0x00, 0x01], "length re-derived as 1 word");
    assert_eq!(&out[4..8], &bye[4..8], "source list is verbatim");
}

// RTCP-ROB-003 — length 撒谎与尾巴：count 驱动的尾巴成为 profile
// extensions；分发器对超额 length 返回 Overflow。
#[test]
fn rtcp_rob_003_length_field_and_tails() {
    // RR count=1：block 区由 count 驱动（8 + 24 = 32），length 改称
    // 8 words（36 字节）后，多出的 4 字节原样成为 profile extensions。
    let mut rr = rr_bytes();
    rr.extend_from_slice(b"TEST");
    rr[2..4].copy_from_slice(&8u16.to_be_bytes());
    assert_eq!(rr.len(), 36);

    let (packet, consumed) = RtcpPacket::decode(&rr).expect("decode rr with tail");
    assert_eq!(consumed, 36, "dispatcher slices by the length field");
    let RtcpPacket::ReceiverReport(rr) = packet else {
        panic!("expected a receiver report");
    };
    assert_eq!(rr.profile_extensions, b"TEST");
    assert_eq!(rr.header().count, 1);
    assert_eq!(rr.header().length, 8);
    assert_eq!(rr.encoded_len(), 36, "re-encode keeps the tail verbatim");
    assert_eq!(rr.report_blocks.len(), 24, "count still drives one block");

    // 分发器层：length = 0xFFFF words 直接 Overflow。
    let mut lying = rr_bytes();
    lying[2] = 0xFF;
    lying[3] = 0xFF;
    assert_eq!(err(&lying), Some(WireError::Overflow));

    // 复合包：分发器只消费第一个子包；CompoundPacket 走完全部。
    let compound = [&sr_bytes()[..], &sdes_bytes()[..]].concat();
    let (front, consumed) = RtcpPacket::decode(&compound).expect("decode compound front");
    assert_eq!(consumed, sr_bytes().len(), "front packet only");
    assert_eq!(front.header().packet_type, rtx_rtcp::header::PacketType::Sr);
    let (walked, walked_consumed) = CompoundPacket::decode(&compound).expect("compound decode");
    assert_eq!(walked_consumed, compound.len());
    assert_eq!(walked.data(), &compound[..]);
}

// RTCP-ROB-004 — 200 轮 LCG 随机复合包：翻转字节不 panic，
// Ok 时 re-encode/decode 稳定。
#[test]
fn rtcp_rob_004_lcg_random_compounds() {
    let pool = [
        sr_bytes(),
        rr_bytes(),
        sdes_bytes(),
        bye_bytes(),
        nack_bytes(),
        twcc_bytes(),
        pli_bytes(),
    ];
    let mut lcg = common::Lcg::new(0x0DEC_0DEC);

    for round in 0..200u32 {
        // 2..=4 个合法包拼接。
        let count = 2 + lcg.below(3);
        let mut bytes = Vec::new();
        for _ in 0..count {
            bytes.extend_from_slice(&pool[lcg.below(pool.len())]);
        }
        // 0..=3 个随机字节翻转。
        let flips = lcg.below(4);
        for _ in 0..flips {
            if bytes.is_empty() {
                break;
            }
            let index = lcg.below(bytes.len());
            bytes[index] ^= lcg.next_u8();
        }

        // 翻转后拒绝同样合法；本测试只锁定 no-panic 与稳定性。
        if let Ok((packet, consumed)) = RtcpPacket::decode(&bytes) {
            assert!(consumed >= 4, "round {round}: decode must make progress");
            assert!(consumed <= bytes.len(), "round {round}: within the input");
            assert_eq!(consumed % 4, 0, "round {round}: word aligned");
            let mut out = vec![0u8; packet.encoded_len()];
            let written = packet.encode(&mut out).expect("re-encode");
            assert_eq!(
                written,
                out.len(),
                "round {round}: writer matches encoded_len"
            );
            // 重新解码必须成功（编码器产出合法报文）。
            RtcpPacket::decode(&out).unwrap_or_else(|error| {
                panic!("round {round}: re-encoded packet must decode: {error:?}")
            });
        }
    }
}

// RTCP-ROB-005 — count 不匹配表：RR/SR 的 block 区与 SDES 的 chunk
// 计数、BYE 的源列表与 reason 偏移。
#[test]
fn rtcp_rob_005_count_mismatch_table() {
    // RR：count=2 但只带 1 个 block（28 字节 < 8 + 48）。
    let mut rr = rr_bytes();
    rr[0] = 0x82; // count = 2
    assert_eq!(err(&rr), Some(WireError::UnexpectedEnd));

    // SR：count=2 但只带 1 个 block。
    let mut sr = sr_bytes();
    sr[0] = 0x82;
    assert_eq!(err(&sr), Some(WireError::UnexpectedEnd));

    // SDES：count=2 但只有 1 个 chunk；count=1 但有 2 个 chunk。
    let mut sdes = sdes_bytes();
    sdes[0] = 0x82;
    assert_eq!(err(&sdes), Some(WireError::InvalidValue));
    let two_chunks = encode_rtcp(&RtcpPacket::SourceDescription(SourceDescription {
        body: leak(
            sdes_chunk(SENDER, &[(1, b"a")])
                .iter()
                .copied()
                .chain(sdes_chunk(MEDIA, &[(1, b"bb")]))
                .collect(),
        ),
    }));
    let mut one_count = two_chunks;
    one_count[0] = 0x81; // count = 1
    assert_eq!(err(&one_count), Some(WireError::InvalidValue));

    // BYE：count=2 但 body 只有 1 个源（reason_offset 12 > 8）。
    // 手工构造使 length 与内容一致（length=1 → 8 字节）。
    let mut bye_two = SENDER.to_be_bytes().to_vec();
    bye_two.splice(0..0, [0x82, 0xCB, 0x00, 0x01]);
    assert_eq!(bye_two.len(), 8);
    assert_eq!(err(&bye_two), Some(WireError::UnexpectedEnd));

    // BYE：count=1 但源列表之后还压了 4 字节——按 reason 解析
    // （长度前缀 + 字符串），这是 count 驱动的既定行为。
    let mut bye_extra = Vec::new();
    bye_extra.extend_from_slice(&[0x81, 0xCB, 0x00, 0x02]); // count=1, length=2 → 12 bytes
    bye_extra.extend_from_slice(&SENDER.to_be_bytes());
    bye_extra.extend_from_slice(&[0x03, b'T', b'E', b'S']); // 第二个“源”按 reason 读
    let (packet, consumed) = RtcpPacket::decode(&bye_extra).expect("decode bye with tail");
    assert_eq!(consumed, 12);
    let RtcpPacket::Goodbye(bye) = packet else {
        panic!("expected a goodbye packet");
    };
    assert_eq!(bye.sources, &SENDER.to_be_bytes());
    assert_eq!(bye.reason, Some(&b"TES"[..]));
}

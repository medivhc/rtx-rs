//! L4 — robustness: layered truncation tables, padding-count edge
//! cases, extension length lies, encode boundary tables and
//! deterministic LCG fuzzing (zero `rand` dependency).

mod common;

use rtx_rtp::header::{Header, RTP_VERSION};
use rtx_rtp::packet::RtpPacket;
use rtx_wire::{Decode, Encode, WireError};

use common::{Lcg, encode_packet, err, leak};

/// A 52-byte reference packet: 12 fixed + 2 CSRC (8) + extension
/// header (4) + extension data (8) + payload (20), no padding.
fn full_packet() -> Vec<u8> {
    let csrc = leak(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    let data = leak(vec![0x11, 0xAA, 0xBB, 0x50, 0xCC, 0x00, 0x00, 0x00]);
    let packet = RtpPacket {
        header: Header {
            version: RTP_VERSION,
            padding: false,
            extension: true,
            marker: false,
            payload_type: 96,
            sequence_number: 0x0ACE,
            timestamp: 0x0ACE_0ACE,
            ssrc: 0x0F00_0BAD,
            csrc,
            extension_profile: 0xBEDE,
            extension_data: data,
        },
        payload: b"twenty-bytes-payload",
    };
    let bytes = encode_packet(&packet);
    assert_eq!(bytes.len(), 52);
    bytes
}

// RTP-ROB-001 — 分层截断表：错误类型由“哪一层先失败”决定。
#[test]
fn rtp_rob_001_layered_truncation_table() {
    let bytes = full_packet();
    for prefix in 0..bytes.len() {
        let slice = &bytes[..prefix];
        let error = err(slice);
        match prefix {
            // 定长头不足 12 字节。
            0..=11 => assert_eq!(
                error,
                Some(WireError::UnexpectedEnd),
                "@{prefix}: fixed header truncated"
            ),
            // CSRC 列表被切断。
            12..=19 => assert_eq!(
                error,
                Some(WireError::UnexpectedEnd),
                "@{prefix}: CSRC list truncated"
            ),
            // 扩展头（profile + words）被切断。
            20..=23 => assert_eq!(
                error,
                Some(WireError::UnexpectedEnd),
                "@{prefix}: extension header truncated"
            ),
            // 扩展数据不足：words 字段指向输入之外 → Overflow。
            24..=31 => assert_eq!(
                error,
                Some(WireError::Overflow),
                "@{prefix}: extension length points past the input"
            ),
            // 负载区“一直到尾”：任意长度都合法。
            _ => {
                let (packet, consumed) =
                    RtpPacket::decode(slice).unwrap_or_else(|e| panic!("@{prefix}: {e:?}"));
                assert_eq!(consumed, prefix, "@{prefix}: consumed all bytes");
                assert_eq!(
                    packet.payload,
                    &slice[32..],
                    "@{prefix}: payload is the tail"
                );
                let mut out = vec![0u8; packet.encoded_len()];
                assert_eq!(
                    packet.encode(&mut out).expect("re-encode"),
                    out.len(),
                    "@{prefix}"
                );
                assert_eq!(out, slice, "@{prefix}: re-encode is verbatim");
            }
        }
    }
    assert_eq!(err(&bytes), None, "the full packet decodes");
}

// RTP-ROB-002 — padding 计数边界：超额、恰好、零计数的归一化。
#[test]
fn rtp_rob_002_padding_count_edges() {
    let mut header_bytes = [0u8; 12];
    header_bytes[0] = (RTP_VERSION << 6) | 0x20; // v=2, P=1, X=0, CC=0
    header_bytes[1] = 96;

    // count = 5 超过 2 字节负载区 → UnexpectedEnd。
    let mut over = header_bytes.to_vec();
    over.extend_from_slice(&[0x61, 0x05]);
    assert_eq!(err(&over), Some(WireError::UnexpectedEnd));

    // count = 2：2 字节负载 + 1 补零 + 计数自身 → 规范 padding。
    let mut exact = header_bytes.to_vec();
    exact.extend_from_slice(&[0x61, 0x62, 0x00, 0x02]);
    let (packet, consumed) = RtpPacket::decode(&exact).expect("decode exact padding");
    assert_eq!(consumed, exact.len());
    assert_eq!(packet.payload, b"ab");
    assert_eq!(packet.padding_len(), 2);
    let mut out = vec![0u8; packet.encoded_len()];
    assert_eq!(packet.encode(&mut out).expect("re-encode"), out.len());
    assert_eq!(out, exact, "canonical padding re-encodes verbatim");

    // count = 0：不剥离任何字节，负载含尾部零；重新编码按规则归一化
    // （2 字节负载 → 2 字节 padding，末字节为计数）。
    let mut zero = header_bytes.to_vec();
    zero.extend_from_slice(&[0x61, 0x00]);
    let (packet, _) = RtpPacket::decode(&zero).expect("decode zero padding count");
    assert_eq!(packet.payload, &[0x61, 0x00], "count 0 strips nothing");
    assert_eq!(
        packet.padding_len(),
        2,
        "re-derived from the 2-byte payload"
    );
    let mut out = vec![0u8; packet.encoded_len()];
    let written = packet.encode(&mut out).expect("re-encode");
    assert_eq!(written, 16);
    assert_eq!(&out[12..14], &[0x61, 0x00], "payload verbatim");
    assert_eq!(
        &out[14..16],
        &[0x00, 0x02],
        "padding normalized to the rule"
    );
}

// RTP-ROB-003 — 扩展 length 撒谎与编码期的对齐校验。
#[test]
fn rtp_rob_003_extension_length_lies_and_encode_alignment() {
    let mut bytes = full_packet();
    // words = 0xFFFF（偏移 22..24：profile 之后）→ Overflow。
    bytes[22] = 0xFF;
    bytes[23] = 0xFF;
    assert_eq!(err(&bytes), Some(WireError::Overflow));

    // words = 2 但只剩 1 个词 → Overflow。
    let mut short = full_packet();
    short.truncate(28); // 24 固定 + 4 扩展数据，声称 8
    assert_eq!(err(&short), Some(WireError::Overflow));

    // 编码期：扩展数据非 4 字节倍数 → InvalidValue。
    let misaligned = RtpPacket {
        header: Header {
            version: RTP_VERSION,
            padding: false,
            extension: true,
            marker: false,
            payload_type: 96,
            sequence_number: 1,
            timestamp: 1,
            ssrc: 1,
            csrc: &[],
            extension_profile: 0xBEDE,
            extension_data: leak(vec![0x11, 0xAA, 0xBB]), // 3 bytes
        },
        payload: b"",
    };
    let mut out = [0u8; 64];
    assert_eq!(misaligned.encode(&mut out), Err(WireError::InvalidValue));
}

// RTP-ROB-004 — 编码边界表：CC 超限、CSRC 未对齐、输出缓冲区不足。
#[test]
fn rtp_rob_004_encode_boundary_table() {
    let base = Header {
        version: RTP_VERSION,
        padding: false,
        extension: false,
        marker: false,
        payload_type: 96,
        sequence_number: 1,
        timestamp: 1,
        ssrc: 1,
        csrc: &[],
        extension_profile: 0,
        extension_data: &[],
    };

    // CC=16（64 字节）超过 CC_MAX=15 → InvalidValue。
    let too_many = RtpPacket {
        header: Header {
            csrc: leak(vec![0u8; 64]),
            ..base
        },
        payload: b"",
    };
    let mut out = [0u8; 128];
    assert_eq!(too_many.encode(&mut out), Err(WireError::InvalidValue));

    // CSRC 区 3 字节（非 4 的倍数）→ InvalidValue。
    let misaligned = RtpPacket {
        header: Header {
            csrc: leak(vec![1, 2, 3]),
            ..base
        },
        payload: b"",
    };
    assert_eq!(misaligned.encode(&mut out), Err(WireError::InvalidValue));

    // 输出缓冲区比 encoded_len 少 1 字节 → OutputTooSmall。
    let plain = RtpPacket {
        header: base,
        payload: b"0123456789",
    };
    let mut tight = vec![0u8; plain.encoded_len() - 1];
    assert_eq!(plain.encode(&mut tight), Err(WireError::OutputTooSmall));
    let mut exact = vec![0u8; plain.encoded_len()];
    assert_eq!(plain.encode(&mut exact).expect("exact buffer"), exact.len());
}

// RTP-ROB-005 — 300 轮纯随机字节模糊：no-panic + 稳定性 +
// 无 padding 时报文级 verbatim。
#[test]
fn rtp_rob_005_lcg_random_fuzz() {
    let mut lcg = Lcg::new(0x0ACE_0ACE);
    let mut decoded_ok = 0usize;

    for round in 0..300u32 {
        let len = lcg.below(80);
        let mut bytes = vec![0u8; len];
        for byte in &mut bytes {
            *byte = lcg.next_u8();
        }
        // 强制 version=2，让模糊集中在结构字段而非版本门。
        if !bytes.is_empty() {
            bytes[0] = 0x80 | (bytes[0] & 0x3F);
        }

        if let Ok((packet, consumed)) = RtpPacket::decode(&bytes) {
            decoded_ok += 1;
            assert_eq!(consumed, len, "round {round}: decode consumes everything");
            let mut out = vec![0u8; packet.encoded_len()];
            let written = packet.encode(&mut out).expect("re-encode");
            assert_eq!(
                written,
                out.len(),
                "round {round}: writer matches encoded_len"
            );
            RtpPacket::decode(&out)
                .unwrap_or_else(|e| panic!("round {round}: re-decode failed: {e:?}"));
            if !packet.header.padding {
                assert_eq!(out, bytes, "round {round}: verbatim without padding");
            }
        }
    }
    assert!(decoded_ok > 0, "the fuzzer should decode some inputs");
}

// RTP-ROB-006 — 300 轮种子变异模糊：合法包翻转移 1..=3 字节。
#[test]
fn rtp_rob_006_seeded_mutation_fuzz() {
    // 变体池：带 padding、带扩展、带 CSRC、纯头。
    let csrc = leak(vec![0x01, 0x02, 0x03, 0x04]);
    let data = leak(vec![0x11, 0xAA, 0xBB, 0x50, 0xCC, 0x00, 0x00, 0x00]);
    let pool = [
        full_packet(),
        encode_packet(&RtpPacket {
            header: Header {
                version: RTP_VERSION,
                padding: true,
                extension: false,
                marker: true,
                payload_type: 96,
                sequence_number: 9,
                timestamp: 9,
                ssrc: 9,
                csrc: &[],
                extension_profile: 0,
                extension_data: &[],
            },
            payload: b"padded-payload!",
        }),
        encode_packet(&RtpPacket {
            header: Header {
                csrc,
                extension: true,
                extension_profile: 0x1000,
                extension_data: data,
                ..Header {
                    version: RTP_VERSION,
                    padding: false,
                    extension: false,
                    marker: false,
                    payload_type: 96,
                    sequence_number: 1,
                    timestamp: 1,
                    ssrc: 1,
                    csrc: &[],
                    extension_profile: 0,
                    extension_data: &[],
                }
            },
            payload: b"ext",
        }),
    ];

    let mut lcg = Lcg::new(0x5EED_5EED);
    let mut decoded_ok = 0usize;
    for round in 0..300u32 {
        let mut bytes = pool[lcg.below(pool.len())].clone();
        let flips = 1 + lcg.below(3);
        for _ in 0..flips {
            let index = lcg.below(bytes.len());
            bytes[index] ^= lcg.next_u8();
        }

        if let Ok((packet, consumed)) = RtpPacket::decode(&bytes) {
            decoded_ok += 1;
            assert_eq!(consumed, bytes.len(), "round {round}");
            let mut out = vec![0u8; packet.encoded_len()];
            let written = packet.encode(&mut out).expect("re-encode");
            assert_eq!(written, out.len(), "round {round}");
            RtpPacket::decode(&out)
                .unwrap_or_else(|e| panic!("round {round}: re-decode failed: {e:?}"));
            if !packet.header.padding {
                assert_eq!(out, bytes, "round {round}: verbatim without padding");
            }
        }
    }
    assert!(
        decoded_ok > 0,
        "the mutation fuzzer should decode some inputs"
    );
}

//! L2/L3 — transport-wide congestion control pipelines
//! (draft-holmer-rmcat-transport-wide-cc-extensions-01).
//!
//! The TWCC report is exercised through both construction paths —
//! [`write_run_length_report`] for single-run reports and a hand-built
//! [`Twcc`] for mixed status-vector reports — and the per-packet view
//! is cross-checked against the RTP packets the transport-wide
//! sequence number extension was stamped on (rtx-rtp).

mod common;

use rtx_rtcp::header::PacketType;
use rtx_rtcp::packet::RtcpPacket;
use rtx_rtcp::twcc::{
    RunLengthChunk, StatusVectorChunk, SymbolTypeTcc, Twcc, TwccRunLengthReport,
    write_run_length_report,
};
use rtx_rtcp::{Decode, WireError};
use rtx_rtp::extension::EXTENSION_PROFILE_ONE_BYTE;
use rtx_rtp::header::Header as RtpHeader;
use rtx_rtp::packet::RtpPacket;
use rtx_wire::{Encode, Writer};

use common::{assert_packet_verbatim, encode_rtcp};

const SENDER: u32 = 0x0FA1_7FA1;
const MEDIA: u32 = 0x0FA1_7FA1;

/// Encodes a single-run-length report and returns the padded bytes.
fn run_length_bytes(report: &TwccRunLengthReport<'_>) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut writer = Writer::new(&mut buf);
    write_run_length_report(&mut writer, report).expect("write run-length report");
    let written = writer.offset();
    buf[..written].to_vec()
}

// RTCP-TWCC-001 — run-length small-delta：4 个包 × 1 字节 delta，µs 换算往返。
#[test]
fn rtcp_twcc_001_run_length_small_delta() {
    let report = TwccRunLengthReport {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
        base_sequence_number: 1000,
        reference_time: 0x0012_3456,
        feedback_packet_count: 7,
        symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
        run_length: 4,
        recv_deltas: &[11, 22, 33, 44],
    };
    let bytes = run_length_bytes(&report);
    assert_eq!(bytes.len(), 28, "20 fixed + 2 chunk + 4 deltas + 2 padding");

    // 线上字节抽查：FMT=15 / PT=205 / padding 位置与 run-length chunk。
    assert_eq!(bytes[0], 0xAF, "v=2, count=15 (FMT)");
    assert_eq!(bytes[1], 0xCD, "TSFB");
    assert_eq!(&bytes[2..4], &[0x00, 0x06], "length 6 words");
    assert_eq!(
        &bytes[20..22],
        &[0x20, 0x04],
        "run-length chunk: small delta, run 4"
    );
    assert_eq!(
        &bytes[26..28],
        &[0x00, 0x02],
        "self-describing padding: 2 bytes"
    );

    let decoded = assert_packet_verbatim(&bytes);
    let RtcpPacket::Twcc(twcc) = decoded else {
        panic!("expected a TWCC packet");
    };
    assert_eq!(twcc.sender_ssrc, SENDER);
    assert_eq!(twcc.media_ssrc, MEDIA);
    assert_eq!(twcc.base_sequence_number, 1000);
    assert_eq!(twcc.packet_status_count, 4);
    assert_eq!(twcc.reference_time, 0x0012_3456);
    assert_eq!(twcc.feedback_packet_count, 7);
    assert_eq!(twcc.header().count, 15);
    assert_eq!(twcc.header().packet_type, PacketType::Tsfb);
    assert!(twcc.header().padding);

    let statuses: Vec<_> = twcc.status_iter().collect();
    assert_eq!(statuses.len(), 4);
    for (index, status) in statuses.iter().enumerate() {
        assert_eq!(
            status.seq,
            1000 + u16::try_from(index).expect("index fits u16")
        );
        assert_eq!(status.status, SymbolTypeTcc::PacketReceivedSmallDelta);
        // delta 单位为 250µs：11/22/33/44 → 2750/5500/8250/11000 µs。
        let raw = 11 * (i64::try_from(index + 1).expect("index fits i64"));
        assert_eq!(status.delta, Some(raw * 250));
    }
}

// RTCP-TWCC-002 — run-length large-delta：i16 有符号 delta 往返。
#[test]
fn rtcp_twcc_002_run_length_large_delta() {
    let report = TwccRunLengthReport {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
        base_sequence_number: 65_000,
        reference_time: 0x0000_FFFF,
        feedback_packet_count: 255,
        symbol: SymbolTypeTcc::PacketReceivedLargeDelta,
        run_length: 3,
        recv_deltas: &[0x00, 0x64, 0xFF, 0x9C, 0x7F, 0xFF],
    };
    let bytes = run_length_bytes(&report);
    assert_eq!(bytes.len(), 28, "20 fixed + 2 chunk + 6 deltas, no padding");
    assert_eq!(bytes[0], 0x8F, "v=2, P=0 (no padding), count=15 (FMT)");
    assert_eq!(&bytes[2..4], &[0x00, 0x06], "length 6 words");
    assert_eq!(
        &bytes[20..22],
        &[0x40, 0x03],
        "run-length chunk: large delta, run 3"
    );

    let decoded = assert_packet_verbatim(&bytes);
    let RtcpPacket::Twcc(twcc) = decoded else {
        panic!("expected a TWCC packet");
    };
    let statuses: Vec<_> = twcc.status_iter().collect();
    assert_eq!(statuses.len(), 3);
    // 100, -100 与 i16 最大值。
    assert_eq!(statuses[0].delta, Some(100 * 250));
    assert_eq!(statuses[1].delta, Some(-100 * 250));
    assert_eq!(statuses[2].delta, Some(i64::from(i16::MAX) * 250));
    // 序列号在 u16 边界回绕。
    assert_eq!(statuses[0].seq, 65_000);
    assert_eq!(statuses[1].seq, 65_001);
    assert_eq!(statuses[2].seq, 65_002);
    for status in &statuses {
        assert_eq!(status.status, SymbolTypeTcc::PacketReceivedLargeDelta);
    }
}

// RTCP-TWCC-003 — one-bit 状态向量：14 个符号（8 received + 6 not）。
#[test]
fn rtcp_twcc_003_one_bit_status_vector() {
    // 上游 unmarshal 向量 chunk：0x9F 0x1C。
    // 0x9F = 1001 1111 → R N N R R R；0x1C = 0001 1100 → N N N R R R N N。
    let chunks: &'static [u8] = Box::leak(vec![0x9F, 0x1C].into_boxed_slice());
    let deltas: &'static [u8] = Box::leak(vec![11, 22, 33, 44, 55, 66, 77, 88].into_boxed_slice());
    let packet = RtcpPacket::Twcc(Twcc {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
        base_sequence_number: 500,
        packet_status_count: 14,
        reference_time: 0x00AB_CDEF,
        feedback_packet_count: 3,
        chunks,
        recv_deltas: deltas,
    });
    let bytes = encode_rtcp(&packet);
    assert_eq!(bytes.len(), 32, "20 fixed + 2 chunk + 8 deltas + 2 padding");

    let decoded = assert_packet_verbatim(&bytes);
    let RtcpPacket::Twcc(twcc) = decoded else {
        panic!("expected a TWCC packet");
    };
    assert_eq!(twcc.chunks, &[0x9F, 0x1C]);
    assert_eq!(twcc.recv_deltas, &[11, 22, 33, 44, 55, 66, 77, 88]);

    // 0x9F = 1001 1111 → 低 6 位（符号 0..5）= 0,1,1,1,1,1 → N R R R R R
    // 0x1C = 0001 1100 → 符号 6..13 = 0,0,0,1,1,1,0,0 → N N N R R R N N
    let statuses: Vec<_> = twcc.status_iter().collect();
    assert_eq!(statuses.len(), 14);
    let expected_received = [
        false, true, true, true, true, true, false, false, false, true, true, true, false, false,
    ];
    for (index, status) in statuses.iter().enumerate() {
        assert_eq!(
            status.seq,
            500 + u16::try_from(index).expect("index fits u16")
        );
        if expected_received[index] {
            assert_eq!(status.status, SymbolTypeTcc::PacketReceivedSmallDelta);
        } else {
            assert_eq!(status.status, SymbolTypeTcc::PacketNotReceived);
            assert_eq!(status.delta, None);
        }
    }
    // 8 个 received 各消耗 1 字节 delta，顺序与线上一致。
    let received_deltas: Vec<i64> = statuses.iter().filter_map(|status| status.delta).collect();
    assert_eq!(
        received_deltas,
        vec![2750, 5500, 8250, 11_000, 13_750, 16_500, 19_250, 22_000]
    );
}

// RTCP-TWCC-004 — 跨 crate：RTP TWCC 扩展序号 ↔ TWCC 报告 base 映射。
#[test]
fn rtcp_twcc_004_rtp_transport_wide_mapping() {
    // 10 个 RTP 包，序列号 1000..1009，各带 id=1 的
    // transport-wide sequence number 扩展（one-byte framing，2 字节值）。
    let mut packets = Vec::new();
    for index in 0..10u16 {
        let seq = 1000 + index;
        let mut extension_data = vec![0x11]; // id=1, length=2-1
        extension_data.extend_from_slice(&seq.to_be_bytes());
        extension_data.push(0x00); // 词对齐补零
        let packet = RtpPacket {
            header: RtpHeader {
                version: 2,
                padding: false,
                extension: true,
                marker: index == 9,
                payload_type: 96,
                sequence_number: seq,
                timestamp: 0xDEAD_BEEF,
                ssrc: 0x1234_5678,
                csrc: &[],
                extension_profile: EXTENSION_PROFILE_ONE_BYTE,
                extension_data: &extension_data,
            },
            payload: b"frame-payload",
        };
        let mut buf = vec![0u8; packet.encoded_len()];
        let written = packet.encode(&mut buf).expect("encode rtp");
        assert_eq!(written, buf.len());
        packets.push(buf);
    }

    // TWCC 报告覆盖同一区间：base=1000、10 个包全部 small-delta。
    let deltas: Vec<u8> = (1..=10u8).collect();
    let report = TwccRunLengthReport {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
        base_sequence_number: 1000,
        reference_time: 0x0001_0203,
        feedback_packet_count: 42,
        symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
        run_length: 10,
        recv_deltas: &deltas,
    };
    let twcc_bytes = run_length_bytes(&report);

    let decoded = assert_packet_verbatim(&twcc_bytes);
    let RtcpPacket::Twcc(twcc) = decoded else {
        panic!("expected a TWCC packet");
    };

    let statuses: Vec<_> = twcc.status_iter().collect();
    assert_eq!(statuses.len(), 10);

    for (index, (bytes, status)) in packets.iter().zip(statuses.iter()).enumerate() {
        // 1) RTP 包自身往返，且扩展值 = RTP 序列号（transport-wide 序号）。
        let (packet, consumed) = RtpPacket::decode(bytes).expect("decode rtp");
        assert_eq!(consumed, bytes.len());
        assert_eq!(
            packet.header.sequence_number,
            1000 + u16::try_from(index).expect("fits")
        );
        let extension = packet
            .header
            .find_extension(1)
            .expect("transport-wide extension");
        assert_eq!(
            extension.payload,
            (1000 + u16::try_from(index).expect("fits")).to_be_bytes()
        );
        assert_eq!(packet.payload, b"frame-payload");
        assert_eq!(packet.header.marker, index == 9);

        // 2) TWCC 逐包 seq 与 RTP 序列号对齐，delta 与打包顺序一致。
        assert_eq!(status.seq, packet.header.sequence_number);
        assert_eq!(
            status.delta,
            Some(i64::from(u8::try_from(index + 1).expect("index fits u8")) * 250)
        );
    }
}

// RTCP-TWCC-005 — `write_run_length_report` 参数校验表。
#[test]
fn rtcp_twcc_005_report_parameter_validation() {
    let base = TwccRunLengthReport {
        symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
        run_length: 4,
        recv_deltas: &[1, 2, 3, 4],
        ..TwccRunLengthReport::default()
    };

    let cases: Vec<(&str, TwccRunLengthReport<'_>, WireError)> = vec![
        (
            "run_length zero",
            TwccRunLengthReport {
                run_length: 0,
                ..base
            },
            WireError::InvalidValue,
        ),
        (
            "run_length exceeds 13 bits",
            TwccRunLengthReport {
                run_length: 0x2000,
                recv_deltas: &[0; 0x2000],
                ..base
            },
            WireError::InvalidValue,
        ),
        (
            "reference time exceeds 24 bits",
            TwccRunLengthReport {
                reference_time: 0x0100_0000,
                ..base
            },
            WireError::InvalidValue,
        ),
        (
            "deltas shorter than the run",
            TwccRunLengthReport {
                recv_deltas: &[1, 2],
                ..base
            },
            WireError::InvalidValue,
        ),
        (
            "deltas longer than the run",
            TwccRunLengthReport {
                recv_deltas: &[1, 2, 3, 4, 5],
                ..base
            },
            WireError::InvalidValue,
        ),
        (
            "not-received symbol must carry no deltas",
            TwccRunLengthReport {
                symbol: SymbolTypeTcc::PacketNotReceived,
                recv_deltas: &[],
                ..base
            },
            WireError::OutputTooSmall,
        ),
    ];

    for (name, report, expected) in cases {
        let mut buf = [0u8; 4]; // 空间不足同样走 OutputTooSmall
        let mut writer = Writer::new(&mut buf);
        assert_eq!(
            write_run_length_report(&mut writer, &report),
            Err(expected),
            "case: {name}"
        );
    }

    // 合法边界：run_length = 0x1FFF 且 ref_time = 0xFFFFFF 放行
    // （写入目标缓冲区足够大）。
    let mut deltas = vec![0u8; 0x1FFF];
    let max = TwccRunLengthReport {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
        base_sequence_number: 0,
        reference_time: 0x00FF_FFFF,
        feedback_packet_count: 0,
        symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
        run_length: 0x1FFF,
        recv_deltas: &deltas,
    };
    let mut buf = vec![0u8; 20 + 2 + deltas.len() + 3];
    let mut writer = Writer::new(&mut buf);
    write_run_length_report(&mut writer, &max).expect("max run length is legal");
    deltas.clear();
}

// RTCP-TWCC-006 — decode 期健壮性：run_length=0 与 delta 区不足拒绝。
#[test]
fn rtcp_twcc_006_decode_rejects_malformed_reports() {
    // 1) run_length = 0 的 run-length chunk（上游会死循环）。
    let zero_run = [
        0xAF, 0xCD, 0x00, 0x06, // v=2, FMT=15, TSFB, length 6
        0x0F, 0xA1, 0x7F, 0xA1, // sender
        0x0F, 0xA1, 0x7F, 0xA1, // media
        0x03, 0xE8, 0x00, 0x04, // base=1000, count=4
        0x12, 0x34, 0x56, 0x07, // ref time + fbc
        0x20, 0x00, // run-length chunk: small delta, run 0
        0x0A, 0x0B, 0x0C, 0x0D, // 4 delta bytes（声称有但 run 为 0）
        0x00, 0x00,
    ];
    assert_eq!(
        RtcpPacket::decode(&zero_run).err(),
        Some(WireError::InvalidValue)
    );

    // 2) delta 区字节不足：count=4 small-delta 只带 2 字节，length=5（total=24）。
    let short_deltas = [
        0xAF, 0xCD, 0x00, 0x05, 0x0F, 0xA1, 0x7F, 0xA1, 0x0F, 0xA1, 0x7F, 0xA1, 0x03, 0xE8, 0x00,
        0x04, 0x12, 0x34, 0x56, 0x07, 0x20, 0x04, 0x0A, 0x0B,
    ];
    assert_eq!(
        RtcpPacket::decode(&short_deltas).err(),
        Some(WireError::UnexpectedEnd)
    );

    // 3) length 撒谎：声称 0xFFFF words（分发器切片前即拒绝）。
    let lying_length = [
        0xAF, 0xCD, 0xFF, 0xFF, 0x0F, 0xA1, 0x7F, 0xA1, 0x0F, 0xA1, 0x7F, 0xA1, 0x03, 0xE8, 0x00,
        0x04, 0x12, 0x34, 0x56, 0x07, 0x20, 0x04, 0x0A, 0x0B, 0x0C, 0x0D,
    ];
    assert_eq!(
        RtcpPacket::decode(&lying_length).err(),
        Some(WireError::Overflow)
    );

    // 4) chunk 构造原语：to_bytes/from_bytes 与 covered 语义。
    let run = RunLengthChunk::new(SymbolTypeTcc::PacketReceivedWithoutDelta, 24)
        .expect("valid run length");
    assert_eq!(run.to_bytes(), [0x60, 0x18], "上游向量：24 个无 delta 包");
    assert_eq!(run.covered(), 24);
    assert_eq!(RunLengthChunk::from_bytes([0x60, 0x18]), run);

    let vector = StatusVectorChunk::from_bytes([0x9F, 0x1C]);
    assert_eq!(vector.visible_len(), 14);
    assert_eq!(vector.symbols().count(), 14);
    assert_eq!(vector.covered(), 14);
    assert_eq!(
        vector.to_bytes(),
        [0x9F, 0x1C],
        "one-bit 向量重编码逐字节相等"
    );
}

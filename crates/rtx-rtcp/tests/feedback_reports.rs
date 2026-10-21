//! L3 — feedback and report packet pipelines (RFC 4585 / RFC 5104 /
//! draft-alvestrand-rmcat-remb / draft-holmer transport-wide cc).
//!
//! Every modelled feedback type is built from its public struct,
//! encoded, decoded back through the [`RtcpPacket`] dispatcher and
//! re-encoded verbatim, with the semantic accessors (pair expansion,
//! entry iteration, bitrate decode) asserted in between.

mod common;

use common::{assert_packet_verbatim, encode_rtcp, fir_entry, nack_pair, report_block, sli_entry};
use rtx_rtcp::Decode;
use rtx_rtcp::fir::Fir;
use rtx_rtcp::header::PacketType;
use rtx_rtcp::nack::{Nack, NackPair};
use rtx_rtcp::packet::RtcpPacket;
use rtx_rtcp::pli::Pli;
use rtx_rtcp::rapid_resync::RapidResync;
use rtx_rtcp::reception_report::ReceptionReport;
use rtx_rtcp::remb::Remb;
use rtx_rtcp::sender_report::SenderReport;
use rtx_rtcp::sli::Sli;

const SENDER: u32 = 0x1111_2222;
const MEDIA: u32 = 0x3333_4444;

// RTCP-FB-001 — Generic NACK 单 pair：packet_ids 展开为单个序列号。
#[test]
fn rtcp_fb_001_nack_single_pair() {
    let pairs = nack_pair(500, 0);
    let packet = RtcpPacket::Nack(Nack {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
        nacks: &pairs,
    });
    let bytes = encode_rtcp(&packet);

    let decoded = assert_packet_verbatim(&bytes);
    let RtcpPacket::Nack(nack) = decoded else {
        panic!("expected a NACK packet");
    };
    assert_eq!(nack.sender_ssrc, SENDER);
    assert_eq!(nack.media_ssrc, MEDIA);
    assert_eq!(nack.header().count, 1, "count carries FMT_NACK");
    assert_eq!(nack.header().packet_type, PacketType::Tsfb);

    let pairs: Vec<_> = nack.pairs().collect();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].packet_id, 500);
    assert_eq!(pairs[0].lost_packets, 0);
    let ids: Vec<_> = pairs[0].packet_ids().collect();
    assert_eq!(ids, vec![500]);
}

// RTCP-FB-002 — NACK bitmask：BLP 位展开为后续丢失序列号。
#[test]
fn rtcp_fb_002_nack_bitmask_expansion() {
    // Bit 0 and bit 5 set: packet_id + 1 and packet_id + 6 are lost too.
    let pairs = nack_pair(1000, 0b0000_0000_0010_0001);
    let packet = RtcpPacket::Nack(Nack {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
        nacks: &pairs,
    });
    let bytes = encode_rtcp(&packet);

    let decoded = assert_packet_verbatim(&bytes);
    let RtcpPacket::Nack(nack) = decoded else {
        panic!("expected a NACK packet");
    };
    // `packet_ids` borrows the pair, so materialize the pairs first.
    let pairs: Vec<_> = nack.pairs().collect();
    let ids: Vec<_> = pairs.iter().flat_map(NackPair::packet_ids).collect();
    assert_eq!(ids, vec![1000, 1001, 1006]);
}

// RTCP-FB-003 — PLI：FMT 与固定长度，往返。
#[test]
fn rtcp_fb_003_pli_round_trip() {
    let packet = RtcpPacket::Pli(Pli {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
    });
    let bytes = encode_rtcp(&packet);
    assert_eq!(bytes.len(), 12, "PLI is a fixed 12 octets");

    let decoded = assert_packet_verbatim(&bytes);
    let RtcpPacket::Pli(pli) = decoded else {
        panic!("expected a PLI packet");
    };
    assert_eq!(pli.sender_ssrc, SENDER);
    assert_eq!(pli.media_ssrc, MEDIA);
    assert_eq!(pli.header().count, 1);
    assert_eq!(pli.header().packet_type, PacketType::Psfb);
    assert_eq!(pli.header().length, 2);
}

// RTCP-FB-004 — SLI 双条目：first/number/picture 字段往返。
#[test]
fn rtcp_fb_004_sli_entries() {
    let mut entries = Vec::new();
    entries.extend_from_slice(&sli_entry(10, 3, 5));
    // Field widths: 13/13/6 bits — over-wide inputs truncate to the max.
    entries.extend_from_slice(&sli_entry(0xFFFF, 0xFFFF, 0xFF));
    let packet = RtcpPacket::Sli(Sli {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
        entries: &entries,
    });
    let bytes = encode_rtcp(&packet);

    let decoded = assert_packet_verbatim(&bytes);
    let RtcpPacket::Sli(sli) = decoded else {
        panic!("expected an SLI packet");
    };
    assert_eq!(sli.header().count, 2, "count carries FMT_SLI");
    let collected: Vec<_> = sli.entries().collect();
    assert_eq!(collected.len(), 2);
    assert_eq!(collected[0].first, 10);
    assert_eq!(collected[0].number, 3);
    assert_eq!(collected[0].picture, 5);
    // Field widths: 13/13/6 bits.
    assert_eq!(collected[1].first, 0x1FFF);
    assert_eq!(collected[1].number, 0x1FFF);
    assert_eq!(collected[1].picture, 0x3F);
}

// RTCP-FB-005 — FIR 双条目：SSRC + 请求序号往返。
#[test]
fn rtcp_fb_005_fir_entries() {
    let mut entries = Vec::new();
    entries.extend_from_slice(&fir_entry(0x0AAA_BBBB, 1));
    entries.extend_from_slice(&fir_entry(0x0CCC_DDDD, 200));
    let packet = RtcpPacket::Fir(Fir {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
        entries: &entries,
    });
    let bytes = encode_rtcp(&packet);

    let decoded = assert_packet_verbatim(&bytes);
    let RtcpPacket::Fir(fir) = decoded else {
        panic!("expected a FIR packet");
    };
    assert_eq!(fir.header().count, 4, "count carries FMT_FIR");
    let collected: Vec<_> = fir.entries().collect();
    assert_eq!(collected.len(), 2);
    assert_eq!(collected[0].ssrc, 0x0AAA_BBBB);
    assert_eq!(collected[0].sequence_number, 1);
    assert_eq!(collected[1].ssrc, 0x0CCC_DDDD);
    assert_eq!(collected[1].sequence_number, 200);
}

// RTCP-FB-006 — REMB：bitrate 定点解码与 SSRC 列表往返。
#[test]
fn rtcp_fb_006_remb_bitrate_and_ssrcs() {
    let mut ssrcs = Vec::new();
    for ssrc in [0x1111_1111u32, 0x2222_2222, 0x3333_3333] {
        ssrcs.extend_from_slice(&ssrc.to_be_bytes());
    }
    let packet = RtcpPacket::Remb(Remb::new(SENDER, 1_500_000.0, &ssrcs));
    let bytes = encode_rtcp(&packet);

    let decoded = assert_packet_verbatim(&bytes);
    let RtcpPacket::Remb(remb) = decoded else {
        panic!("expected a REMB packet");
    };
    assert_eq!(remb.header().count, 15, "count carries FMT_REMB");
    assert_eq!(remb.header().packet_type, PacketType::Psfb);
    assert_eq!(remb.ssrc_count(), 3);
    let collected: Vec<_> = remb.ssrc_entries().collect();
    assert_eq!(collected, vec![0x1111_1111, 0x2222_2222, 0x3333_3333]);
    // 1.5 Mbps survives the 18-bit mantissa / 6-bit exponent round trip.
    assert!((remb.bitrate() - 1_500_000.0).abs() < f32::EPSILON);
}

// RTCP-FB-007 — Rapid Resynchronization Request 往返。
#[test]
fn rtcp_fb_007_rapid_resync_round_trip() {
    let packet = RtcpPacket::RapidResync(RapidResync {
        sender_ssrc: SENDER,
        media_ssrc: MEDIA,
    });
    let bytes = encode_rtcp(&packet);
    assert_eq!(bytes.len(), 12);

    let decoded = assert_packet_verbatim(&bytes);
    let RtcpPacket::RapidResync(rrr) = decoded else {
        panic!("expected a rapid resync packet");
    };
    assert_eq!(rrr.sender_ssrc, SENDER);
    assert_eq!(rrr.media_ssrc, MEDIA);
    assert_eq!(rrr.header().count, 5);
    assert_eq!(rrr.header().packet_type, PacketType::Tsfb);
}

// RTCP-FB-008 — 未建模 FMT（TSFB 11 / PSFB 3）原样保留为 Raw。
#[test]
fn rtcp_fb_008_unknown_fmt_stays_raw() {
    // TSFB FMT=11 (RFC 8888 congestion control feedback) and PSFB FMT=3.
    let mut tsfb_11 = vec![0x8B, 0xCD, 0x00, 0x03]; // v=2, count=11, TSFB, length 3
    tsfb_11.extend_from_slice(&SENDER.to_be_bytes());
    tsfb_11.extend_from_slice(&MEDIA.to_be_bytes());
    tsfb_11.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // opaque FCI payload
    let mut psfb_3 = vec![0x83, 0xCE, 0x00, 0x03]; // v=2, count=3, PSFB, length 3
    psfb_3.extend_from_slice(&SENDER.to_be_bytes());
    psfb_3.extend_from_slice(&MEDIA.to_be_bytes());
    psfb_3.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

    for bytes in [&tsfb_11, &psfb_3] {
        let (packet, consumed) = RtcpPacket::decode(bytes).expect("decode raw");
        assert_eq!(consumed, bytes.len());
        let RtcpPacket::Raw(raw) = packet else {
            panic!("expected a raw packet");
        };
        assert_eq!(raw.data(), bytes, "verbatim passthrough");
        let reencoded = encode_rtcp(&RtcpPacket::Raw(raw));
        assert_eq!(reencoded, *bytes, "re-encode is verbatim");
    }
}

// RTCP-FB-009 — SR/RR 的 reception block 迭代与逐字段断言。
#[test]
fn rtcp_fb_009_reception_report_blocks() {
    let block = report_block(
        0x0BAD_C0DE,
        200,
        1_000_000,
        0x46E1,
        273,
        0x09F3_6432,
        150_137,
    );

    let sr = RtcpPacket::SenderReport(SenderReport {
        ssrc: 0x902F_9E2E,
        ntp_time: 0x1122_3344_5566_7788,
        rtp_time: 0x0DEE_DBAD,
        packet_count: 1_000,
        octet_count: 250_000,
        report_blocks: &block,
        profile_extensions: &[],
    });
    let sr_bytes = encode_rtcp(&sr);
    let decoded = assert_packet_verbatim(&sr_bytes);
    let RtcpPacket::SenderReport(sr) = decoded else {
        panic!("expected a sender report");
    };
    assert_eq!(sr.ntp_time, 0x1122_3344_5566_7788);
    assert_eq!(sr.packet_count, 1_000);
    assert_eq!(sr.octet_count, 250_000);
    let reports: Vec<ReceptionReport> = sr.reports().collect();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].ssrc, 0x0BAD_C0DE);
    assert_eq!(reports[0].fraction_lost, 200);
    assert_eq!(reports[0].total_lost, 1_000_000);
    assert_eq!(reports[0].highest_sequence, 0x46E1);
    assert_eq!(reports[0].jitter, 273);
    assert_eq!(reports[0].last_sr, 0x09F3_6432);
    assert_eq!(reports[0].delay_since_last_sr, 150_137);
}

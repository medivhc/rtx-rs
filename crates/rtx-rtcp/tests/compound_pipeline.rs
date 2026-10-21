//! L1/L3 — compound packet pipeline: RFC 3550 §6.4.1 validation rules,
//! the CNAME walk and back-to-back sub-packet iteration.
//!
//! The compound rules are the one place RTCP has cross-packet semantics,
//! so these tests build real multi-packet datagrams (SR/RR + SDES + BYE)
//! and check `validate`, `cname` and the packet walk together.

mod common;

use common::{assert_compound_verbatim, compound, encode_rtcp, report_block, sdes_chunk};
use rtx_rtcp::goodbye::Goodbye;
use rtx_rtcp::header::PacketType;
use rtx_rtcp::packet::RtcpPacket;
use rtx_rtcp::receiver_report::ReceiverReport;
use rtx_rtcp::sdes::SourceDescription;
use rtx_rtcp::sender_report::SenderReport;
use rtx_rtcp::{CompoundPacket, Decode, WireError};
use rtx_wire::Encode;

/// A sender report with one reception block.
fn sr() -> RtcpPacket<'static> {
    let block = report_block(0x0BAD_C0DE, 0, 12, 0x46E1, 273, 0x09F3_6432, 150_137);
    // Leak-free: the block lives in a Box that is never freed again, so
    // the returned packet can borrow it with a 'static lifetime.
    let block: &'static [u8] = Box::leak(block.to_vec().into_boxed_slice());
    RtcpPacket::SenderReport(SenderReport {
        ssrc: 0x902F_9E2E,
        ntp_time: 0x1122_3344_5566_7788,
        rtp_time: 0x0DEE_DBAD,
        packet_count: 1_000,
        octet_count: 250_000,
        report_blocks: block,
        profile_extensions: &[],
    })
}

/// A receiver report with the same reception block.
fn rr() -> RtcpPacket<'static> {
    let block = report_block(0x0BAD_C0DE, 0, 12, 0x46E1, 273, 0x09F3_6432, 150_137);
    let block: &'static [u8] = Box::leak(block.to_vec().into_boxed_slice());
    RtcpPacket::ReceiverReport(ReceiverReport {
        ssrc: 0x902F_9E2E,
        report_blocks: block,
        profile_extensions: &[],
    })
}

/// An SDES packet whose single chunk carries a CNAME.
fn sdes_cname(cname: &[u8]) -> RtcpPacket<'static> {
    let body: &'static [u8] = Box::leak(sdes_chunk(0x0102_0304, &[(1, cname)]).into_boxed_slice());
    RtcpPacket::SourceDescription(SourceDescription { body })
}

/// An SDES packet whose chunk carries only a NAME (no CNAME).
fn sdes_without_cname() -> RtcpPacket<'static> {
    let body: &'static [u8] =
        Box::leak(sdes_chunk(0x0102_0304, &[(2, b"alice")]).into_boxed_slice());
    RtcpPacket::SourceDescription(SourceDescription { body })
}

/// A BYE packet with one source and a reason.
fn bye() -> RtcpPacket<'static> {
    let sources: &'static [u8] =
        Box::leak(0xAABB_CCDDu32.to_be_bytes().to_vec().into_boxed_slice());
    RtcpPacket::Goodbye(Goodbye {
        sources,
        reason: Some(b"session end"),
    })
}

/// Returns the packet types yielded by walking `bytes`.
fn walked_types(bytes: &[u8]) -> Vec<PacketType> {
    CompoundPacket::new(bytes)
        .packets()
        .map(|packet| packet.expect("walk").header().packet_type)
        .collect()
}

// RTCP-IT-001 — SR + SDES 复合包：validate 通过，cname 提取，两包顺序正确。
#[test]
fn rtcp_it_001_sr_sdes_compound_valid() {
    let bytes = compound(&[encode_rtcp(&sr()), encode_rtcp(&sdes_cname(b"user@host"))]);
    let compound_packet = assert_compound_verbatim(&bytes);

    compound_packet.validate().expect("valid compound");
    assert_eq!(compound_packet.cname(), Ok(&b"user@host"[..]));
    assert_eq!(walked_types(&bytes), vec![PacketType::Sr, PacketType::Sdes]);
    assert_eq!(compound_packet.packets().count(), 2);
}

// RTCP-IT-002 — RR + SDES 复合包同样满足 compound 规则。
#[test]
fn rtcp_it_002_rr_sdes_compound_valid() {
    let bytes = compound(&[encode_rtcp(&rr()), encode_rtcp(&sdes_cname(b"rtx@local"))]);
    let compound_packet = assert_compound_verbatim(&bytes);

    compound_packet.validate().expect("valid compound");
    assert_eq!(compound_packet.cname(), Ok(&b"rtx@local"[..]));
    assert_eq!(walked_types(&bytes), vec![PacketType::Rr, PacketType::Sdes]);
}

// RTCP-IT-003 — 首包既非 SR 也非 RR：validate 拒绝。
#[test]
fn rtcp_it_003_first_packet_not_a_report() {
    let bytes = compound(&[encode_rtcp(&sdes_cname(b"user@host")), encode_rtcp(&bye())]);
    let compound_packet = assert_compound_verbatim(&bytes);

    assert_eq!(
        compound_packet.validate().unwrap_err(),
        WireError::InvalidValue
    );
    // `cname` skips the first packet without a type check but still
    // refuses a non-RR packet before the CNAME.
    assert_eq!(
        compound_packet.cname().unwrap_err(),
        WireError::InvalidValue
    );
}

// RTCP-IT-004 — SDES 无 CNAME：validate 拒绝，cname 也找不到。
#[test]
fn rtcp_it_004_sdes_without_cname() {
    let bytes = compound(&[encode_rtcp(&sr()), encode_rtcp(&sdes_without_cname())]);
    let compound_packet = assert_compound_verbatim(&bytes);

    assert_eq!(
        compound_packet.validate().unwrap_err(),
        WireError::InvalidValue
    );
    assert_eq!(
        compound_packet.cname().unwrap_err(),
        WireError::InvalidValue
    );
}

// RTCP-IT-005 — CNAME 之前出现 BYE：两个入口都拒绝。
#[test]
fn rtcp_it_005_non_rr_before_cname() {
    let bytes = compound(&[
        encode_rtcp(&sr()),
        encode_rtcp(&bye()),
        encode_rtcp(&sdes_cname(b"user@host")),
    ]);
    let compound_packet = assert_compound_verbatim(&bytes);

    assert_eq!(
        compound_packet.validate().unwrap_err(),
        WireError::InvalidValue
    );
    assert_eq!(
        compound_packet.cname().unwrap_err(),
        WireError::InvalidValue
    );
}

// RTCP-IT-006 — CNAME 之后的 BYE 合法：validate 在 CNAME 处即返回成功。
#[test]
fn rtcp_it_006_bye_after_cname() {
    let bytes = compound(&[
        encode_rtcp(&sr()),
        encode_rtcp(&sdes_cname(b"user@host")),
        encode_rtcp(&bye()),
    ]);
    let compound_packet = assert_compound_verbatim(&bytes);

    compound_packet.validate().expect("bye after cname is fine");
    assert_eq!(compound_packet.packets().count(), 3);
}

// RTCP-IT-007 — 四包遍历：类型顺序与每包切片逐一比对。
#[test]
fn rtcp_it_007_packets_iteration_slices() {
    let parts = [
        encode_rtcp(&sr()),
        encode_rtcp(&rr()),
        encode_rtcp(&sdes_cname(b"user@host")),
        encode_rtcp(&bye()),
    ];
    let bytes = compound(&parts);
    let compound_packet = assert_compound_verbatim(&bytes);

    let mut offset = 0usize;
    let mut index = 0usize;
    for packet in compound_packet.packets() {
        let packet = packet.expect("walk");
        let len = packet.encoded_len();
        assert_eq!(
            &bytes[offset..offset + len],
            &parts[index][..],
            "sub-packet {index} slice"
        );
        offset += len;
        index += 1;
    }
    assert_eq!(offset, bytes.len());
    assert_eq!(index, parts.len());
    assert_eq!(
        walked_types(&bytes),
        vec![
            PacketType::Sr,
            PacketType::Rr,
            PacketType::Sdes,
            PacketType::Bye
        ]
    );
}

// RTCP-IT-008 — 复合包尾部被截断：CompoundPacket::decode 拒绝。
#[test]
fn rtcp_it_008_truncated_tail_rejected() {
    let bytes = compound(&[encode_rtcp(&sr()), encode_rtcp(&sdes_cname(b"user@host"))]);
    for cut in 1..=3usize {
        let truncated = &bytes[..bytes.len() - cut];
        assert!(
            CompoundPacket::decode(truncated).is_err(),
            "cut {cut} bytes"
        );
    }
}

// RTCP-IT-009 — CNAME 位于第二个 chunk：cname 跨 chunk 查找成功。
#[test]
fn rtcp_it_009_cname_in_second_chunk() {
    let first = sdes_chunk(0x0102_0304, &[(2, b"alice")]);
    let second = sdes_chunk(0x0506_0708, &[(1, b"second@host")]);
    let mut body = first;
    body.extend_from_slice(&second);
    let body: &'static [u8] = Box::leak(body.into_boxed_slice());
    let packet = RtcpPacket::SourceDescription(SourceDescription { body });

    let bytes = compound(&[encode_rtcp(&sr()), encode_rtcp(&packet)]);
    let compound_packet = assert_compound_verbatim(&bytes);

    compound_packet.validate().expect("cname in second chunk");
    assert_eq!(compound_packet.cname(), Ok(&b"second@host"[..]));
}

// RTCP-IT-010 — 空 datagram：decode 成功但 validate/cname 拒绝。
#[test]
fn rtcp_it_010_empty_datagram() {
    let (compound_packet, consumed) = CompoundPacket::decode(&[]).expect("empty decodes");
    assert_eq!(consumed, 0);
    assert_eq!(compound_packet.packets().count(), 0);
    assert_eq!(
        compound_packet.validate().unwrap_err(),
        WireError::InvalidValue
    );
    assert_eq!(
        compound_packet.cname().unwrap_err(),
        WireError::InvalidValue
    );
}

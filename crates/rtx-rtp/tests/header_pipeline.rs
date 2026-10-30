//! L1 — RTP header and packet pipelines over the public API only
//! (RFC 3550 §5.1, RFC 8285 extension framing).
//!
//! Every packet is built from its public struct, encoded, decoded back
//! through [`RtpPacket`]/[`Header`] and re-encoded verbatim, with the
//! semantic accessors (CSRC iteration, extension lookup, padding
//! derivation) asserted in between.

mod common;

use rtx_rtp::header::{Header, RTP_VERSION};
use rtx_rtp::packet::RtpPacket;
use rtx_wire::{Decode, Encode, WireError};

use common::{assert_packet_verbatim, encode_header, encode_packet, leak};

// RTP-IT-001 — 最小 12 字节定长头：全字段往返 + verbatim。
#[test]
fn rtp_it_001_fixed_header_round_trip() {
    let header = Header {
        version: RTP_VERSION,
        padding: false,
        extension: false,
        marker: true,
        payload_type: 96,
        sequence_number: 0x1234,
        timestamp: 0x0102_0304,
        ssrc: 0x0A0B_0C0D,
        csrc: &[],
        extension_profile: 0,
        extension_data: &[],
    };
    let bytes = encode_header(&header);
    assert_eq!(bytes.len(), 12, "fixed header is 12 octets");
    assert_eq!(bytes[0], 0x80, "v=2, P=0, X=0, CC=0");
    assert_eq!(bytes[1], 0xE0, "M=1, PT=96");
    assert_eq!(&bytes[2..4], &[0x12, 0x34]);
    assert_eq!(&bytes[4..8], &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(&bytes[8..12], &[0x0A, 0x0B, 0x0C, 0x0D]);

    let (decoded, consumed) = Header::decode(&bytes).expect("decode header");
    assert_eq!(consumed, 12);
    assert_eq!(decoded, header);
    assert_eq!(decoded.encoded_len(), 12);
    assert!(decoded.marker);
    assert_eq!(decoded.payload_type, 96);

    let packet = RtpPacket {
        header: decoded,
        payload: b"",
    };
    let _ = assert_packet_verbatim(&encode_packet(&packet));
}

// RTP-IT-002 — CSRC 列表：CC=3 迭代 + verbatim。
#[test]
fn rtp_it_002_csrc_list_round_trip() {
    let csrc = leak(vec![
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x33, 0x33, 0x33, 0x33,
    ]);
    let header = Header {
        version: RTP_VERSION,
        padding: false,
        extension: false,
        marker: false,
        payload_type: 0,
        sequence_number: 0,
        timestamp: 0,
        ssrc: 0,
        csrc,
        extension_profile: 0,
        extension_data: &[],
    };
    let bytes = encode_header(&header);
    assert_eq!(bytes.len(), 24, "12 fixed + 3 CSRC words");
    assert_eq!(bytes[0] & 0x0F, 3, "CC field carries the list length");

    let (decoded, _) = Header::decode(&bytes).expect("decode header");
    let csrcs: Vec<u32> = decoded.csrcs().collect();
    assert_eq!(csrcs, vec![0x1111_1111, 0x2222_2222, 0x3333_3333]);
    assert_eq!(decoded.csrc, csrc, "CSRC region is verbatim");
}

// RTP-IT-003 — marker / payload type / version 边界表。
#[test]
fn rtp_it_003_marker_pt_and_version_bounds() {
    let base = Header {
        version: RTP_VERSION,
        padding: false,
        extension: false,
        marker: true,
        payload_type: 127, // 7-bit maximum
        sequence_number: 0xFFFF,
        timestamp: 0xFFFF_FFFF,
        ssrc: 0xFFFF_FFFF,
        csrc: &[],
        extension_profile: 0,
        extension_data: &[],
    };
    let bytes = encode_header(&base);
    assert_eq!(bytes[1], 0xFF, "M=1 with the maximum payload type");
    let (decoded, _) = Header::decode(&bytes).expect("decode max fields");
    assert!(decoded.marker);
    assert_eq!(decoded.payload_type, 127);
    assert_eq!(decoded.sequence_number, 0xFFFF);
    assert_eq!(decoded.timestamp, 0xFFFF_FFFF);
    assert_eq!(decoded.ssrc, 0xFFFF_FFFF);

    // payload type 128 超过 7 位 → 编码拒（经 RtpPacket 的编码路径）。
    let too_wide = RtpPacket {
        header: Header {
            payload_type: 128,
            ..base
        },
        payload: b"",
    };
    let mut out = [0u8; 12];
    assert_eq!(too_wide.encode(&mut out), Err(WireError::InvalidValue));

    // version != 2：编码拒，解码也拒。
    for version in [0u8, 1, 3] {
        let bad = RtpPacket {
            header: Header { version, ..base },
            payload: b"",
        };
        let mut out = [0u8; 12];
        assert_eq!(bad.encode(&mut out), Err(WireError::InvalidValue));
        let mut wire = bytes.clone();
        wire[0] = (version << 6) | (wire[0] & 0x3F);
        assert_eq!(Header::decode(&wire), Err(WireError::InvalidValue));
    }
}

// RTP-IT-004 — 带负载与 padding 的完整报文往返。
#[test]
fn rtp_it_004_packet_with_payload_and_padding() {
    let payload = b"rtx-rtp media payload!!"; // 23 bytes → 1 padding byte
    let packet = RtpPacket {
        header: Header {
            version: RTP_VERSION,
            padding: true,
            extension: false,
            marker: false,
            payload_type: 98,
            sequence_number: 7,
            timestamp: 70_000,
            ssrc: 0x0BAD_F00D,
            csrc: &[],
            extension_profile: 0,
            extension_data: &[],
        },
        payload,
    };
    assert_eq!(packet.padding_len(), 1, "23 % 4 = 3 → 1 padding octet");
    let bytes = encode_packet(&packet);
    assert_eq!(bytes.len(), 36, "12 header + 23 payload + 1 padding");
    assert_eq!(*bytes.last().expect("padding byte"), 1, "count octet");

    let decoded = assert_packet_verbatim(&bytes);
    assert_eq!(decoded.payload, payload, "padding stripped on decode");
    assert!(decoded.header.padding);
    assert_eq!(
        decoded.padding_len(),
        1,
        "padding re-derived from the payload"
    );
}

// RTP-IT-005 — padding 推导规则表（RFC 3550 §5.1：对齐负载得整词 padding）。
#[test]
fn rtp_it_005_padding_derivation_table() {
    let header = Header {
        version: RTP_VERSION,
        padding: true,
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
    // (payload len, expected padding octets)
    let table = [
        (0usize, 4usize), // aligned → a full word per RFC 3550
        (1, 3),
        (2, 2),
        (3, 1),
        (4, 4),
        (5, 3),
        (24, 4),
    ];
    for (len, expected) in table {
        let packet = RtpPacket {
            header,
            payload: &vec![0xABu8; len],
        };
        assert_eq!(packet.padding_len(), expected, "payload len {len}");
        assert_eq!(packet.encoded_len(), 12 + len + expected);
        let bytes = encode_packet(&packet);
        assert_eq!(bytes.len(), 12 + len + expected);
        assert_eq!(*bytes.last().expect("count") as usize, expected);
        // 解码后负载逐字节相等，padding 标记保留。
        let decoded = assert_packet_verbatim(&bytes);
        assert_eq!(decoded.payload.len(), len);
        assert!(decoded.payload.iter().all(|&b| b == 0xAB));
    }

    // padding 标志清零 → 不追加任何 padding。
    let plain = RtpPacket {
        header: Header {
            padding: false,
            ..header
        },
        payload: b"abcd",
    };
    assert_eq!(plain.padding_len(), 0);
    assert_eq!(plain.encoded_len(), 16);
}

// RTP-IT-006 — 头部扩展往返：0xBEDE profile 双元素 + find_extension。
#[test]
fn rtp_it_006_extension_round_trip() {
    // id=1 len=2 → 0x11 aa bb；id=5 len=1 → 0x50 cc；补零到词边界。
    let data = leak(vec![0x11, 0xAA, 0xBB, 0x50, 0xCC, 0x00, 0x00, 0x00]);
    let header = Header {
        version: RTP_VERSION,
        padding: false,
        extension: true,
        marker: true,
        payload_type: 96,
        sequence_number: 0x0F0F,
        timestamp: 0x0E0E_0D0D,
        ssrc: 0x0102_0304,
        csrc: &[],
        extension_profile: 0xBEDE,
        extension_data: data,
    };
    let bytes = encode_header(&header);
    assert_eq!(bytes.len(), 24, "12 fixed + 4 ext header + 8 ext data");
    assert_eq!(&bytes[12..14], &[0xBE, 0xDE], "one-byte profile");
    assert_eq!(&bytes[14..16], &[0x00, 0x02], "two 32-bit words of data");

    let (decoded, _) = Header::decode(&bytes).expect("decode header");
    assert_eq!(decoded.extension_profile, 0xBEDE);
    let ext1 = decoded.find_extension(1).expect("id 1 element");
    assert_eq!(ext1.id, 1);
    assert_eq!(ext1.payload, &[0xAA, 0xBB]);
    let ext5 = decoded.find_extension(5).expect("id 5 element");
    assert_eq!(ext5.payload, &[0xCC]);
    assert!(decoded.find_extension(9).is_none(), "absent element");
    assert_eq!(decoded.extensions().count(), 2, "padding is not an element");

    // 完整报文（带负载）verbatim。
    let packet = RtpPacket {
        header: decoded,
        payload: b"x",
    };
    let _ = assert_packet_verbatim(&encode_packet(&packet));
}

// RTP-IT-007 — 字段边界：CC=15（60 字节 CSRC）+ 全 0xFF 字段。
#[test]
fn rtp_it_007_field_boundaries() {
    let mut csrc_bytes = Vec::new();
    for index in 0..15u8 {
        csrc_bytes.extend_from_slice(&u32::from(index).to_be_bytes());
    }
    let csrc = leak(csrc_bytes);
    let header = Header {
        version: RTP_VERSION,
        padding: false,
        extension: false,
        marker: true,
        payload_type: 127,
        sequence_number: 0xFFFF,
        timestamp: 0xFFFF_FFFF,
        ssrc: 0xFFFF_FFFF,
        csrc,
        extension_profile: 0,
        extension_data: &[],
    };
    let bytes = encode_header(&header);
    assert_eq!(bytes.len(), 72, "12 fixed + 15 CSRC words");
    assert_eq!(bytes[0], 0x8F, "v=2, CC=15");

    let (decoded, _) = Header::decode(&bytes).expect("decode header");
    assert_eq!(decoded.csrcs().count(), 15);
    let csrcs: Vec<u32> = decoded.csrcs().collect();
    assert_eq!(csrcs.first(), Some(&0));
    assert_eq!(csrcs.last(), Some(&14));
}

// RTP-IT-008 — 空负载报文：头即全部，往返后 consumed 覆盖全部输入。
#[test]
fn rtp_it_008_empty_payload_packet() {
    let packet = RtpPacket {
        header: Header {
            version: RTP_VERSION,
            padding: false,
            extension: false,
            marker: false,
            payload_type: 111,
            sequence_number: 0x0ABC,
            timestamp: 0x0DEF_0123,
            ssrc: 0x0F0F_0F0F,
            csrc: &[],
            extension_profile: 0,
            extension_data: &[],
        },
        payload: b"",
    };
    let bytes = encode_packet(&packet);
    assert_eq!(bytes.len(), 12);
    let (decoded, consumed) = RtpPacket::decode(&bytes).expect("decode empty packet");
    assert_eq!(consumed, 12);
    assert_eq!(decoded.payload, []);
    assert_eq!(decoded.header.payload_type, 111);
    assert_eq!(decoded.padding_len(), 0);
}

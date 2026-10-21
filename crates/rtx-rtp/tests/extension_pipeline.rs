//! L2/L3 — header extension element framing pipelines (RFC 8285
//! §4.1/§4.2, RFC 3550 §5.3.1 legacy profiles).
//!
//! The extension layer is exercised through a decoded [`Header`]:
//! multi-element walks in both framings, opaque legacy profiles and
//! the strict validation table used while decoding.

mod common;

use rtx_rtp::extension::{
    EXTENSION_ONE_BYTE_ID_MAX, EXTENSION_ONE_BYTE_LEN_MAX, EXTENSION_PROFILE_ONE_BYTE,
    EXTENSION_PROFILE_TWO_BYTE, EXTENSION_TWO_BYTE_LEN_MAX, ExtensionItem,
    validate_extension_block,
};
use rtx_rtp::header::{Header, RTP_VERSION};
use rtx_rtp::packet::RtpPacket;
use rtx_wire::{Decode, Encode, WireError};

use common::{encode_packet, leak};

/// Wraps extension bytes in a full packet and decodes it back.
fn header_with_extension(profile: u16, data: &'static [u8]) -> Header<'static> {
    let packet = RtpPacket {
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
            extension_profile: profile,
            extension_data: data,
        },
        payload: b"",
    };
    let bytes = leak(encode_packet(&packet));
    let (decoded, _) = RtpPacket::decode(bytes).expect("decode packet with extension");
    assert_eq!(decoded.header.extension_profile, profile);
    assert_eq!(
        decoded.header.extension_data, data,
        "extension region verbatim"
    );
    decoded.header
}

// RTP-EXT-001 — one-byte framing：三元素遍历 + 内部 padding + verbatim。
#[test]
fn rtp_ext_001_one_byte_multi_element_walk() {
    // id=1 len=2 → 0x11 aa bb
    // id=2 len=3 → 0x22 cc dd ee
    // id=14 (max) len=1 → 0xe0 ff
    // 尾部 1 字节补零到词边界（12 字节数据 → 3 words）。
    let data = leak(vec![
        0x11, 0xAA, 0xBB, //
        0x22, 0xCC, 0xDD, 0xEE, //
        0xE0, 0xFF, //
        0x00, 0x00, 0x00, //
    ]);
    let header = header_with_extension(EXTENSION_PROFILE_ONE_BYTE, data);

    let items: Vec<ExtensionItem<'_>> = header.extensions().collect();
    assert_eq!(
        items,
        vec![
            ExtensionItem {
                id: 1,
                payload: &[0xAA, 0xBB]
            },
            ExtensionItem {
                id: 2,
                payload: &[0xCC, 0xDD, 0xEE]
            },
            ExtensionItem {
                id: EXTENSION_ONE_BYTE_ID_MAX,
                payload: &[0xFF]
            },
        ]
    );
    assert_eq!(
        header.find_extension(2).map(|item| item.payload),
        Some(&[0xCC, 0xDD, 0xEE][..])
    );
    assert!(header.find_extension(3).is_none());
    // 16 字节是一字节框架单元素负载上限。
    assert_eq!(EXTENSION_ONE_BYTE_LEN_MAX, 16);

    // 带 CSRC 与负载的完整报文 verbatim。
    let csrc = leak(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let packet = RtpPacket {
        header: Header { csrc, ..header },
        payload: b"payload-bytes",
    };
    let bytes = encode_packet(&packet);
    let (decoded, consumed) = RtpPacket::decode(&bytes).expect("decode full packet");
    assert_eq!(consumed, bytes.len());
    assert_eq!(
        decoded.header.csrcs().collect::<Vec<_>>(),
        vec![0xDEAD_BEEF]
    );
    assert_eq!(decoded.payload, b"payload-bytes");
    let mut out = vec![0u8; decoded.encoded_len()];
    assert_eq!(decoded.encode(&mut out).expect("re-encode"), out.len());
    assert_eq!(out, bytes, "full packet re-encodes verbatim");
}

// RTP-EXT-002 — two-byte framing：双元素 + 255 字节大元素。
#[test]
fn rtp_ext_002_two_byte_framing_walk() {
    // id=5 len=1 → 05 01 aa；id=200 len=255 → c8 ff + 255 字节。
    let mut data = vec![0x05, 0x01, 0xAA];
    data.push(200);
    data.push(255);
    let large: Vec<u8> = (0..=254u8).collect();
    data.extend_from_slice(&large);
    // 3 + 2 + 255 = 260 字节 → 补 4 字节到 264（66 words）。
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    assert_eq!(data.len() % 4, 0);
    let data = leak(data);

    let header = header_with_extension(EXTENSION_PROFILE_TWO_BYTE, data);
    let items: Vec<ExtensionItem<'_>> = header.extensions().collect();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].id, 5);
    assert_eq!(items[0].payload, &[0xAA]);
    assert_eq!(items[1].id, 200);
    assert_eq!(items[1].payload.len(), EXTENSION_TWO_BYTE_LEN_MAX);
    assert_eq!(items[1].payload, &large[..], "large element is verbatim");
}

// RTP-EXT-003 — legacy profile：不透明数据、无元素遍历、宽容校验。
#[test]
fn rtp_ext_003_legacy_profile_opaque() {
    let data = leak(vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
    let header = header_with_extension(0x1234, data);
    assert_eq!(
        header.extensions().count(),
        0,
        "legacy profiles frame nothing"
    );
    assert!(header.find_extension(1).is_none());
    assert_eq!(header.extension_data, data, "opaque region stays verbatim");
    assert_eq!(
        validate_extension_block(0x1234, data),
        Ok(()),
        "legacy profiles always validate"
    );
}

// RTP-EXT-004 — 校验表：两种框架的超长负载 / 缺失长度字节 → InvalidValue。
#[test]
fn rtp_ext_004_validate_error_table() {
    // one-byte：元素负载越过数据末端。
    assert_eq!(
        validate_extension_block(EXTENSION_PROFILE_ONE_BYTE, &[0x11, 0xAA]),
        Err(WireError::InvalidValue)
    );
    // one-byte：长度前缀后一个字节都没有。
    assert_eq!(
        validate_extension_block(EXTENSION_PROFILE_ONE_BYTE, &[0x11]),
        Err(WireError::InvalidValue)
    );
    // one-byte：保留 id=15 之后的字节不算元素数据 → 放行。
    assert_eq!(
        validate_extension_block(EXTENSION_PROFILE_ONE_BYTE, &[0xF1, 0x02]),
        Ok(())
    );
    // one-byte：仅含补零 → 放行。
    assert_eq!(
        validate_extension_block(EXTENSION_PROFILE_ONE_BYTE, &[0x00, 0x00, 0x00, 0x00]),
        Ok(())
    );
    // two-byte：长度字节缺失。
    assert_eq!(
        validate_extension_block(EXTENSION_PROFILE_TWO_BYTE, &[0x05]),
        Err(WireError::InvalidValue)
    );
    // two-byte：负载越过末端。
    assert_eq!(
        validate_extension_block(EXTENSION_PROFILE_TWO_BYTE, &[0x05, 0x02, 0x01]),
        Err(WireError::InvalidValue)
    );
    // two-byte：合法单元素 + 补零。
    assert_eq!(
        validate_extension_block(EXTENSION_PROFILE_TWO_BYTE, &[0x05, 0x01, 0xAA, 0x00]),
        Ok(())
    );
    // 空数据对两种框架都合法（扩展头存在但无元素）。
    assert_eq!(
        validate_extension_block(EXTENSION_PROFILE_ONE_BYTE, &[]),
        Ok(())
    );
    assert_eq!(
        validate_extension_block(EXTENSION_PROFILE_TWO_BYTE, &[]),
        Ok(())
    );
}

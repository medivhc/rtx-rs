//! L2 — cross-crate bridge tests: `rtx-stun` address attributes against
//! the `rtx-core` socket types.
//!
//! These are the only integration tests that span two crates: they pin
//! the contract between the wire codec and the runtime address model
//! (`rtx_core::IpAddr` / `rtx_core::SocketAddr`), including the XOR
//! mask bytes that depend on the magic cookie and the transaction id.

mod common;

use common::{assert_verbatim, build, tx};
use rtx_core::{IpAddr, SocketAddr};
use rtx_stun::WireError;
use rtx_stun::addr::MappedAddress;
use rtx_stun::attributes::{ATTR_MAPPED_ADDRESS, ATTR_XORMAPPED_ADDRESS};
use rtx_stun::message::{BINDING_SUCCESS, MESSAGE_HEADER_SIZE};
use rtx_stun::xoraddr::XorMappedAddress;

// STUN-BRIDGE-001 — MAPPED-ADDRESS v4 往返与线上字节（family/port/ip）。
#[test]
fn stun_bridge_001_mapped_address_v4() {
    let address = MappedAddress::new(IpAddr::V4([198, 51, 100, 7]), 0xFFFF);
    let mut buf = [0u8; 64];
    let written = build(&mut buf, BINDING_SUCCESS, tx(0x51), |writer| {
        address.push_to(ATTR_MAPPED_ADDRESS, writer)
    })
    .expect("build");
    assert_eq!(written, MESSAGE_HEADER_SIZE + 4 + 8);

    // No XOR mask here: family 0x0001, port 0xFFFF, ip verbatim.
    let value = &buf[MESSAGE_HEADER_SIZE + 4..MESSAGE_HEADER_SIZE + 12];
    assert_eq!(value, &[0x00, 0x01, 0xFF, 0xFF, 0xC6, 0x33, 0x64, 0x07]);

    let msg = assert_verbatim(&buf[..written]);
    let raw = msg.get(ATTR_MAPPED_ADDRESS).expect("mapped-address");
    let decoded = MappedAddress::from_value(raw.value).expect("decode");
    assert_eq!(decoded, address);
    assert_eq!(decoded.ip, IpAddr::V4([198, 51, 100, 7]));
    assert_eq!(decoded.port, 0xFFFF);
}

// STUN-BRIDGE-002 — XOR-MAPPED-ADDRESS v4 掩码字节级验证。
#[test]
fn stun_bridge_002_xor_mapped_address_v4_mask() {
    let address = XorMappedAddress::new(IpAddr::V4([192, 0, 2, 1]), 32_853);
    let mut buf = [0u8; 64];
    let written = build(&mut buf, BINDING_SUCCESS, tx(0x52), |writer| {
        address.push_to(ATTR_XORMAPPED_ADDRESS, writer)
    })
    .expect("build");

    let value = &buf[MESSAGE_HEADER_SIZE + 4..MESSAGE_HEADER_SIZE + 12];
    assert_eq!(&value[0..2], &[0x00, 0x01], "family");
    assert_eq!(&value[2..4], &[0xA1, 0x47], "port ^ cookie-high");
    assert_eq!(&value[4..8], &[0xE1, 0x12, 0xA6, 0x43], "ip ^ cookie");

    let msg = assert_verbatim(&buf[..written]);
    let raw = msg.get(ATTR_XORMAPPED_ADDRESS).expect("xor-mapped-address");
    let decoded = XorMappedAddress::from_value(raw.value, msg.transaction_id).expect("unmask");
    assert_eq!(decoded, address);
}

// STUN-BRIDGE-003 — XOR-MAPPED-ADDRESS v6 掩码 = cookie ‖ transaction id。
#[test]
fn stun_bridge_003_xor_mapped_address_v6_mask() {
    let ip = IpAddr::V6([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ]);
    let address = XorMappedAddress::new(ip, 1234);
    let mut buf = [0u8; 64];
    let written = build(&mut buf, BINDING_SUCCESS, tx(0xB5), |writer| {
        address.push_to(ATTR_XORMAPPED_ADDRESS, writer)
    })
    .expect("build");
    // 4 (family+port) + 16 = 20 value bytes, word-aligned.
    assert_eq!(written, MESSAGE_HEADER_SIZE + 4 + 20);

    let value = &buf[MESSAGE_HEADER_SIZE + 4..MESSAGE_HEADER_SIZE + 24];
    assert_eq!(&value[0..2], &[0x00, 0x02], "ipv6 family");
    // 1234 = 0x04D2 ^ 0x2112 = 0x25C0.
    assert_eq!(&value[2..4], &[0x25, 0xC0], "masked port");
    // First four address octets 20 01 0D B8 ^ 21 12 A4 42.
    assert_eq!(&value[4..8], &[0x01, 0x13, 0xA9, 0xFA], "masked ipv6 head");
    // The tail is masked by the transaction id 0xB5 repeated.
    assert_eq!(&value[12..16], &[0xB5, 0xB5, 0xB5, 0xB5], "tx-masked tail");

    let msg = assert_verbatim(&buf[..written]);
    let raw = msg.get(ATTR_XORMAPPED_ADDRESS).expect("xor-mapped-address");
    let decoded = XorMappedAddress::from_value(raw.value, msg.transaction_id).expect("unmask");
    assert_eq!(decoded, address);
}

// STUN-BRIDGE-004 — rtx_core::SocketAddr ↔ XOR-MAPPED-ADDRESS 全链路桥接。
#[test]
fn stun_bridge_004_socket_addr_bridge() {
    struct Case {
        name: &'static str,
        addr: SocketAddr,
        tag: u8,
    }
    let cases = [
        Case {
            name: "v4 private",
            addr: SocketAddr::new(IpAddr::V4([10, 144, 144, 66]), 11_010),
            tag: 0x61,
        },
        Case {
            name: "v4 loopback",
            addr: SocketAddr::new(IpAddr::V4([127, 0, 0, 1]), 8080),
            tag: 0x62,
        },
        Case {
            name: "v6 ula",
            addr: SocketAddr::new(
                IpAddr::V6([0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]),
                443,
            ),
            tag: 0x63,
        },
    ];

    for case in cases {
        let mut buf = [0u8; 64];
        let written = build(&mut buf, BINDING_SUCCESS, tx(case.tag), |writer| {
            XorMappedAddress::new(case.addr.ip, case.addr.port)
                .push_to(ATTR_XORMAPPED_ADDRESS, writer)
        })
        .expect("build");

        let msg = assert_verbatim(&buf[..written]);
        let raw = msg.get(ATTR_XORMAPPED_ADDRESS).expect("xor-mapped-address");
        let decoded = XorMappedAddress::from_value(raw.value, msg.transaction_id).expect("unmask");
        let round_tripped = SocketAddr::new(decoded.ip, decoded.port);
        assert_eq!(round_tripped, case.addr, "{}", case.name);
    }
}

// STUN-BRIDGE-005 — 非法 family / 长度组合一律 InvalidValue。
#[test]
fn stun_bridge_005_malformed_address_values() {
    struct Case {
        name: &'static str,
        value: Vec<u8>,
    }
    let cases = [
        Case {
            name: "unknown family 3",
            value: vec![0x00, 0x03, 0x00, 0x01, 1, 2, 3, 4],
        },
        Case {
            name: "family zero",
            value: vec![0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4],
        },
        Case {
            name: "ipv4 family with 20-byte value",
            value: {
                let mut v = vec![0x00, 0x01, 0x00, 0x01];
                v.extend_from_slice(&[0u8; 16]);
                v
            },
        },
        Case {
            name: "truncated before port",
            value: vec![0x00, 0x01, 0x00],
        },
        Case {
            name: "empty value",
            value: Vec::new(),
        },
    ];

    let transaction_id = tx(0x71);
    for case in cases {
        assert_eq!(
            XorMappedAddress::from_value(&case.value, transaction_id).unwrap_err(),
            WireError::InvalidValue,
            "xor {}",
            case.name
        );
        assert_eq!(
            MappedAddress::from_value(&case.value).unwrap_err(),
            WireError::InvalidValue,
            "mapped {}",
            case.name
        );
    }
}

// STUN-BRIDGE-006 — 边界地址表：0.0.0.0 / 广播 / v6 未指定 / v6 回环。
#[test]
fn stun_bridge_006_edge_addresses() {
    struct Case {
        name: &'static str,
        ip: IpAddr,
        port: u16,
    }
    let cases = [
        Case {
            name: "unspecified v4",
            ip: IpAddr::V4([0, 0, 0, 0]),
            port: 0,
        },
        Case {
            name: "broadcast",
            ip: IpAddr::V4([255, 255, 255, 255]),
            port: 65_535,
        },
        Case {
            name: "loopback with ephemeral port",
            ip: IpAddr::V4([127, 0, 0, 1]),
            port: 49_152,
        },
        Case {
            name: "unspecified v6",
            ip: IpAddr::V6([0; 16]),
            port: 0,
        },
        Case {
            name: "v6 loopback",
            ip: IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            port: 443,
        },
        Case {
            name: "public dns",
            ip: IpAddr::V4([8, 8, 8, 8]),
            port: 53,
        },
    ];

    for case in cases {
        // MAPPED-ADDRESS (no mask).
        let mut buf = [0u8; 64];
        let written = build(&mut buf, BINDING_SUCCESS, tx(0x81), |writer| {
            MappedAddress::new(case.ip, case.port).push_to(ATTR_MAPPED_ADDRESS, writer)
        })
        .expect("build");
        let msg = assert_verbatim(&buf[..written]);
        let raw = msg.get(ATTR_MAPPED_ADDRESS).expect("mapped");
        let decoded = MappedAddress::from_value(raw.value).expect("decode");
        assert_eq!(decoded.ip, case.ip, "{} mapped ip", case.name);
        assert_eq!(decoded.port, case.port, "{} mapped port", case.name);

        // XOR-MAPPED-ADDRESS (masked, tx-dependent).
        let mut xor_buf = [0u8; 64];
        let xor_len = build(&mut xor_buf, BINDING_SUCCESS, tx(0x82), |writer| {
            XorMappedAddress::new(case.ip, case.port).push_to(ATTR_XORMAPPED_ADDRESS, writer)
        })
        .expect("xor build");
        let xor_msg = assert_verbatim(&xor_buf[..xor_len]);
        let raw = xor_msg.get(ATTR_XORMAPPED_ADDRESS).expect("xor mapped");
        let decoded =
            XorMappedAddress::from_value(raw.value, xor_msg.transaction_id).expect("unmask");
        assert_eq!(decoded.ip, case.ip, "{} xor ip", case.name);
        assert_eq!(decoded.port, case.port, "{} xor port", case.name);
    }
}

// STUN-BRIDGE-007 — 默认值语义：MappedAddress / XorMappedAddress 默认构造。
#[test]
fn stun_bridge_007_default_addresses() {
    let mapped = MappedAddress::default();
    assert_eq!(mapped.ip, IpAddr::V4([0, 0, 0, 0]));
    assert_eq!(mapped.port, 0);

    let xor = XorMappedAddress::default();
    assert_eq!(xor.ip, IpAddr::V4([0, 0, 0, 0]));
    assert_eq!(xor.port, 0);
}

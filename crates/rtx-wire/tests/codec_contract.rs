//! L2 — the `rtx-wire` codec contract: `Cursor`/`Writer` boundary
//! semantics, the generic [`Decode`]/[`Encode`] round-trip over real
//! protocol types from the sibling crates, and the [`WireError`]
//! variant matrix.
//!
//! Everything here runs against the public trait surface only, so the
//! file doubles as executable documentation of the contract every
//! protocol crate builds on.

use rtx_rtcp::RtcpPacket;
use rtx_rtcp::reception_report::ReceptionReport;
use rtx_rtp::header::{Header, RTP_VERSION};
use rtx_rtp::packet::RtpPacket;
use rtx_wire::{Cursor, Decode, Encode, WireError, Writer};

/// Generic round-trip over any value satisfying the full contract:
/// decode consumes the whole input, `encoded_len` matches the writer,
/// re-encoding is verbatim and decoding again yields an equal value.
fn roundtrip<'a, T>(bytes: &'a [u8]) -> T
where
    T: Decode<'a, Error: core::fmt::Debug>
        + Encode<Error: core::fmt::Debug>
        + PartialEq
        + core::fmt::Debug,
{
    let (value, consumed) = T::decode(bytes).expect("decode under the contract");
    assert_eq!(consumed, bytes.len(), "decode must consume every byte");
    let mut out = vec![0u8; value.encoded_len()];
    let written = value.encode(&mut out).expect("encode under the contract");
    assert_eq!(written, out.len(), "encoded_len must match the writer");
    assert_eq!(out, bytes, "re-encode must be verbatim");
    // 重新解码的值也要借到 `'a`，故泄漏编码缓冲（测试辅助，调用有界）。
    let out: &'a [u8] = Box::leak(out.into_boxed_slice());
    let (again, _) = T::decode(out).expect("re-decode under the contract");
    assert_eq!(again, value, "decode(encode(v)) == v");
    value
}

/// Builds a 25-byte RTP packet (12 fixed + 13 payload).
fn rtp_bytes() -> Vec<u8> {
    let packet = RtpPacket {
        header: Header {
            version: RTP_VERSION,
            padding: false,
            extension: false,
            marker: true,
            payload_type: 96,
            sequence_number: 0x0ACE,
            timestamp: 0x0102_0304,
            ssrc: 0x1122_3344,
            csrc: &[],
            extension_profile: 0,
            extension_data: &[],
        },
        payload: b"rtx-wire payload",
    };
    let mut out = vec![0u8; packet.encoded_len()];
    let written = packet.encode(&mut out).expect("encode rtp");
    assert_eq!(written, out.len());
    out
}

/// Builds a 16-byte Generic NACK packet (12 fixed + one 4-byte pair).
fn nack_bytes() -> Vec<u8> {
    let pairs = Box::leak(vec![0x03, 0xE8, 0x00, 0x21].into_boxed_slice());
    let packet = RtcpPacket::Nack(rtx_rtcp::Nack {
        sender_ssrc: 0x1111_2222,
        media_ssrc: 0x3333_4444,
        nacks: pairs,
    });
    let mut out = vec![0u8; packet.encoded_len()];
    let written = packet.encode(&mut out).expect("encode nack");
    assert_eq!(written, out.len());
    out
}

// WIRE-IT-001 — Cursor::take 边界：精确、超尾、错误时 offset 不变。
#[test]
fn wire_it_001_cursor_take_boundaries() {
    let input = [1u8, 2, 3, 4, 5];
    let mut cursor = Cursor::new(&input);
    assert_eq!(cursor.offset(), 0);
    assert_eq!(cursor.remaining().len(), 5);

    let first = cursor.take(2).expect("take two");
    assert_eq!(first, &[1, 2]);
    assert_eq!(cursor.offset(), 2);
    assert_eq!(cursor.remaining(), &[3, 4, 5]);

    // 精确取到尾。
    let rest = cursor.take(3).expect("take the rest");
    assert_eq!(rest, &[3, 4, 5]);
    assert_eq!(cursor.offset(), 5);
    assert_eq!(cursor.remaining(), []);

    // 超尾：UnexpectedEnd，offset 保持不动。
    assert_eq!(cursor.take(1), Err(WireError::UnexpectedEnd));
    assert_eq!(cursor.offset(), 5, "failed take does not advance");

    // 空输入上的 take(0) 合法但无字节。
    let mut empty = Cursor::new(&[]);
    assert_eq!(empty.take(0), Ok(&[][..]));
    assert_eq!(empty.take(1), Err(WireError::UnexpectedEnd));
}

// WIRE-IT-002 — Cursor 整数读取：u8/u16_be/u32_be 顺序与边界。
#[test]
fn wire_it_002_cursor_integer_reads() {
    let input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let mut cursor = Cursor::new(&input);
    assert_eq!(cursor.u8(), Ok(0x01));
    assert_eq!(cursor.u16_be(), Ok(0x0203));
    assert_eq!(cursor.u32_be(), Ok(0x0405_0607));
    assert_eq!(cursor.u8(), Err(WireError::UnexpectedEnd));

    // 各整数读取的短输入错误。
    let mut one = Cursor::new(&[0xFF]);
    assert_eq!(one.u16_be(), Err(WireError::UnexpectedEnd));
    assert_eq!(one.u32_be(), Err(WireError::UnexpectedEnd));
    let mut two = Cursor::new(&[0xFF, 0xFF]);
    assert_eq!(two.u32_be(), Err(WireError::UnexpectedEnd));

    // 大端序确认：0x0102 而非 0x0201。
    let mut be = Cursor::new(&[0x01, 0x02]);
    assert_eq!(be.u16_be(), Ok(0x0102));
}

// WIRE-IT-003 — Cursor 溢出守卫：offset + len 溢出 usize → Overflow。
#[test]
fn wire_it_003_cursor_overflow_guard() {
    let input = [0u8; 4];
    let mut cursor = Cursor::new(&input);
    // offset = 0 时 0 + usize::MAX 不溢出，走 UnexpectedEnd。
    assert_eq!(cursor.take(usize::MAX), Err(WireError::UnexpectedEnd));
    // 先推进 offset，再取 usize::MAX：checked_add 溢出 → Overflow。
    let mut cursor = Cursor::new(&input);
    cursor.take(2).expect("take two");
    assert_eq!(cursor.take(usize::MAX), Err(WireError::Overflow));
    assert_eq!(cursor.offset(), 2, "overflow does not advance");
    // 之后仍可正常读取（状态未被破坏）。
    assert_eq!(cursor.u16_be(), Ok(0));
}

// WIRE-IT-004 — Writer::put 边界：精确、差一字节、错误时 offset 不变。
#[test]
fn wire_it_004_writer_put_boundaries() {
    // 恰好写满 6 字节缓冲区，然后验证已满写入器的拒绝语义。
    let mut buf = [0u8; 6];
    let mut writer = Writer::new(&mut buf);
    assert_eq!(writer.offset(), 0);

    writer.put(&[1, 2]).expect("put two");
    writer.u8(3).expect("put one byte");
    assert_eq!(writer.offset(), 3);
    // 剩余 3 字节：u16 放得下，还剩 1 字节给最后一个 u8。
    writer.u16_be(0x0405).expect("put one u16");
    assert_eq!(writer.offset(), 5);
    writer.u8(9).expect("last byte fits");
    assert_eq!(writer.offset(), 6);

    // 已满：任何写入 OutputTooSmall，offset 不变。
    assert_eq!(writer.u8(0), Err(WireError::OutputTooSmall));
    assert_eq!(writer.offset(), 6, "failed write does not advance");
    assert_eq!(writer.put(&[0]), Err(WireError::OutputTooSmall));
    assert_eq!(writer.put(&[]), Ok(()), "empty put is always fine");
    assert_eq!(buf, [1, 2, 3, 4, 5, 9]);

    // 差一字节：3 字节缓冲区写 4 字节 → OutputTooSmall。
    let mut tight = [0u8; 3];
    let mut writer = Writer::new(&mut tight);
    assert_eq!(writer.u32_be(0x0102_0304), Err(WireError::OutputTooSmall));
    assert_eq!(writer.offset(), 0);
    writer.put(&[1, 2, 3]).expect("exact fit");
    assert_eq!(writer.offset(), 3);
}

// WIRE-IT-005 — 泛型往返：同一契约函数覆盖 RTP 与 RTCP 真实类型。
#[test]
fn wire_it_005_generic_roundtrip_over_protocol_types() {
    // RTP 报文。
    let rtp = rtp_bytes();
    let packet = roundtrip::<RtpPacket<'_>>(&rtp);
    assert_eq!(packet.payload, b"rtx-wire payload");
    assert_eq!(packet.header.sequence_number, 0x0ACE);

    // RTCP Generic NACK（经 RtcpPacket 分发器）。
    let nack = nack_bytes();
    let decoded = roundtrip::<RtcpPacket<'_>>(&nack);
    let RtcpPacket::Nack(nack) = decoded else {
        panic!("expected a NACK packet");
    };
    assert_eq!(nack.sender_ssrc, 0x1111_2222);
    assert_eq!(nack.nacks.len(), 4);

    // ReceptionReport 块（24 字节定长）。
    let report = ReceptionReport {
        ssrc: 0x0BAD_C0DE,
        fraction_lost: 200,
        total_lost: 1_000,
        highest_sequence: 0x46E1,
        jitter: 273,
        last_sr: 0x09F3_6432,
        delay_since_last_sr: 150_137,
    };
    let mut block = [0u8; 24];
    let written = report.encode(&mut block).expect("encode report");
    assert_eq!(written, 24);
    let (again, consumed) = ReceptionReport::decode(&block).expect("decode report");
    assert_eq!(consumed, 24);
    assert_eq!(again, report);
}

// WIRE-IT-006 — encoded_len 契约：精确匹配写入量，少一字节即拒。
#[test]
fn wire_it_006_encoded_len_matches_writer() {
    let packet = RtpPacket {
        header: Header {
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
        },
        payload: b"1234567890",
    };
    assert_eq!(packet.encoded_len(), 22, "12 header + 10 payload");
    let mut exact = vec![0u8; 22];
    assert_eq!(packet.encode(&mut exact).expect("exact buffer"), 22);
    let mut short = vec![0u8; 21];
    assert_eq!(packet.encode(&mut short), Err(WireError::OutputTooSmall));

    // NACK 同样遵守：16 字节定长。
    let nack = nack_bytes();
    let decoded = RtcpPacket::decode(&nack).expect("decode nack").0;
    assert_eq!(decoded.encoded_len(), 16);
    let mut short = vec![0u8; 15];
    assert_eq!(decoded.encode(&mut short), Err(WireError::OutputTooSmall));
}

// WIRE-IT-007 — 自定义类型实现契约：第三方值类型可零依赖接入。
#[test]
fn wire_it_007_custom_type_implements_contract() {
    /// 一个最小自定义 codec：1 字节标签 + 2 字节大端长度 + 负载。
    #[derive(Debug, PartialEq, Eq)]
    struct Labelled<'a> {
        tag: u8,
        body: &'a [u8],
    }

    impl<'a> Decode<'a> for Labelled<'a> {
        type Error = WireError;

        fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
            let mut cursor = Cursor::new(input);
            let tag = cursor.u8()?;
            let len = usize::from(cursor.u16_be()?);
            let body = cursor.take(len)?;
            Ok((Labelled { tag, body }, cursor.offset()))
        }
    }

    impl Encode for Labelled<'_> {
        type Error = WireError;

        fn encoded_len(&self) -> usize {
            3 + self.body.len()
        }

        fn encode(&self, output: &mut [u8]) -> Result<usize, Self::Error> {
            let mut writer = Writer::new(output);
            writer.u8(self.tag)?;
            let len = u16::try_from(self.body.len()).map_err(|_| WireError::Overflow)?;
            writer.u16_be(len)?;
            writer.put(self.body)?;
            Ok(writer.offset())
        }
    }

    let wire = [0x07u8, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
    let value = roundtrip::<Labelled<'_>>(&wire);
    assert_eq!(value.tag, 7);
    assert_eq!(value.body, &[0xAA, 0xBB, 0xCC]);

    // 自定义类型的错误路径：负载不足 → UnexpectedEnd。
    assert_eq!(
        Labelled::decode(&[0x07, 0x00, 0x04, 0xAA]),
        Err(WireError::UnexpectedEnd)
    );
    // 负载超 16 位 → 编码 Overflow。
    let big_body = vec![0u8; 70_000];
    let big = Labelled {
        tag: 1,
        body: &big_body,
    };
    let mut out = vec![0u8; big.encoded_len()];
    assert_eq!(big.encode(&mut out), Err(WireError::Overflow));
}

// WIRE-IT-008 — WireError 变体矩阵：互异、Debug、Copy/Eq。
#[test]
fn wire_it_008_error_variant_matrix() {
    let variants = [
        WireError::UnexpectedEnd,
        WireError::OutputTooSmall,
        WireError::InvalidValue,
        WireError::Overflow,
    ];
    for (index, left) in variants.iter().enumerate() {
        for (other, right) in variants.iter().enumerate() {
            if index != other {
                assert_ne!(left, right);
            }
        }
    }
    for variant in variants {
        let copied = variant; // Copy
        assert_eq!(variant, copied);
        assert_ne!(format!("{variant:?}"), "");
    }
}

// WIRE-IT-009 — Cursor/Writer 互操作：写入的字节被原样读回。
#[test]
fn wire_it_009_cursor_writer_interop() {
    let mut buf = [0u8; 16];
    let mut writer = Writer::new(&mut buf);
    writer.u8(0xDE).expect("u8");
    writer.u16_be(0xADBE).expect("u16");
    writer.u32_be(0x0BAD_F00D).expect("u32");
    writer.put(b"ef").expect("put");
    let written = writer.offset();
    assert_eq!(written, 9);

    let mut cursor = Cursor::new(&buf[..written]);
    assert_eq!(cursor.u8(), Ok(0xDE));
    assert_eq!(cursor.u16_be(), Ok(0xADBE));
    assert_eq!(cursor.u32_be(), Ok(0x0BAD_F00D));
    assert_eq!(cursor.take(2), Ok(&b"ef"[..]));
    assert_eq!(cursor.remaining(), []);

    // 交错写读：writer 与 cursor 独立推进，互不影响。
    let mut second = [0u8; 8];
    {
        let mut writer = Writer::new(&mut second);
        writer.put(&[1, 2, 3]).expect("put three");
        assert_eq!(writer.offset(), 3);
    }
    let mut cursor = Cursor::new(&second);
    assert_eq!(cursor.take(2), Ok(&[1u8, 2][..]));
    assert_eq!(cursor.offset(), 2);
}

// WIRE-IT-010 — consumed 语义表：分发器按 length 切片，整包解码器
// 消费全部输入。
#[test]
fn wire_it_010_decode_consumed_semantics() {
    // RTP 无长度字段：consumed == 输入长度（负载一直到尾）。
    let rtp = rtp_bytes();
    let (packet, consumed) = RtpPacket::decode(&rtp).expect("decode rtp");
    assert_eq!(consumed, rtp.len());
    assert_eq!(packet.payload.len(), rtp.len() - 12);

    // RtcpPacket 分发器：consumed == 4 + length * 4，可以小于输入
    // （复合包场景下剩余字节属于下一个子包）。
    let nack = nack_bytes();
    let mut compound = nack.clone();
    compound.extend_from_slice(&nack); // 两个相同子包
    let (first, consumed) = RtcpPacket::decode(&compound).expect("decode compound front");
    assert_eq!(consumed, nack.len(), "only the first sub-packet");
    assert!(consumed < compound.len());
    let (second, consumed2) =
        RtcpPacket::decode(&compound[consumed..]).expect("decode compound second");
    assert_eq!(consumed2, nack.len());
    assert_eq!(first, second, "both sub-packets decode identically");

    // 空输入：两种层级都拒绝。
    assert_eq!(RtpPacket::decode(&[]), Err(WireError::UnexpectedEnd));
    assert_eq!(RtcpPacket::decode(&[]), Err(WireError::UnexpectedEnd));
}

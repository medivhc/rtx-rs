//! Receiver Estimated Maximum Bitrate (PT=206, FMT=15).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P| FMT=15  |   PT=206      |             length            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of packet sender                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of media source (= 0)                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Unique identifier 'R' 'E' 'M' 'B'                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Num SSRC     | BR Exp    |  BR Mantissa                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   SSRC feedback                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  ...                                                          |
//! ```
//!
//! The bitrate is carried as `mantissa * 2^exp` with an 18-bit
//! mantissa and a 6-bit exponent (draft-alvestrand-rmcat-remb-03).
//! This module converts between that fixed-point form and `f32`
//! bits/s with [`Remb::bitrate`] / [`Remb::new`], mirroring the
//! upstream webrtc-rs reference implementation bit for bit,
//! including its two quirks:
//!
//! 1. **Zero mantissa on decode**: a mantissa of 0 keeps the biased
//!    exponent as-is (no implicit leading bit normalization), which
//!    decodes to a tiny denormal-ish float rather than 0.
//! 2. **Clamp on encode**: bitrates above `BITRATE_MAX` are clamped
//!    instead of rejected, so `f32::MAX` round-trips through the
//!    largest representable value.
//!
//! The media SSRC field MUST be zero (upstream: `SsrcMustBeZero`) and
//! is validated on decode. The bitrate is stored as raw `f32` bits so
//! the packet stays `Copy + Eq` (an `f32` field would break `Eq` on
//! [`crate::packet::RtcpPacket`]).
//!
//! `f32::floor` is not available in `no_std` on this toolchain, so the
//! mantissa is computed as `value - value % 1.0`, which is exact for
//! `value < 2^24` (guaranteed by the halving loop).

use rtx_wire::{Cursor, Decode, Encode, WireError, Writer};

use crate::header::{Header, PacketType};

/// FMT value of the receiver estimated maximum bitrate message.
pub const FMT_REMB: u8 = 15;

/// Unique identifier `"REMB"` (RFC/draft magic, 4 bytes).
pub const REMB_IDENTIFIER: [u8; 4] = *b"REMB";

/// Offset of the first SSRC entry: header, both SSRCs, magic and the
/// `Num SSRC | BR Exp | BR Mantissa` triple.
pub const REMB_SSRC_OFFSET: usize = 20;

/// Minimum wire size: the fixed part with zero SSRC entries.
pub const REMB_MIN_OCTET_COUNT: usize = REMB_SSRC_OFFSET;

/// Largest bitrate representable on the wire: `0x3FFFFp+63`.
pub const REMB_BITRATE_MAX: f32 = 2.417_842_4e24;

/// Maximum value of the 23-bit IEEE-754 mantissa.
const MANTISSA_MAX: u32 = 0x007F_FFFF;

/// Maximum number of SSRC entries (`Num SSRC` is one byte).
const REMB_MAX_SSRC_ENTRIES: usize = u8::MAX as usize;

/// Halving threshold of the mantissa: once the bitrate is below this,
/// its integer part fits the 18-bit wire mantissa.
const REMB_MANTISSA_THRESHOLD: f32 = 262_144.0;

/// Computes `floor(value)` without the std-only `f32::floor`.
///
/// Only called with non-negative, non-huge values (the caller rejects
/// negatives and the halving loop guarantees `value < 2^24`), where
/// `value % 1.0` is exact and the subtraction is lossless.
fn floor_f32(value: f32) -> f32 {
    value - value % 1.0
}

/// Receiver Estimated Maximum Bitrate borrowing its SSRC region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Remb<'a> {
    /// SSRC of the packet sender.
    pub sender_ssrc: u32,
    /// Estimated maximum bitrate, stored as raw `f32` bits.
    ///
    /// Use [`Remb::bitrate`] to read the value in bit/s; the raw form
    /// keeps the packet `Eq` and avoids float comparisons in callers.
    pub bitrate_bits: u32,
    /// Raw SSRC feedback entries (4 bytes each), borrowed verbatim.
    pub ssrcs: &'a [u8],
}

impl<'a> Remb<'a> {
    /// Creates a REMB report from a bitrate in bit/s.
    ///
    /// The bitrate is stored verbatim (as `f32` bits); validation and
    /// clamping happen at encode time, mirroring upstream.
    #[must_use]
    pub const fn new(sender_ssrc: u32, bitrate: f32, ssrcs: &'a [u8]) -> Self {
        Remb {
            sender_ssrc,
            bitrate_bits: bitrate.to_bits(),
            ssrcs,
        }
    }

    /// The estimated maximum bitrate in bit/s.
    #[must_use]
    pub const fn bitrate(&self) -> f32 {
        f32::from_bits(self.bitrate_bits)
    }

    /// Iterates over the SSRC feedback entries.
    pub fn ssrc_entries(&self) -> impl Iterator<Item = u32> + '_ {
        self.ssrcs
            .chunks_exact(4)
            .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
    }

    /// Number of SSRC entries carried by this report.
    #[must_use]
    pub const fn ssrc_count(&self) -> usize {
        self.ssrcs.len() / 4
    }

    /// Header implied by the current field values.
    ///
    /// `count` is the FMT value (15), never the SSRC count.
    #[must_use]
    pub fn header(&self) -> Header {
        Header {
            padding: false,
            count: FMT_REMB,
            packet_type: PacketType::Psfb,
            length: u16::try_from(self.raw_len() / 4 - 1).unwrap_or(u16::MAX),
        }
    }

    /// Unpadded wire size (fixed part + SSRC region).
    fn raw_len(&self) -> usize {
        REMB_SSRC_OFFSET + self.ssrcs.len()
    }

    /// Encodes the packet into `writer`.
    ///
    /// # Errors
    ///
    /// - [`WireError::InvalidValue`] when the bitrate is negative, the
    ///   SSRC region is not a multiple of 4 bytes, or more than 255
    ///   SSRC entries are present (stricter than upstream, which
    ///   silently truncates the count to `u8`).
    /// - [`WireError::OutputTooSmall`] when the writer lacks room.
    pub(crate) fn write_to(&self, writer: &mut Writer<'_>) -> Result<(), WireError> {
        if self.ssrcs.len() % 4 != 0 {
            return Err(WireError::InvalidValue);
        }
        if self.ssrc_count() > REMB_MAX_SSRC_ENTRIES {
            return Err(WireError::InvalidValue);
        }

        let mut bitrate = self.bitrate();
        if bitrate < 0.0 {
            return Err(WireError::InvalidValue);
        }
        if bitrate >= REMB_BITRATE_MAX {
            bitrate = REMB_BITRATE_MAX;
        }

        let mut exp: u32 = 0;
        // Halve until the mantissa fits in 18 bits (2^18 threshold).
        while bitrate >= REMB_MANTISSA_THRESHOLD {
            bitrate /= 2.0;
            exp += 1;
        }

        // `bitrate` is now < 2^24 and non-negative, so the subtraction
        // floor is exact and the `f32` -> `u32` conversion can neither
        // truncate a fraction nor lose the sign.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let mantissa = floor_f32(bitrate) as u32;

        let length = u16::try_from(self.raw_len() / 4 - 1).map_err(|_| WireError::Overflow)?;
        let header = Header {
            padding: false,
            count: FMT_REMB,
            packet_type: PacketType::Psfb,
            length,
        };
        header.write_to(writer)?;

        writer.u32_be(self.sender_ssrc)?;
        writer.u32_be(0)?; // media SSRC is always zero
        writer.put(&REMB_IDENTIFIER)?;
        writer.u8(u8::try_from(self.ssrc_count()).map_err(|_| WireError::Overflow)?)?;

        // 24-bit fixed point: 6-bit exponent plus the 18-bit mantissa,
        // written as the three big-endian tail bytes of the word.
        let fixed_point = (exp << 18) | mantissa;
        let bytes = fixed_point.to_be_bytes();
        writer.u8(bytes[1])?;
        writer.u8(bytes[2])?;
        writer.u8(bytes[3])?;

        writer.put(self.ssrcs)?;
        Ok(())
    }
}

impl<'a> Decode<'a> for Remb<'a> {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        if input.len() < REMB_MIN_OCTET_COUNT {
            return Err(WireError::UnexpectedEnd);
        }

        let (header, consumed) = Header::decode(input)?;
        if header.packet_type != PacketType::Psfb || header.count != FMT_REMB {
            return Err(WireError::InvalidValue);
        }

        // The length field must describe at least the fixed part; the
        // dispatcher slices one sub-packet by the same field, so bytes
        // beyond it only matter for direct calls.
        let total = usize::from(header.length)
            .checked_mul(4)
            .and_then(|words| words.checked_add(consumed))
            .ok_or(WireError::Overflow)?;
        if total < REMB_MIN_OCTET_COUNT || input.len() < total {
            return Err(WireError::UnexpectedEnd);
        }

        let mut cursor = Cursor::new(&input[consumed..]);
        let sender_ssrc = cursor.u32_be()?;
        let media_ssrc = cursor.u32_be()?;
        if media_ssrc != 0 {
            // Upstream: Error::SsrcMustBeZero.
            return Err(WireError::InvalidValue);
        }

        let magic = cursor.take(4)?;
        if magic != REMB_IDENTIFIER {
            // Upstream: Error::MissingRembIdentifier.
            return Err(WireError::InvalidValue);
        }

        let ssrc_count = cursor.u8()? as usize;
        if input.len() < REMB_SSRC_OFFSET + ssrc_count * 4 {
            return Err(WireError::UnexpectedEnd);
        }

        let b17 = cursor.u8()?;
        let b18 = cursor.u8()?;
        let b19 = cursor.u8()?;

        // 6-bit exponent, biased for IEEE-754 (127) and shifted 23 more
        // because the wire mantissa is right-aligned.
        let mut exp = u32::from(b17) >> 2;
        exp += 127;
        exp += 23;

        // 18-bit mantissa: top 2 bits in b17, then 16 more.
        let mut mantissa = (u32::from(b17 & 0x3) << 16) | (u32::from(b18) << 8) | u32::from(b19);

        if mantissa != 0 {
            // IEEE-754 requires an implicit leading bit: normalize until
            // bit 23 is set, shifting the exponent down. (Upstream quirk:
            // a zero mantissa skips this entirely.)
            while (mantissa & (MANTISSA_MAX + 1)) == 0 {
                exp -= 1;
                mantissa <<= 1;
            }
        }

        let bitrate_bits = (exp << 23) | (mantissa & MANTISSA_MAX);

        let ssrcs = cursor.take(ssrc_count * 4)?;

        let remb = Remb {
            sender_ssrc,
            bitrate_bits,
            ssrcs,
        };
        Ok((remb, input.len()))
    }
}

impl Encode for Remb<'_> {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        self.raw_len()
    }

    fn encode(&self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let mut writer = Writer::new(output);
        self.write_to(&mut writer)?;
        Ok(writer.offset())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// Differential vector: upstream
    /// `rtcp/payload_feedbacks/receiver_estimated_maximum_bitrate/receiver_estimated_maximum_bitrate_test.rs:5-12`
    /// (marshal: bitrate 8927168.0 bit/s, one SSRC).
    const REMB_MARSHAL: [u8; 24] = [
        143, 206, 0, 5, // v=2, p=0, FMT=15, PSFB, len=5
        0, 0, 0, 1, // sender=1
        0, 0, 0, 0, // media=0
        82, 69, 77, 66, // "REMB"
        1, 26, 32, 223, // num=1, exp=6, mantissa=139_487
        72, 116, 237, 22, // ssrc=1_215_622_422
    ];

    /// Differential vector: upstream `receiver_estimated_maximum_bitrate_test.rs:16-21`
    /// ("Real data sent by Chrome while watching a 6Mb/s stream").
    const REMB_CHROME: [u8; 24] = [
        143, 206, 0, 5, 0, 0, 0, 1, 0, 0, 0, 0, 82, 69, 77, 66, 1, 26, 32, 223, 72, 116, 237, 22,
    ];

    /// Differential vector: upstream `receiver_estimated_maximum_bitrate_test.rs:79-84`
    /// (overflow: `f32::MAX` clamps to the wire maximum).
    const REMB_OVERFLOW: [u8; 20] = [
        143, 206, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 82, 69, 77, 66, 0, 255, 255, 255,
    ];

    /// Differential vector: upstream `receiver_estimated_maximum_bitrate_test.rs:93-97`
    /// (exp=47, mantissa=0 → the zero-mantissa quirk).
    const REMB_ZERO_MANTISSA: [u8; 20] = [
        143, 206, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 82, 69, 77, 66, 0, 188, 0, 0,
    ];

    /// Compares two `f32` bit patterns exactly (avoids `float_cmp`).
    fn assert_f32_eq(got: f32, want: f32) {
        assert_eq!(
            got.to_bits(),
            want.to_bits(),
            "f32 mismatch: {got} vs {want}"
        );
    }

    // RTCP-REMB-001 — 差分：上游 marshal 向量（8_927_168.0 b/s，1 个 SSRC）字节级往返。
    #[test]
    fn rtcp_remb_001_upstream_marshal_vector_round_trip() {
        let ssrcs: [u8; 4] = 1_215_622_422u32.to_be_bytes();
        let remb = Remb::new(1, 8_927_168.0, &ssrcs);

        let mut output = [0u8; 24];
        let written = remb
            .encode(&mut output)
            .expect("encode REMB marshal vector");
        assert_eq!(written, 24);
        assert_eq!(written, remb.encoded_len());
        assert_eq!(output, REMB_MARSHAL);

        let (decoded, consumed) = Remb::decode(&REMB_MARSHAL).expect("decode REMB marshal vector");
        assert_eq!(consumed, REMB_MARSHAL.len());
        assert_eq!(decoded, remb);
        assert_f32_eq(decoded.bitrate(), 8_927_168.0);
    }

    // RTCP-REMB-002 — 差分：上游 unmarshal 向量（Chrome 真实报告）字段级。
    #[test]
    fn rtcp_remb_002_upstream_chrome_vector_fields() {
        let (remb, consumed) = Remb::decode(&REMB_CHROME).expect("decode REMB Chrome vector");
        assert_eq!(consumed, REMB_CHROME.len());
        assert_eq!(remb.sender_ssrc, 1);
        assert_f32_eq(remb.bitrate(), 8_927_168.0);
        let entries: Vec<u32> = remb.ssrc_entries().collect();
        assert_eq!(entries, vec![1_215_622_422]);

        let header = remb.header();
        assert_eq!(header.packet_type, PacketType::Psfb);
        assert_eq!(header.count, FMT_REMB);
        assert_eq!(header.length, 5);
    }

    // RTCP-REMB-003 — 差分：上游 truncate 向量（bitrate-1 → mantissa-1）。
    #[test]
    fn rtcp_remb_003_upstream_truncate_vector() {
        let (remb, _) = Remb::decode(&REMB_CHROME).expect("decode REMB Chrome vector");
        assert_f32_eq(remb.bitrate(), 8_927_168.0);

        // 先确认重新 marshal 与输入一致。
        let mut output = [0u8; 24];
        let written = remb.encode(&mut output).expect("re-encode REMB");
        assert_eq!(written, 24);
        assert_eq!(output, REMB_CHROME);

        // bitrate 减 1：8927167 → floor 后 mantissa = 139486。
        let ssrc_bytes = 1_215_622_422u32.to_be_bytes();
        let lowered = Remb::new(1, 8_927_167.0, &ssrc_bytes);
        let mut output = [0u8; 24];
        lowered.encode(&mut output).expect("encode lowered REMB");
        let expected: [u8; 24] = [
            143, 206, 0, 5, 0, 0, 0, 1, 0, 0, 0, 0, 82, 69, 77, 66, 1, 26, 32, 222, 72, 116, 237,
            22,
        ];
        assert_eq!(output, expected);

        // 解回来时因为量化会再降 63（= 2^exp）。
        let (again, _) = Remb::decode(&expected).expect("decode lowered REMB");
        assert_f32_eq(again.bitrate(), 8_927_104.0);
    }

    // RTCP-REMB-004 — 差分：上游 overflow 向量（f32::MAX 钳制 + 零 mantissa 怪癖）。
    #[test]
    fn rtcp_remb_004_upstream_overflow_vector() {
        let remb = Remb::new(0, f32::MAX, &[]);
        let mut output = [0u8; 20];
        let written = remb.encode(&mut output).expect("encode REMB overflow");
        assert_eq!(written, 20);
        assert_eq!(output, REMB_OVERFLOW);

        let (decoded, _) = Remb::decode(&REMB_OVERFLOW).expect("decode REMB overflow");
        assert_f32_eq(decoded.bitrate(), f32::from_bits(0x67FF_FFC0));

        // 解码值重新 marshal 必须字节级一致（钳制路径）。
        let mut again = [0u8; 20];
        decoded.encode(&mut again).expect("re-encode REMB overflow");
        assert_eq!(again, REMB_OVERFLOW);

        // 上游最后一个向量：exp=47、mantissa=0 时不做归一化。
        let (zero_mantissa, _) = Remb::decode(&REMB_ZERO_MANTISSA).expect("decode zero mantissa");
        assert_f32_eq(zero_mantissa.bitrate(), f32::from_bits(0x6280_0000));
    }

    // RTCP-REMB-005 — 差分：bitrate ↔ (exp, mantissa) 换算（已知定点值）。
    #[test]
    fn rtcp_remb_005_bitrate_to_fixed_point_conversion() {
        let cases: [(f32, u32, u32); 4] = [
            (8_927_168.0, 6, 139_487), // 上游 Chrome 向量
            (262_144.0, 1, 131_072),   // 恰好 2^18：`>=` 进入循环一次
            (262_143.0, 0, 262_143),   // 低于阈值，不折半
            (1_048_576.0, 3, 131_072), // 2^20 → 3 次折半
        ];
        for (bitrate, want_exp, want_mantissa) in cases {
            let remb = Remb::new(1, bitrate, &[]);
            let mut output = [0u8; 20];
            remb.encode(&mut output).expect("encode conversion case");
            // 布局：header(4) + sender(4) + media(4) + "REMB"(4) +
            // num_ssrc(1) + b17(1) + b18(1) + b19(1)。
            let b17 = output[17];
            let b18 = output[18];
            let b19 = output[19];
            let exp = u32::from(b17) >> 2;
            let mantissa = (u32::from(b17 & 0x3) << 16) | (u32::from(b18) << 8) | u32::from(b19);
            assert_eq!(exp, want_exp, "exp for {bitrate}");
            assert_eq!(mantissa, want_mantissa, "mantissa for {bitrate}");
        }
    }

    // RTCP-REMB-006 — 差分：bitrate() 访问器还原已知定点值（bit/s）。
    #[test]
    fn rtcp_remb_006_bitrate_accessor_round_trip() {
        // 手工定点：mantissa=139_487, exp=6 → 139_487 * 64 = 8927168。
        let (remb, _) = Remb::decode(&REMB_MARSHAL).expect("decode");
        assert_f32_eq(remb.bitrate(), 139_487.0 * 64.0);

        // 零 mantissa 怪癖：编码 0 得到 mantissa=0/exp=0，解码时不做归一化，
        // 于是 exp=150 → 2^23 = 8388608（与上游一致，0 无法往返）。
        let zero = Remb::new(7, 0.0, &[]);
        let mut output = [0u8; 20];
        zero.encode(&mut output).expect("encode zero");
        assert_eq!(&output[16..20], &[0, 0, 0, 0]);
        let (decoded, _) = Remb::decode(&output).expect("decode zero");
        assert_f32_eq(decoded.bitrate(), 8_388_608.0);
        assert_eq!(decoded.sender_ssrc, 7);
    }
    // RTCP-REMB-007 — 差分：错误路径（nil / 短包 / 坏 magic / media SSRC 非零）。
    #[test]
    fn rtcp_remb_007_upstream_error_paths() {
        assert_eq!(Remb::decode(&[]), Err(WireError::UnexpectedEnd));
        assert_eq!(
            Remb::decode(&REMB_CHROME[..19]),
            Err(WireError::UnexpectedEnd)
        );

        let mut bad_magic = REMB_CHROME;
        bad_magic[12] = b'X';
        assert_eq!(Remb::decode(&bad_magic), Err(WireError::InvalidValue));

        let mut bad_media_ssrc = REMB_CHROME;
        bad_media_ssrc[8] = 1;
        assert_eq!(Remb::decode(&bad_media_ssrc), Err(WireError::InvalidValue));
    }

    // RTCP-REMB-008 — 差分：错误路径（错误 PT / 错误 FMT / length 过短 / 截断 SSRC 区）。
    #[test]
    fn rtcp_remb_008_header_and_length_errors() {
        let mut wrong_type = REMB_CHROME;
        wrong_type[1] = 0xcd; // PT=205 (TSFB)
        assert_eq!(Remb::decode(&wrong_type), Err(WireError::InvalidValue));

        let mut wrong_fmt = REMB_CHROME;
        wrong_fmt[0] = 0x81; // FMT=1 (PLI)
        assert_eq!(Remb::decode(&wrong_fmt), Err(WireError::InvalidValue));

        let mut short_length = REMB_CHROME;
        short_length[3] = 0x3; // len=3 implies 16 bytes < 20
        assert_eq!(Remb::decode(&short_length), Err(WireError::UnexpectedEnd));

        // num_ssrc=2 但缓冲区只有一个 SSRC。
        let mut truncated_ssrcs = REMB_CHROME;
        truncated_ssrcs[16] = 2;
        assert_eq!(
            Remb::decode(&truncated_ssrcs),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTCP-REMB-009 — 错误路径：负 bitrate → encode InvalidValue。
    #[test]
    fn rtcp_remb_009_negative_bitrate_rejected_on_encode() {
        let remb = Remb::new(1, -1.0, &[]);
        let mut output = [0u8; 20];
        assert_eq!(remb.encode(&mut output), Err(WireError::InvalidValue));
    }

    // RTCP-REMB-010 — 错误路径：SSRC 区非 4 倍数 / 超过 255 条 → InvalidValue。
    #[test]
    fn rtcp_remb_010_ssrc_region_validation() {
        let unaligned = Remb {
            sender_ssrc: 1,
            bitrate_bits: 0,
            ssrcs: &[1, 2, 3],
        };
        let mut output = [0u8; 23];
        assert_eq!(unaligned.encode(&mut output), Err(WireError::InvalidValue));

        let too_many = Remb {
            sender_ssrc: 1,
            bitrate_bits: 0,
            ssrcs: &[0u8; 1024],
        };
        let mut big = [0u8; 1044];
        assert_eq!(too_many.encode(&mut big), Err(WireError::InvalidValue));
    }

    // RTCP-REMB-011 — 属性：多个 SSRC 条目往返。
    #[test]
    fn rtcp_remb_011_multiple_ssrc_entries_round_trip() {
        let ssrc_bytes: [u8; 12] = [
            0x11, 0x22, 0x33, 0x44, // 0x11223344
            0x55, 0x66, 0x77, 0x88, // 0x55667788
            0x99, 0xaa, 0xbb, 0xcc, // 0x99aabbcc
        ];
        let remb = Remb::new(5000, 200_000.0, &ssrc_bytes);

        let mut output = [0u8; 32];
        let written = remb.encode(&mut output).expect("encode multi-SSRC REMB");
        assert_eq!(written, 32);

        let (decoded, consumed) = Remb::decode(&output[..written]).expect("decode multi-SSRC REMB");
        assert_eq!(consumed, 32);
        assert_eq!(decoded, remb);
        let entries: Vec<u32> = decoded.ssrc_entries().collect();
        assert_eq!(entries, vec![0x1122_3344, 0x5566_7788, 0x99aa_bbcc]);
        assert_eq!(decoded.ssrc_count(), 3);
        // 200000 < 2^18，故 exp=0 且 mantissa=200000，往返无损。
        assert_f32_eq(decoded.bitrate(), 200_000.0);
    }
}

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod h3_frame;
pub mod varint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    UnexpectedEnd,
    OutputTooSmall,
    InvalidValue,
    Overflow,
}

/// Allocation-free decoder. Returned values may borrow directly from `input`.
pub trait Decode<'a>: Sized {
    type Error;

    /// Decodes a value from the front of `input`.
    ///
    /// # Errors
    ///
    /// Returns `Self::Error` when `input` does not contain a complete,
    /// well-formed value.
    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error>;
}

/// Allocation-free encoder into caller-owned storage.
pub trait Encode {
    type Error;

    fn encoded_len(&self) -> usize;

    /// Encodes the value into `output`, returning the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns `Self::Error` when the value does not fit into `output` (for
    /// example when `output.len()` is smaller than [`Encode::encoded_len`]).
    fn encode(&self, output: &mut [u8]) -> Result<usize, Self::Error>;
}

#[derive(Debug, Clone, Copy)]
pub struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.offset..]
    }

    /// Takes the next `len` bytes as a slice borrowed from the input.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Overflow`] if `offset + len` overflows `usize`,
    /// or [`WireError::UnexpectedEnd`] if fewer than `len` bytes remain. The
    /// offset is not advanced on error.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self.offset.checked_add(len).ok_or(WireError::Overflow)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(WireError::UnexpectedEnd)?;
        self.offset = end;
        Ok(value)
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::UnexpectedEnd`] when no bytes remain.
    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    /// Reads a big-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::UnexpectedEnd`] when fewer than 2 bytes remain.
    pub fn u16_be(&mut self) -> Result<u16, WireError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Reads a big-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::UnexpectedEnd`] when fewer than 4 bytes remain.
    pub fn u32_be(&mut self) -> Result<u32, WireError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

#[derive(Debug)]
pub struct Writer<'a> {
    output: &'a mut [u8],
    offset: usize,
}

impl<'a> Writer<'a> {
    pub fn new(output: &'a mut [u8]) -> Self {
        Self { output, offset: 0 }
    }

    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Writes `input` at the current offset.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Overflow`] if `offset + input.len()` overflows
    /// `usize`, or [`WireError::OutputTooSmall`] when `output` lacks room for
    /// `input`. Nothing is written and the offset is not advanced on error.
    pub fn put(&mut self, input: &[u8]) -> Result<(), WireError> {
        let end = self
            .offset
            .checked_add(input.len())
            .ok_or(WireError::Overflow)?;
        let target = self
            .output
            .get_mut(self.offset..end)
            .ok_or(WireError::OutputTooSmall)?;
        target.copy_from_slice(input);
        self.offset = end;
        Ok(())
    }

    /// Writes one byte.
    ///
    /// # Errors
    ///
    /// Propagates the errors of [`Writer::put`](Self::put).
    pub fn u8(&mut self, value: u8) -> Result<(), WireError> {
        self.put(&[value])
    }

    /// Writes a big-endian `u16`.
    ///
    /// # Errors
    ///
    /// Propagates the errors of [`Writer::put`](Self::put).
    pub fn u16_be(&mut self, value: u16) -> Result<(), WireError> {
        self.put(&value.to_be_bytes())
    }

    /// Writes a big-endian `u32`.
    ///
    /// # Errors
    ///
    /// Propagates the errors of [`Writer::put`](Self::put).
    pub fn u32_be(&mut self, value: u32) -> Result<(), WireError> {
        self.put(&value.to_be_bytes())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    // ---- WIRE-ERR ---------------------------------------------------------

    // WIRE-ERR-001 — WireError 变体可构造与比较。
    // `InvalidValue` 为预留变体（当前无使用方）。
    #[test]
    fn wire_error_variants_construct_and_compare() {
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
        let error = WireError::UnexpectedEnd;
        let copied = error; // Copy
        assert_eq!(error, copied);
        assert_ne!(format!("{error:?}"), "");
    }

    // ---- WIRE-CUR ---------------------------------------------------------

    const CONST_CURSOR: Cursor = Cursor::new(b"abcd");

    // WIRE-CUR-001 — Cursor::new/offset/remaining 初始状态（const 构造）。
    #[test]
    fn cursor_initial_state() {
        assert_eq!(CONST_CURSOR.offset(), 0);
        assert_eq!(CONST_CURSOR.remaining(), b"abcd");

        let cursor = Cursor::new(&[1, 2, 3]);
        assert_eq!(cursor.offset(), 0);
        assert_eq!(cursor.remaining(), &[1, 2, 3]);
    }

    // WIRE-CUR-002 — take 正常路径。
    #[test]
    fn cursor_take_advances_offset_and_returns_borrowed_slices() {
        let mut cursor = Cursor::new(&[1, 2, 3, 4, 5]);
        let first = cursor.take(2).expect("take 2");
        assert_eq!(first, &[1, 2]);
        assert_eq!(cursor.offset(), 2);
        let second = cursor.take(1).expect("take 1");
        assert_eq!(second, &[3]);
        assert_eq!(cursor.offset(), 3);
        assert_eq!(cursor.remaining(), &[4, 5]);
    }

    // WIRE-CUR-003 — take 恰好耗尽边界。
    #[test]
    fn cursor_take_exact_exhaustion_boundary() {
        let mut cursor = Cursor::new(&[1, 2, 3, 4, 5]);
        assert_eq!(cursor.take(5).expect("take all"), &[1, 2, 3, 4, 5]);
        assert_eq!(cursor.offset(), 5);
        assert_eq!(cursor.take(1), Err(WireError::UnexpectedEnd));
        let zero = cursor.take(0).expect("zero-length take at boundary");
        assert!(zero.is_empty());
        assert_eq!(cursor.offset(), 5);
    }

    // WIRE-CUR-004 — take 越界错误且 offset 不变。
    #[test]
    fn cursor_take_out_of_bounds_keeps_offset() {
        let mut cursor = Cursor::new(&[1, 2, 3, 4, 5]);
        assert_eq!(cursor.take(6), Err(WireError::UnexpectedEnd));
        assert_eq!(cursor.offset(), 0);
        assert_eq!(
            cursor.take(5).expect("take all after failed take"),
            &[1, 2, 3, 4, 5]
        );
        assert_eq!(cursor.offset(), 5);
    }

    // WIRE-CUR-005 — 空输入行为。
    #[test]
    fn cursor_empty_input_behavior() {
        let mut cursor = Cursor::new(&[]);
        let zero = cursor.take(0).expect("zero-length take on empty input");
        assert!(zero.is_empty());
        assert_eq!(cursor.take(1), Err(WireError::UnexpectedEnd));
        assert_eq!(cursor.u8(), Err(WireError::UnexpectedEnd));
        assert_eq!(cursor.offset(), 0);
    }

    // WIRE-CUR-006 — take 的 checked_add Overflow 防护。
    #[test]
    fn cursor_take_overflow_is_distinct_from_unexpected_end() {
        let mut cursor = Cursor::new(&[1, 2, 3, 4, 5]);
        cursor.take(5).expect("take all");
        assert_eq!(cursor.take(usize::MAX), Err(WireError::Overflow));

        let mut empty = Cursor::new(&[]);
        assert_eq!(empty.take(usize::MAX), Err(WireError::UnexpectedEnd));
    }

    // WIRE-CUR-007 — u8 读取。
    #[test]
    fn cursor_u8_reads() {
        let mut cursor = Cursor::new(&[0x42]);
        assert_eq!(cursor.u8(), Ok(0x42));
        assert_eq!(cursor.offset(), 1);

        let mut empty = Cursor::new(&[]);
        assert_eq!(empty.u8(), Err(WireError::UnexpectedEnd));

        let mut pair = Cursor::new(&[1, 2]);
        assert_eq!(pair.u8(), Ok(1));
        assert_eq!(pair.u8(), Ok(2));
        assert_eq!(pair.u8(), Err(WireError::UnexpectedEnd));
    }

    // WIRE-CUR-008 — u16_be 大端读取。
    #[test]
    fn cursor_u16_be_reads() {
        let mut cursor = Cursor::new(&[0x12, 0x34]);
        assert_eq!(cursor.u16_be(), Ok(0x1234));
        assert_eq!(cursor.offset(), 2);

        let mut wide = Cursor::new(&[0xFF, 0x00]);
        assert_eq!(wide.u16_be(), Ok(0xFF00));

        let mut short = Cursor::new(&[0x01]);
        assert_eq!(short.u16_be(), Err(WireError::UnexpectedEnd));
    }

    // WIRE-CUR-009 — u32_be 大端读取。
    #[test]
    fn cursor_u32_be_reads() {
        let mut cursor = Cursor::new(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(cursor.u32_be(), Ok(0x1234_5678));
        assert_eq!(cursor.offset(), 4);

        let mut marker = Cursor::new(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(marker.u32_be(), Ok(0xDEAD_BEEF));

        let mut short = Cursor::new(&[1, 2, 3]);
        assert_eq!(short.u32_be(), Err(WireError::UnexpectedEnd));
    }

    // WIRE-CUR-010 — 混合读取序列与 offset 一致性。
    #[test]
    fn cursor_mixed_reads_track_offset() {
        let mut cursor = Cursor::new(&[
            0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xCC, 0xDD, 0x09,
        ]);
        assert_eq!(cursor.u8(), Ok(0xAA));
        assert_eq!(cursor.offset(), 1);
        assert_eq!(cursor.u8(), Ok(0xBB));
        assert_eq!(cursor.offset(), 2);
        assert_eq!(cursor.u16_be(), Ok(0x0102));
        assert_eq!(cursor.offset(), 4);
        assert_eq!(cursor.u32_be(), Ok(0x0304_0506));
        assert_eq!(cursor.offset(), 8);
        assert_eq!(cursor.u16_be(), Ok(0xCCDD));
        assert_eq!(cursor.offset(), 10);
        assert_eq!(cursor.u8(), Ok(0x09));
        assert_eq!(cursor.offset(), 11);
        assert!(cursor.remaining().is_empty());
    }

    // WIRE-CUR-011 — remaining() 返回与输入同生命周期（借用输入而非游标）。
    // 若 `remaining` 的返回生命周期绑定到 `&self`，本函数无法通过编译。
    fn borrow_remaining_from_static(input: &'static [u8]) -> &'static [u8] {
        let mut cursor = Cursor::new(input);
        cursor.take(1).expect("take one byte");
        cursor.remaining()
    }

    #[test]
    fn cursor_remaining_borrows_input_not_cursor() {
        let slice: &'static [u8] = borrow_remaining_from_static(b"xyz");
        assert_eq!(slice, b"yz");
    }

    // ---- WIRE-WR ----------------------------------------------------------
    //
    // 注：`Writer::put` 的 `checked_add` Overflow 分支（wire:86-89）不可达——
    // 由不变式 `offset <= output.len() <= isize::MAX` 且合法切片长度
    // `input.len() <= isize::MAX`，有 `offset + input.len() <= usize::MAX - 1
    // < usize::MAX`，加法永不溢出。故故意不为其增设用例（审阅 m1）。

    // WIRE-WR-001 — Writer::new/offset 初始状态。
    #[test]
    fn writer_initial_state() {
        let mut output = [0u8; 8];
        {
            let writer = Writer::new(&mut output);
            assert_eq!(writer.offset(), 0);
            assert_ne!(format!("{writer:?}"), "");
        }
    }

    // WIRE-WR-002 — put 正常路径与空片边界。
    #[test]
    fn writer_put_advances_offset_and_handles_empty_slices() {
        let mut output = [0u8; 8];
        {
            let mut writer = Writer::new(&mut output);
            writer.put(&[1, 2, 3]).expect("put 3 bytes");
            assert_eq!(writer.offset(), 3);
            writer.put(&[]).expect("put empty slice");
            assert_eq!(writer.offset(), 3);
            writer.put(&[4]).expect("put 1 byte");
            assert_eq!(writer.offset(), 4);
        }
        assert_eq!(&output[..4], &[1, 2, 3, 4]);
    }

    // WIRE-WR-003 — u8/u16_be/u32_be 大端写入。
    #[test]
    fn writer_big_endian_primitive_writes() {
        let mut output = [0u8; 7];
        {
            let mut writer = Writer::new(&mut output);
            writer.u8(0x42).expect("u8");
            writer.u16_be(0x1234).expect("u16");
            writer.u32_be(0xDEAD_BEEF).expect("u32");
            assert_eq!(writer.offset(), 7);
        }
        assert_eq!(output, [0x42, 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // WIRE-WR-004 — OutputTooSmall 错误且 offset 不变、无部分写入。
    #[test]
    fn writer_output_too_small_keeps_offset_and_leaves_buffer_intact() {
        let mut output = [0u8; 2];
        {
            let mut writer = Writer::new(&mut output);
            assert_eq!(writer.put(&[1, 2, 3]), Err(WireError::OutputTooSmall));
            assert_eq!(writer.offset(), 0);
            writer.u8(0xAA).expect("u8");
            assert_eq!(writer.offset(), 1);
            assert_eq!(writer.u16_be(0x0102), Err(WireError::OutputTooSmall));
            assert_eq!(writer.offset(), 1);
        }
        assert_eq!(output, [0xAA, 0]);
    }

    // WIRE-WR-005 — 恰好写满边界。
    #[test]
    fn writer_exact_fill_boundary() {
        let mut output = [0u8; 4];
        {
            let mut writer = Writer::new(&mut output);
            writer.u32_be(0x0102_0304).expect("exact fill");
            assert_eq!(writer.offset(), 4);
            assert_eq!(writer.u8(0), Err(WireError::OutputTooSmall));
            writer.put(&[]).expect("zero-length put on full output");
        }
        assert_eq!(output, [0x01, 0x02, 0x03, 0x04]);
    }

    // WIRE-WR-006 — Writer→Cursor 往返一致。
    #[test]
    fn writer_to_cursor_roundtrip() {
        let mut buffer = [0u8; 16];
        let written = {
            let mut writer = Writer::new(&mut buffer);
            writer.u8(0x42).expect("u8");
            writer.u16_be(0x1234).expect("u16");
            writer.u32_be(0xDEAD_BEEF).expect("u32");
            writer.put(b"END").expect("put END");
            writer.offset()
        };
        let mut cursor = Cursor::new(&buffer[..written]);
        assert_eq!(cursor.u8(), Ok(0x42));
        assert_eq!(cursor.u16_be(), Ok(0x1234));
        assert_eq!(cursor.u32_be(), Ok(0xDEAD_BEEF));
        assert_eq!(cursor.take(3), Ok(&b"END"[..]));
        assert_eq!(cursor.offset(), written);
    }

    // ---- WIRE-CODEC -------------------------------------------------------

    // WIRE-CODEC-001..003 支撑 mock：最小示例消息 Ping。
    #[derive(Debug, PartialEq)]
    struct Ping {
        seq: u32,
        tag: u8,
    }

    impl Decode<'_> for Ping {
        type Error = WireError;

        fn decode(input: &[u8]) -> Result<(Self, usize), WireError> {
            let mut cursor = Cursor::new(input);
            let seq = cursor.u32_be()?;
            let tag = cursor.u8()?;
            Ok((Ping { seq, tag }, cursor.offset()))
        }
    }

    impl Encode for Ping {
        type Error = WireError;

        fn encoded_len(&self) -> usize {
            5
        }

        fn encode(&self, output: &mut [u8]) -> Result<usize, WireError> {
            let mut writer = Writer::new(output);
            writer.u32_be(self.seq)?;
            writer.u8(self.tag)?;
            Ok(writer.offset())
        }
    }

    // WIRE-CODEC-001 — Decode 最小示例消息（Ping）。
    #[test]
    fn ping_decode_shape_and_error_propagation() {
        let (ping, consumed) = Ping::decode(&[0, 0, 0, 7, 0x2A]).expect("decode ping");
        assert_eq!(ping, Ping { seq: 7, tag: 0x2A });
        assert_eq!(consumed, 5);

        // 多余字节不属于本消息（wire:15 `(Message, consumed)` 契约）。
        let (ping, consumed) =
            Ping::decode(&[0, 0, 0, 7, 0x2A, 0xFF, 0xFF]).expect("decode with trailing bytes");
        assert_eq!(ping, Ping { seq: 7, tag: 0x2A });
        assert_eq!(consumed, 5);

        assert_eq!(Ping::decode(&[0, 0, 0]), Err(WireError::UnexpectedEnd));
    }

    // WIRE-CODEC-002 — Encode 最小示例消息（Ping）。
    #[test]
    fn ping_encode_matches_encoded_len() {
        let ping = Ping {
            seq: 0x0102_0304,
            tag: 0x2A,
        };
        assert_eq!(ping.encoded_len(), 5);

        let mut output = [0u8; 5];
        let written = ping.encode(&mut output).expect("encode into exact buffer");
        assert_eq!(written, 5);
        assert_eq!(written, ping.encoded_len());
        assert_eq!(output, [0x01, 0x02, 0x03, 0x04, 0x2A]);

        let mut small = [0u8; 4];
        assert_eq!(ping.encode(&mut small), Err(WireError::OutputTooSmall));
    }

    // WIRE-CODEC-003 — Encode→Decode 往返属性。
    #[test]
    fn ping_encode_decode_roundtrip() {
        for (seq, tag) in [
            (0u32, 0u8),
            (1, 0xFF),
            (u32::MAX, 0x80),
            (0xDEAD_BEEF, 0x01),
        ] {
            let ping = Ping { seq, tag };
            let mut buffer = [0u8; 5];
            let written = ping.encode(&mut buffer).expect("encode");
            let (decoded, consumed) = Ping::decode(&buffer[..written]).expect("decode");
            assert_eq!(decoded, ping);
            assert_eq!(consumed, written);
        }
    }

    // WIRE-CODEC-004 支撑 mock：借用输入的 Blob。
    // 最小借用消息格式：`[claimed_len: u8][payload: claimed_len bytes]`；
    // `data` 即 `Cursor::take(len)` 的返回切片，零拷贝借用输入。
    #[derive(Debug, PartialEq, Eq)]
    struct Blob<'a> {
        data: &'a [u8],
    }

    impl<'a> Decode<'a> for Blob<'a> {
        type Error = WireError;

        fn decode(input: &'a [u8]) -> Result<(Self, usize), WireError> {
            let mut cursor = Cursor::new(input);
            let len = usize::from(cursor.u8()?);
            let data = cursor.take(len)?;
            Ok((Blob { data }, cursor.offset()))
        }
    }

    // WIRE-CODEC-004 — Decode borrowed lifetime 验证（Blob）。
    #[test]
    fn blob_decode_borrows_input_zero_copy() {
        // `blob` 不可比 `input` 活得更久由类型系统在编译期强制
        // （`fn decode(input: &'a [u8]) -> (Blob<'a>, usize)`）。
        let input = [1u8, 2, 3, 4];
        let (blob, consumed) = Blob::decode(&input).expect("decode blob");
        assert_eq!(consumed, 2);
        assert_eq!(blob.data, &input[1..2]);
        // 零拷贝证明：借用切片与输入存储同址。
        assert_eq!(blob.data.as_ptr(), input[1..].as_ptr());

        // 更长 payload 样本。
        let rich = [3u8, 10, 20, 30];
        let (blob, consumed) = Blob::decode(&rich).expect("decode rich blob");
        assert_eq!(consumed, 4);
        assert_eq!(blob.data, &rich[1..4]);

        // 声称 len=2 而输入仅 1 字节（无 payload 空间）→ UnexpectedEnd。
        assert_eq!(Blob::decode(&[2u8]), Err(WireError::UnexpectedEnd));
    }
}

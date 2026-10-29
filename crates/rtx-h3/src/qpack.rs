//! The minimal QPACK form behind extended CONNECT (`RFC 9204`, gate item
//! `M3-H4`).
//!
//! Scope: the static table plus the literal representations needed by a
//! CONNECT field section, with the dynamic table permanently disabled:
//!
//! | Representation | Encoder (`encode_fields`) | Decoder (`FieldSection`) |
//! |---|---|---|
//! | Indexed field line, static table | yes (full name+value match) | yes |
//! | Literal with name reference, static table | yes (name match) | yes |
//! | Literal with literal name | yes (non-Huffman) | yes |
//! | Indexed field line, dynamic table | never | rejected (`DynamicTableNotSupported`) |
//! | Literal with name reference, dynamic table | never | rejected (`DynamicTableNotSupported`) |
//! | Post-Base representations | never | rejected (`DynamicTableNotSupported`) |
//! | Huffman string literal | not emitted | decoded (`RFC 7541` Appendix B table) |
//!
//! The dynamic table is disabled in both directions: a field section prefix
//! whose Required Insert Count or Delta Base is not zero is rejected, the
//! encoder always writes the `00 00` prefix, and
//! [`ensure_dynamic_table_disabled`] rejects a SETTINGS combination whose
//! `SETTINGS_QPACK_MAX_TABLE_CAPACITY` or `SETTINGS_QPACK_BLOCKED_STREAMS` is
//! non-zero (`RFC 9204` section 5, both defaults are zero).
//!
//! The decoder handles Huffman because Chrome emits Huffman-encoded names and
//! values. The encoder emits non-Huffman literals only; whether Chrome accepts
//! that encoding is `R6-3` interoperability work, not a claim made here.
//!
//! # Bounds
//!
//! A field section carries at most [`MAX_FIELD_LINES`] field lines; decoded
//! strings are written into the caller-supplied scratch slice of
//! [`FieldSection::next_field`], and a string that does not fit is rejected
//! instead of truncated. A declared string length that extends past the
//! borrowed input is rejected as [`QpackError::Wire`]. The static table is
//! borrowed from this module and never copied. Nothing allocates.

use crate::settings::Settings;
use rtx_wire::WireError;

/// Largest number of field lines a [`FieldSection`] accepts.
pub const MAX_FIELD_LINES: usize = 64;

/// The QPACK static table (`RFC 9204` Appendix A), indexed from zero.
pub const STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// Index of the EOS symbol in the `RFC 7541` Appendix B table.
const HUFFMAN_EOS: u16 = 256;

// `RFC 7541` Appendix B codes are verbatim protocol values; grouping them with
// underscores would obscure the source table.
#[allow(clippy::unreadable_literal)]
const HUFFMAN_FIRST_CODE: [u32; 31] = [
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0x5C, 0xF8, 0x0, 0x3F8, 0x7FA, 0xFFA, 0x1FF8, 0x3FFC,
    0x7FFC, 0x0, 0x0, 0x0, 0x7FFF0, 0xFFFE6, 0x1FFFDC, 0x3FFFD2, 0x7FFFD8, 0xFFFFEA, 0x1FFFFEC,
    0x3FFFFE0, 0x7FFFFDE, 0xFFFFFE2, 0x0, 0x3FFFFFFC,
];

const HUFFMAN_COUNT: [u16; 31] = [
    0, 0, 0, 0, 0, 10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3, 0, 0, 0, 3, 8, 13, 26, 29, 12, 4, 15, 19,
    29, 0, 4,
];

const HUFFMAN_OFFSET: [u16; 31] = [
    0, 0, 0, 0, 0, 0, 10, 36, 68, 0, 74, 79, 82, 84, 90, 92, 0, 0, 0, 95, 98, 106, 119, 145, 174,
    186, 190, 205, 224, 0, 253,
];

const HUFFMAN_SYMBOLS: [u16; 257] = [
    48, 49, 50, 97, 99, 101, 105, 111, 115, 116, 32, 37, 45, 46, 47, 51, 52, 53, 54, 55, 56, 57,
    61, 65, 95, 98, 100, 102, 103, 104, 108, 109, 110, 112, 114, 117, 58, 66, 67, 68, 69, 70, 71,
    72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 89, 106, 107, 113, 118, 119,
    120, 121, 122, 38, 42, 44, 59, 88, 90, 33, 34, 40, 41, 63, 39, 43, 124, 35, 62, 0, 36, 64, 91,
    93, 126, 94, 125, 60, 96, 123, 92, 195, 208, 128, 130, 131, 162, 184, 194, 224, 226, 153, 161,
    167, 172, 176, 177, 179, 209, 216, 217, 227, 229, 230, 129, 132, 133, 134, 136, 146, 154, 156,
    160, 163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232, 233, 1,
    135, 137, 138, 139, 140, 141, 143, 147, 149, 150, 151, 152, 155, 157, 158, 165, 166, 168, 174,
    175, 180, 182, 183, 188, 191, 197, 231, 239, 9, 142, 144, 145, 148, 159, 171, 206, 215, 225,
    236, 237, 199, 207, 234, 235, 192, 193, 200, 201, 202, 205, 210, 213, 218, 219, 238, 240, 242,
    243, 255, 203, 204, 211, 212, 214, 221, 222, 223, 241, 244, 245, 246, 247, 248, 250, 251, 252,
    253, 254, 2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28,
    29, 30, 31, 127, 220, 249, 10, 13, 22, 256,
];

/// One decoded field line. Both slices borrow the caller's scratch storage or
/// the static table, never the encoded input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

impl<'a> Field<'a> {
    /// Returns the field name.
    #[must_use]
    pub const fn name(self) -> &'a [u8] {
        self.name
    }

    /// Returns the field value.
    #[must_use]
    pub const fn value(self) -> &'a [u8] {
        self.value
    }
}

/// One field line to encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldLine<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

impl<'a> FieldLine<'a> {
    /// Builds a field line from a borrowed name and value.
    #[must_use]
    pub const fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self { name, value }
    }

    /// Returns the field name.
    #[must_use]
    pub const fn name(self) -> &'a [u8] {
        self.name
    }

    /// Returns the field value.
    #[must_use]
    pub const fn value(self) -> &'a [u8] {
        self.value
    }
}

/// A decoder over one encoded field section.
#[derive(Debug, Clone, Copy)]
pub struct FieldSection<'a> {
    input: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> FieldSection<'a> {
    /// Parses the field section prefix.
    ///
    /// The prefix is accepted only with Required Insert Count zero and Delta
    /// Base zero, the only values representable without a dynamic table.
    ///
    /// # Errors
    ///
    /// Returns [`QpackError::Wire`] when the prefix is truncated and
    /// [`QpackError::DynamicTableNotSupported`] when the prefix references a
    /// dynamic table state.
    pub fn new(input: &'a [u8]) -> Result<Self, QpackError> {
        let (required_insert_count, pos) = decode_prefixed(input, 0, 8)?;
        if required_insert_count != 0 {
            return Err(QpackError::DynamicTableNotSupported);
        }
        let sign_bit = *input
            .get(pos)
            .ok_or(QpackError::Wire(WireError::UnexpectedEnd))?;
        let (delta_base, pos) = decode_prefixed(input, pos, 7)?;
        if sign_bit & 0x80 != 0 || delta_base != 0 {
            return Err(QpackError::DynamicTableNotSupported);
        }
        Ok(Self {
            input,
            pos,
            remaining: MAX_FIELD_LINES,
        })
    }

    /// Returns the next field line, or `None` at the end of the section.
    ///
    /// Decoded names and values are written into `scratch`; `scratch` must be
    /// large enough for the name and the value of one field line together.
    ///
    /// # Errors
    ///
    /// Returns [`QpackError::Wire`] when a length or string extends past the
    /// input, [`QpackError::ScratchTooSmall`] when the decoded name and value
    /// do not fit `scratch`, [`QpackError::InvalidHuffman`] when a Huffman
    /// string is malformed, and
    /// [`QpackError::DynamicTableNotSupported`] for every dynamic-table
    /// representation.
    pub fn next_field<'s>(
        &mut self,
        scratch: &'s mut [u8],
    ) -> Result<Option<Field<'s>>, QpackError> {
        if self.pos >= self.input.len() {
            return Ok(None);
        }
        if self.remaining == 0 {
            return Err(QpackError::TooManyFieldLines);
        }
        self.remaining -= 1;
        let first = *self
            .input
            .get(self.pos)
            .ok_or(QpackError::Wire(WireError::UnexpectedEnd))?;
        if first & 0x80 != 0 {
            if first & 0x40 == 0 {
                return Err(QpackError::DynamicTableNotSupported);
            }
            let (name, value) = static_entry(self.take_index(6)?)?;
            Ok(Some(Field {
                name: name.as_bytes(),
                value: value.as_bytes(),
            }))
        } else if first & 0x40 != 0 {
            if first & 0x10 == 0 {
                return Err(QpackError::DynamicTableNotSupported);
            }
            let name = static_name(self.take_index(4)?)?;
            let value_len = self.read_string(scratch, 7)?;
            let value = scratch
                .get(..value_len)
                .ok_or(QpackError::ScratchTooSmall)?;
            Ok(Some(Field { name, value }))
        } else if first & 0x20 != 0 {
            let name_len = self.read_string(scratch, 3)?;
            let (name, value_storage) = scratch.split_at_mut(name_len);
            let value_len = self.read_string(value_storage, 7)?;
            let value = value_storage
                .get(..value_len)
                .ok_or(QpackError::ScratchTooSmall)?;
            Ok(Some(Field { name, value }))
        } else {
            Err(QpackError::DynamicTableNotSupported)
        }
    }

    /// Returns `true` when every field line has been consumed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Returns the number of field lines still available before
    /// [`MAX_FIELD_LINES`] is exceeded.
    #[must_use]
    pub const fn remaining_lines(&self) -> usize {
        self.remaining
    }

    /// Reads the remaining indexed field line index for the given prefix
    /// width.
    fn take_index(&mut self, bits: u8) -> Result<u64, QpackError> {
        let (index, next) = decode_prefixed(self.input, self.pos, bits)?;
        self.pos = next;
        Ok(index)
    }

    /// Reads one string literal, writing it into `output`.
    fn read_string(&mut self, output: &mut [u8], prefix_bits: u8) -> Result<usize, QpackError> {
        let first = *self
            .input
            .get(self.pos)
            .ok_or(QpackError::Wire(WireError::UnexpectedEnd))?;
        let huffman = first & (1u8 << prefix_bits) != 0;
        let (length, next) = decode_prefixed(self.input, self.pos, prefix_bits)?;
        let length = usize::try_from(length).map_err(|_| QpackError::IntegerOverflow)?;
        let end = next
            .checked_add(length)
            .ok_or(QpackError::IntegerOverflow)?;
        let bytes = self
            .input
            .get(next..end)
            .ok_or(QpackError::Wire(WireError::UnexpectedEnd))?;
        self.pos = end;
        if huffman {
            huffman_decode(bytes, output)
        } else {
            let target = output
                .get_mut(..length)
                .ok_or(QpackError::ScratchTooSmall)?;
            target.copy_from_slice(bytes);
            Ok(length)
        }
    }
}

/// Writes one encoded field section with a static table and non-Huffman
/// literals.
///
/// The output starts with the `00 00` prefix and never contains a dynamic
/// table reference.
///
/// # Errors
///
/// Returns [`QpackError::TooManyFieldLines`] above [`MAX_FIELD_LINES`],
/// [`QpackError::IntegerOverflow`] when a length cannot be represented and
/// [`QpackError::Wire`] when `output` is smaller than
/// [`fields_encoded_len`].
pub fn encode_fields(fields: &[FieldLine<'_>], output: &mut [u8]) -> Result<usize, QpackError> {
    if fields.len() > MAX_FIELD_LINES {
        return Err(QpackError::TooManyFieldLines);
    }
    let total = fields_encoded_len(fields);
    let target = output
        .get_mut(..total)
        .ok_or(QpackError::Wire(WireError::OutputTooSmall))?;
    target[0] = 0;
    target[1] = 0;
    let mut pos = 2;
    for field in fields {
        pos = encode_field(*field, target, pos)?;
    }
    Ok(pos)
}

/// Returns the number of bytes [`encode_fields`] writes for `fields`.
#[must_use]
pub fn fields_encoded_len(fields: &[FieldLine<'_>]) -> usize {
    let mut total = 2usize;
    for field in fields {
        let field_len = encoded_field_len(*field);
        total = total.saturating_add(field_len);
    }
    total
}

/// Rejects a SETTINGS combination that enables the QPACK dynamic table.
///
/// This crate implements the zero-capacity profile only: both
/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (`0x01`) and
/// `SETTINGS_QPACK_BLOCKED_STREAMS` (`0x07`) must be absent or zero
/// (`RFC 9204` section 5).
///
/// # Errors
///
/// Returns [`QpackError::DynamicTableNotSupported`] when either setting is
/// non-zero.
pub fn ensure_dynamic_table_disabled(settings: &Settings) -> Result<(), QpackError> {
    let capacity = settings.qpack_max_table_capacity().unwrap_or(0);
    let blocked = settings.qpack_blocked_streams().unwrap_or(0);
    if capacity != 0 || blocked != 0 {
        return Err(QpackError::DynamicTableNotSupported);
    }
    Ok(())
}

/// Returns the static table entry for a full index, or an error when the
/// index is out of range.
fn static_entry(index: u64) -> Result<(&'static str, &'static str), QpackError> {
    let index = usize::try_from(index).map_err(|_| QpackError::IntegerOverflow)?;
    STATIC_TABLE
        .get(index)
        .copied()
        .ok_or(QpackError::StaticIndexOutOfRange)
}

fn static_name(index: u64) -> Result<&'static [u8], QpackError> {
    static_entry(index).map(|(name, _)| name.as_bytes())
}

/// Reads a `RFC 9204` section 4.1.1 prefixed integer starting at `pos`.
fn decode_prefixed(input: &[u8], pos: usize, bits: u8) -> Result<(u64, usize), QpackError> {
    let first = *input
        .get(pos)
        .ok_or(QpackError::Wire(WireError::UnexpectedEnd))?;
    let mask = u8::try_from((1u16 << bits) - 1).map_err(|_| QpackError::IntegerOverflow)?;
    let mut value = u64::from(first & mask);
    let mut next = pos + 1;
    if value == u64::from(mask) {
        let mut shift = 0u32;
        loop {
            let byte = *input
                .get(next)
                .ok_or(QpackError::Wire(WireError::UnexpectedEnd))?;
            next += 1;
            let multiplier = 1u64.checked_shl(shift).ok_or(QpackError::IntegerOverflow)?;
            let chunk = u64::from(byte & 0x7F)
                .checked_mul(multiplier)
                .ok_or(QpackError::IntegerOverflow)?;
            value = value
                .checked_add(chunk)
                .ok_or(QpackError::IntegerOverflow)?;
            if byte & 0x80 == 0 {
                break;
            }
            shift = shift.checked_add(7).ok_or(QpackError::IntegerOverflow)?;
        }
    }
    Ok((value, next))
}

/// Decodes an `RFC 7541` Appendix B Huffman string into `output`.
fn huffman_decode(input: &[u8], output: &mut [u8]) -> Result<usize, QpackError> {
    let mut written = 0usize;
    let mut code = 0u32;
    let mut length = 0usize;
    for byte in input {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            length += 1;
            if (5..=30).contains(&length) {
                let first = HUFFMAN_FIRST_CODE[length];
                let count = u32::from(HUFFMAN_COUNT[length]);
                if count != 0 && code >= first && code - first < count {
                    let offset = usize::try_from(u64::from(HUFFMAN_OFFSET[length]))
                        .map_err(|_| QpackError::IntegerOverflow)?;
                    let offset = offset
                        .checked_add(
                            usize::try_from(code - first)
                                .map_err(|_| QpackError::IntegerOverflow)?,
                        )
                        .ok_or(QpackError::IntegerOverflow)?;
                    let symbol = *HUFFMAN_SYMBOLS
                        .get(offset)
                        .ok_or(QpackError::InvalidHuffman)?;
                    if symbol == HUFFMAN_EOS {
                        return Err(QpackError::InvalidHuffman);
                    }
                    let symbol = u8::try_from(symbol).map_err(|_| QpackError::InvalidHuffman)?;
                    let slot = output.get_mut(written).ok_or(QpackError::ScratchTooSmall)?;
                    *slot = symbol;
                    written += 1;
                    code = 0;
                    length = 0;
                }
            } else if length > 30 {
                return Err(QpackError::InvalidHuffman);
            }
        }
    }
    if length != 0 && (length > 7 || code != (1u32 << length) - 1) {
        return Err(QpackError::InvalidHuffman);
    }
    Ok(written)
}

/// Encodes one field line into `output` starting at `pos`.
fn encode_field(field: FieldLine<'_>, output: &mut [u8], pos: usize) -> Result<usize, QpackError> {
    let name = field.name;
    let value = field.value;
    if let Some(index) = find_static(name, Some(value)) {
        let index = u64::try_from(index).map_err(|_| QpackError::IntegerOverflow)?;
        return write_prefixed(output, pos, index, 6, 0xC0);
    }
    if let Some(index) = find_static(name, None) {
        let index = u64::try_from(index).map_err(|_| QpackError::IntegerOverflow)?;
        let pos = write_prefixed(output, pos, index, 4, 0x50)?;
        return write_string(output, pos, value);
    }
    let name_len = u64::try_from(name.len()).map_err(|_| QpackError::IntegerOverflow)?;
    let pos = write_prefixed(output, pos, name_len, 3, 0x20)?;
    let name_end = pos
        .checked_add(name.len())
        .ok_or(QpackError::IntegerOverflow)?;
    let target = output
        .get_mut(pos..name_end)
        .ok_or(QpackError::Wire(WireError::OutputTooSmall))?;
    target.copy_from_slice(name);
    write_string(output, name_end, value)
}

/// Returns the encoded length of one field line.
fn encoded_field_len(field: FieldLine<'_>) -> usize {
    if let Some(index) = find_static(field.name, Some(field.value)) {
        let index = u64::try_from(index).unwrap_or(u64::MAX);
        return prefixed_len(index, 6);
    }
    if let Some(index) = find_static(field.name, None) {
        let index = u64::try_from(index).unwrap_or(u64::MAX);
        return prefixed_len(index, 4) + string_len(field.value.len());
    }
    prefixed_len(u64::try_from(field.name.len()).unwrap_or(u64::MAX), 3)
        .saturating_add(field.name.len())
        .saturating_add(string_len(field.value.len()))
}

/// Writes a prefixed integer with the given high flag bits.
fn write_prefixed(
    output: &mut [u8],
    pos: usize,
    value: u64,
    bits: u8,
    flags: u8,
) -> Result<usize, QpackError> {
    let mask = u8::try_from((1u16 << bits) - 1).map_err(|_| QpackError::IntegerOverflow)?;
    let mut cursor = pos;
    let first = output
        .get_mut(cursor)
        .ok_or(QpackError::Wire(WireError::OutputTooSmall))?;
    *first = flags;
    if value < u64::from(mask) {
        *first |= u8::try_from(value).map_err(|_| QpackError::IntegerOverflow)?;
        return Ok(cursor + 1);
    }
    *first |= mask;
    cursor += 1;
    let mut rest = value - u64::from(mask);
    loop {
        let mut byte = u8::try_from(rest & 0x7F).map_err(|_| QpackError::IntegerOverflow)?;
        rest >>= 7;
        if rest != 0 {
            byte |= 0x80;
        }
        *output
            .get_mut(cursor)
            .ok_or(QpackError::Wire(WireError::OutputTooSmall))? = byte;
        cursor += 1;
        if rest == 0 {
            return Ok(cursor);
        }
    }
}

/// Writes a non-Huffman string literal (8-bit prefix length).
fn write_string(output: &mut [u8], pos: usize, value: &[u8]) -> Result<usize, QpackError> {
    let length = u64::try_from(value.len()).map_err(|_| QpackError::IntegerOverflow)?;
    let pos = write_prefixed(output, pos, length, 7, 0x00)?;
    let end = pos
        .checked_add(value.len())
        .ok_or(QpackError::IntegerOverflow)?;
    let target = output
        .get_mut(pos..end)
        .ok_or(QpackError::Wire(WireError::OutputTooSmall))?;
    target.copy_from_slice(value);
    Ok(end)
}

/// Returns the number of bytes a prefixed integer occupies.
fn prefixed_len(value: u64, bits: u8) -> usize {
    let mask = u64::from(u8::MAX) & ((1u64 << bits) - 1);
    if value < mask {
        return 1;
    }
    let mut rest = value - mask;
    let mut length = 2;
    while rest >= 0x80 {
        rest >>= 7;
        length += 1;
    }
    length
}

/// Returns the number of bytes a non-Huffman string literal occupies.
fn string_len(value_len: usize) -> usize {
    prefixed_len(u64::try_from(value_len).unwrap_or(u64::MAX), 7).saturating_add(value_len)
}

/// Returns the static table index whose name and optional value match.
fn find_static(name: &[u8], value: Option<&[u8]>) -> Option<usize> {
    STATIC_TABLE.iter().position(|(static_name, static_value)| {
        static_name.as_bytes() == name && value.is_none_or(|value| static_value.as_bytes() == value)
    })
}

/// QPACK decoding or encoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QpackError {
    /// A varint was truncated or the output slice was too small.
    Wire(WireError),
    /// The field section carries more than [`MAX_FIELD_LINES`] field lines.
    TooManyFieldLines,
    /// A static table index is outside the 99 registered entries.
    StaticIndexOutOfRange,
    /// A representation or the field section prefix needs the dynamic table,
    /// which this profile never enables.
    DynamicTableNotSupported,
    /// The caller's scratch slice cannot hold the decoded name and value.
    ScratchTooSmall,
    /// A Huffman string is malformed (invalid code, EOS or bad padding).
    InvalidHuffman,
    /// An integer or length cannot be represented as `usize`.
    IntegerOverflow,
}

impl From<WireError> for QpackError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

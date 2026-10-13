//! Source description packet (RFC 3550 section 6.4.3, type 202).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|   SC   |  PT=SDES=202  |             length            |
//! +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//! |                          SSRC/CSRC_1                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           SDES items                          |
//! |                              ...                              |
//! +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//! |                          SSRC/CSRC_2                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           SDES items                          |
//! |                              ...                              |
//! +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//! ```
//!
//! Each chunk is terminated by a zero type octet plus zero padding up to
//! the next 32-bit boundary. The chunk body is kept verbatim so that
//! `encode(decode(bytes))` reproduces the input exactly.

use rtx_wire::{Decode, Encode, WireError, Writer};

use crate::header::{COUNT_MAX, Header, PacketType};
use crate::util::padding_size;

/// Maximum length of an SDES item text field (one length octet).
pub const SDES_MAX_OCTET_COUNT: usize = 255;

/// Offset of the first chunk (after the 4-byte common header).
pub const SDES_CHUNK_OFFSET: usize = 4;

/// Size of the SSRC/CSRC field at the start of each chunk.
pub const SDES_SOURCE_LENGTH: usize = 4;

/// SDES item type (RFC 3550 section 6.5.1). Unknown values are preserved
/// verbatim via [`SdesType::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum SdesType {
    /// End of item list (zero octet).
    End = 0,
    /// Canonical name (CNAME).
    Cname = 1,
    /// User name (NAME).
    Name = 2,
    /// Electronic mail address (EMAIL).
    Email = 3,
    /// Phone number (PHONE).
    Phone = 4,
    /// Geographic user location (LOC).
    Location = 5,
    /// Application or tool name (TOOL).
    Tool = 6,
    /// Notice/status (NOTE).
    Note = 7,
    /// Private extensions (PRIV).
    Private = 8,
    /// Unknown or reserved type, preserved verbatim.
    Unknown(u8) = 255,
}

impl SdesType {
    /// Returns the wire byte value of this item type.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            SdesType::End => 0,
            SdesType::Cname => 1,
            SdesType::Name => 2,
            SdesType::Email => 3,
            SdesType::Phone => 4,
            SdesType::Location => 5,
            SdesType::Tool => 6,
            SdesType::Note => 7,
            SdesType::Private => 8,
            SdesType::Unknown(value) => value,
        }
    }
}

impl From<u8> for SdesType {
    /// Maps a wire byte to an item type, preserving unknown values.
    fn from(value: u8) -> Self {
        match value {
            0 => SdesType::End,
            1 => SdesType::Cname,
            2 => SdesType::Name,
            3 => SdesType::Email,
            4 => SdesType::Phone,
            5 => SdesType::Location,
            6 => SdesType::Tool,
            7 => SdesType::Note,
            8 => SdesType::Private,
            other => SdesType::Unknown(other),
        }
    }
}

/// One SDES item: a type octet, a length octet, and the text bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdesItem<'a> {
    /// Item type.
    pub sdes_type: SdesType,
    /// Item text, borrowed verbatim.
    pub text: &'a [u8],
}

/// One SDES chunk describing a single source.
///
/// `items` is the verbatim item region of the chunk, excluding the
/// terminating zero octet and any padding; iterate it with
/// [`SdesChunk::items`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdesChunk<'a> {
    /// SSRC/CSRC identifier described by this chunk.
    pub source: u32,
    /// Verbatim item region (type/len/text triples), without terminator.
    pub items: &'a [u8],
}

impl<'a> SdesChunk<'a> {
    /// Iterates over the items in this chunk.
    #[must_use]
    pub fn items(&self) -> SdesItems<'a> {
        SdesItems {
            data: self.items,
            offset: 0,
        }
    }
}

/// Iterator over the items of an SDES chunk.
#[derive(Debug, Clone)]
pub struct SdesItems<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for SdesItems<'a> {
    type Item = SdesItem<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let data = self.data.get(self.offset..)?;
        if data.is_empty() {
            return None;
        }
        let sdes_type = SdesType::from(data[0]);
        if sdes_type == SdesType::End {
            // The item region excludes the terminator; a zero type here can
            // only appear in malformed input, so stop iterating.
            return None;
        }
        if data.len() < 2 {
            return None;
        }
        let len = usize::from(data[1]);
        let text_end = 2 + len;
        if data.len() < text_end {
            return None;
        }
        let item = SdesItem {
            sdes_type,
            text: &data[2..text_end],
        };
        self.offset += text_end;
        Some(item)
    }
}

/// Walks one chunk at the front of `data`.
///
/// Returns `(chunk_len, source, items)` where `chunk_len` includes the
/// SSRC, all items, the terminating zero octet and the 32-bit padding.
fn walk_chunk(data: &[u8]) -> Result<(usize, u32, &[u8]), WireError> {
    if data.len() < SDES_SOURCE_LENGTH + 1 {
        return Err(WireError::UnexpectedEnd);
    }
    let source = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    let mut offset = SDES_SOURCE_LENGTH;
    loop {
        let item_type = *data.get(offset).ok_or(WireError::UnexpectedEnd)?;
        if item_type == 0 {
            // End of item list: consume the terminator plus padding.
            offset += 1;
            let pad = padding_size(offset);
            let end = offset.checked_add(pad).ok_or(WireError::Overflow)?;
            if end > data.len() {
                return Err(WireError::UnexpectedEnd);
            }
            let items = &data[SDES_SOURCE_LENGTH..offset - 1];
            return Ok((end, source, items));
        }
        let len = usize::from(*data.get(offset + 1).ok_or(WireError::UnexpectedEnd)?);
        let text_start = offset + 2;
        let text_end = text_start.checked_add(len).ok_or(WireError::Overflow)?;
        if text_end > data.len() {
            return Err(WireError::UnexpectedEnd);
        }
        offset = text_end;
    }
}

/// Iterator over the chunks of an SDES packet.
#[derive(Debug, Clone)]
pub struct SdesChunks<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for SdesChunks<'a> {
    type Item = Result<SdesChunk<'a>, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }
        match walk_chunk(&self.data[self.offset..]) {
            Ok((chunk_len, source, items)) => {
                self.offset += chunk_len;
                Some(Ok(SdesChunk { source, items }))
            }
            Err(err) => {
                // Stop iteration after an error.
                self.offset = self.data.len();
                Some(Err(err))
            }
        }
    }
}

/// Source description packet borrowing its chunk body from the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceDescription<'a> {
    /// Verbatim chunk body (everything after the common header).
    pub body: &'a [u8],
}

impl<'a> SourceDescription<'a> {
    /// Iterates over the chunks of this packet.
    #[must_use]
    pub fn chunks(&self) -> SdesChunks<'a> {
        SdesChunks {
            data: self.body,
            offset: 0,
        }
    }

    /// Returns the text of the first CNAME item across all chunks, if any.
    #[must_use]
    pub fn cname(&self) -> Option<&'a [u8]> {
        self.chunks().flatten().find_map(|chunk| {
            chunk
                .items()
                .find(|item| item.sdes_type == SdesType::Cname)
                .map(|item| item.text)
        })
    }

    /// Header implied by the current body.
    ///
    /// `count` saturates at 31 and `length` at `u16::MAX` when the packet
    /// is too large; [`Encode`] performs the real validation.
    #[must_use]
    pub fn header(&self) -> Header {
        let count = self.chunks().flatten().count();
        let total = SDES_CHUNK_OFFSET + self.body.len();
        Header {
            padding: false,
            count: u8::try_from(count).unwrap_or(COUNT_MAX),
            packet_type: PacketType::Sdes,
            length: u16::try_from(total / 4 - 1).unwrap_or(u16::MAX),
        }
    }

    /// Encodes the packet into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the body does not decode
    /// into at most 31 well-formed chunks, and
    /// [`WireError::OutputTooSmall`] when the writer lacks room.
    pub(crate) fn write_to(&self, writer: &mut Writer<'_>) -> Result<(), WireError> {
        // Validate the body before writing so that encode never emits a
        // packet that decode would reject.
        let mut count = 0usize;
        let mut offset = 0usize;
        while offset < self.body.len() {
            let (chunk_len, _, _) = walk_chunk(&self.body[offset..])?;
            offset += chunk_len;
            count += 1;
            if count > usize::from(COUNT_MAX) {
                return Err(WireError::InvalidValue);
            }
        }
        let total = SDES_CHUNK_OFFSET + self.body.len();
        let length = u16::try_from(total / 4 - 1).map_err(|_| WireError::Overflow)?;

        let header = Header {
            padding: false,
            count: u8::try_from(count).map_err(|_| WireError::InvalidValue)?,
            packet_type: PacketType::Sdes,
            length,
        };
        header.write_to(writer)?;
        writer.put(self.body)?;
        Ok(())
    }
}

impl<'a> Decode<'a> for SourceDescription<'a> {
    type Error = WireError;

    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        let (header, consumed) = Header::decode(input)?;
        if header.packet_type != PacketType::Sdes {
            return Err(WireError::InvalidValue);
        }

        // Walk every chunk up front so the chunk count can be validated
        // against the header count field.
        let body = &input[consumed..];
        let mut offset = 0usize;
        let mut chunks = 0usize;
        while offset < body.len() {
            let (chunk_len, _, _) = walk_chunk(&body[offset..])?;
            offset += chunk_len;
            chunks += 1;
        }
        if chunks != usize::from(header.count) {
            return Err(WireError::InvalidValue);
        }

        let sdes = SourceDescription { body };
        Ok((sdes, input.len()))
    }
}

impl Encode for SourceDescription<'_> {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        SDES_CHUNK_OFFSET + self.body.len()
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
    /// `rtcp/source_description/source_description_test.rs:161-173`
    /// ("two chunks", 24 bytes, bogus length 24 — real length is 5).
    const SDES_TWO_CHUNKS: [u8; 24] = [
        0x82, 0xca, 0x00, 0x18, // v=2, p=0, count=2, SDES, len=24 (bogus)
        0x01, 0x02, 0x03, 0x04, // chunk 1 source 0x01020304
        0x01, 0x01, 0x41, // CNAME, len=1, "A"
        0x00, // END
        0x05, 0x06, 0x07, 0x08, // chunk 2 source 0x05060708
        0x01, 0x03, 0x42, 0x43, 0x44, // CNAME, len=3, "BCD"
        0x00, 0x00, 0x00, // END + padding
    ];

    /// Differential vector: upstream
    /// `rtcp/source_description/source_description_test.rs:110-121`
    /// ("empty string", 12 bytes, bogus length 12 — real length is 2).
    const SDES_EMPTY_TEXT: [u8; 12] = [
        0x81, 0xca, 0x00, 0x0c, // v=2, p=0, count=1, SDES, len=12 (bogus)
        0x01, 0x02, 0x03, 0x04, // source 0x01020304
        0x01, 0x00, // CNAME, len=0
        0x00, 0x00, // END + padding
    ];

    /// Differential vector: upstream
    /// `rtcp/source_description/source_description_test.rs:134-148`
    /// ("two items", 16 bytes, bogus length 16 — real length is 3).
    const SDES_TWO_ITEMS: [u8; 16] = [
        0x81, 0xca, 0x00, 0x10, // v=2, p=0, count=1, SDES, len=16 (bogus)
        0x10, 0x00, 0x00, 0x00, // source 0x10000000
        0x01, 0x01, 0x41, // CNAME, len=1, "A"
        0x04, 0x01, 0x42, // PHONE, len=1, "B"
        0x00, 0x00, // END + padding
    ];

    /// Differential vector: upstream
    /// `rtcp/source_description/source_description_test.rs:87-96`
    /// ("zero item chunk", 12 bytes, bogus length 12 — real length is 2).
    const SDES_ZERO_ITEMS: [u8; 12] = [
        0x81, 0xca, 0x00, 0x0c, // v=2, p=0, count=1, SDES, len=12 (bogus)
        0x01, 0x02, 0x03, 0x04, // source 0x01020304
        0x00, 0x00, 0x00, 0x00, // END + padding
    ];

    /// Differential vector: upstream
    /// `rtcp/source_description/source_description_test.rs:99-110`
    /// ("wrong type": SR header).
    const SDES_WRONG_TYPE: [u8; 12] = [
        0x81, 0xc8, 0x00, 0x0c, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00,
    ];

    // RTCP-SDES-001 — 差分：上游 "two chunks" 向量（2 chunk、CNAME 内容）。
    #[test]
    fn rtcp_sdes_001_upstream_two_chunks_vector() {
        let (sdes, consumed) =
            SourceDescription::decode(&SDES_TWO_CHUNKS).expect("decode two chunks");
        assert_eq!(consumed, SDES_TWO_CHUNKS.len());
        assert_eq!(sdes.body.len(), 20);

        let chunks: Vec<SdesChunk<'_>> = sdes.chunks().collect::<Result<_, _>>().expect("chunks");
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].source, 0x0102_0304);
        assert_eq!(chunks[1].source, 0x0506_0708);

        let items0: Vec<SdesItem<'_>> = chunks[0].items().collect();
        assert_eq!(items0.len(), 1);
        assert_eq!(items0[0].sdes_type, SdesType::Cname);
        assert_eq!(items0[0].text, b"A");

        let items1: Vec<SdesItem<'_>> = chunks[1].items().collect();
        assert_eq!(items1.len(), 1);
        assert_eq!(items1[0].text, b"BCD");

        assert_eq!(sdes.cname(), Some(&b"A"[..]));

        let header = sdes.header();
        assert_eq!(header.count, 2);
        assert_eq!(header.length, 5);
    }

    // RTCP-SDES-002 — 差分：encode(decode(v)) 除 length 字段外逐字节一致。
    #[test]
    fn rtcp_sdes_002_encode_recomputes_length_field() {
        let (sdes, _) = SourceDescription::decode(&SDES_TWO_CHUNKS).expect("decode two chunks");
        let mut output = [0u8; 24];
        let written = sdes.encode(&mut output).expect("encode two chunks");
        assert_eq!(written, 24);
        assert_eq!(written, sdes.encoded_len());

        let mut expected = SDES_TWO_CHUNKS;
        expected[2..4].copy_from_slice(&5u16.to_be_bytes()); // corrected length
        assert_eq!(&output[..written], &expected);

        let (again, _) = SourceDescription::decode(&output[..written]).expect("re-decode");
        assert_eq!(again, sdes);
    }

    // RTCP-SDES-003 — 差分：上游 "empty string" / "zero item chunk" 向量。
    #[test]
    fn rtcp_sdes_003_empty_text_and_zero_item_chunks() {
        let (sdes, _) = SourceDescription::decode(&SDES_EMPTY_TEXT).expect("decode empty text");
        let chunks: Vec<SdesChunk<'_>> = sdes.chunks().collect::<Result<_, _>>().expect("chunks");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].source, 0x0102_0304);
        let items: Vec<SdesItem<'_>> = chunks[0].items().collect();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].sdes_type, SdesType::Cname);
        assert!(items[0].text.is_empty());
        assert_eq!(sdes.cname(), Some(&b""[..]));

        let mut output = [0u8; 12];
        let written = sdes.encode(&mut output).expect("encode empty text");
        let mut expected = SDES_EMPTY_TEXT;
        expected[2..4].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(&output[..written], &expected);

        let (zero, _) = SourceDescription::decode(&SDES_ZERO_ITEMS).expect("decode zero items");
        let chunks: Vec<SdesChunk<'_>> = zero.chunks().collect::<Result<_, _>>().expect("chunks");
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].items().next().is_none());
        assert_eq!(zero.cname(), None);
    }

    // RTCP-SDES-004 — 差分：上游 "two items" 向量（多 item chunk 迭代）。
    #[test]
    fn rtcp_sdes_004_upstream_two_items_vector() {
        let (sdes, _) = SourceDescription::decode(&SDES_TWO_ITEMS).expect("decode two items");
        let chunks: Vec<SdesChunk<'_>> = sdes.chunks().collect::<Result<_, _>>().expect("chunks");
        assert_eq!(chunks.len(), 1);
        let items: Vec<SdesItem<'_>> = chunks[0].items().collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].sdes_type, SdesType::Cname);
        assert_eq!(items[0].text, b"A");
        assert_eq!(items[1].sdes_type, SdesType::Phone);
        assert_eq!(items[1].text, b"B");
        assert_eq!(sdes.cname(), Some(&b"A"[..]));

        let mut output = [0u8; 16];
        let written = sdes.encode(&mut output).expect("encode two items");
        let mut expected = SDES_TWO_ITEMS;
        expected[2..4].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(&output[..written], &expected);
    }

    // RTCP-SDES-005 — 差分：错误类型头 → InvalidValue（上游 "wrong type"）。
    #[test]
    fn rtcp_sdes_005_wrong_type_rejected() {
        assert_eq!(
            SourceDescription::decode(&SDES_WRONG_TYPE),
            Err(WireError::InvalidValue)
        );
    }

    // RTCP-SDES-006 — chunk 数与 count 不一致 → InvalidValue（上游
    // "bad count in header"）。
    #[test]
    fn rtcp_sdes_006_count_mismatch_rejected() {
        let mut bad = SDES_TWO_CHUNKS;
        bad[0] = 0x81; // count = 1 but body has 2 chunks
        assert_eq!(
            SourceDescription::decode(&bad),
            Err(WireError::InvalidValue)
        );
    }

    // RTCP-SDES-007 — chunk 截断/缺终止符 → UnexpectedEnd（上游
    // "missing type"/"no end" 路径）。
    #[test]
    fn rtcp_sdes_007_truncated_chunk_rejected() {
        // Missing terminator: chunk never ends.
        let no_end = [
            0x81, 0xca, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x41,
        ];
        assert_eq!(
            SourceDescription::decode(&no_end),
            Err(WireError::UnexpectedEnd)
        );

        // Text length overruns the body.
        let bad_len = [0x81, 0xca, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01];
        assert_eq!(
            SourceDescription::decode(&bad_len),
            Err(WireError::UnexpectedEnd)
        );

        // Too short for source + type.
        let tiny = [0x81, 0xca, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            SourceDescription::decode(&tiny),
            Err(WireError::UnexpectedEnd)
        );
    }

    // RTCP-SDES-008 — 属性：SdesType 字节映射往返（含 Unknown 保留）。
    #[test]
    fn rtcp_sdes_008_type_mapping_round_trip() {
        for byte in 0..=u8::MAX {
            let mapped = SdesType::from(byte);
            assert_eq!(mapped.as_u8(), byte, "type byte {byte} must round-trip");
        }
        assert_eq!(SdesType::from(0), SdesType::End);
        assert_eq!(SdesType::from(8), SdesType::Private);
        assert_eq!(SdesType::from(9), SdesType::Unknown(9));
    }
}

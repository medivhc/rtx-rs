//! The STUN message: header, message type field, transaction id, and the
//! attribute section.
//!
//! A message is a class and method ([`MessageType`]), a 96-bit
//! [`TransactionId`] and a sequence of [`RawAttribute`]s ([RFC 5389] §6).
//! [`Message`] borrows the encoded attribute region from the decoded input;
//! [`MessageWriter`] builds a message into a caller-owned buffer.
//!
//! The message type field packs the 12-bit method and the 2-bit class into
//! 16 bits with two zero "holes", per [RFC 5389] Figure 3:
//!
//! ```text
//! 0                 1
//! 2  3  4 5 6 7 8 9 0 1 2 3 4 5
//! +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
//! |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
//! |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
//! +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! [RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389

use core::fmt;

use rtx_wire::{Decode, Encode, WireError};

use crate::attributes::{
    ATTRIBUTE_HEADER_SIZE, AttrType, RawAttribute, nearest_padded_value_length,
};

/// Fixed value that aids in distinguishing STUN packets from packets of
/// other protocols when STUN is multiplexed with those other protocols on
/// the same port ([RFC 5389] §6).
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Bytes in the STUN message header.
pub const MESSAGE_HEADER_SIZE: usize = 20;

/// Length of the transaction id, in bytes (96 bits).
pub const TRANSACTION_ID_SIZE: usize = 12;

/// A 96-bit transaction id, which pairs a response with its request
/// ([RFC 5389] §6).
///
/// The codec never generates randomness — `no_std` has no RNG — so the
/// embedding runtime supplies a fresh id per transaction, e.g. from a
/// hardware entropy source or the OS CSPRNG at the edge of the crate.
#[derive(PartialEq, Eq, Hash, Default, Debug, Copy, Clone)]
pub struct TransactionId(pub [u8; TRANSACTION_ID_SIZE]);

/// A STUN message class: request, indication, success response or error
/// response ([RFC 5389] §6).
#[derive(Default, PartialEq, Eq, Debug, Copy, Clone, Hash)]
pub struct MessageClass(u8);

/// Class bits `0b00`: a request.
pub const CLASS_REQUEST: MessageClass = MessageClass(0x00);
/// Class bits `0b01`: an indication.
pub const CLASS_INDICATION: MessageClass = MessageClass(0x01);
/// Class bits `0b10`: a success response.
pub const CLASS_SUCCESS_RESPONSE: MessageClass = MessageClass(0x02);
/// Class bits `0b11`: an error response.
pub const CLASS_ERROR_RESPONSE: MessageClass = MessageClass(0x03);

impl MessageClass {
    /// Returns the 2-bit wire representation of the class.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl fmt::Display for MessageClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            CLASS_REQUEST => "request",
            CLASS_INDICATION => "indication",
            CLASS_SUCCESS_RESPONSE => "success response",
            CLASS_ERROR_RESPONSE => "error response",
            _ => "unknown message class",
        };
        f.write_str(s)
    }
}

/// A STUN method, such as Binding or one of TURN's ([RFC 5389] §6,
/// [RFC 5766] §14, [RFC 6062] §4).
///
/// [RFC 5766]: https://www.rfc-editor.org/rfc/rfc5766
/// [RFC 6062]: https://www.rfc-editor.org/rfc/rfc6062
#[derive(Default, PartialEq, Eq, Debug, Copy, Clone, Hash)]
pub struct Method(u16);

/// Binding: the classic NAT discovery exchange.
pub const METHOD_BINDING: Method = Method(0x001);
/// TURN Allocate: asks a relay for a public address.
pub const METHOD_ALLOCATE: Method = Method(0x003);
/// TURN Refresh: extends or releases an allocation.
pub const METHOD_REFRESH: Method = Method(0x004);
/// TURN Send: an indication carrying data to a peer through the relay.
pub const METHOD_SEND: Method = Method(0x006);
/// TURN Data: an indication carrying data from a peer through the relay.
pub const METHOD_DATA: Method = Method(0x007);
/// TURN `CreatePermission`: authorizes traffic to and from a peer address.
pub const METHOD_CREATE_PERMISSION: Method = Method(0x008);
/// TURN `ChannelBind`: binds a channel number to a peer for compact framing.
pub const METHOD_CHANNEL_BIND: Method = Method(0x009);
/// TURN-TCP Connect: asks the relay to connect to a peer (RFC 6062).
pub const METHOD_CONNECT: Method = Method(0x000a);
/// TURN-TCP `ConnectionBind`: associates a new TCP connection with an
/// allocation (RFC 6062).
pub const METHOD_CONNECTION_BIND: Method = Method(0x000b);
/// TURN-TCP `ConnectionAttempt`: notifies the client of an inbound TCP
/// connection (RFC 6062).
pub const METHOD_CONNECTION_ATTEMPT: Method = Method(0x000c);

impl Method {
    /// Returns the 12-bit wire representation of the method.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            METHOD_BINDING => "Binding",
            METHOD_ALLOCATE => "Allocate",
            METHOD_REFRESH => "Refresh",
            METHOD_SEND => "Send",
            METHOD_DATA => "Data",
            METHOD_CREATE_PERMISSION => "CreatePermission",
            METHOD_CHANNEL_BIND => "ChannelBind",
            METHOD_CONNECT => "Connect",
            METHOD_CONNECTION_BIND => "ConnectionBind",
            METHOD_CONNECTION_ATTEMPT => "ConnectionAttempt",
            _ => return write!(f, "0x{:x}", self.0),
        };
        f.write_str(s)
    }
}

/// A message's class and method together, as encoded in the first two header
/// bytes.
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
pub struct MessageType {
    /// The method, such as Binding or Allocate.
    pub method: Method,
    /// The class: request, indication, success response or error response.
    pub class: MessageClass,
}

/// Binding request message type.
pub const BINDING_REQUEST: MessageType = MessageType {
    method: METHOD_BINDING,
    class: CLASS_REQUEST,
};
/// Binding success response message type.
pub const BINDING_SUCCESS: MessageType = MessageType {
    method: METHOD_BINDING,
    class: CLASS_SUCCESS_RESPONSE,
};
/// Binding error response message type.
pub const BINDING_ERROR: MessageType = MessageType {
    method: METHOD_BINDING,
    class: CLASS_ERROR_RESPONSE,
};

impl MessageType {
    /// Returns a new message type with the provided method and class.
    #[must_use]
    pub const fn new(method: Method, class: MessageClass) -> Self {
        Self { method, class }
    }

    /// Returns the 16-bit wire representation of the message type, packing
    /// method and class with the zero holes of [RFC 5389] Figure 3.
    #[must_use]
    pub fn value(self) -> u16 {
        // Splitting the method into A(M0-M3), B(M4-M6), D(M7-M11).
        let method = self.method.value();
        let a = method & METHOD_ABITS;
        let b = method & METHOD_BBITS;
        let d = method & METHOD_DBITS;

        // Shifting to add the "holes" for C0 (bit 4) and C1 (bit 8).
        let method = a + (b << METHOD_BSHIFT) + (d << METHOD_DSHIFT);

        // C0 is the low bit of the class, C1 the high bit.
        let class = u16::from(self.class.value());
        let c0 = (class & C0BIT) << CLASS_C0SHIFT;
        let c1 = (class & C1BIT) << CLASS_C1SHIFT;

        method + c0 + c1
    }

    /// Decodes the 16-bit message type field back into class and method.
    ///
    /// The two reserved most significant bits ([RFC 5389] §6) are dropped:
    /// callers that must reject a non-zero reserved field — such as
    /// [`Message`]'s [`Decode`] — check [`MessageType::is_valid_raw_value`]
    /// first.
    pub fn read_value(&mut self, value: u16) {
        // Class: first bit from bit 4, second from bit 7.
        let c0 = (value >> CLASS_C0SHIFT) & C0BIT;
        let c1 = (value >> CLASS_C1SHIFT) & C1BIT;
        // Both are masked to 0 or 1, so the sum fits `u8` by construction.
        #[allow(clippy::cast_possible_truncation)]
        let class = (c0 + c1) as u8;
        self.class = MessageClass(class);

        // Method: undo the A/B/D split and re-join the three fields.
        let a = value & METHOD_ABITS;
        let b = (value >> METHOD_BSHIFT) & METHOD_BBITS;
        let d = (value >> METHOD_DSHIFT) & METHOD_DBITS;
        self.method = Method(a + b + d);
    }

    /// Returns `true` when a raw 16-bit type field is a legal STUN message type,
    /// i.e. when neither reserved bit is set.
    ///
    /// [RFC 5389] §6 reserves the two most significant bits: `00` marks a
    /// STUN message and `01` a TURN `ChannelData`. A raw value that sets either
    /// bit is therefore not a STUN message and must be rejected rather than
    /// silently normalised — normalising would break
    /// `encode(decode(bytes)) == bytes` and let a peer smuggle a non-STUN
    /// type past the demultiplex boundary. [`MessageType`] itself keeps no
    /// room for the original bits, so the check has to happen on the raw
    /// field, which is what [`Message`]'s [`Decode`] does.
    #[must_use]
    pub const fn is_valid_raw_value(value: u16) -> bool {
        value & RESERVED_TYPE_BITS == 0
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.method, self.class)
    }
}

// Method field masks: A = M0-M3, B = M4-M6, D = M7-M11.
const METHOD_ABITS: u16 = 0xf; // 0b0000000000001111
const METHOD_BBITS: u16 = 0x70; // 0b0000000001110000
const METHOD_DBITS: u16 = 0xf80; // 0b0000111110000000

// Method field shifts, leaving room for the class bits.
const METHOD_BSHIFT: u16 = 1;
const METHOD_DSHIFT: u16 = 2;

// Class bits within the 2-bit class value.
const C0BIT: u16 = 0x1;
const C1BIT: u16 = 0x2;

// Class bit positions inside the 16-bit message type field.
const CLASS_C0SHIFT: u16 = 4;
const CLASS_C1SHIFT: u16 = 7;

/// The two most significant bits of the message type field.
///
/// [RFC 5389] §6 reserves them: `00` marks a STUN message, `01` a TURN
/// `ChannelData`. A type with either bit set is therefore not a STUN message
/// at all and must be rejected rather than silently normalised, otherwise
/// `encode(decode(bytes)) == bytes` would not hold and the type field could
/// be spoofed across the STUN/ChannelData demultiplex boundary.
const RESERVED_TYPE_BITS: u16 = 0xc000;

/// A decoded STUN message that borrows its attribute region from the input.
///
/// The region is re-encoded verbatim by [`Encode`], which keeps
/// `encode(decode(bytes)) == bytes` for the whole message. Use
/// [`Message::attributes`] to walk the attributes, [`Message::get`] to look
/// one up by type, or [`MessageWriter`] to build a message from scratch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    /// The message class and method.
    pub typ: MessageType,
    /// The attribute section's length in bytes, header excluded.
    ///
    /// Always equals `attribute_region.len()` for messages produced by
    /// [`Decode`].
    pub length: u16,
    /// The transaction id, echoed by the responder.
    pub transaction_id: TransactionId,
    /// The attribute section, borrowed from the decoded input.
    pub attribute_region: &'a [u8],
}

impl<'a> Message<'a> {
    /// Iterates over the attributes in declaration order.
    ///
    /// The legacy `0x8020` code is translated to `XOR-MAPPED-ADDRESS` on the
    /// way; see the module documentation of [`crate::attributes`]. Messages decoded
    /// through [`Decode`] are validated eagerly, so iteration never fails;
    /// for a hand-constructed message with a malformed region, iteration
    /// stops at the first bad attribute.
    #[must_use]
    pub fn attributes(&self) -> AttributeIter<'a> {
        AttributeIter {
            remaining: self.attribute_region,
        }
    }

    /// Returns the first attribute of type `typ`, or `None` when absent.
    #[must_use]
    pub fn get(&self, typ: AttrType) -> Option<RawAttribute<'a>> {
        self.attributes().find(|attr| attr.typ == typ)
    }

    /// Returns `true` if the message contains an attribute of type `typ`.
    #[must_use]
    pub fn contains(&self, typ: AttrType) -> bool {
        self.attributes().any(|attr| attr.typ == typ)
    }
}

impl<'a> Decode<'a> for Message<'a> {
    type Error = WireError;

    /// Decodes one message from the front of `input`, consuming exactly
    /// `MESSAGE_HEADER_SIZE + length` bytes.
    ///
    /// Every attribute in the region is validated eagerly, so the returned
    /// message is guaranteed well-formed; trailing bytes after the message
    /// are left to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::UnexpectedEnd`] when `input` cannot hold the
    /// header or the attribute section announced by the length field, or an
    /// attribute is truncated, and [`WireError::InvalidValue`] when the
    /// magic cookie is wrong or an attribute TLV is malformed.
    fn decode(input: &'a [u8]) -> Result<(Self, usize), Self::Error> {
        if input.len() < MESSAGE_HEADER_SIZE {
            return Err(WireError::UnexpectedEnd);
        }
        let typ_value = u16::from_be_bytes([input[0], input[1]]);
        // RFC 5389 section 6: the two most significant bits of the type
        // field are reserved and must be zero for STUN (`01` there means a
        // TURN ChannelData). Rejecting is mandatory rather than cosmetic:
        // `MessageType` cannot retain the discarded bits, so accepting the
        // packet would make re-encoding normalise the header and break the
        // byte-exact round trip that MESSAGE-INTEGRITY and FINGERPRINT
        // verification rely on.
        if !MessageType::is_valid_raw_value(typ_value) {
            return Err(WireError::InvalidValue);
        }
        let length = u16::from_be_bytes([input[2], input[3]]);
        let cookie = u32::from_be_bytes([input[4], input[5], input[6], input[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(WireError::InvalidValue);
        }
        let full_size = MESSAGE_HEADER_SIZE + usize::from(length);
        if input.len() < full_size {
            return Err(WireError::UnexpectedEnd);
        }

        let mut typ = MessageType::default();
        typ.read_value(typ_value);
        let mut transaction_id = TransactionId::default();
        transaction_id
            .0
            .copy_from_slice(&input[8..MESSAGE_HEADER_SIZE]);
        let region = &input[MESSAGE_HEADER_SIZE..full_size];

        // Eager validation: walk every TLV so a decoded message can never
        // yield a partially-parsed attribute region.
        let mut offset = 0;
        while offset < region.len() {
            let (_, consumed) = RawAttribute::decode(&region[offset..])?;
            offset += consumed;
        }

        Ok((
            Message {
                typ,
                length,
                transaction_id,
                attribute_region: region,
            },
            full_size,
        ))
    }
}

impl Encode for Message<'_> {
    type Error = WireError;

    fn encoded_len(&self) -> usize {
        MESSAGE_HEADER_SIZE + usize::from(self.length)
    }

    /// Re-encodes the message verbatim: the attribute region is copied as
    /// decoded, padding bytes included.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::OutputTooSmall`] when `output` cannot hold the
    /// message, and [`WireError::InvalidValue`] when the `length` field does
    /// not match `attribute_region.len()` (only possible for a
    /// hand-constructed message; [`Decode`] upholds the invariant).
    fn encode(&self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if self.attribute_region.len() != usize::from(self.length) {
            return Err(WireError::InvalidValue);
        }
        let size = self.encoded_len();
        if output.len() < size {
            return Err(WireError::OutputTooSmall);
        }
        output[0..2].copy_from_slice(&self.typ.value().to_be_bytes());
        output[2..4].copy_from_slice(&self.length.to_be_bytes());
        output[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        output[8..MESSAGE_HEADER_SIZE].copy_from_slice(&self.transaction_id.0);
        output[MESSAGE_HEADER_SIZE..size].copy_from_slice(self.attribute_region);
        Ok(size)
    }
}

/// Iterator over the attributes of a [`Message`], in declaration order.
#[derive(Debug, Clone)]
pub struct AttributeIter<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for AttributeIter<'a> {
    type Item = RawAttribute<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        // Validated eagerly at decode time; a hand-built malformed region
        // ends iteration instead of panicking.
        let (attr, consumed) = RawAttribute::decode(self.remaining).ok()?;
        self.remaining = &self.remaining[consumed..];
        Some(attr)
    }
}

/// Rebuilds the 20-byte header with the given attribute-section length.
///
/// The trailer attributes (`FINGERPRINT`, `MESSAGE-INTEGRITY`) verify
/// their value over a header whose length field differs from the decoded
/// one — the full length for `FINGERPRINT`, and the length up to and
/// including the `MESSAGE-INTEGRITY` TLV for that one (RFC 5389 §15.4/§15.5).
pub(crate) fn header_bytes(
    typ: MessageType,
    length: u16,
    transaction_id: TransactionId,
) -> [u8; MESSAGE_HEADER_SIZE] {
    let mut header = [0u8; MESSAGE_HEADER_SIZE];
    header[0..2].copy_from_slice(&typ.value().to_be_bytes());
    header[2..4].copy_from_slice(&length.to_be_bytes());
    header[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    header[8..MESSAGE_HEADER_SIZE].copy_from_slice(&transaction_id.0);
    header
}

/// Builds a STUN message into a caller-owned buffer.
///
/// The header is written on construction and each [`MessageWriter::push`]
/// appends one attribute TLV and patches the length field, so the buffer
/// always holds a complete message. Attributes whose value covers the
/// message itself — `MESSAGE-INTEGRITY` and `FINGERPRINT` — must be pushed
/// last, after every attribute they cover.
#[derive(Debug)]
pub struct MessageWriter<'a> {
    out: &'a mut [u8],
    typ: MessageType,
    length: u16,
    transaction_id: TransactionId,
}

impl<'a> MessageWriter<'a> {
    /// Starts a message in `out`, writing the header with a zero attribute
    /// length.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::OutputTooSmall`] when `out` cannot hold the
    /// 20-byte header; nothing is written in that case.
    pub fn new(
        out: &'a mut [u8],
        typ: MessageType,
        transaction_id: TransactionId,
    ) -> Result<Self, WireError> {
        if out.len() < MESSAGE_HEADER_SIZE {
            return Err(WireError::OutputTooSmall);
        }
        out[0..2].copy_from_slice(&typ.value().to_be_bytes());
        out[2..4].copy_from_slice(&0u16.to_be_bytes());
        out[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out[8..MESSAGE_HEADER_SIZE].copy_from_slice(&transaction_id.0);
        Ok(Self {
            out,
            typ,
            length: 0,
            transaction_id,
        })
    }

    /// Appends one attribute TLV and updates the length field.
    ///
    /// The value is padded to the next 32-bit boundary with zero bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Overflow`] when the value does not fit the
    /// 16-bit attribute length field or the message length would exceed
    /// `u16::MAX`, and [`WireError::OutputTooSmall`] when `out` lacks room.
    /// Nothing is written and the length field is left untouched on error.
    pub fn push(&mut self, typ: AttrType, value: &[u8]) -> Result<(), WireError> {
        self.push_with(typ, value.len(), |region| region.copy_from_slice(value))
    }

    /// Appends one attribute TLV whose value is produced by `fill`.
    ///
    /// `value_len` is the exact value length in bytes; `fill` receives a
    /// mutable slice of that length positioned where the value belongs, and
    /// the writer zeroes the padding after it. This streams values that do
    /// not fit a fixed scratch buffer — `UNKNOWN-ATTRIBUTES` with many
    /// types, for example — without allocating.
    ///
    /// # Errors
    ///
    /// Same contract as [`MessageWriter::push`]: on error nothing is
    /// written and the length field is left untouched.
    pub fn push_with(
        &mut self,
        typ: AttrType,
        value_len: usize,
        fill: impl FnOnce(&mut [u8]),
    ) -> Result<(), WireError> {
        let length_field = u16::try_from(value_len).map_err(|_| WireError::Overflow)?;
        let total = ATTRIBUTE_HEADER_SIZE + nearest_padded_value_length(value_len);
        let new_length = usize::from(self.length)
            .checked_add(total)
            .ok_or(WireError::Overflow)?;
        if new_length > usize::from(u16::MAX) {
            return Err(WireError::Overflow);
        }
        let first = MESSAGE_HEADER_SIZE + usize::from(self.length);
        let end = first + total;
        if end > self.out.len() {
            return Err(WireError::OutputTooSmall);
        }

        self.out[first..first + 2].copy_from_slice(&typ.value().to_be_bytes());
        self.out[first + 2..first + ATTRIBUTE_HEADER_SIZE]
            .copy_from_slice(&length_field.to_be_bytes());
        let value_start = first + ATTRIBUTE_HEADER_SIZE;
        let value_end = value_start + value_len;
        // Zero the padding first so no buffer content leaks into the message.
        for byte in &mut self.out[value_end..end] {
            *byte = 0;
        }
        fill(&mut self.out[value_start..value_end]);

        #[allow(clippy::cast_possible_truncation)]
        let length = new_length as u16; // checked against u16::MAX above
        self.length = length;
        self.out[2..4].copy_from_slice(&length.to_be_bytes());
        Ok(())
    }

    /// Returns the message type of the message being built.
    #[must_use]
    pub const fn typ(&self) -> MessageType {
        self.typ
    }

    /// Returns the transaction id of the message being built.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Returns the attribute section length accumulated so far.
    #[must_use]
    pub const fn length(&self) -> u16 {
        self.length
    }

    /// Returns the total number of message bytes written so far, header
    /// included.
    #[must_use]
    pub fn written(&self) -> usize {
        MESSAGE_HEADER_SIZE + usize::from(self.length)
    }

    /// The attribute section written so far, borrowed from the output
    /// buffer. Used by trailer attributes to inspect what precedes them.
    pub(crate) fn written_attributes(&self) -> &[u8] {
        &self.out[MESSAGE_HEADER_SIZE..self.written()]
    }

    /// Runs `f` over the bytes written so far with the header length field
    /// temporarily increased by `extra`, then restores the field.
    ///
    /// Trailer attributes — `FINGERPRINT` and `MESSAGE-INTEGRITY` — compute
    /// their value over the message including a header whose length field
    /// accounts for their own TLV (RFC 5389 §15.4 and §15.5).
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Overflow`] when `self.length + extra` does not
    /// fit `u16`.
    pub(crate) fn with_trailer_length<R>(
        &mut self,
        extra: usize,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, WireError> {
        let adjusted = usize::from(self.length)
            .checked_add(extra)
            .ok_or(WireError::Overflow)?;
        let adjusted = u16::try_from(adjusted).map_err(|_| WireError::Overflow)?;
        self.out[2..4].copy_from_slice(&adjusted.to_be_bytes());
        let result = f(&self.out[..self.written()]);
        self.out[2..4].copy_from_slice(&self.length.to_be_bytes());
        Ok(result)
    }

    /// Returns the message bytes written so far, header included.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.out[..self.written()]
    }
}

/// Returns `true` if `b` looks like a STUN message, i.e. it is at least a
/// header long and carries the magic cookie at the right offset.
///
/// Useful for multiplexing. This does not guarantee that decoding will
/// succeed.
#[must_use]
pub fn is_stun_message(b: &[u8]) -> bool {
    b.len() >= MESSAGE_HEADER_SIZE && u32::from_be_bytes([b[4], b[5], b[6], b[7]]) == MAGIC_COOKIE
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::attributes::{
        ATTR_DATA, ATTR_ERROR_CODE, ATTR_NONCE, ATTR_PRIORITY, ATTR_SOFTWARE, ATTR_USE_CANDIDATE,
        ATTR_USERNAME, ATTR_XORMAPPED_ADDRESS,
    };

    // 构造一个携带 ERROR-CODE 属性的 Binding request，返回编码后的字节数。
    // 属性值 [0xff, 0xfe, 0xfa] 取自上游 message_test.rs:17。
    // 需要至少 28 字节的输出空间（20 头部 + 8 TLV）。
    fn binding_request_with_error_code(buf: &mut [u8]) -> usize {
        let mut writer = MessageWriter::new(
            buf,
            BINDING_REQUEST,
            TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
        )
        .expect("writer over 28 bytes");
        writer
            .push(ATTR_ERROR_CODE, &[0xff, 0xfe, 0xfa])
            .expect("push 3-byte value");
        writer.written()
    }

    // 辅助：按消息长度字段算出 writer 已写字节数。
    fn writer_len(buf: &[u8; 64]) -> usize {
        usize::from(u16::from_be_bytes([buf[2], buf[3]])) + MESSAGE_HEADER_SIZE
    }

    // ---- MSG-TYPE ---------------------------------------------------------

    // MSG-TYPE-001 — MessageType::value 位打包向量。
    // 向量来源：上游 message_test.rs:31-68。
    #[test]
    fn stun_msg_001_message_type_value_vectors() {
        let vectors = [
            (BINDING_REQUEST, 0x0001),
            (BINDING_SUCCESS, 0x0101),
            (BINDING_ERROR, 0x0111),
            (MessageType::new(Method(0xb6d), MessageClass(0x3)), 0x2ddd),
        ];
        for (input, expected) in vectors {
            let got = input.value();
            assert_eq!(got, expected, "value({input}) -> {got:#06x}");
        }
    }

    // MSG-TYPE-002 — MessageType::read_value 解包向量。
    // 向量来源：上游 message_test.rs:71-103。
    #[test]
    fn stun_msg_002_message_type_read_value_vectors() {
        let vectors = [
            (0x0001, BINDING_REQUEST),
            (0x0101, BINDING_SUCCESS),
            (0x0111, BINDING_ERROR),
        ];
        for (input, expected) in vectors {
            let mut got = MessageType::default();
            got.read_value(input);
            assert_eq!(got, expected, "read_value({input:#06x}) -> {got}");
        }
    }

    // MSG-TYPE-003 — value/read_value 往返（含高位 method 向量）。
    // 向量来源：上游 message_test.rs:106-134。
    #[test]
    fn stun_msg_003_message_type_read_write_roundtrip() {
        for typ in [
            BINDING_REQUEST,
            BINDING_SUCCESS,
            BINDING_ERROR,
            MessageType::new(Method(0x12), CLASS_ERROR_RESPONSE),
        ] {
            let mut got = MessageType::default();
            got.read_value(typ.value());
            assert_eq!(got, typ, "roundtrip through {:#06x}", typ.value());
        }
    }

    // MSG-TYPE-004 — 回归：保留位（bits 14-15）非 0 的 type 必须被拒绝。
    // 这是 fuzz 发现的真实缺陷：`read_value` 会丢弃这两位，若 decode
    // 接受，re-encode 就会把首字节从 0x40 归一化成 0x00，破坏
    // `encode(decode(bytes)) == bytes`（fuzz 输入首字节 0x40 vs 0x00）。
    #[test]
    fn stun_msg_004_reserved_type_bits_rejected() {
        // 0x4000 = TURN ChannelData marker per RFC 5389 section 6; 0x8000
        // and 0xc000 are the other reserved combinations.
        for raw in [0x4000u16, 0x8000, 0xc000, 0xffff] {
            assert!(
                !MessageType::is_valid_raw_value(raw),
                "{raw:#06x} must be rejected"
            );

            // A full 20-byte header with the offending type field: the
            // cookie is valid and the length is 0, so only the reserved
            // bits can cause the rejection.
            let mut packet = [0u8; MESSAGE_HEADER_SIZE];
            packet[0..2].copy_from_slice(&raw.to_be_bytes());
            packet[2..4].copy_from_slice(&0u16.to_be_bytes());
            packet[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            assert_eq!(
                Message::decode(&packet),
                Err(WireError::InvalidValue),
                "{raw:#06x} must not decode"
            );
        }

        // The canonical Binding request type (0x0001) must still decode.
        assert!(MessageType::is_valid_raw_value(0x0001));
        let mut good = [0u8; MESSAGE_HEADER_SIZE];
        good[0..2].copy_from_slice(&BINDING_REQUEST.value().to_be_bytes());
        good[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        let Ok((msg, consumed)) = Message::decode(&good) else {
            panic!("Binding request header must decode");
        };
        assert_eq!(consumed, MESSAGE_HEADER_SIZE);
        assert_eq!(msg.typ, BINDING_REQUEST);
    }

    // ---- MSG-CODEC --------------------------------------------------------

    // MSG-CODEC-001 — 头部 + 单属性编解码往返，属性区零拷贝借用。
    // 向量来源：上游 message_test.rs:10-27（test_message_buffer）与 :707-727
    // （test_decode）。
    #[test]
    fn stun_msg_004_header_and_attribute_roundtrip() {
        let mut buf = [0u8; 32];
        let written = binding_request_with_error_code(&mut buf);
        assert_eq!(written, 28); // 20 头部 + 8 TLV（3 字节值补 1 字节 padding）
        assert_eq!(
            &buf[..written],
            &[
                0x00, 0x01, // type: Binding request
                0x00, 0x08, // length: 8
                0x21, 0x12, 0xA4, 0x42, // magic cookie
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, // transaction id
                0x00, 0x09, 0x00, 0x03, 0xFF, 0xFE, 0xFA, 0x00, // ERROR-CODE TLV
            ][..]
        );

        let (msg, consumed) = Message::decode(&buf[..written]).expect("decode roundtrip");
        assert_eq!(consumed, 28);
        assert_eq!(msg.typ, BINDING_REQUEST);
        assert_eq!(msg.length, 8);
        assert_eq!(
            msg.transaction_id,
            TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
        );
        let attr = msg.get(ATTR_ERROR_CODE).expect("error-code attribute");
        assert_eq!(attr.value, &[0xFF, 0xFE, 0xFA]);
        assert_eq!(attr.length, 3);

        // 零拷贝：属性值借用输入存储。
        assert_eq!(attr.value.as_ptr(), buf[24..].as_ptr());

        // 逐字重编码还原全部字节（含 padding）。
        let mut out = [0u8; 28];
        let encoded = msg.encode(&mut out).expect("re-encode message");
        assert_eq!(encoded, 28);
        assert_eq!(out, buf[..28]);
    }

    // MSG-CODEC-002 — 输入不足一个头部 → UnexpectedEnd。
    // 向量来源：上游 message_test.rs:172-180（8 字节缓冲）与 :266-274（空）。
    #[test]
    fn stun_msg_005_buffer_shorter_than_header() {
        assert_eq!(Message::decode(&[]), Err(WireError::UnexpectedEnd));
        assert_eq!(Message::decode(&[0u8; 8]), Err(WireError::UnexpectedEnd));
        assert_eq!(
            Message::decode(&[0u8; MESSAGE_HEADER_SIZE - 1]),
            Err(WireError::UnexpectedEnd)
        );
    }

    // MSG-CODEC-003 — 魔数 cookie 错误 → InvalidValue。
    // 向量来源：上游 message_test.rs:161-169（全零 20 字节）。
    #[test]
    fn stun_msg_006_bad_magic_cookie() {
        assert_eq!(
            Message::decode(&[0u8; MESSAGE_HEADER_SIZE]),
            Err(WireError::InvalidValue)
        );
    }

    // MSG-CODEC-004 — 属性 TLV 声称的长度超过消息长度 → UnexpectedEnd。
    // 向量来源：上游 message_test.rs:183-203（attr length 篡改为 10）。
    #[test]
    fn stun_msg_007_attribute_length_overruns_message() {
        let mut buf = [0u8; 28];
        let written = binding_request_with_error_code(&mut buf);
        // 属性长度字段 3 → 10，但属性区总共只有 8 字节。
        buf[22] = 10;
        assert_eq!(
            Message::decode(&buf[..written]),
            Err(WireError::UnexpectedEnd)
        );
    }

    // MSG-CODEC-005 — 消息长度大于实际缓冲 → UnexpectedEnd。
    // 向量来源：上游 message_test.rs:206-233（attr_length_less_than_header）。
    #[test]
    fn stun_msg_008_message_length_exceeds_buffer() {
        let mut buf = [0u8; 32];
        binding_request_with_error_code(&mut buf);
        // 消息长度 8 → 12，但只提供 20 + 4 字节。
        buf[3] = 12;
        assert_eq!(
            Message::decode(&buf[..MESSAGE_HEADER_SIZE + 4]),
            Err(WireError::UnexpectedEnd)
        );
        // 长度 8 但属性区只有 2 字节（TLV 头都放不下）→ InvalidValue。
        buf[3] = 2;
        assert_eq!(
            Message::decode(&buf[..MESSAGE_HEADER_SIZE + 2]),
            Err(WireError::InvalidValue)
        );
    }

    // MSG-CODEC-006 — 属性区长度对不上 TLV 声称长度 → UnexpectedEnd。
    // 向量来源：上游 message_test.rs:236-263（attr_size_less_than_length）。
    #[test]
    fn stun_msg_009_attribute_region_shorter_than_tlv() {
        let mut buf = [0u8; 32];
        binding_request_with_error_code(&mut buf);
        // 消息长度 8 → 5，属性区 5 字节放不下 L=4 的 TLV（需 4 + 4）。
        buf[3] = 5;
        assert_eq!(
            Message::decode(&buf[..MESSAGE_HEADER_SIZE + 5]),
            Err(WireError::UnexpectedEnd)
        );
    }

    // MSG-CODEC-007 — 属性区恰好耗尽且无残留：空属性区往返。
    // 边界补充：length = 0 时 decode 成功且 attributes() 为空。
    #[test]
    fn stun_msg_010_empty_attribute_region_roundtrip() {
        let tx = TransactionId([0xAB; TRANSACTION_ID_SIZE]);
        let mut buf = [0u8; MESSAGE_HEADER_SIZE];
        let writer =
            MessageWriter::new(&mut buf, BINDING_REQUEST, tx).expect("header-sized buffer");
        assert_eq!(writer.written(), MESSAGE_HEADER_SIZE);
        assert_eq!(writer.as_bytes().len(), MESSAGE_HEADER_SIZE);

        let (msg, consumed) = Message::decode(&buf).expect("decode header-only message");
        assert_eq!(consumed, MESSAGE_HEADER_SIZE);
        assert_eq!(msg.length, 0);
        assert_eq!(msg.attributes().count(), 0);
        assert!(msg.get(ATTR_ERROR_CODE).is_none());

        let mut out = [0u8; MESSAGE_HEADER_SIZE];
        assert_eq!(
            msg.encode(&mut out).expect("re-encode"),
            MESSAGE_HEADER_SIZE
        );
        assert_eq!(out, buf);
    }

    // ---- MSG-STR ----------------------------------------------------------

    // MSG-STR-001 — MessageClass stringer：已知类有名字，未知值回落。
    // 向量来源：上游 message_test.rs:277-296。
    #[test]
    fn stun_msg_011_message_class_stringer() {
        for class in [
            CLASS_REQUEST,
            CLASS_ERROR_RESPONSE,
            CLASS_SUCCESS_RESPONSE,
            CLASS_INDICATION,
        ] {
            assert_ne!(class.to_string(), "unknown message class", "{class}");
        }
        assert_eq!(MessageClass(0x05).to_string(), "unknown message class");
        assert_eq!(CLASS_REQUEST.to_string(), "request");
        assert_eq!(CLASS_SUCCESS_RESPONSE.to_string(), "success response");
        assert_eq!(CLASS_ERROR_RESPONSE.to_string(), "error response");
        assert_eq!(CLASS_INDICATION.to_string(), "indication");
    }

    // MSG-STR-002 — Method stringer：已知方法有名字，未知码带 0x 前缀。
    // 向量来源：上游 message_test.rs:327-341。
    #[test]
    fn stun_msg_012_method_stringer() {
        assert_eq!(METHOD_BINDING.to_string(), "Binding");
        assert_eq!(Method(0x616).to_string(), "0x616");
        for method in [
            METHOD_ALLOCATE,
            METHOD_REFRESH,
            METHOD_SEND,
            METHOD_DATA,
            METHOD_CREATE_PERMISSION,
            METHOD_CHANNEL_BIND,
            METHOD_CONNECT,
            METHOD_CONNECTION_BIND,
            METHOD_CONNECTION_ATTEMPT,
        ] {
            assert!(
                !method.to_string().starts_with("0x"),
                "bad stringer {method}"
            );
        }
        // MessageType stringer 组合 method 与 class。
        assert_eq!(BINDING_REQUEST.to_string(), "Binding request");
        assert_eq!(BINDING_ERROR.to_string(), "Binding error response");
    }

    // ---- MSG-MUX ----------------------------------------------------------

    // MSG-MUX-001 — is_stun_message 判别向量（复用多路复用场景）。
    // 向量来源：上游 message_test.rs:574-603。
    #[test]
    fn stun_msg_013_is_stun_message_vectors() {
        let mut buf = [0u8; 32];
        let written = binding_request_with_error_code(&mut buf);

        let vectors: [(&[u8], bool); 6] = [
            (&[], false),
            (&[1, 2, 3], false),
            (&[1, 2, 4], false),
            (&[1, 2, 4, 5, 6, 7, 8, 9, 20], false),
            (&buf[..written], true),
            (
                &[
                    0, 0, 0, 0, 33, 18, 164, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                true,
            ),
        ];
        for (input, expected) in vectors {
            let got = is_stun_message(input);
            assert_eq!(got, expected, "is_stun_message({input:?}) -> {got}");
        }
    }

    // ---- MSG-GET ----------------------------------------------------------

    // MSG-GET-001 — get/contains 语义与迭代时的 0x8020 兼容映射。
    // 向量来源：上游 message_test.rs:606-614（contains）+ attributes.rs
    // compat_attr_type（0x8020 在解码侧映射）。
    #[test]
    fn stun_msg_014_get_contains_and_legacy_code_mapping() {
        // SOFTWARE "value" + 一个 0x8020 旧码零长属性。
        let mut buf = [0u8; 64];
        {
            let mut writer = MessageWriter::new(
                &mut buf,
                BINDING_REQUEST,
                TransactionId([7; TRANSACTION_ID_SIZE]),
            )
            .expect("writer");
            writer.push(ATTR_SOFTWARE, b"value").expect("push software");
            writer
                .push(AttrType(0x8020), &[])
                .expect("push legacy xor-mapped");
        }

        let (msg, _) = Message::decode(&buf[..writer_len(&buf)]).expect("decode");
        assert!(msg.contains(ATTR_SOFTWARE));
        assert!(!msg.contains(ATTR_NONCE));
        assert_eq!(msg.get(ATTR_SOFTWARE).expect("software").value, b"value");

        // 迭代顺序即声明顺序，且 0x8020 呈现为 XOR-MAPPED-ADDRESS。
        let types: Vec<AttrType> = msg.attributes().map(|attr| attr.typ).collect();
        assert_eq!(types, [ATTR_SOFTWARE, ATTR_XORMAPPED_ADDRESS]);
        // get 命中兼容映射后的类型。
        assert!(msg.get(ATTR_XORMAPPED_ADDRESS).is_some());
    }

    // ---- MSG-VERBATIM -----------------------------------------------------

    // MSG-VERBATIM-001 — 逐字重编码保留原始 padding；trailing 字节不归属消息。
    // 设计差异 #8：Message 编解码为字节级往返（含非零 padding），与
    // RawAttribute::encode 的 padding 归一化形成对照。
    #[test]
    fn stun_msg_015_verbatim_reencode_and_trailing_bytes() {
        // 手工消息：length=8，一个 L=2 的 TLV，padding 为非零。
        let mut raw = [0u8; 28 + 5];
        raw[0] = 0x00;
        raw[1] = 0x01; // Binding request
        raw[2] = 0x00;
        raw[3] = 0x08; // length = 8
        raw[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        raw[8..20].copy_from_slice(&[0x5A; 12]);
        raw[20] = 0x00;
        raw[21] = 0x25; // USE-CANDIDATE
        raw[22] = 0x00;
        raw[23] = 0x02; // L=2
        raw[24] = 0xDE;
        raw[25] = 0xAD;
        raw[26] = 0x00; // padding：非零
        raw[27] = 0xFF;
        raw[28..].copy_from_slice(&[0x99; 5]); // trailing bytes

        let (msg, consumed) = Message::decode(&raw).expect("decode verbatim vector");
        assert_eq!(consumed, 28);
        assert_eq!(msg.length, 8);
        let attr = msg.get(ATTR_USE_CANDIDATE).expect("use-candidate");
        assert_eq!(attr.value, &[0xDE, 0xAD]);

        let mut out = [0u8; 28 + 5];
        let encoded = msg.encode(&mut out).expect("verbatim re-encode");
        assert_eq!(encoded, 28);
        // 原始 padding（0x00, 0xFF）被逐字保留。
        assert_eq!(out[..28], raw[..28]);
        assert_eq!(&out[26..28], &[0x00, 0xFF]);
    }

    // ---- MSG-WRITER -------------------------------------------------------

    // MSG-WRITER-001 — MessageWriter 错误路径：缓冲不足 / u16 溢出。
    // 输出过小沿用 stun_attr_006 先例；长度溢出为严于上游的新增拒绝
    // （上游 `as u16` 静默截断）。
    #[test]
    fn stun_msg_016_writer_error_paths() {
        // 值长超过 u16::MAX 的溢出向量。
        static HUGE: [u8; 65_536] = [0u8; 65_536];

        // 头部都放不下 → OutputTooSmall。
        let mut tiny = [0u8; MESSAGE_HEADER_SIZE - 1];
        assert_eq!(
            MessageWriter::new(&mut tiny, BINDING_REQUEST, TransactionId::default()).unwrap_err(),
            WireError::OutputTooSmall
        );

        // push 超出输出 → OutputTooSmall，已写内容与长度字段不变。
        let mut buf = [0u8; 24];
        let mut writer = MessageWriter::new(
            &mut buf,
            BINDING_REQUEST,
            TransactionId([3; TRANSACTION_ID_SIZE]),
        )
        .expect("24-byte buffer fits the header");
        assert_eq!(
            writer.push(ATTR_PRIORITY, &[1, 2, 3, 4, 5]),
            Err(WireError::OutputTooSmall)
        );
        assert_eq!(writer.length(), 0);
        assert_eq!(writer.written(), MESSAGE_HEADER_SIZE);
        assert_eq!(&writer.as_bytes()[2..4], &[0x00, 0x00]);

        // 值长超过 u16::MAX → Overflow。
        let mut buf = [0u8; MESSAGE_HEADER_SIZE];
        let mut writer = MessageWriter::new(&mut buf, BINDING_REQUEST, TransactionId::default())
            .expect("header");
        assert_eq!(writer.push(ATTR_DATA, &HUGE), Err(WireError::Overflow));

        // 累积属性区超过 u16::MAX → Overflow（而非截断）。
        // 65_528 字节值 → padded 65_528 + 4 = 65_532 ≤ u16::MAX；
        // 再叠加任意属性（≥4 字节）即越过 65_535。
        let mut big = vec![0u8; 65_552];
        let mut writer = MessageWriter::new(&mut big, BINDING_REQUEST, TransactionId::default())
            .expect("65_552-byte buffer");
        assert_eq!(writer.push(ATTR_DATA, &HUGE[..65_528]), Ok(()));
        assert_eq!(writer.length(), 65_532);
        // 零长属性也要 4 字节 TLV：65_532 + 4 = 65_536 > u16::MAX。
        assert_eq!(writer.push(ATTR_PRIORITY, &[]), Err(WireError::Overflow));
        assert_eq!(writer.length(), 65_532);

        // 编解码长度一致性：writer 产物可通过 Decode 读回。
        let mut buf = [0u8; 40];
        let written = {
            let mut writer = MessageWriter::new(
                &mut buf,
                BINDING_REQUEST,
                TransactionId([9; TRANSACTION_ID_SIZE]),
            )
            .expect("40-byte buffer");
            writer.push(ATTR_USERNAME, b"alice").expect("push username");
            writer.push(ATTR_USE_CANDIDATE, &[]).expect("push empty");
            writer.written()
        };
        assert_eq!(written, 20 + 12 + 4); // USERNAME "alice"(5B→8B) + 空 USE-CANDIDATE
        let (msg, consumed) = Message::decode(&buf[..written]).expect("decode writer output");
        assert_eq!(consumed, written);
        assert_eq!(msg.length as usize, written - MESSAGE_HEADER_SIZE);
        assert_eq!(msg.get(ATTR_USERNAME).expect("username").value, b"alice");
    }

    // MSG-INV-001 — length 字段与属性区不一致的手工消息 → InvalidValue。
    // （Decode 产物恒等；仅 pub 字段可破坏该不变式。）
    #[test]
    fn stun_msg_017_length_region_invariant_enforced_on_encode() {
        let msg = Message {
            typ: BINDING_REQUEST,
            length: 4,
            transaction_id: TransactionId::default(),
            attribute_region: &[0, 0, 0, 0, 0, 0, 0, 0], // 8 ≠ 4
        };
        let mut out = [0u8; 28];
        assert_eq!(msg.encode(&mut out), Err(WireError::InvalidValue));
        assert_eq!(msg.encoded_len(), 24); // 按 length 字段计算
        assert_eq!(msg.encode(&mut out[..24]), Err(WireError::InvalidValue));
    }
}

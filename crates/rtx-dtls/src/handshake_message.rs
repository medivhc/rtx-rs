//! DTLS 1.2 handshake message codec and the minimal-profile parsers.
//!
//! The 12-byte DTLS handshake header is
//!
//! ```text
//! type (1) || length (3) || message_seq (2) || fragment_offset (3) ||
//! fragment_length (3)
//! ```
//!
//! This crate keeps one complete handshake message per record and rejects
//! fragmentation. `decode_handshake_message` therefore requires the input to
//! contain exactly one unfragmented message, and every body parser validates
//! its length fields before indexing.
//!
//! Only the messages of the minimal profile are recognised: `ClientHello`,
//! `ServerHello`, `ServerKeyExchange`, `ServerHello`Done, `ClientKeyExchange` and
//! Finished. Anything else is [`HandshakeError::UnsupportedMessage`].

use rtx_wire::Cursor;

use crate::handshake_error::HandshakeError;

/// Largest handshake message (header plus body) this profile accepts.
pub const MAX_HANDSHAKE_MESSAGE_LEN: usize = 512;
/// Fixed DTLS handshake header length.
pub const HANDSHAKE_HEADER_LEN: usize = 12;

/// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (RFC 5289).
pub(crate) const CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256: u16 = 0xC02B;
/// X25519 named group (RFC 8422).
pub(crate) const GROUP_X25519: u16 = 0x001D;
/// Ed25519 signature algorithm (RFC 8422 / RFC 8446 registry).
pub(crate) const SIGNATURE_ED25519: u16 = 0x0807;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_USE_SRTP: u16 = 14;

/// Handshake message types in the minimal profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakeType {
    /// `client_hello` (1).
    ClientHello,
    /// `server_hello` (2).
    ServerHello,
    /// `server_key_exchange` (12).
    ServerKeyExchange,
    /// `server_hello_done` (14).
    ServerHelloDone,
    /// `client_key_exchange` (16).
    ClientKeyExchange,
    /// `finished` (20).
    Finished,
}

impl HandshakeType {
    /// Parses the one-byte handshake type.
    ///
    /// Returns `None` for every type outside the minimal profile.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ClientHello),
            2 => Some(Self::ServerHello),
            12 => Some(Self::ServerKeyExchange),
            14 => Some(Self::ServerHelloDone),
            16 => Some(Self::ClientKeyExchange),
            20 => Some(Self::Finished),
            _ => None,
        }
    }

    /// Returns the one-byte handshake type.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::ClientHello => 1,
            Self::ServerHello => 2,
            Self::ServerKeyExchange => 12,
            Self::ServerHelloDone => 14,
            Self::ClientKeyExchange => 16,
            Self::Finished => 20,
        }
    }
}

/// One decoded, unfragmented handshake message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeMessage<'a> {
    /// Decoded message type.
    pub message_type: HandshakeType,
    /// DTLS message sequence number.
    pub message_seq: u16,
    /// Message body without the 12-byte header.
    pub body: &'a [u8],
    /// Complete message bytes, header included.
    pub raw: &'a [u8],
}

/// Decodes exactly one complete, unfragmented DTLS handshake message.
///
/// # Errors
///
/// Returns [`HandshakeError::MalformedMessage`] for a truncated header/body or
/// trailing bytes, [`HandshakeError::UnsupportedMessage`] for an unknown type,
/// [`HandshakeError::MessageTooLong`] above
/// [`MAX_HANDSHAKE_MESSAGE_LEN`], and [`HandshakeError::FragmentedMessage`]
/// when the fragment fields disagree with the message length.
pub fn decode_handshake_message(input: &[u8]) -> Result<HandshakeMessage<'_>, HandshakeError> {
    if input.len() < HANDSHAKE_HEADER_LEN {
        return Err(HandshakeError::MalformedMessage);
    }
    let message_type =
        HandshakeType::from_u8(input[0]).ok_or(HandshakeError::UnsupportedMessage(input[0]))?;
    let length = read_u24(&input[1..4]);
    let message_seq = u16::from_be_bytes([input[4], input[5]]);
    let fragment_offset = read_u24(&input[6..9]);
    let fragment_length = read_u24(&input[9..12]);

    if length > MAX_HANDSHAKE_MESSAGE_LEN - HANDSHAKE_HEADER_LEN {
        return Err(HandshakeError::MessageTooLong);
    }
    if fragment_offset != 0 || fragment_length != length {
        return Err(HandshakeError::FragmentedMessage);
    }
    let total = HANDSHAKE_HEADER_LEN + length;
    if input.len() != total {
        return Err(HandshakeError::MalformedMessage);
    }
    Ok(HandshakeMessage {
        message_type,
        message_seq,
        body: &input[HANDSHAKE_HEADER_LEN..],
        raw: input,
    })
}

/// Offers observed in a `ClientHello`.
///
/// The minimal profile needs one cipher suite, X25519, Ed25519 and the
/// RFC 5764 SRTP profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OfferedAlgorithms(u8);

impl OfferedAlgorithms {
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
    pub const CIPHER_SUITE: Self = Self(0x01);
    /// X25519 key exchange.
    pub const X25519: Self = Self(0x02);
    /// Ed25519 signatures.
    pub const ED25519: Self = Self(0x04);
    /// `SRTP_AES128_CM_HMAC_SHA1_80`.
    pub const SRTP_AES128_CM_HMAC_SHA1_80: Self = Self(0x08);
    /// Every offer the minimal profile requires.
    pub const REQUIRED: Self = Self(0x0F);

    /// Returns `true` when every bit of `other` is present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn insert(&mut self, flag: Self) {
        self.0 |= flag.0;
    }
}

/// Parsed `ClientHello` fields needed by the minimal profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// 32-byte client random.
    pub random: [u8; 32],
    /// Session ID length; the value itself is ignored (resumption is out of
    /// scope) but its length is bounded to 32.
    pub session_id_len: u8,
    /// DTLS cookie length; the value itself is ignored (`HelloVerifyRequest` is
    /// out of scope).
    pub cookie_len: u8,
    /// Number of advertised cipher suites.
    pub cipher_suite_count: u16,
    /// Number of advertised extensions.
    pub extension_count: u16,
    /// Algorithms the client offered.
    pub offers: OfferedAlgorithms,
}

/// Parses the fields of a `ClientHello` message.
///
/// # Errors
///
/// Returns [`HandshakeError::UnexpectedMessage`] when `message` is another
/// type, [`HandshakeError::UnsupportedVersion`] for a non-DTLS-1.2 version,
/// and [`HandshakeError::MalformedMessage`] for any inconsistent length field
/// or truncated extension. Unknown extensions are skipped.
pub fn parse_client_hello(
    message: &HandshakeMessage<'_>,
) -> Result<ClientHelloInfo, HandshakeError> {
    if message.message_type != HandshakeType::ClientHello {
        return Err(HandshakeError::UnexpectedMessage);
    }
    let mut cursor = Cursor::new(message.body);
    let version = read_version(&mut cursor)?;
    if version != crate::record::DTLS12_VERSION {
        return Err(HandshakeError::UnsupportedVersion);
    }
    let random = read_array::<32>(&mut cursor)?;
    let session_id_len = cursor.u8().map_err(|_| HandshakeError::MalformedMessage)?;
    if session_id_len > 32 {
        return Err(HandshakeError::MalformedMessage);
    }
    cursor
        .take(usize::from(session_id_len))
        .map_err(|_| HandshakeError::MalformedMessage)?;
    let cookie_len = cursor.u8().map_err(|_| HandshakeError::MalformedMessage)?;
    cursor
        .take(usize::from(cookie_len))
        .map_err(|_| HandshakeError::MalformedMessage)?;

    let suites_len = usize::from(
        cursor
            .u16_be()
            .map_err(|_| HandshakeError::MalformedMessage)?,
    );
    if suites_len < 2 || suites_len % 2 != 0 {
        return Err(HandshakeError::MalformedMessage);
    }
    let suites = cursor
        .take(suites_len)
        .map_err(|_| HandshakeError::MalformedMessage)?;
    let mut offers = OfferedAlgorithms::default();
    let mut cipher_suite_count = 0u16;
    for chunk in suites.chunks_exact(2) {
        cipher_suite_count = cipher_suite_count.saturating_add(1);
        if u16::from_be_bytes([chunk[0], chunk[1]]) == CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256 {
            offers.insert(OfferedAlgorithms::CIPHER_SUITE);
        }
    }

    let compression_len = usize::from(cursor.u8().map_err(|_| HandshakeError::MalformedMessage)?);
    if compression_len == 0 {
        return Err(HandshakeError::MalformedMessage);
    }
    let compression = cursor
        .take(compression_len)
        .map_err(|_| HandshakeError::MalformedMessage)?;
    if !compression.contains(&0) {
        return Err(HandshakeError::NoCommonAlgorithm);
    }

    let extension_count = if cursor.remaining().is_empty() {
        0
    } else {
        let extensions_total = usize::from(
            cursor
                .u16_be()
                .map_err(|_| HandshakeError::MalformedMessage)?,
        );
        let extensions = cursor
            .take(extensions_total)
            .map_err(|_| HandshakeError::MalformedMessage)?;
        if !cursor.remaining().is_empty() {
            return Err(HandshakeError::MalformedMessage);
        }
        parse_client_hello_extensions(extensions, &mut offers)?
    };

    if !cursor.remaining().is_empty() {
        return Err(HandshakeError::MalformedMessage);
    }
    Ok(ClientHelloInfo {
        random,
        session_id_len,
        cookie_len,
        cipher_suite_count,
        extension_count,
        offers,
    })
}

fn parse_client_hello_extensions(
    extensions: &[u8],
    offers: &mut OfferedAlgorithms,
) -> Result<u16, HandshakeError> {
    let mut cursor = Cursor::new(extensions);
    let mut extension_count = 0u16;
    while !cursor.remaining().is_empty() {
        let extension_type = cursor
            .u16_be()
            .map_err(|_| HandshakeError::MalformedMessage)?;
        let ext_len = usize::from(
            cursor
                .u16_be()
                .map_err(|_| HandshakeError::MalformedMessage)?,
        );
        let data = cursor
            .take(ext_len)
            .map_err(|_| HandshakeError::MalformedMessage)?;
        extension_count = extension_count.saturating_add(1);
        match extension_type {
            EXT_SUPPORTED_GROUPS => {
                if u16_list_contains(data, GROUP_X25519)? {
                    offers.insert(OfferedAlgorithms::X25519);
                }
            }
            EXT_SIGNATURE_ALGORITHMS => {
                if u16_list_contains(data, SIGNATURE_ED25519)? {
                    offers.insert(OfferedAlgorithms::ED25519);
                }
            }
            EXT_USE_SRTP if use_srtp_contains_aes128_cm_sha1_80(data)? => {
                offers.insert(OfferedAlgorithms::SRTP_AES128_CM_HMAC_SHA1_80);
            }
            _ => {}
        }
    }
    Ok(extension_count)
}

/// Parses a `ServerHello` and returns its 32-byte server random.
///
/// # Errors
///
/// Returns [`HandshakeError::MalformedMessage`] for inconsistent lengths,
/// [`HandshakeError::UnsupportedVersion`] for a non-DTLS-1.2 version, and
/// [`HandshakeError::NoCommonAlgorithm`] unless the server selected the
/// profile's cipher suite, null compression and SRTP profile 0x0001 with an
/// empty MKI.
pub(crate) fn parse_server_hello(body: &[u8]) -> Result<[u8; 32], HandshakeError> {
    let mut cursor = Cursor::new(body);
    if read_version(&mut cursor)? != crate::record::DTLS12_VERSION {
        return Err(HandshakeError::UnsupportedVersion);
    }
    let random = read_array::<32>(&mut cursor)?;
    let session_id_len = cursor.u8().map_err(|_| HandshakeError::MalformedMessage)?;
    if session_id_len > 32 {
        return Err(HandshakeError::MalformedMessage);
    }
    cursor
        .take(usize::from(session_id_len))
        .map_err(|_| HandshakeError::MalformedMessage)?;
    if cursor
        .u16_be()
        .map_err(|_| HandshakeError::MalformedMessage)?
        != CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256
    {
        return Err(HandshakeError::NoCommonAlgorithm);
    }
    if cursor.u8().map_err(|_| HandshakeError::MalformedMessage)? != 0 {
        return Err(HandshakeError::NoCommonAlgorithm);
    }

    let mut selected_srtp = false;
    if !cursor.remaining().is_empty() {
        let extensions_total = usize::from(
            cursor
                .u16_be()
                .map_err(|_| HandshakeError::MalformedMessage)?,
        );
        let extensions = cursor
            .take(extensions_total)
            .map_err(|_| HandshakeError::MalformedMessage)?;
        if !cursor.remaining().is_empty() {
            return Err(HandshakeError::MalformedMessage);
        }
        let mut extensions_cursor = Cursor::new(extensions);
        while !extensions_cursor.remaining().is_empty() {
            let extension_type = extensions_cursor
                .u16_be()
                .map_err(|_| HandshakeError::MalformedMessage)?;
            let ext_len = usize::from(
                extensions_cursor
                    .u16_be()
                    .map_err(|_| HandshakeError::MalformedMessage)?,
            );
            let data = extensions_cursor
                .take(ext_len)
                .map_err(|_| HandshakeError::MalformedMessage)?;
            if extension_type == EXT_USE_SRTP {
                selected_srtp = selected_srtp || use_srtp_selected(data)?;
            }
        }
    }
    if !cursor.remaining().is_empty() {
        return Err(HandshakeError::MalformedMessage);
    }
    if !selected_srtp {
        return Err(HandshakeError::NoCommonAlgorithm);
    }
    Ok(random)
}

/// Parsed `ServerECDHParams` plus its signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServerKeyExchangeInfo {
    /// `curve_type || named_curve || point_len || point` bytes.
    pub(crate) params: [u8; 36],
    /// 64-byte Ed25519 signature.
    pub(crate) signature: [u8; 64],
}

/// Parses a `ServerKeyExchange` for X25519 and Ed25519.
///
/// # Errors
///
/// Returns [`HandshakeError::MalformedMessage`] for truncated or trailing
/// bytes, and [`HandshakeError::NoCommonAlgorithm`] for a curve or signature
/// algorithm outside the profile.
pub(crate) fn parse_server_key_exchange(
    body: &[u8],
) -> Result<ServerKeyExchangeInfo, HandshakeError> {
    if body.len() != 36 + 2 + 2 + 64 {
        return Err(HandshakeError::MalformedMessage);
    }
    let mut cursor = Cursor::new(body);
    if cursor.u8().map_err(|_| HandshakeError::MalformedMessage)? != 3 {
        return Err(HandshakeError::NoCommonAlgorithm);
    }
    if cursor
        .u16_be()
        .map_err(|_| HandshakeError::MalformedMessage)?
        != GROUP_X25519
    {
        return Err(HandshakeError::NoCommonAlgorithm);
    }
    if cursor.u8().map_err(|_| HandshakeError::MalformedMessage)? != 32 {
        return Err(HandshakeError::MalformedMessage);
    }
    let mut params = [0u8; 36];
    params[0] = 3;
    params[1..3].copy_from_slice(&GROUP_X25519.to_be_bytes());
    params[3] = 32;
    params[4..].copy_from_slice(
        cursor
            .take(32)
            .map_err(|_| HandshakeError::MalformedMessage)?,
    );
    if cursor
        .u16_be()
        .map_err(|_| HandshakeError::MalformedMessage)?
        != SIGNATURE_ED25519
    {
        return Err(HandshakeError::NoCommonAlgorithm);
    }
    let signature_len = usize::from(
        cursor
            .u16_be()
            .map_err(|_| HandshakeError::MalformedMessage)?,
    );
    if signature_len != 64 {
        return Err(HandshakeError::MalformedMessage);
    }
    let signature = read_array::<64>(&mut cursor)?;
    if !cursor.remaining().is_empty() {
        return Err(HandshakeError::MalformedMessage);
    }
    Ok(ServerKeyExchangeInfo { params, signature })
}

/// Parses a `ClientKeyExchange` and returns the 32-byte X25519 public key.
///
/// # Errors
///
/// Returns [`HandshakeError::MalformedMessage`] unless the body is exactly a
/// 32-byte `ECPoint`.
pub(crate) fn parse_client_key_exchange(body: &[u8]) -> Result<[u8; 32], HandshakeError> {
    if body.len() != 33 || body[0] != 32 {
        return Err(HandshakeError::MalformedMessage);
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&body[1..]);
    Ok(public_key)
}

/// Parses a Finished body and returns its 12-byte `verify_data`.
///
/// # Errors
///
/// Returns [`HandshakeError::MalformedMessage`] unless the body is exactly 12
/// bytes.
pub(crate) fn parse_finished(body: &[u8]) -> Result<[u8; 12], HandshakeError> {
    let verify_data: [u8; 12] = body
        .try_into()
        .map_err(|_| HandshakeError::MalformedMessage)?;
    Ok(verify_data)
}

/// Parses `ServerHello`Done, which has an empty body.
///
/// # Errors
///
/// Returns [`HandshakeError::MalformedMessage`] when the body is not empty.
pub(crate) fn parse_server_hello_done(body: &[u8]) -> Result<(), HandshakeError> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(HandshakeError::MalformedMessage)
    }
}

/// Builds a `ClientHello` body with the profile's single suite and extensions.
///
/// # Errors
///
/// Returns [`HandshakeError::MessageTooLong`] when `output` is too small.
pub(crate) fn build_client_hello_body(
    output: &mut [u8],
    random: &[u8; 32],
) -> Result<usize, HandshakeError> {
    // 2 version + 32 random + 1 sid + 1 cookie + 2 suites_len + 2 suite
    // + 1 compression_len + 1 compression + 2 extensions_len
    // + 8 supported_groups + 8 signature_algorithms + 9 use_srtp.
    const BODY_LEN: usize = 69;
    if output.len() < BODY_LEN {
        return Err(HandshakeError::MessageTooLong);
    }
    let mut writer = rtx_wire::Writer::new(output);
    put(&mut writer, &crate::record::DTLS12_VERSION)?;
    put(&mut writer, random)?;
    put(&mut writer, &[0])?; // empty session ID
    put(&mut writer, &[0])?; // empty cookie
    put(&mut writer, &2u16.to_be_bytes())?;
    put(
        &mut writer,
        &CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256.to_be_bytes(),
    )?;
    put(&mut writer, &[1, 0])?; // one compression method: null
    put(&mut writer, &25u16.to_be_bytes())?;
    // supported_groups: list length 2, x25519.
    put(&mut writer, &EXT_SUPPORTED_GROUPS.to_be_bytes())?;
    put(&mut writer, &4u16.to_be_bytes())?;
    put(&mut writer, &2u16.to_be_bytes())?;
    put(&mut writer, &GROUP_X25519.to_be_bytes())?;
    // signature_algorithms: list length 2, ed25519.
    put(&mut writer, &EXT_SIGNATURE_ALGORITHMS.to_be_bytes())?;
    put(&mut writer, &4u16.to_be_bytes())?;
    put(&mut writer, &2u16.to_be_bytes())?;
    put(&mut writer, &SIGNATURE_ED25519.to_be_bytes())?;
    // use_srtp: one profile, empty MKI.
    put(&mut writer, &EXT_USE_SRTP.to_be_bytes())?;
    put(&mut writer, &5u16.to_be_bytes())?;
    put(&mut writer, &2u16.to_be_bytes())?;
    put(
        &mut writer,
        &crate::srtp::SRTP_PROFILE_AES128_CM_HMAC_SHA1_80.to_be_bytes(),
    )?;
    put(&mut writer, &[0])?;
    Ok(writer.offset())
}

/// Builds a `ServerHello` body selecting the profile's parameters.
///
/// # Errors
///
/// Returns [`HandshakeError::MessageTooLong`] when `output` is too small.
pub(crate) fn build_server_hello_body(
    output: &mut [u8],
    random: &[u8; 32],
) -> Result<usize, HandshakeError> {
    // 2 version + 32 random + 1 sid + 2 suite + 1 compression
    // + 2 extensions_len + 9 use_srtp.
    const BODY_LEN: usize = 49;
    if output.len() < BODY_LEN {
        return Err(HandshakeError::MessageTooLong);
    }
    let mut writer = rtx_wire::Writer::new(output);
    put(&mut writer, &crate::record::DTLS12_VERSION)?;
    put(&mut writer, random)?;
    put(&mut writer, &[0])?;
    put(
        &mut writer,
        &CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256.to_be_bytes(),
    )?;
    put(&mut writer, &[0])?;
    put(&mut writer, &9u16.to_be_bytes())?;
    put(&mut writer, &EXT_USE_SRTP.to_be_bytes())?;
    put(&mut writer, &5u16.to_be_bytes())?;
    put(&mut writer, &2u16.to_be_bytes())?;
    put(
        &mut writer,
        &crate::srtp::SRTP_PROFILE_AES128_CM_HMAC_SHA1_80.to_be_bytes(),
    )?;
    put(&mut writer, &[0])?;
    Ok(writer.offset())
}

/// Builds a `ServerKeyExchange` body from the encoded params and signature.
///
/// # Errors
///
/// Returns [`HandshakeError::MessageTooLong`] when `output` is too small.
pub(crate) fn build_server_key_exchange_body(
    output: &mut [u8],
    params: &[u8; 36],
    signature: &[u8; 64],
) -> Result<usize, HandshakeError> {
    const BODY_LEN: usize = 104;
    if output.len() < BODY_LEN {
        return Err(HandshakeError::MessageTooLong);
    }
    let mut writer = rtx_wire::Writer::new(output);
    put(&mut writer, params)?;
    put(&mut writer, &SIGNATURE_ED25519.to_be_bytes())?;
    put(&mut writer, &64u16.to_be_bytes())?;
    put(&mut writer, signature)?;
    Ok(writer.offset())
}

/// Builds a `ClientKeyExchange` body carrying an X25519 public key.
///
/// # Errors
///
/// Returns [`HandshakeError::MessageTooLong`] when `output` is too small.
pub(crate) fn build_client_key_exchange_body(
    output: &mut [u8],
    public_key: &[u8; 32],
) -> Result<usize, HandshakeError> {
    if output.len() < 33 {
        return Err(HandshakeError::MessageTooLong);
    }
    output[0] = 32;
    output[1..33].copy_from_slice(public_key);
    Ok(33)
}

/// Encodes one handshake message into `output`, header included.
///
/// # Errors
///
/// Returns [`HandshakeError::MessageTooLong`] when the body plus header
/// exceeds [`MAX_HANDSHAKE_MESSAGE_LEN`] or `output` cannot hold it.
pub(crate) fn encode_handshake_message(
    output: &mut [u8],
    message_type: HandshakeType,
    message_seq: u16,
    body: &[u8],
) -> Result<usize, HandshakeError> {
    if body.len() > MAX_HANDSHAKE_MESSAGE_LEN - HANDSHAKE_HEADER_LEN {
        return Err(HandshakeError::MessageTooLong);
    }
    let body_len = u32::try_from(body.len()).map_err(|_| HandshakeError::MessageTooLong)?;
    let total = HANDSHAKE_HEADER_LEN + body.len();
    if output.len() < total {
        return Err(HandshakeError::MessageTooLong);
    }
    output[0] = message_type.to_u8();
    output[1..4].copy_from_slice(&body_len.to_be_bytes()[1..]);
    output[4..6].copy_from_slice(&message_seq.to_be_bytes());
    output[6..9].copy_from_slice(&[0, 0, 0]);
    output[9..12].copy_from_slice(&body_len.to_be_bytes()[1..]);
    output[HANDSHAKE_HEADER_LEN..total].copy_from_slice(body);
    Ok(total)
}

fn read_u24(input: &[u8]) -> usize {
    usize::from(input[0]) << 16 | usize::from(input[1]) << 8 | usize::from(input[2])
}

fn read_version(cursor: &mut Cursor<'_>) -> Result<[u8; 2], HandshakeError> {
    let bytes = cursor
        .take(2)
        .map_err(|_| HandshakeError::MalformedMessage)?;
    Ok([bytes[0], bytes[1]])
}

fn read_array<const N: usize>(cursor: &mut Cursor<'_>) -> Result<[u8; N], HandshakeError> {
    cursor
        .take(N)
        .map_err(|_| HandshakeError::MalformedMessage)?
        .try_into()
        .map_err(|_| HandshakeError::MalformedMessage)
}

fn put(writer: &mut rtx_wire::Writer<'_>, bytes: &[u8]) -> Result<(), HandshakeError> {
    writer
        .put(bytes)
        .map_err(|_| HandshakeError::MessageTooLong)
}

/// Parses a `u16` vector with a leading 2-byte length (`supported_groups` and
/// `signature_algorithms`).
fn u16_list_contains(data: &[u8], wanted: u16) -> Result<bool, HandshakeError> {
    if data.len() < 2 {
        return Err(HandshakeError::MalformedMessage);
    }
    let list_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    if list_len % 2 != 0 || list_len != data.len() - 2 {
        return Err(HandshakeError::MalformedMessage);
    }
    for chunk in data[2..].chunks_exact(2) {
        if u16::from_be_bytes([chunk[0], chunk[1]]) == wanted {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Parses a `use_srtp` extension offer and reports profile 0x0001 with any MKI
/// length. A client may offer an MKI; the server selects an empty MKI.
fn use_srtp_contains_aes128_cm_sha1_80(data: &[u8]) -> Result<bool, HandshakeError> {
    if data.len() < 3 {
        return Err(HandshakeError::MalformedMessage);
    }
    let profiles_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    if profiles_len % 2 != 0 || profiles_len + 2 >= data.len() {
        return Err(HandshakeError::MalformedMessage);
    }
    let mki_len = usize::from(data[2 + profiles_len]);
    if 2 + profiles_len + 1 + mki_len != data.len() {
        return Err(HandshakeError::MalformedMessage);
    }
    for chunk in data[2..2 + profiles_len].chunks_exact(2) {
        if u16::from_be_bytes([chunk[0], chunk[1]])
            == crate::srtp::SRTP_PROFILE_AES128_CM_HMAC_SHA1_80
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Parses a server's `use_srtp` selection: exactly one profile, empty MKI.
fn use_srtp_selected(data: &[u8]) -> Result<bool, HandshakeError> {
    if data.len() != 5 {
        return Err(HandshakeError::MalformedMessage);
    }
    let profiles_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    if profiles_len != 2 || data[4] != 0 {
        return Err(HandshakeError::MalformedMessage);
    }
    Ok(u16::from_be_bytes([data[2], data[3]]) == crate::srtp::SRTP_PROFILE_AES128_CM_HMAC_SHA1_80)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    const SEQ: u16 = 7;

    fn message(body: &[u8], message_type: HandshakeType, seq: u16) -> Vec<u8> {
        let mut output = vec![0u8; HANDSHAKE_HEADER_LEN + body.len()];
        let written =
            encode_handshake_message(&mut output, message_type, seq, body).expect("encode message");
        assert_eq!(written, output.len());
        output
    }

    fn client_hello(random: &[u8; 32]) -> Vec<u8> {
        let mut body = [0u8; 128];
        let written = build_client_hello_body(&mut body, random).expect("build client hello");
        message(&body[..written], HandshakeType::ClientHello, 0)
    }

    fn server_hello(random: &[u8; 32]) -> Vec<u8> {
        let mut body = [0u8; 128];
        let written = build_server_hello_body(&mut body, random).expect("build server hello");
        message(&body[..written], HandshakeType::ServerHello, 1)
    }

    fn server_key_exchange() -> Vec<u8> {
        let mut params = [0u8; 36];
        params[0] = 3;
        params[1..3].copy_from_slice(&GROUP_X25519.to_be_bytes());
        params[3] = 32;
        params[4..].copy_from_slice(&[3u8; 32]);
        let signature = [0x5Au8; 64];
        let mut body = [0u8; 128];
        let written =
            build_server_key_exchange_body(&mut body, &params, &signature).expect("build ske");
        message(&body[..written], HandshakeType::ServerKeyExchange, 2)
    }

    // DTLS-HSMSG-001 — handshake type mapping covers the profile exactly.
    #[test]
    fn handshake_type_roundtrips_and_rejects_unknown_values() {
        for (value, message_type) in [
            (1, HandshakeType::ClientHello),
            (2, HandshakeType::ServerHello),
            (12, HandshakeType::ServerKeyExchange),
            (14, HandshakeType::ServerHelloDone),
            (16, HandshakeType::ClientKeyExchange),
            (20, HandshakeType::Finished),
        ] {
            assert_eq!(HandshakeType::from_u8(value), Some(message_type));
            assert_eq!(message_type.to_u8(), value);
        }
        for value in [0u8, 3, 11, 13, 15, 17, 21, 255] {
            assert_eq!(HandshakeType::from_u8(value), None);
        }
    }

    // DTLS-HSMSG-002 — header encode/decode roundtrip and body slicing.
    #[test]
    fn handshake_header_roundtrip() {
        let body = b"body";
        let bytes = message(body, HandshakeType::Finished, SEQ);
        let decoded = decode_handshake_message(&bytes).expect("decode");
        assert_eq!(decoded.message_type, HandshakeType::Finished);
        assert_eq!(decoded.message_seq, SEQ);
        assert_eq!(decoded.body, body);
        assert_eq!(decoded.raw, bytes);
        assert_eq!(bytes[6..9], [0, 0, 0]);
        assert_eq!(bytes[9..12], [0, 0, 4]);
    }

    // DTLS-HSMSG-003 — every truncation and trailing bytes are rejected.
    #[test]
    fn handshake_decoder_length_checks() {
        let bytes = client_hello(&[0x11; 32]);
        for len in 0..bytes.len() {
            assert_eq!(
                decode_handshake_message(&bytes[..len]),
                Err(HandshakeError::MalformedMessage),
                "truncated to {len}"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            decode_handshake_message(&longer),
            Err(HandshakeError::MalformedMessage)
        );
        assert!(decode_handshake_message(&bytes).is_ok());
    }

    // DTLS-HSMSG-004 — unknown type, fragment fields and oversize lengths.
    #[test]
    fn handshake_decoder_rejects_unsupported_and_fragmented_messages() {
        let mut bytes = client_hello(&[0x22; 32]);
        bytes[0] = 99;
        assert_eq!(
            decode_handshake_message(&bytes),
            Err(HandshakeError::UnsupportedMessage(99))
        );

        let mut fragmented = client_hello(&[0x22; 32]);
        fragmented[6..9].copy_from_slice(&[0, 0, 1]);
        assert_eq!(
            decode_handshake_message(&fragmented),
            Err(HandshakeError::FragmentedMessage)
        );
        let mut short_fragment = client_hello(&[0x22; 32]);
        short_fragment[9..12].copy_from_slice(&[0, 0, 1]);
        assert_eq!(
            decode_handshake_message(&short_fragment),
            Err(HandshakeError::FragmentedMessage)
        );

        let mut oversized = vec![0u8; HANDSHAKE_HEADER_LEN + MAX_HANDSHAKE_MESSAGE_LEN];
        oversized[0] = HandshakeType::ClientHello.to_u8();
        let length =
            u32::try_from(MAX_HANDSHAKE_MESSAGE_LEN - HANDSHAKE_HEADER_LEN + 1).expect("fits");
        oversized[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
        assert_eq!(
            decode_handshake_message(&oversized),
            Err(HandshakeError::MessageTooLong)
        );
    }

    // DTLS-HSMSG-005 — ClientHello builder parses back and offers every bit.
    #[test]
    fn client_hello_roundtrip_and_offers() {
        let random = [0x33u8; 32];
        let bytes = client_hello(&random);
        let decoded = decode_handshake_message(&bytes).expect("decode");
        let info = parse_client_hello(&decoded).expect("parse");
        assert_eq!(info.random, random);
        assert_eq!(info.session_id_len, 0);
        assert_eq!(info.cookie_len, 0);
        assert_eq!(info.cipher_suite_count, 1);
        assert_eq!(info.extension_count, 3);
        assert_eq!(info.offers, OfferedAlgorithms::REQUIRED);
        assert!(
            info.offers
                .contains(OfferedAlgorithms::SRTP_AES128_CM_HMAC_SHA1_80)
        );
        assert!(!OfferedAlgorithms::default().contains(OfferedAlgorithms::X25519));
        assert!(format!("{info:?}").contains("ClientHelloInfo"));
    }

    // DTLS-HSMSG-006 — ServerHello builder parses back with use_srtp.
    #[test]
    fn server_hello_roundtrip() {
        let random = [0x44u8; 32];
        let bytes = server_hello(&random);
        let decoded = decode_handshake_message(&bytes).expect("decode");
        assert_eq!(parse_server_hello(decoded.body).expect("parse"), random);
    }

    // DTLS-HSMSG-007 — ServerKeyExchange, ClientKeyExchange, ServerHelloDone
    // and Finished builders parse back.
    #[test]
    fn remaining_message_roundtrips() {
        let ske = server_key_exchange();
        let decoded = decode_handshake_message(&ske).expect("ske");
        let info = parse_server_key_exchange(decoded.body).expect("parse ske");
        assert_eq!(info.params[..4], [3, 0, 0x1D, 32]);
        assert_eq!(info.params[4..], [3u8; 32]);
        assert_eq!(info.signature, [0x5Au8; 64]);

        let public_key = [0x77u8; 32];
        let mut body = [0u8; 64];
        let written = build_client_key_exchange_body(&mut body, &public_key).expect("build cke");
        let cke = message(&body[..written], HandshakeType::ClientKeyExchange, 4);
        let decoded = decode_handshake_message(&cke).expect("cke");
        assert_eq!(
            parse_client_key_exchange(decoded.body).expect("parse cke"),
            public_key
        );

        let done = message(&[], HandshakeType::ServerHelloDone, 3);
        let decoded = decode_handshake_message(&done).expect("done");
        assert_eq!(parse_server_hello_done(decoded.body), Ok(()));

        let finished = message(&[0xAA; 12], HandshakeType::Finished, 5);
        let decoded = decode_handshake_message(&finished).expect("finished");
        assert_eq!(
            parse_finished(decoded.body).expect("parse finished"),
            [0xAA; 12]
        );
    }

    // DTLS-HSMSG-008 — wrong message types and malformed bodies.
    #[test]
    fn parsers_reject_wrong_types_and_malformed_bodies() {
        let hello = client_hello(&[0; 32]);
        let decoded = decode_handshake_message(&hello).expect("decode");
        let mut wrong_type = decoded;
        wrong_type.message_type = HandshakeType::ServerHello;
        assert_eq!(
            parse_client_hello(&wrong_type),
            Err(HandshakeError::UnexpectedMessage)
        );

        assert_eq!(
            parse_client_key_exchange(&[0u8; 32]),
            Err(HandshakeError::MalformedMessage)
        );
        assert_eq!(
            parse_client_key_exchange(&[33u8; 33]),
            Err(HandshakeError::MalformedMessage)
        );
        assert_eq!(
            parse_finished(&[0u8; 11]),
            Err(HandshakeError::MalformedMessage)
        );
        assert_eq!(
            parse_finished(&[0u8; 13]),
            Err(HandshakeError::MalformedMessage)
        );
        assert_eq!(
            parse_server_hello_done(&[0u8]),
            Err(HandshakeError::MalformedMessage)
        );
        assert_eq!(
            parse_server_key_exchange(&[0u8; 10]),
            Err(HandshakeError::MalformedMessage)
        );
    }

    // DTLS-HSMSG-009 — ClientHello version and section errors.
    #[test]
    fn client_hello_parser_rejects_version_and_section_errors() {
        let random = [0u8; 32];
        let valid = client_hello(&random);
        let decoded = decode_handshake_message(&valid).expect("decode");
        let body = decoded.body;

        let mut wrong_version = body.to_vec();
        wrong_version[..2].copy_from_slice(&[254, 255]);
        assert_eq!(
            parse_client_hello(
                &decode_handshake_message(&message(&wrong_version, HandshakeType::ClientHello, 0,))
                    .expect("decode wrong version")
            ),
            Err(HandshakeError::UnsupportedVersion)
        );

        // Session ID longer than 32.
        let mut long_session = body.to_vec();
        long_session[34] = 33;
        assert_eq!(
            parse_client_hello(
                &decode_handshake_message(&message(&long_session, HandshakeType::ClientHello, 0))
                    .expect("decode session")
            ),
            Err(HandshakeError::MalformedMessage)
        );

        // Odd cipher-suite length.
        let mut odd_suites = body.to_vec();
        odd_suites[36..38].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(
            parse_client_hello(
                &decode_handshake_message(&message(&odd_suites, HandshakeType::ClientHello, 0))
                    .expect("decode suites")
            ),
            Err(HandshakeError::MalformedMessage)
        );

        // No null compression method.
        let mut no_null = body.to_vec();
        no_null[40] = 1;
        no_null[41] = 1;
        assert_eq!(
            parse_client_hello(
                &decode_handshake_message(&message(&no_null, HandshakeType::ClientHello, 0))
                    .expect("decode compression")
            ),
            Err(HandshakeError::NoCommonAlgorithm)
        );

        // Extension length shorter than the bytes that follow.
        let mut bad_extensions = body.to_vec();
        bad_extensions[42..44].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_client_hello(
                &decode_handshake_message(&message(&bad_extensions, HandshakeType::ClientHello, 0))
                    .expect("decode extensions")
            ),
            Err(HandshakeError::MalformedMessage)
        );
    }

    // DTLS-HSMSG-010 — ServerHello selects only the profile parameters.
    #[test]
    fn server_hello_parser_rejects_other_selections() {
        let mut body = [0u8; 128];
        let written = build_server_hello_body(&mut body, &[0; 32]).expect("build");
        let mut wrong_suite = body[..written].to_vec();
        wrong_suite[35..37].copy_from_slice(&0xC02Cu16.to_be_bytes());
        assert_eq!(
            parse_server_hello(&wrong_suite),
            Err(HandshakeError::NoCommonAlgorithm)
        );

        let mut wrong_compression = body[..written].to_vec();
        wrong_compression[37] = 1;
        assert_eq!(
            parse_server_hello(&wrong_compression),
            Err(HandshakeError::NoCommonAlgorithm)
        );

        let mut no_srtp = body[..written].to_vec();
        no_srtp[40..42].copy_from_slice(&0x000Bu16.to_be_bytes());
        assert_eq!(
            parse_server_hello(&no_srtp),
            Err(HandshakeError::NoCommonAlgorithm)
        );

        let mut bad_mki = body[..written].to_vec();
        let last = bad_mki.len() - 1;
        bad_mki[last] = 1;
        assert_eq!(
            parse_server_hello(&bad_mki),
            Err(HandshakeError::MalformedMessage)
        );
    }

    // DTLS-HSMSG-011 — ServerKeyExchange curve, point and signature checks.
    #[test]
    fn server_key_exchange_parser_rejects_other_profiles() {
        let mut params = [0u8; 36];
        params[0] = 3;
        params[1..3].copy_from_slice(&GROUP_X25519.to_be_bytes());
        params[3] = 32;
        params[4..].copy_from_slice(&[0x33u8; 32]);
        let mut body = [0u8; 128];
        let written =
            build_server_key_exchange_body(&mut body, &params, &[0u8; 64]).expect("build");
        let base = body[..written].to_vec();

        let mut wrong_curve_type = base.clone();
        wrong_curve_type[0] = 2;
        assert_eq!(
            parse_server_key_exchange(&wrong_curve_type),
            Err(HandshakeError::NoCommonAlgorithm)
        );

        let mut wrong_group = base.clone();
        wrong_group[1..3].copy_from_slice(&0x0017u16.to_be_bytes());
        assert_eq!(
            parse_server_key_exchange(&wrong_group),
            Err(HandshakeError::NoCommonAlgorithm)
        );

        let mut wrong_point_len = base.clone();
        wrong_point_len[3] = 31;
        assert_eq!(
            parse_server_key_exchange(&wrong_point_len),
            Err(HandshakeError::MalformedMessage)
        );

        let mut wrong_sig_algorithm = base.clone();
        wrong_sig_algorithm[36..38].copy_from_slice(&0x0403u16.to_be_bytes());
        assert_eq!(
            parse_server_key_exchange(&wrong_sig_algorithm),
            Err(HandshakeError::NoCommonAlgorithm)
        );

        let mut wrong_sig_len = base;
        wrong_sig_len[38..40].copy_from_slice(&63u16.to_be_bytes());
        assert_eq!(
            parse_server_key_exchange(&wrong_sig_len),
            Err(HandshakeError::MalformedMessage)
        );
    }

    // DTLS-HSMSG-012 — extension helpers reject malformed lists.
    #[test]
    fn extension_list_helpers_reject_malformed_input() {
        assert_eq!(
            u16_list_contains(&[0], 1),
            Err(HandshakeError::MalformedMessage)
        );
        assert_eq!(
            u16_list_contains(&[0, 3, 0, 1, 0], 1),
            Err(HandshakeError::MalformedMessage)
        );
        assert_eq!(
            u16_list_contains(&[0, 4, 0, 1], 1),
            Err(HandshakeError::MalformedMessage)
        );
        assert_eq!(u16_list_contains(&[0, 2, 0, 1], 1), Ok(true));
        assert_eq!(u16_list_contains(&[0, 2, 0, 2], 1), Ok(false));

        assert_eq!(
            use_srtp_contains_aes128_cm_sha1_80(&[0, 1]),
            Err(HandshakeError::MalformedMessage)
        );
        assert_eq!(
            use_srtp_contains_aes128_cm_sha1_80(&[0, 3, 0, 1, 0]),
            Err(HandshakeError::MalformedMessage)
        );
        assert_eq!(
            use_srtp_contains_aes128_cm_sha1_80(&[0, 2, 0, 1, 0]),
            Ok(true)
        );
        assert_eq!(
            use_srtp_contains_aes128_cm_sha1_80(&[0, 2, 0, 2, 0]),
            Ok(false)
        );

        assert_eq!(
            use_srtp_selected(&[0, 2, 0, 1]),
            Err(HandshakeError::MalformedMessage)
        );
        assert_eq!(use_srtp_selected(&[0, 2, 0, 1, 0]), Ok(true));
        assert_eq!(use_srtp_selected(&[0, 2, 0, 2, 0]), Ok(false));
    }

    // DTLS-HSMSG-013 — encoders reject short output and oversize bodies.
    #[test]
    fn encoders_reject_short_buffers() {
        assert_eq!(
            build_client_hello_body(&mut [0u8; 68], &[0; 32]),
            Err(HandshakeError::MessageTooLong)
        );
        assert_eq!(
            build_server_hello_body(&mut [0u8; 48], &[0; 32]),
            Err(HandshakeError::MessageTooLong)
        );
        assert_eq!(
            build_server_key_exchange_body(&mut [0u8; 103], &[0; 36], &[0; 64]),
            Err(HandshakeError::MessageTooLong)
        );
        assert_eq!(
            build_client_key_exchange_body(&mut [0u8; 32], &[0; 32]),
            Err(HandshakeError::MessageTooLong)
        );
        assert_eq!(
            encode_handshake_message(&mut [0u8; 20], HandshakeType::Finished, 0, &[0; 12]),
            Err(HandshakeError::MessageTooLong)
        );
        assert_eq!(
            encode_handshake_message(
                &mut [0u8; MAX_HANDSHAKE_MESSAGE_LEN],
                HandshakeType::Finished,
                0,
                &[0; MAX_HANDSHAKE_MESSAGE_LEN]
            ),
            Err(HandshakeError::MessageTooLong)
        );
    }

    // DTLS-HSMSG-014 — deterministic random bytes never panic the decoder.
    #[test]
    fn random_bytes_never_panic_in_handshake_decoders() {
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            state
        };
        for _ in 0..4096 {
            let len = usize::try_from(next() % 300).expect("small");
            let mut bytes = vec![0u8; len];
            for byte in &mut bytes {
                *byte = u8::try_from(next() & 0xFF).expect("byte");
            }
            let _ = decode_handshake_message(&bytes);
            if let Ok(message) = decode_handshake_message(&bytes) {
                let _ = parse_client_hello(&message);
                let _ = parse_server_hello(message.body);
                let _ = parse_server_key_exchange(message.body);
                let _ = parse_client_key_exchange(message.body);
                let _ = parse_finished(message.body);
                let _ = parse_server_hello_done(message.body);
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod extra_tests {
    use super::*;

    fn own_message(body: &[u8], message_type: HandshakeType, seq: u16) -> Vec<u8> {
        let mut output = vec![0u8; HANDSHAKE_HEADER_LEN + body.len()];
        let written =
            encode_handshake_message(&mut output, message_type, seq, body).expect("encode");
        assert_eq!(written, output.len());
        output
    }

    // DTLS-HSMSG-015 — a ClientHello without extensions parses with no offers,
    // and zero compression length / trailing bytes are rejected.
    #[test]
    fn client_hello_extension_edges() {
        let mut body = Vec::new();
        body.extend_from_slice(&crate::record::DTLS12_VERSION);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0); // session ID
        body.push(0); // cookie
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256.to_be_bytes());
        body.extend_from_slice(&[1, 0]);
        let message = own_message(&body, HandshakeType::ClientHello, 0);
        let decoded = decode_handshake_message(&message).expect("decode");
        let info = parse_client_hello(&decoded).expect("parse without extensions");
        assert_eq!(info.extension_count, 0);
        assert_eq!(info.offers, OfferedAlgorithms::CIPHER_SUITE);

        let mut no_compression = body.clone();
        no_compression[40] = 0;
        let raw = own_message(&no_compression, HandshakeType::ClientHello, 0);
        let decoded = decode_handshake_message(&raw).expect("decode");
        assert_eq!(
            parse_client_hello(&decoded),
            Err(HandshakeError::MalformedMessage)
        );

        let mut trailing = body.clone();
        trailing.push(0);
        let raw = own_message(&trailing, HandshakeType::ClientHello, 0);
        let decoded = decode_handshake_message(&raw).expect("decode");
        assert_eq!(
            parse_client_hello(&decoded),
            Err(HandshakeError::MalformedMessage)
        );
    }

    // DTLS-HSMSG-016 — ServerHello version, session id and trailing bytes.
    #[test]
    fn server_hello_extension_edges() {
        let mut body = [0u8; 128];
        let written = build_server_hello_body(&mut body, &[0x22; 32]).expect("build");
        let valid = body[..written].to_vec();

        let mut wrong_version = valid.clone();
        wrong_version[..2].copy_from_slice(&[254, 255]);
        assert_eq!(
            parse_server_hello(&wrong_version),
            Err(HandshakeError::UnsupportedVersion)
        );

        let mut long_session = valid.clone();
        long_session[34] = 33;
        assert_eq!(
            parse_server_hello(&long_session),
            Err(HandshakeError::MalformedMessage)
        );

        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            parse_server_hello(&trailing),
            Err(HandshakeError::MalformedMessage)
        );

        let mut no_extensions = valid[..40].to_vec();
        no_extensions[38..40].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            parse_server_hello(&no_extensions),
            Err(HandshakeError::NoCommonAlgorithm)
        );
    }

    // DTLS-HSMSG-017 — use_srtp MKI length must consume the extension exactly.
    #[test]
    fn use_srtp_mki_length_mismatch() {
        assert_eq!(
            use_srtp_contains_aes128_cm_sha1_80(&[0, 2, 0, 1, 1]),
            Err(HandshakeError::MalformedMessage)
        );
    }

    // DTLS-HSMSG-018 — structurally valid random handshake messages reach
    // every body parser without panicking.
    #[test]
    fn random_valid_headers_reach_every_parser() {
        let mut state = 0x2468_ACE0_1357_9BDFu64;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            state
        };
        let types = [
            HandshakeType::ClientHello,
            HandshakeType::ServerHello,
            HandshakeType::ServerKeyExchange,
            HandshakeType::ServerHelloDone,
            HandshakeType::ClientKeyExchange,
            HandshakeType::Finished,
        ];
        for _ in 0..512 {
            let body_len = usize::try_from(next() % 100).expect("small");
            let mut body = vec![0u8; body_len];
            for byte in &mut body {
                *byte = u8::try_from(next() & 0xFF).expect("byte");
            }
            let message_type = types[usize::try_from(next() % 6).expect("type")];
            let raw = own_message(&body, message_type, 0);
            let decoded = decode_handshake_message(&raw).expect("valid header");
            let _ = parse_client_hello(&decoded);
            let _ = parse_server_hello(decoded.body);
            let _ = parse_server_key_exchange(decoded.body);
            let _ = parse_client_key_exchange(decoded.body);
            let _ = parse_finished(decoded.body);
            let _ = parse_server_hello_done(decoded.body);
        }
    }
}

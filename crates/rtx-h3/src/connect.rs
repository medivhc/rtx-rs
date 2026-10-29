//! Extended CONNECT request and response representation (`RFC 9114` section
//! 4.3.1, `RFC 9220` section 3, gate items `M3-H4` and `M3-H5`).
//!
//! This module is a representation layer only. It has no connection state, no
//! stream state and no server-push logic; it encodes and decodes the extended
//! CONNECT header fields and validates their H3 ordering and uniqueness
//! rules. It does not depend on `url::Url`: the request keeps `scheme`,
//! `authority`, `path` and `protocol` as independent fields, so a caller can
//! build a URL elsewhere if it wants one.
//!
//! # Fields decoded from the Chrome fixture
//!
//! `crates/rtx-h3/tests/fixtures/chrome-connect.bin` is the verbatim
//! `connect-headers-frame.bin` of `R6-2c` (`interop/m3/chrome/2026-10-29-chrome-156.0.8078.4/`).
//! Decoding it with [`crate::qpack::FieldSection`] yields exactly these
//! field lines, in this order:
//!
//! | Order | Name | Value |
//! |---|---|---|
//! | 1 | `:scheme` | `https` |
//! | 2 | `:method` | `CONNECT` |
//! | 3 | `:authority` | `127.0.0.1:4433` |
//! | 4 | `:path` | `/session` |
//! | 5 | `:protocol` | `webtransport` |
//! | 6 | `sec-webtransport-http3-draft02` | `1` |
//! | 7 | `origin` | `https://127.0.0.1:8443` |
//!
//! Chrome emits `:scheme` before `:method`, which `RFC 9114` section 4.3.1
//! permits: the rule is that every pseudo-header field precedes every
//! non-pseudo field, not that the pseudo-header fields have a fixed mutual
//! order. The validation here enforces that rule, rejects duplicate
//! pseudo-header fields, rejects unknown pseudo-header fields and requires
//! `:method`, `:scheme`, `:authority`, `:path` and `:protocol`. The decoded
//! `scheme`, `authority` and `path` reconstruct the `R6-2c` server-log URL
//! `https://127.0.0.1:4433/session`, and the two regular fields match the
//! server log entries `origin: https://127.0.0.1:8443` and
//! `sec-webtransport-http3-draft02: 1`. The legacy draft-02 signal is
//! recorded as Chrome sent it; it is not "corrected" to a newer spelling.
//!
//! # Bounds
//!
//! One field line is decoded through a `MAX_FIELD_LINE_LEN` scratch slice
//! ([`MAX_FIELD_LINE_LEN`]); a longer line is rejected instead of truncated.
//! The four retained pseudo-header values are copied once into the
//! caller-supplied [`ConnectBuffers`]; a value larger than its buffer is
//! rejected with [`ConnectError::FieldTooLong`]. Neither path allocates.

use crate::qpack::{self, FieldLine, FieldSection, QpackError};

/// Largest decoded name-plus-value of one field line in
/// [`ConnectRequest::decode`] and [`ConnectResponse::decode`].
pub const MAX_FIELD_LINE_LEN: usize = 1024;

/// Caller-owned storage for the four retained extended CONNECT fields.
#[derive(Debug)]
pub struct ConnectBuffers<'a> {
    /// Storage for the `:scheme` value.
    pub scheme: &'a mut [u8],
    /// Storage for the `:authority` value.
    pub authority: &'a mut [u8],
    /// Storage for the `:path` value.
    pub path: &'a mut [u8],
    /// Storage for the `:protocol` value.
    pub protocol: &'a mut [u8],
}

impl<'a> ConnectBuffers<'a> {
    /// Builds the four buffers.
    #[must_use]
    pub const fn new(
        scheme: &'a mut [u8],
        authority: &'a mut [u8],
        path: &'a mut [u8],
        protocol: &'a mut [u8],
    ) -> Self {
        Self {
            scheme,
            authority,
            path,
            protocol,
        }
    }
}

/// An extended CONNECT request (`RFC 9220` section 3).
///
/// `:method` is always `CONNECT` and is therefore not stored; `protocol` is
/// the extended CONNECT protocol identifier (`webtransport` for a WebTransport
/// session).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectRequest<'a> {
    scheme: &'a str,
    authority: &'a str,
    path: &'a str,
    protocol: &'a str,
}

impl<'a> ConnectRequest<'a> {
    /// Builds a request representation from its four fields.
    #[must_use]
    pub const fn new(
        scheme: &'a str,
        authority: &'a str,
        path: &'a str,
        protocol: &'a str,
    ) -> Self {
        Self {
            scheme,
            authority,
            path,
            protocol,
        }
    }

    /// Returns the `:scheme` value.
    #[must_use]
    pub const fn scheme(self) -> &'a str {
        self.scheme
    }

    /// Returns the `:authority` value.
    #[must_use]
    pub const fn authority(self) -> &'a str {
        self.authority
    }

    /// Returns the `:path` value.
    #[must_use]
    pub const fn path(self) -> &'a str {
        self.path
    }

    /// Returns the `:protocol` value.
    #[must_use]
    pub const fn protocol(self) -> &'a str {
        self.protocol
    }

    /// Decodes and validates an extended CONNECT field section.
    ///
    /// The returned representation borrows the four values from `buffers`.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError::Qpack`] when the QPACK field section is
    /// malformed, [`ConnectError::MissingPseudoHeader`] when a required
    /// pseudo-header field is absent, [`ConnectError::DuplicatePseudoHeader`]
    /// when one repeats, [`ConnectError::PseudoHeaderAfterField`] when a
    /// pseudo-header field follows a regular field,
    /// [`ConnectError::UnexpectedPseudoHeader`] for a pseudo-header field that
    /// is not defined for requests, [`ConnectError::NotConnect`] when
    /// `:method` is not `CONNECT`, [`ConnectError::FieldTooLong`] when a value
    /// does not fit its buffer, and [`ConnectError::NonUtf8`] when a retained
    /// value is not UTF-8.
    pub fn decode(encoded: &[u8], buffers: ConnectBuffers<'a>) -> Result<Self, ConnectError> {
        let ConnectBuffers {
            scheme,
            authority,
            path,
            protocol,
        } = buffers;
        let mut section = FieldSection::new(encoded)?;
        let mut scratch = [0u8; MAX_FIELD_LINE_LEN];
        let mut seen = [false; 5];
        let mut lengths = [0usize; 4];
        let mut regular_seen = false;
        while let Some(field) = section.next_field(&mut scratch)? {
            let name = field.name();
            if name.first() == Some(&b':') {
                if regular_seen {
                    return Err(ConnectError::PseudoHeaderAfterField);
                }
                if name == b":method" {
                    if seen[0] {
                        return Err(ConnectError::DuplicatePseudoHeader);
                    }
                    seen[0] = true;
                    if field.value() != b"CONNECT" {
                        return Err(ConnectError::NotConnect);
                    }
                } else if name == b":scheme" {
                    lengths[0] = set_pseudo(&mut seen, 1, scheme, field.value())?;
                } else if name == b":authority" {
                    lengths[1] = set_pseudo(&mut seen, 2, authority, field.value())?;
                } else if name == b":path" {
                    lengths[2] = set_pseudo(&mut seen, 3, path, field.value())?;
                } else if name == b":protocol" {
                    lengths[3] = set_pseudo(&mut seen, 4, protocol, field.value())?;
                } else {
                    return Err(ConnectError::UnexpectedPseudoHeader);
                }
            } else {
                regular_seen = true;
            }
        }
        if !seen.iter().all(|value| *value) {
            return Err(ConnectError::MissingPseudoHeader);
        }
        Ok(Self {
            scheme: freeze(scheme, lengths[0])?,
            authority: freeze(authority, lengths[1])?,
            path: freeze(path, lengths[2])?,
            protocol: freeze(protocol, lengths[3])?,
        })
    }

    /// Encodes the request as one QPACK field section.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError::Qpack`] when the output slice is too small.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, ConnectError> {
        qpack::encode_fields(&self.fields(), output).map_err(ConnectError::Qpack)
    }

    /// Returns the number of bytes [`ConnectRequest::encode`] would write.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        qpack::fields_encoded_len(&self.fields())
    }

    fn fields(&self) -> [FieldLine<'_>; 5] {
        [
            FieldLine::new(b":method", b"CONNECT"),
            FieldLine::new(b":scheme", self.scheme.as_bytes()),
            FieldLine::new(b":authority", self.authority.as_bytes()),
            FieldLine::new(b":path", self.path.as_bytes()),
            FieldLine::new(b":protocol", self.protocol.as_bytes()),
        ]
    }
}

/// An extended CONNECT response status.
///
/// The status is stored as the exact value from the `:status` field. Error
/// statuses are preserved verbatim; nothing is collapsed into a generic
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectResponse {
    status: u16,
    digits: [u8; 3],
}

impl ConnectResponse {
    /// Builds a response with an HTTP status in `100..=599`.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError::InvalidStatus`] outside the status range.
    pub fn new(status: u16) -> Result<Self, ConnectError> {
        if !(100..=599).contains(&status) {
            return Err(ConnectError::InvalidStatus);
        }
        Ok(Self {
            status,
            digits: status_digits(status),
        })
    }

    /// Returns the exact `:status` value.
    #[must_use]
    pub const fn status(self) -> u16 {
        self.status
    }

    /// Returns `true` for a 2xx status.
    #[must_use]
    pub fn is_success(self) -> bool {
        (200..=299).contains(&self.status)
    }

    /// Decodes a response field section and keeps the `:status` value.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError::Qpack`] when the field section is malformed,
    /// [`ConnectError::MissingPseudoHeader`] when `:status` is absent,
    /// [`ConnectError::DuplicatePseudoHeader`] when it repeats,
    /// [`ConnectError::PseudoHeaderAfterField`] when it follows a regular
    /// field, [`ConnectError::UnexpectedPseudoHeader`] for any other
    /// pseudo-header field, and [`ConnectError::InvalidStatus`] when the value
    /// is not a three-digit status in `100..=599`.
    pub fn decode(encoded: &[u8]) -> Result<Self, ConnectError> {
        let mut section = FieldSection::new(encoded)?;
        let mut scratch = [0u8; MAX_FIELD_LINE_LEN];
        let mut status = None;
        let mut regular_seen = false;
        while let Some(field) = section.next_field(&mut scratch)? {
            let name = field.name();
            if name.first() == Some(&b':') {
                if regular_seen {
                    return Err(ConnectError::PseudoHeaderAfterField);
                }
                if name != b":status" {
                    return Err(ConnectError::UnexpectedPseudoHeader);
                }
                if status.is_some() {
                    return Err(ConnectError::DuplicatePseudoHeader);
                }
                status = Some(parse_status(field.value())?);
            } else {
                regular_seen = true;
            }
        }
        let status = status.ok_or(ConnectError::MissingPseudoHeader)?;
        Self::new(status)
    }

    /// Encodes the response as one QPACK field section.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError::Qpack`] when the output slice is too small.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, ConnectError> {
        let fields = [FieldLine::new(b":status", &self.digits[..])];
        qpack::encode_fields(&fields, output).map_err(ConnectError::Qpack)
    }

    /// Returns the number of bytes [`ConnectResponse::encode`] would write.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        qpack::fields_encoded_len(&[FieldLine::new(b":status", &self.digits[..])])
    }
}

/// Marks a pseudo-header field as seen and copies its value into `buffer`.
fn set_pseudo(
    seen: &mut [bool; 5],
    slot: usize,
    buffer: &mut [u8],
    value: &[u8],
) -> Result<usize, ConnectError> {
    if seen[slot] {
        return Err(ConnectError::DuplicatePseudoHeader);
    }
    seen[slot] = true;
    if value.len() > buffer.len() {
        return Err(ConnectError::FieldTooLong);
    }
    let target = buffer
        .get_mut(..value.len())
        .ok_or(ConnectError::FieldTooLong)?;
    target.copy_from_slice(value);
    Ok(value.len())
}

/// Freezes a filled buffer into a borrowed string.
fn freeze<'a>(buffer: &'a mut [u8], length: usize) -> Result<&'a str, ConnectError> {
    let bytes: &'a [u8] = buffer;
    let window = bytes.get(..length).ok_or(ConnectError::FieldTooLong)?;
    core::str::from_utf8(window).map_err(|_| ConnectError::NonUtf8)
}

/// Parses a three-digit `:status` value.
fn parse_status(value: &[u8]) -> Result<u16, ConnectError> {
    if value.len() != 3 {
        return Err(ConnectError::InvalidStatus);
    }
    let mut status = 0u16;
    for &byte in value {
        if !byte.is_ascii_digit() {
            return Err(ConnectError::InvalidStatus);
        }
        status = status
            .checked_mul(10)
            .and_then(|status| status.checked_add(u16::from(byte - b'0')))
            .ok_or(ConnectError::InvalidStatus)?;
    }
    if !(100..=599).contains(&status) {
        return Err(ConnectError::InvalidStatus);
    }
    Ok(status)
}

/// Renders a status as its three ASCII digits.
fn status_digits(status: u16) -> [u8; 3] {
    let hundreds = u8::try_from(status / 100).unwrap_or(0);
    let tens = u8::try_from((status / 10) % 10).unwrap_or(0);
    let ones = u8::try_from(status % 10).unwrap_or(0);
    [b'0' + hundreds, b'0' + tens, b'0' + ones]
}

/// Extended CONNECT decoding or encoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectError {
    /// The QPACK layer rejected the field section.
    Qpack(QpackError),
    /// A required pseudo-header field is absent.
    MissingPseudoHeader,
    /// A pseudo-header field appeared twice.
    DuplicatePseudoHeader,
    /// A pseudo-header field is not defined for this message.
    UnexpectedPseudoHeader,
    /// A pseudo-header field followed a regular field.
    PseudoHeaderAfterField,
    /// `:method` is not `CONNECT`.
    NotConnect,
    /// The `:status` value is not a valid status.
    InvalidStatus,
    /// A retained field does not fit its caller buffer.
    FieldTooLong,
    /// A retained field is not valid UTF-8.
    NonUtf8,
}

impl From<QpackError> for ConnectError {
    fn from(error: QpackError) -> Self {
        Self::Qpack(error)
    }
}

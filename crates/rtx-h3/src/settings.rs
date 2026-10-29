//! HTTP/3 SETTINGS for the WebTransport subset (`RFC 9114` section 7.2.4,
//! gate item `M3-H3`).
//!
//! A SETTINGS payload is a sequence of `identifier` varint / `value` varint
//! pairs. This module encodes and decodes that payload; the HTTP/3 frame
//! header that carries it (type `0x04`) is [`rtx_wire::h3_frame::Frame`] and
//! is not re-implemented here.
//!
//! # Constant table and provenance
//!
//! | Constant | Identifier | Source |
//! |---|---|---|
//! | [`SETTINGS_QPACK_MAX_TABLE_CAPACITY`] | `0x01` | `RFC 9114` section 7.2.4.1 |
//! | [`SETTINGS_MAX_FIELD_SECTION_SIZE`] | `0x06` | `RFC 9114` section 7.2.4.1 |
//! | [`SETTINGS_QPACK_BLOCKED_STREAMS`] | `0x07` | `RFC 9114` section 7.2.4.1 |
//! | [`SETTINGS_ENABLE_CONNECT_PROTOCOL`] | `0x08` | `RFC 9220` section 3 |
//! | [`SETTINGS_H3_DATAGRAM`] | `0x33` | `RFC 9297` section 2.1.1 |
//! | [`SETTINGS_H3_DATAGRAM_DEPRECATED`] | `0xffd277` | pre-RFC `H3_DATAGRAM` identifier (`draft-ietf-masque-h3-datagram-04` to `-06`, IANA registration); replaced by `0x33` in `RFC 9297`. Chrome still sends it: decode-only |
//! | [`SETTINGS_WEBTRANSPORT_ENABLE_DEPRECATED`] | `0x2b603742` | `ENABLE_WEBTRANSPORT` in `draft-ietf-webtrans-http3-06` (IANA registration), removed after that draft. Chrome still sends it: decode-only |
//! | [`SETTINGS_WEBTRANSPORT_MAX_SESSIONS`] | `0xc671706a` | `WEBTRANSPORT_MAX_SESSIONS`, IANA registration in `draft-ietf-webtrans-http3-08` to `-12` |
//!
//! The deprecated identifiers are decoded (`Settings::deprecated_h3_datagram`
//! and `Settings::deprecated_webtransport_enable` expose them), but
//! [`Settings::encode`] and [`Settings::set`] refuse them: this crate never
//! emits a deprecated identifier actively. They are accepted on the decode
//! side because Chrome emits them, and a receiver that rejected them would
//! fail against the capture in `crates/rtx-h3/tests/fixtures/`.
//!
//! # `0xc671706a` provenance note
//!
//! `0xc671706a` is the max-sessions setting that gate `M3-H3` requires. Its
//! registered name and value come from `draft-ietf-webtrans-http3-08` through
//! `-12`; `-13`/`-14` renamed it to `SETTINGS_WT_MAX_SESSIONS`, and `-15`
//! removed max-sessions altogether in favour of `SETTINGS_WT_ENABLED`
//! (`0x2c7cf000`, `draft-ietf-webtrans-http3-15` section 9.2) plus the
//! flow-control settings of its section 5. The task brief attributes
//! `0xc671706a` to `draft-15` section 5; the published `draft-15` text does
//! **not** contain that identifier or a max-sessions setting, so this module
//! documents the registration value against its actual drafts instead of
//! repeating a citation that the draft itself contradicts. The value itself
//! is implemented as required.
//!
//! # Chrome fixture coverage
//!
//! `m3_h3_chrome_settings_fixture_parsed` parses
//! `crates/rtx-h3/tests/fixtures/chrome-settings.bin` verbatim. That fixture
//! contains the six non-GREASE identifiers `0x01`, `0x06`, `0x07`, `0x33`,
//! `0xffd277` and `0x2b603742`; it does **not** contain `0x08` or
//! `0xc671706a`. Those two are covered by the round-trip test, not by the
//! fixture, and are not claimed to be "proven by the fixture".
//!
//! # Bounds
//!
//! A SETTINGS payload with more than [`MAX_SETTINGS_ITEMS`] pairs is rejected
//! with [`SettingError::TooManySettings`]; a repeated identifier (known,
//! GREASE or unknown) is rejected with [`SettingError::DuplicateSetting`],
//! which is the `H3_SETTINGS_ERROR` condition of `RFC 9114` section 7.2.4.1.
//! Unknown identifiers are stored verbatim, never interpreted, and never
//! re-encoded; GREASE identifiers therefore have no observable meaning and no
//! test asserts their randomised identifier or value. Nothing allocates.

use rtx_wire::{WireError, Writer, varint};

/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (`RFC 9114` section 7.2.4.1).
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;

/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (`RFC 9114` section 7.2.4.1).
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;

/// `SETTINGS_QPACK_BLOCKED_STREAMS` (`RFC 9114` section 7.2.4.1).
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;

/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (`RFC 9220` section 3).
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

/// `SETTINGS_H3_DATAGRAM` (`RFC 9297` section 2.1.1).
pub const SETTINGS_H3_DATAGRAM: u64 = 0x33;

/// Deprecated `SETTINGS_H3_DATAGRAM` identifier that Chrome still sends.
///
/// The pre-RFC `H3_DATAGRAM` identifier (`draft-ietf-masque-h3-datagram-04`
/// to `-06`) was replaced by `0x33` in `RFC 9297`. It is accepted on decode
/// only; see the module documentation.
pub const SETTINGS_H3_DATAGRAM_DEPRECATED: u64 = 0xFF_D277;

/// Deprecated `ENABLE_WEBTRANSPORT` identifier that Chrome still sends.
///
/// Registered as `ENABLE_WEBTRANSPORT` in `draft-ietf-webtrans-http3-06` and
/// removed after that draft. It is accepted on decode only; see the module
/// documentation.
pub const SETTINGS_WEBTRANSPORT_ENABLE_DEPRECATED: u64 = 0x2B60_3742;

/// `WEBTRANSPORT_MAX_SESSIONS`: the max-sessions setting required by
/// `M3-H3`.
///
/// The value is the IANA registration of
/// `draft-ietf-webtrans-http3-08` through `-12`. Later drafts renamed and
/// then removed the setting; see the module documentation for the full
/// provenance note.
pub const SETTINGS_WEBTRANSPORT_MAX_SESSIONS: u64 = 0xC671_706A;

/// Largest number of identifier/value pairs a [`Settings`] value accepts.
///
/// The bound is a compiled constant rather than an unbounded receiver: a
/// decode that exceeds it fails with [`SettingError::TooManySettings`]. The
/// Chrome capture carries seven pairs.
pub const MAX_SETTINGS_ITEMS: usize = 32;

/// Identifiers this crate is willing to emit.
const ENCODABLE: [u64; 6] = [
    SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    SETTINGS_MAX_FIELD_SECTION_SIZE,
    SETTINGS_QPACK_BLOCKED_STREAMS,
    SETTINGS_ENABLE_CONNECT_PROTOCOL,
    SETTINGS_H3_DATAGRAM,
    SETTINGS_WEBTRANSPORT_MAX_SESSIONS,
];

/// One decoded SETTINGS pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    id: u64,
    value: u64,
}

impl Setting {
    /// Returns the setting identifier.
    #[must_use]
    pub const fn id(self) -> u64 {
        self.id
    }

    /// Returns the setting value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }
}

/// A decoded SETTINGS payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    items: [Setting; MAX_SETTINGS_ITEMS],
    len: usize,
}

impl Settings {
    /// Creates an empty SETTINGS payload.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            items: [Setting { id: 0, value: 0 }; MAX_SETTINGS_ITEMS],
            len: 0,
        }
    }

    /// Decodes a SETTINGS payload (the frame payload, without the frame
    /// header).
    ///
    /// Unknown identifiers are stored verbatim so that a repetition can be
    /// detected, but they are never interpreted and never re-encoded.
    ///
    /// # Errors
    ///
    /// Returns [`SettingError::Wire`] when an identifier or value varint is
    /// truncated or when it cannot be represented, and
    /// [`SettingError::DuplicateSetting`] when an identifier repeats,
    /// regardless of whether it is known.
    pub fn decode(payload: &[u8]) -> Result<Self, SettingError> {
        let mut settings = Self::new();
        let mut rest = payload;
        while !rest.is_empty() {
            let (id, id_len) = varint::decode(rest).map_err(SettingError::Wire)?;
            let after_id = rest
                .get(id_len..)
                .ok_or(SettingError::Wire(WireError::UnexpectedEnd))?;
            let (value, value_len) = varint::decode(after_id).map_err(SettingError::Wire)?;
            if settings.position(id).is_some() {
                return Err(SettingError::DuplicateSetting);
            }
            settings.push(id, value)?;
            rest = after_id
                .get(value_len..)
                .ok_or(SettingError::Wire(WireError::UnexpectedEnd))?;
        }
        Ok(settings)
    }

    /// Sets an encodable setting, replacing the value of an existing entry.
    ///
    /// # Errors
    ///
    /// Returns [`SettingError::NotEncodable`] for an identifier this crate
    /// refuses to emit (deprecated or unrecognised), and
    /// [`SettingError::TooManySettings`] when the container is full.
    pub fn set(&mut self, id: u64, value: u64) -> Result<(), SettingError> {
        if !is_encodable(id) {
            return Err(SettingError::NotEncodable);
        }
        if let Some(index) = self.position(id) {
            self.items[index].value = value;
            Ok(())
        } else {
            self.push(id, value)
        }
    }

    /// Returns the number of stored pairs, including unknown and deprecated
    /// identifiers.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no pair is stored.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterates over every stored pair in payload order.
    pub fn iter(&self) -> impl Iterator<Item = Setting> + '_ {
        self.items.iter().take(self.len).copied()
    }

    /// Returns the value of [`SETTINGS_QPACK_MAX_TABLE_CAPACITY`].
    #[must_use]
    pub fn qpack_max_table_capacity(&self) -> Option<u64> {
        self.value_of(SETTINGS_QPACK_MAX_TABLE_CAPACITY)
    }

    /// Returns the value of [`SETTINGS_MAX_FIELD_SECTION_SIZE`].
    #[must_use]
    pub fn max_field_section_size(&self) -> Option<u64> {
        self.value_of(SETTINGS_MAX_FIELD_SECTION_SIZE)
    }

    /// Returns the value of [`SETTINGS_QPACK_BLOCKED_STREAMS`].
    #[must_use]
    pub fn qpack_blocked_streams(&self) -> Option<u64> {
        self.value_of(SETTINGS_QPACK_BLOCKED_STREAMS)
    }

    /// Returns the value of [`SETTINGS_ENABLE_CONNECT_PROTOCOL`].
    #[must_use]
    pub fn enable_connect_protocol(&self) -> Option<u64> {
        self.value_of(SETTINGS_ENABLE_CONNECT_PROTOCOL)
    }

    /// Returns the value of [`SETTINGS_H3_DATAGRAM`].
    #[must_use]
    pub fn h3_datagram(&self) -> Option<u64> {
        self.value_of(SETTINGS_H3_DATAGRAM)
    }

    /// Returns the value of [`SETTINGS_WEBTRANSPORT_MAX_SESSIONS`].
    #[must_use]
    pub fn webtransport_max_sessions(&self) -> Option<u64> {
        self.value_of(SETTINGS_WEBTRANSPORT_MAX_SESSIONS)
    }

    /// Returns the value of the deprecated [`SETTINGS_H3_DATAGRAM_DEPRECATED`]
    /// identifier.
    #[must_use]
    pub fn deprecated_h3_datagram(&self) -> Option<u64> {
        self.value_of(SETTINGS_H3_DATAGRAM_DEPRECATED)
    }

    /// Returns the value of the deprecated
    /// [`SETTINGS_WEBTRANSPORT_ENABLE_DEPRECATED`] identifier.
    #[must_use]
    pub fn deprecated_webtransport_enable(&self) -> Option<u64> {
        self.value_of(SETTINGS_WEBTRANSPORT_ENABLE_DEPRECATED)
    }

    /// Returns the number of bytes [`Settings::encode`] would write.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.iter()
            .filter(|setting| is_encodable(setting.id))
            .map(|setting| varint::encoded_len(setting.id) + varint::encoded_len(setting.value))
            .sum()
    }

    /// Encodes the SETTINGS payload (without the `0x04` frame header).
    ///
    /// Deprecated and unknown identifiers are skipped: this encoder never
    /// emits them actively.
    ///
    /// # Errors
    ///
    /// Returns [`SettingError::Wire`] when the output slice is too small.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, SettingError> {
        let mut writer = Writer::new(output);
        for setting in self.iter().filter(|setting| is_encodable(setting.id)) {
            let mut buffer = [0u8; 8];
            let written = varint::encode(setting.id, &mut buffer).map_err(SettingError::Wire)?;
            writer.put(&buffer[..written]).map_err(SettingError::Wire)?;
            let written = varint::encode(setting.value, &mut buffer).map_err(SettingError::Wire)?;
            writer.put(&buffer[..written]).map_err(SettingError::Wire)?;
        }
        Ok(writer.offset())
    }

    fn position(&self, id: u64) -> Option<usize> {
        self.items
            .get(..self.len)
            .and_then(|items| items.iter().position(|setting| setting.id == id))
    }

    fn value_of(&self, id: u64) -> Option<u64> {
        self.position(id).map(|index| self.items[index].value)
    }

    fn push(&mut self, id: u64, value: u64) -> Result<(), SettingError> {
        if self.len >= MAX_SETTINGS_ITEMS {
            return Err(SettingError::TooManySettings);
        }
        self.items[self.len] = Setting { id, value };
        self.len += 1;
        Ok(())
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `true` for identifiers this crate is willing to emit.
fn is_encodable(id: u64) -> bool {
    ENCODABLE.contains(&id)
}

/// SETTINGS decoding or encoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingError {
    /// A varint was truncated, could not be represented, or the output slice
    /// was too small.
    Wire(WireError),
    /// The same identifier appeared more than once (`H3_SETTINGS_ERROR`).
    DuplicateSetting,
    /// The payload contains more than [`MAX_SETTINGS_ITEMS`] pairs.
    TooManySettings,
    /// The identifier is deprecated or unknown, so this crate will not emit
    /// it.
    NotEncodable,
}

//! `M3-H3` evidence: SETTINGS round trip for the WebTransport subset, duplicate
//! rejection, and verbatim parsing of the `R6-2c` Chrome capture.
//!
//! Fixture source report:
//! `interop/m3/chrome/2026-10-29-chrome-156.0.8078.4/report.md`
//! (Chrome `Google Chrome for Testing 156.0.8078.4`). The raw frame is
//! `interop/m3/chrome/2026-10-29-chrome-156.0.8078.4/capture/settings-frame.bin`,
//! copied byte for byte to `tests/fixtures/chrome-settings.bin`.
//!
//! - `chrome-settings.bin`: 43 bytes, SHA-256
//!   `bfa48ebd0fca2fde0d560f13fb6198123c88b66ed2d1245e56de6ace120453ac`
//! - `chrome-connect.bin` (used by `tests/connect.rs`): 90 bytes, SHA-256
//!   `62b04ba11f2bcb7313764b783f57462f29f00b2b3622e027dcd6b560adab0753`
//!
//! The fixture contains one random GREASE setting per Chrome connection. Its
//! identifier and value are deliberately never asserted here; only the six
//! non-GREASE pairs and the "unknown pair is not re-encoded" property are
//! checked.

#![allow(clippy::too_many_lines)]

use rtx_h3::settings::{
    MAX_SETTINGS_ITEMS, SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_H3_DATAGRAM,
    SETTINGS_H3_DATAGRAM_DEPRECATED, SETTINGS_WEBTRANSPORT_ENABLE_DEPRECATED,
    SETTINGS_WEBTRANSPORT_MAX_SESSIONS, SettingError, Settings,
};
use rtx_wire::h3_frame::Frame;
use rtx_wire::varint::{self, VarInt};
use rtx_wire::{Decode, WireError};

const FIXTURE: &[u8] = include_bytes!("fixtures/chrome-settings.bin");

fn push_varint(buffer: &mut Vec<u8>, value: u64) {
    let mut bytes = [0u8; 8];
    let written = varint::encode(value, &mut bytes).expect("varint fits");
    buffer.extend_from_slice(&bytes[..written]);
}

fn payload(pairs: &[(u64, u64)]) -> Vec<u8> {
    let mut buffer = Vec::new();
    for (id, value) in pairs {
        push_varint(&mut buffer, *id);
        push_varint(&mut buffer, *value);
    }
    buffer
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::new();
    push_varint(&mut buffer, 0x04);
    push_varint(
        &mut buffer,
        u64::try_from(payload.len()).expect("payload length fits"),
    );
    buffer.extend_from_slice(payload);
    buffer
}

#[test]
fn m3_h3_settings_round_trip() {
    let pairs = [
        (SETTINGS_H3_DATAGRAM, 1),
        (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
        (SETTINGS_WEBTRANSPORT_MAX_SESSIONS, 3),
        (SETTINGS_H3_DATAGRAM_DEPRECATED, 1),
        (SETTINGS_WEBTRANSPORT_ENABLE_DEPRECATED, 1),
    ];
    let payload = payload(&pairs);
    let settings = Settings::decode(&payload).expect("decode settings");
    assert_eq!(settings.len(), 5);
    assert_eq!(settings.h3_datagram(), Some(1));
    assert_eq!(settings.enable_connect_protocol(), Some(1));
    assert_eq!(settings.webtransport_max_sessions(), Some(3));
    assert_eq!(settings.deprecated_h3_datagram(), Some(1));
    assert_eq!(settings.deprecated_webtransport_enable(), Some(1));

    // The encoder never emits a deprecated identifier actively.
    let mut encoded = [0u8; 32];
    let written = settings.encode(&mut encoded).expect("encode settings");
    assert_eq!(written, settings.encoded_len());
    let mut expected = Vec::new();
    push_varint(&mut expected, SETTINGS_H3_DATAGRAM);
    push_varint(&mut expected, 1);
    push_varint(&mut expected, SETTINGS_ENABLE_CONNECT_PROTOCOL);
    push_varint(&mut expected, 1);
    push_varint(&mut expected, SETTINGS_WEBTRANSPORT_MAX_SESSIONS);
    push_varint(&mut expected, 3);
    assert_eq!(&encoded[..written], &expected[..]);

    let decoded = Settings::decode(&encoded[..written]).expect("decode encoded settings");
    assert_eq!(decoded.len(), 3);
    assert_eq!(decoded.h3_datagram(), Some(1));
    assert_eq!(decoded.enable_connect_protocol(), Some(1));
    assert_eq!(decoded.webtransport_max_sessions(), Some(3));
    assert_eq!(decoded.deprecated_h3_datagram(), None);
    assert_eq!(decoded.deprecated_webtransport_enable(), None);

    // `set` accepts encodable identifiers and refuses the decode-only ones.
    let mut built = Settings::new();
    built
        .set(SETTINGS_H3_DATAGRAM, 1)
        .expect("h3 datagram is encodable");
    built
        .set(SETTINGS_H3_DATAGRAM, 1)
        .expect("replacing an existing pair is allowed");
    let mut encoded = [0u8; 8];
    assert_eq!(built.encode(&mut encoded), Ok(2));
    assert_eq!(
        built.set(SETTINGS_H3_DATAGRAM_DEPRECATED, 1),
        Err(SettingError::NotEncodable)
    );

    // The frame header is `rtx-wire`'s; a declared payload longer than the
    // remaining input must be rejected.
    let framed = frame(&payload);
    let (decoded_frame, consumed) = Frame::decode(&framed).expect("frame decodes");
    assert_eq!(decoded_frame.frame_type(), VarInt::new(0x04).expect("type"));
    assert_eq!(decoded_frame.payload(), &payload[..]);
    assert_eq!(consumed, framed.len());
    assert_eq!(
        Frame::decode(&framed[..framed.len() - 1]),
        Err(WireError::UnexpectedEnd)
    );

    // Empty SETTINGS is legal.
    let empty = Settings::default();
    assert!(empty.is_empty());
    let mut nothing: [u8; 0] = [];
    assert_eq!(empty.encode(&mut nothing), Ok(0));
}

#[test]
fn m3_h3_duplicate_setting_rejected() {
    let duplicate_known = payload(&[(SETTINGS_H3_DATAGRAM, 1), (SETTINGS_H3_DATAGRAM, 0)]);
    assert_eq!(
        Settings::decode(&duplicate_known),
        Err(SettingError::DuplicateSetting)
    );

    // A GREASE-shaped identifier repeats. The identifier is synthetic here; it
    // is not the fixture's random value.
    let duplicate_reserved = payload(&[(0x21, 1), (0x21, 2)]);
    assert_eq!(
        Settings::decode(&duplicate_reserved),
        Err(SettingError::DuplicateSetting)
    );

    // One more pair than the compiled cap.
    let many: Vec<(u64, u64)> = (0..=MAX_SETTINGS_ITEMS)
        .map(|index| (0x1000 + u64::try_from(index).expect("index"), 0))
        .collect();
    assert_eq!(
        Settings::decode(&payload(&many)),
        Err(SettingError::TooManySettings)
    );

    assert_eq!(
        Settings::decode(&[0x80]),
        Err(SettingError::Wire(WireError::UnexpectedEnd))
    );
    assert_eq!(
        Settings::decode(&[0x33_u8]),
        Err(SettingError::Wire(WireError::UnexpectedEnd))
    );

    let settings =
        Settings::decode(&payload(&[(SETTINGS_H3_DATAGRAM, 1)])).expect("decode one setting");
    let mut too_small = [0u8; 1];
    assert_eq!(
        settings.encode(&mut too_small),
        Err(SettingError::Wire(WireError::OutputTooSmall))
    );
}

#[test]
fn m3_h3_chrome_settings_fixture_parsed() {
    assert_eq!(FIXTURE.len(), 43, "verbatim frame length");

    let (frame, consumed) = Frame::decode(FIXTURE).expect("fixture frame decodes");
    assert_eq!(
        frame.frame_type(),
        VarInt::new(0x04).expect("SETTINGS type")
    );
    assert_eq!(frame.payload().len(), 41, "declared SETTINGS payload");
    assert_eq!(consumed, FIXTURE.len());
    assert_eq!(
        Frame::decode(&FIXTURE[..FIXTURE.len() - 1]),
        Err(WireError::UnexpectedEnd)
    );

    let settings = Settings::decode(frame.payload()).expect("fixture settings decode");
    assert_eq!(settings.len(), 7, "six named pairs and one GREASE pair");
    let first = settings.iter().next().expect("first pair");
    assert_eq!(first.id(), 0x01);
    assert_eq!(first.value(), 65536);
    assert_eq!(
        settings.qpack_max_table_capacity(),
        Some(65536),
        "QPACK_MAX_TABLE_CAPACITY"
    );
    assert_eq!(
        settings.max_field_section_size(),
        Some(16384),
        "MAX_FIELD_SECTION_SIZE"
    );
    assert_eq!(
        settings.qpack_blocked_streams(),
        Some(100),
        "QPACK_BLOCKED_STREAMS"
    );
    assert_eq!(settings.h3_datagram(), Some(1), "ENABLE_DATAGRAM");
    assert_eq!(
        settings.deprecated_h3_datagram(),
        Some(1),
        "ENABLE_DATAGRAM_DEPRECATED"
    );
    assert_eq!(
        settings.deprecated_webtransport_enable(),
        Some(1),
        "WEBTRANSPORT_ENABLE_DEPRECATED"
    );

    // Neither of these is in the Chrome fixture; they are covered by the
    // round-trip test above and are not claimed to be fixture-proven.
    assert_eq!(settings.enable_connect_protocol(), None);
    assert_eq!(settings.webtransport_max_sessions(), None);

    // Re-encoding drops the deprecated pair and the unknown GREASE pair, which
    // is how "unknown settings are ignored" is observed without asserting a
    // randomised identifier or value.
    let mut encoded = [0u8; 32];
    let written = settings.encode(&mut encoded).expect("re-encode fixture");
    let re_encoded = Settings::decode(&encoded[..written]).expect("decode re-encoded settings");
    assert_eq!(re_encoded.len(), 4);
    assert_eq!(re_encoded.qpack_max_table_capacity(), Some(65536));
    assert_eq!(re_encoded.max_field_section_size(), Some(16384));
    assert_eq!(re_encoded.qpack_blocked_streams(), Some(100));
    assert_eq!(re_encoded.h3_datagram(), Some(1));
    assert_eq!(re_encoded.deprecated_h3_datagram(), None);
    assert_eq!(re_encoded.deprecated_webtransport_enable(), None);
}

//! `M3-H4` / `M3-H5` evidence: verbatim Chrome CONNECT decoding, the encoder
//! round trip, the disabled QPACK dynamic table, the extended CONNECT
//! representation and error-status preservation.
//!
//! Fixture source report:
//! `interop/m3/chrome/2026-10-29-chrome-156.0.8078.4/report.md`
//! (Chrome `Google Chrome for Testing 156.0.8078.4`). The raw frame is
//! `interop/m3/chrome/2026-10-29-chrome-156.0.8078.4/capture/connect-headers-frame.bin`,
//! copied byte for byte to `tests/fixtures/chrome-connect.bin`.
//!
//! - `chrome-connect.bin`: 90 bytes, SHA-256
//!   `62b04ba11f2bcb7313764b783f57462f29f00b2b3622e027dcd6b560adab0753`
//! - `chrome-settings.bin` (used by `tests/settings.rs`): 43 bytes, SHA-256
//!   `bfa48ebd0fca2fde0d560f13fb6198123c88b66ed2d1245e56de6ace120453ac`

#![allow(clippy::too_many_lines, clippy::similar_names)]

use rtx_h3::connect::{ConnectBuffers, ConnectError, ConnectRequest, ConnectResponse};
use rtx_h3::qpack::{self, FieldLine, FieldSection, MAX_FIELD_LINES, QpackError};
use rtx_h3::settings::{
    SETTINGS_QPACK_BLOCKED_STREAMS, SETTINGS_QPACK_MAX_TABLE_CAPACITY, Settings,
};
use rtx_wire::h3_frame::Frame;
use rtx_wire::varint::VarInt;
use rtx_wire::{Decode, WireError};

const FIXTURE: &[u8] = include_bytes!("fixtures/chrome-connect.bin");

fn collect(payload: &[u8], scratch: &mut [u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut section = FieldSection::new(payload).expect("field section prefix");
    let mut fields = Vec::new();
    while let Some(field) = section.next_field(scratch).expect("field line") {
        fields.push((field.name().to_vec(), field.value().to_vec()));
    }
    assert!(section.is_complete());
    fields
}

fn encode_section(fields: &[FieldLine<'_>]) -> Vec<u8> {
    let mut buffer = vec![0u8; qpack::fields_encoded_len(fields)];
    let written = qpack::encode_fields(fields, &mut buffer).expect("encode field section");
    buffer.truncate(written);
    buffer
}

fn decode_fixture_request(payload: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut scheme = [0u8; 16];
    let mut authority = [0u8; 64];
    let mut path = [0u8; 64];
    let mut protocol = [0u8; 32];
    let request = ConnectRequest::decode(
        payload,
        ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol),
    )
    .expect("fixture request decodes");
    assert_eq!(request.scheme(), "https");
    assert_eq!(request.authority(), "127.0.0.1:4433");
    assert_eq!(request.path(), "/session");
    assert_eq!(request.protocol(), "webtransport");
    (
        request.scheme().as_bytes().to_vec(),
        request.authority().as_bytes().to_vec(),
        request.path().as_bytes().to_vec(),
        request.protocol().as_bytes().to_vec(),
    )
}

#[test]
fn m3_h4_connect_request_decode_chrome_fixture() {
    assert_eq!(FIXTURE.len(), 90, "verbatim frame length");
    let (frame, consumed) = Frame::decode(FIXTURE).expect("fixture frame decodes");
    assert_eq!(frame.frame_type(), VarInt::new(0x01).expect("HEADERS type"));
    assert_eq!(frame.payload().len(), 87, "declared HEADERS payload");
    assert_eq!(consumed, FIXTURE.len());
    let payload = frame.payload();
    assert_eq!(&payload[..2], &[0, 0], "QPACK prefix: no dynamic table");

    let mut scratch = [0u8; 512];
    let fields = collect(payload, &mut scratch);
    let expected: [(&str, &str); 7] = [
        (":scheme", "https"),
        (":method", "CONNECT"),
        (":authority", "127.0.0.1:4433"),
        (":path", "/session"),
        (":protocol", "webtransport"),
        ("sec-webtransport-http3-draft02", "1"),
        ("origin", "https://127.0.0.1:8443"),
    ];
    assert_eq!(fields.len(), expected.len(), "field count");
    for ((name, value), (expected_name, expected_value)) in fields.iter().zip(expected) {
        assert_eq!(name.as_slice(), expected_name.as_bytes());
        assert_eq!(value.as_slice(), expected_value.as_bytes());
    }

    let (scheme, authority, path, protocol) = decode_fixture_request(payload);
    assert_eq!(protocol, b"webtransport");
    assert_eq!(
        format!(
            "{}://{}{}",
            String::from_utf8(scheme).expect("scheme"),
            String::from_utf8(authority).expect("authority"),
            String::from_utf8(path).expect("path")
        ),
        "https://127.0.0.1:4433/session",
        "server-log URL anchor"
    );
    // Anchors recorded by the R6-2c server log; all three must be present.
    assert_eq!(
        fields[5],
        (b"sec-webtransport-http3-draft02".to_vec(), b"1".to_vec())
    );
    assert_eq!(
        fields[6],
        (b"origin".to_vec(), b"https://127.0.0.1:8443".to_vec())
    );
}

#[test]
fn m3_h4_connect_request_encode_round_trip() {
    let request = ConnectRequest::new("https", "127.0.0.1:4433", "/session", "webtransport");
    let mut buffer = [0u8; 256];
    let written = request.encode(&mut buffer).expect("encode request");
    assert_eq!(written, request.encoded_len());
    assert_eq!(&buffer[..2], &[0, 0], "encoder writes the zero prefix");

    let mut scratch = [0u8; 512];
    let fields = collect(&buffer[..written], &mut scratch);
    let expected: [(&[u8], &[u8]); 5] = [
        (b":method", b"CONNECT"),
        (b":scheme", b"https"),
        (b":authority", b"127.0.0.1:4433"),
        (b":path", b"/session"),
        (b":protocol", b"webtransport"),
    ];
    assert_eq!(fields.len(), expected.len());
    for ((name, value), (expected_name, expected_value)) in fields.iter().zip(expected) {
        assert_eq!(name.as_slice(), expected_name);
        assert_eq!(value.as_slice(), expected_value);
    }

    let mut scheme = [0u8; 16];
    let mut authority = [0u8; 64];
    let mut path = [0u8; 64];
    let mut protocol = [0u8; 32];
    let decoded = ConnectRequest::decode(
        &buffer[..written],
        ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol),
    )
    .expect("decode own encoding");
    assert_eq!(decoded, request);
}

#[test]
fn m3_h4_qpack_dynamic_table_disabled() {
    let empty = Settings::new();
    assert_eq!(qpack::ensure_dynamic_table_disabled(&empty), Ok(()));

    let mut capacity = Settings::new();
    capacity
        .set(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 65536)
        .expect("set capacity");
    assert_eq!(
        qpack::ensure_dynamic_table_disabled(&capacity),
        Err(QpackError::DynamicTableNotSupported)
    );

    let mut blocked = Settings::new();
    blocked
        .set(SETTINGS_QPACK_BLOCKED_STREAMS, 100)
        .expect("set blocked");
    assert_eq!(
        qpack::ensure_dynamic_table_disabled(&blocked),
        Err(QpackError::DynamicTableNotSupported)
    );

    // A prefix that names a dynamic table state is rejected before decoding.
    assert!(matches!(
        FieldSection::new(&[0x01, 0x00]),
        Err(QpackError::DynamicTableNotSupported)
    ));
    assert!(matches!(
        FieldSection::new(&[0x00, 0x01]),
        Err(QpackError::DynamicTableNotSupported)
    ));
    assert!(matches!(
        FieldSection::new(&[0x00_u8, 0x80]),
        Err(QpackError::DynamicTableNotSupported)
    ));

    // Every dynamic representation form is rejected.
    let mut scratch = [0u8; 64];
    for bytes in [
        [0x00, 0x00, 0x80],
        [0x00, 0x00, 0x40],
        [0x00, 0x00, 0x10],
        [0x00, 0x00, 0x00],
    ] {
        let mut section = FieldSection::new(&bytes).expect("zero prefix");
        assert_eq!(
            section.next_field(&mut scratch).expect_err("dynamic"),
            QpackError::DynamicTableNotSupported
        );
    }

    // The encoder emits only static-table and literal representations.
    let request = ConnectRequest::new("https", "203.0.113.9", "/abc", "webtransport");
    let mut buffer = [0u8; 256];
    let written = request.encode(&mut buffer).expect("encode");
    assert_eq!(written, request.encoded_len());
    assert_eq!(&buffer[..2], &[0, 0]);
}

#[test]
fn m3_h5_extended_connect_round_trip() {
    let request = ConnectRequest::new("https", "203.0.113.9:443", "/ws", "webtransport");
    let mut buffer = [0u8; 256];
    let written = request.encode(&mut buffer).expect("encode request");
    assert_eq!(written, request.encoded_len());

    let mut scheme = [0u8; 16];
    let mut authority = [0u8; 64];
    let mut path = [0u8; 64];
    let mut protocol = [0u8; 32];
    let decoded = ConnectRequest::decode(
        &buffer[..written],
        ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol),
    )
    .expect("decode request");
    assert_eq!(decoded, request);
    assert_eq!(decoded.scheme(), "https");
    assert_eq!(decoded.authority(), "203.0.113.9:443");
    assert_eq!(decoded.path(), "/ws");
    assert_eq!(decoded.protocol(), "webtransport");
}

#[test]
fn m3_h5_error_status_preserved() {
    for status in [200u16, 204, 404, 500, 503, 429] {
        let response = ConnectResponse::new(status).expect("valid status");
        let mut buffer = [0u8; 64];
        let written = response.encode(&mut buffer).expect("encode response");
        assert_eq!(written, response.encoded_len());
        let decoded = ConnectResponse::decode(&buffer[..written]).expect("decode response");
        assert_eq!(decoded.status(), status, "status preserved verbatim");
        assert_eq!(decoded, response);
        assert_eq!(decoded.is_success(), (200..=299).contains(&status));
    }
    assert_eq!(ConnectResponse::new(99), Err(ConnectError::InvalidStatus));
    assert_eq!(ConnectResponse::new(600), Err(ConnectError::InvalidStatus));
}

#[test]
fn m3_h5_connect_request_validation() {
    let mut scheme = [0u8; 16];
    let mut authority = [0u8; 64];
    let mut path = [0u8; 64];
    let mut protocol = [0u8; 32];

    let duplicate = encode_section(&[
        FieldLine::new(b":method", b"CONNECT"),
        FieldLine::new(b":scheme", b"https"),
        FieldLine::new(b":authority", b"example.test"),
        FieldLine::new(b":path", b"/"),
        FieldLine::new(b":protocol", b"webtransport"),
        FieldLine::new(b":method", b"CONNECT"),
    ]);
    assert_eq!(
        ConnectRequest::decode(
            &duplicate,
            ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol)
        ),
        Err(ConnectError::DuplicatePseudoHeader)
    );

    let duplicate_scheme = encode_section(&[
        FieldLine::new(b":method", b"CONNECT"),
        FieldLine::new(b":scheme", b"https"),
        FieldLine::new(b":authority", b"example.test"),
        FieldLine::new(b":path", b"/"),
        FieldLine::new(b":protocol", b"webtransport"),
        FieldLine::new(b":scheme", b"http"),
    ]);
    assert_eq!(
        ConnectRequest::decode(
            &duplicate_scheme,
            ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol)
        ),
        Err(ConnectError::DuplicatePseudoHeader)
    );

    let not_connect = encode_section(&[
        FieldLine::new(b":method", b"GET"),
        FieldLine::new(b":scheme", b"https"),
        FieldLine::new(b":authority", b"example.test"),
        FieldLine::new(b":path", b"/"),
        FieldLine::new(b":protocol", b"webtransport"),
    ]);
    assert_eq!(
        ConnectRequest::decode(
            &not_connect,
            ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol)
        ),
        Err(ConnectError::NotConnect)
    );

    let missing = encode_section(&[FieldLine::new(b":method", b"CONNECT")]);
    assert_eq!(
        ConnectRequest::decode(
            &missing,
            ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol)
        ),
        Err(ConnectError::MissingPseudoHeader)
    );

    let after_regular = encode_section(&[
        FieldLine::new(b"x-regular", b"1"),
        FieldLine::new(b":method", b"CONNECT"),
        FieldLine::new(b":scheme", b"https"),
        FieldLine::new(b":authority", b"example.test"),
        FieldLine::new(b":path", b"/"),
        FieldLine::new(b":protocol", b"webtransport"),
    ]);
    assert_eq!(
        ConnectRequest::decode(
            &after_regular,
            ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol)
        ),
        Err(ConnectError::PseudoHeaderAfterField)
    );

    let unknown = encode_section(&[
        FieldLine::new(b":method", b"CONNECT"),
        FieldLine::new(b":scheme", b"https"),
        FieldLine::new(b":authority", b"example.test"),
        FieldLine::new(b":path", b"/"),
        FieldLine::new(b":protocol", b"webtransport"),
        FieldLine::new(b":status", b"200"),
    ]);
    assert_eq!(
        ConnectRequest::decode(
            &unknown,
            ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol)
        ),
        Err(ConnectError::UnexpectedPseudoHeader)
    );

    let valid = encode_section(&[
        FieldLine::new(b":method", b"CONNECT"),
        FieldLine::new(b":scheme", b"https"),
        FieldLine::new(b":authority", b"a-very-long-authority"),
        FieldLine::new(b":path", b"/"),
        FieldLine::new(b":protocol", b"webtransport"),
    ]);
    let mut short_authority = [0u8; 2];
    let mut scheme = [0u8; 16];
    let mut path = [0u8; 64];
    let mut protocol = [0u8; 32];
    assert_eq!(
        ConnectRequest::decode(
            &valid,
            ConnectBuffers::new(&mut scheme, &mut short_authority, &mut path, &mut protocol)
        ),
        Err(ConnectError::FieldTooLong)
    );

    let non_utf8 = encode_section(&[
        FieldLine::new(b":method", b"CONNECT"),
        FieldLine::new(b":scheme", b"https"),
        FieldLine::new(b":authority", b"example.test"),
        FieldLine::new(b":path", &[0xFF]),
        FieldLine::new(b":protocol", b"webtransport"),
    ]);
    let mut scheme = [0u8; 16];
    let mut authority = [0u8; 64];
    let mut path = [0u8; 64];
    let mut protocol = [0u8; 32];
    assert_eq!(
        ConnectRequest::decode(
            &non_utf8,
            ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol)
        ),
        Err(ConnectError::NonUtf8)
    );

    // QPACK failures surface as `ConnectError::Qpack`.
    let mut scratch = [0u8; 8];
    let mut section = FieldSection::new(&[0x00, 0x00, 0x80]).expect("prefix");
    assert!(matches!(
        section.next_field(&mut scratch),
        Err(QpackError::DynamicTableNotSupported)
    ));
    let mut scheme = [0u8; 16];
    let mut authority = [0u8; 64];
    let mut path = [0u8; 64];
    let mut protocol = [0u8; 32];
    assert_eq!(
        ConnectRequest::decode(
            &[0x00, 0x00, 0x80],
            ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol)
        ),
        Err(ConnectError::Qpack(QpackError::DynamicTableNotSupported))
    );
}

#[test]
fn m3_h5_connect_response_validation() {
    let duplicate = encode_section(&[
        FieldLine::new(b":status", b"200"),
        FieldLine::new(b":status", b"404"),
    ]);
    assert_eq!(
        ConnectResponse::decode(&duplicate),
        Err(ConnectError::DuplicatePseudoHeader)
    );

    let missing = encode_section(&[FieldLine::new(b"x-regular", b"1")]);
    assert_eq!(
        ConnectResponse::decode(&missing),
        Err(ConnectError::MissingPseudoHeader)
    );

    let after_regular = encode_section(&[
        FieldLine::new(b"x-regular", b"1"),
        FieldLine::new(b":status", b"200"),
    ]);
    assert_eq!(
        ConnectResponse::decode(&after_regular),
        Err(ConnectError::PseudoHeaderAfterField)
    );

    let unexpected = encode_section(&[FieldLine::new(b":method", b"CONNECT")]);
    assert_eq!(
        ConnectResponse::decode(&unexpected),
        Err(ConnectError::UnexpectedPseudoHeader)
    );

    assert_eq!(
        ConnectResponse::decode(&[0x00_u8, 0x00, 0x80]),
        Err(ConnectError::Qpack(QpackError::DynamicTableNotSupported))
    );

    for value in [
        &b"099"[..],
        &b"999"[..],
        &b"abc"[..],
        &b"20"[..],
        &b"2000"[..],
    ] {
        let invalid = encode_section(&[FieldLine::new(b":status", value)]);
        assert_eq!(
            ConnectResponse::decode(&invalid),
            Err(ConnectError::InvalidStatus)
        );
    }

    let response = ConnectResponse::new(404).expect("status");
    let mut too_small = [0u8; 1];
    assert_eq!(
        response.encode(&mut too_small),
        Err(ConnectError::Qpack(QpackError::Wire(
            WireError::OutputTooSmall
        )))
    );
}

#[test]
fn m3_h4_qpack_literal_forms_and_bounds() {
    // A literal name that needs a multi-byte 3-bit-prefix length, and a
    // non-static value, exercise the literal-name encoder and decoder.
    let fields = [
        FieldLine::new(b"x-very-long-custom-header-name", b"some-value"),
        FieldLine::new(b":path", b"/a-longer-path-than-the-static-entry"),
    ];
    let encoded = encode_section(&fields);
    let mut scratch = [0u8; 512];
    let decoded = collect(&encoded, &mut scratch);
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].0, b"x-very-long-custom-header-name");
    assert_eq!(decoded[0].1, b"some-value");
    assert_eq!(decoded[1].0, b":path");
    assert_eq!(decoded[1].1, b"/a-longer-path-than-the-static-entry");

    // `RFC 7541` Appendix C Huffman vectors (`custom-key: custom-value`),
    // carried as a QPACK literal-name field with a Huffman name and value.
    let huffman_vector = [
        0x00, 0x00, 0x2F, 0x01, 0x25, 0xA8, 0x49, 0xE9, 0x5B, 0xA9, 0x7D, 0x7F, 0x89, 0x25, 0xA8,
        0x49, 0xE9, 0x5B, 0xB8, 0xE8, 0xB4, 0xBF,
    ];
    let mut scratch = [0u8; 64];
    let mut section = FieldSection::new(&huffman_vector).expect("prefix");
    let field = section
        .next_field(&mut scratch)
        .expect("vector")
        .expect("field");
    assert_eq!(field.name(), b"custom-key");
    assert_eq!(field.value(), b"custom-value");
    assert!(section.is_complete());

    // A value that needs the 7-bit prefix continuation bytes still round-trips.
    let long_value = [b'a'; 200];
    let encoded = encode_section(&[FieldLine::new(b"x-long", &long_value)]);
    let mut scratch = [0u8; 512];
    let decoded = collect(&encoded, &mut scratch);
    assert_eq!(decoded[0].0, b"x-long");
    assert_eq!(decoded[0].1, long_value);

    // Huffman strings that Chrome emits are decoded; malformed ones are not.
    let eos = [0x00, 0x00, 0x50, 0x84, 0xFF, 0xFF, 0xFF, 0xFC];
    let mut scratch = [0u8; 64];
    let mut section = FieldSection::new(&eos).expect("prefix");
    assert_eq!(
        section.next_field(&mut scratch).expect_err("EOS"),
        QpackError::InvalidHuffman
    );
    for bytes in [
        &[0x00, 0x00, 0x50, 0x81, 0xFF][..],
        &[0x00, 0x00, 0x50, 0x81, 0x00][..],
        &[0x00, 0x00, 0x50, 0x84, 0xBF, 0xFF, 0xFF, 0xFF][..],
    ] {
        let mut section = FieldSection::new(bytes).expect("prefix");
        assert_eq!(
            section.next_field(&mut scratch).expect_err("Huffman"),
            QpackError::InvalidHuffman
        );
    }

    // Scratch bounds, for Huffman and non-Huffman strings.
    let mut empty: [u8; 0] = [];
    let huffman_value = [0x00, 0x00, 0x50, 0x81, 0x00];
    let mut section = FieldSection::new(&huffman_value).expect("prefix");
    assert_eq!(
        section.next_field(&mut empty).expect_err("scratch"),
        QpackError::ScratchTooSmall
    );
    let plain_value = [0x00, 0x00, 0x50, 0x02, b'a', b'b'];
    let mut section = FieldSection::new(&plain_value).expect("prefix");
    assert_eq!(
        section.next_field(&mut empty).expect_err("scratch"),
        QpackError::ScratchTooSmall
    );

    // Static table bounds.
    let out_of_range = [0x00, 0x00, 0xFF, 0x24];
    let mut section = FieldSection::new(&out_of_range).expect("prefix");
    assert_eq!(
        section.next_field(&mut scratch).expect_err("index"),
        QpackError::StaticIndexOutOfRange
    );
    let name_out_of_range = [0x00, 0x00, 0x5F, 0x54, 0x00];
    let mut section = FieldSection::new(&name_out_of_range).expect("prefix");
    assert_eq!(
        section.next_field(&mut scratch).expect_err("name index"),
        QpackError::StaticIndexOutOfRange
    );

    // A prefixed integer that cannot fit in `u64`.
    let mut overflow = vec![0x00, 0xFF];
    overflow.extend_from_slice(&[0xFF; 11]);
    assert_eq!(
        FieldSection::new(&overflow).expect_err("base overflow"),
        QpackError::IntegerOverflow
    );

    // The field line cap.
    let mut capped = vec![0x00, 0x00];
    capped.extend(std::iter::repeat_n(0xCF, MAX_FIELD_LINES + 1));
    let mut section = FieldSection::new(&capped).expect("prefix");
    assert_eq!(section.remaining_lines(), MAX_FIELD_LINES);
    for _ in 0..MAX_FIELD_LINES {
        assert!(section.next_field(&mut scratch).expect("field").is_some());
    }
    assert_eq!(
        section.next_field(&mut scratch).expect_err("cap"),
        QpackError::TooManyFieldLines
    );
    assert!(!section.is_complete());

    // Encoder bounds.
    let mut too_small: [u8; 0] = [];
    assert_eq!(
        qpack::encode_fields(&[FieldLine::new(b"a", b"b")], &mut too_small),
        Err(QpackError::Wire(WireError::OutputTooSmall))
    );
    let many = vec![FieldLine::new(b":method", b"CONNECT"); MAX_FIELD_LINES + 1];
    let mut buffer = [0u8; 512];
    assert_eq!(
        qpack::encode_fields(&many, &mut buffer),
        Err(QpackError::TooManyFieldLines)
    );

    // A truncated prefix surfaces as a wire error.
    assert!(matches!(
        FieldSection::new(&[]),
        Err(QpackError::Wire(WireError::UnexpectedEnd))
    ));
    assert!(matches!(
        FieldSection::new(&[0x00]),
        Err(QpackError::Wire(WireError::UnexpectedEnd))
    ));

    // Name-plus-value scratch is a single budget.
    let mut tiny = [0u8; 1];
    let long_name = encode_section(&[FieldLine::new(b"a-long-name", b"v")]);
    let mut section = FieldSection::new(&long_name).expect("prefix");
    assert_eq!(
        section.next_field(&mut tiny).expect_err("name scratch"),
        QpackError::ScratchTooSmall
    );
}

//! `M3-H2` evidence: H3 frame header round trip, rejection of a declared
//! length larger than the input, and preservation of unknown frame types.

use rtx_wire::h3_frame::Frame;
use rtx_wire::varint::VarInt;
use rtx_wire::{Decode, Encode, WireError};

fn frame(frame_type: u64, payload: &[u8]) -> Frame<'_> {
    Frame::new(VarInt::new(frame_type).expect("valid frame type"), payload)
}

#[test]
fn m3_h2_frame_header_round_trip() {
    let cases: [(u64, &[u8]); 4] = [
        (0x01, b"DATA"),
        (0x21, b""),
        (0x2700, b"large type"),
        (0x1F, b"settings"),
    ];
    for (frame_type, payload) in cases {
        let mut buffer = [0u8; 64];
        let written = frame(frame_type, payload)
            .encode(&mut buffer)
            .expect("encode frame");
        assert_eq!(written, frame(frame_type, payload).encoded_len());

        let (decoded, consumed) = Frame::decode(&buffer[..written]).expect("decode frame");
        assert_eq!(decoded.frame_type().get(), frame_type);
        assert_eq!(decoded.payload(), payload);
        assert_eq!(consumed, written);

        // The payload borrows the decoded buffer directly (zero copy).
        let header_len = written - payload.len();
        let expected = &buffer[header_len..written];
        assert_eq!(decoded.payload().as_ptr(), expected.as_ptr());
    }

    // Trailing bytes after the frame belong to the caller.
    let mut buffer = [0u8; 16];
    let written = frame(0x01, b"abc")
        .encode(&mut buffer)
        .expect("encode frame");
    buffer[written] = 0xFF;
    let (decoded, consumed) = Frame::decode(&buffer[..=written]).expect("decode with trailing");
    assert_eq!(consumed, written);
    assert_eq!(decoded.payload(), b"abc");

    // A buffer smaller than `encoded_len` is rejected without a partial frame.
    assert_eq!(
        frame(0x01, b"abc").encode(&mut [0u8; 2]),
        Err(WireError::OutputTooSmall)
    );
}

#[test]
fn m3_h2_truncated_payload_rejected() {
    // Type 0x01, declared payload length 5, only 3 payload bytes present.
    assert_eq!(
        Frame::decode(&[0x01, 0x05, 0xAA, 0xBB, 0xCC]),
        Err(WireError::UnexpectedEnd)
    );
    // Truncated frame type varint.
    assert_eq!(Frame::decode(&[]), Err(WireError::UnexpectedEnd));
    // Truncated length varint (2-byte prefix with no second byte).
    assert_eq!(Frame::decode(&[0x01, 0x40]), Err(WireError::UnexpectedEnd));
    // A declared length of zero is legal and consumes only the header.
    let (empty, consumed) = Frame::decode(&[0x01, 0x00]).expect("empty payload");
    assert!(empty.payload().is_empty());
    assert_eq!(empty.frame_type().get(), 0x01);
    assert_eq!(consumed, 2);
}

#[test]
fn m3_h2_unknown_frame_preserved() {
    // Unregistered type 0x21 with a 3-byte payload, then an empty type 0x01.
    let bytes = [0x21u8, 0x03, 0xAA, 0xBB, 0xCC, 0x01, 0x00];
    let (unknown, consumed) = Frame::decode(&bytes).expect("unknown frame");
    assert_eq!(consumed, 5);
    assert_eq!(unknown.frame_type().get(), 0x21);
    assert_eq!(unknown.payload(), &[0xAA, 0xBB, 0xCC]);

    // The parser hands the frame back verbatim, so skipping it is the caller's
    // decision rather than a silent drop inside the codec.
    let mut output = [0u8; 8];
    let written = unknown.encode(&mut output).expect("re-encode unknown");
    assert_eq!(&output[..written], &bytes[..consumed]);

    // The caller can now skip the unknown frame and read the next one.
    let (next, next_consumed) = Frame::decode(&bytes[consumed..]).expect("next frame");
    assert_eq!(next.frame_type().get(), 0x01);
    assert!(next.payload().is_empty());
    assert_eq!(next_consumed, 2);
}

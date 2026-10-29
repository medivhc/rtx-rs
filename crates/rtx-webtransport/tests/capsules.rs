//! `M3-H7` evidence: capsule round trip with the draft-registered type values,
//! unknown capsules preserved for the caller to skip, and payload-limit
//! rejection.

use rtx_webtransport::capsules::{
    Capsule, CapsuleError, MAX_CLOSE_MESSAGE_LEN, WT_CLOSE_SESSION, WT_DRAIN_SESSION,
    WT_STREAM_FIN, WT_STREAM_NO_FIN,
};
use rtx_webtransport::ids::StreamId;
use rtx_wire::Encode;
use rtx_wire::varint;

#[test]
fn m3_h7_capsule_round_trip() {
    let close = Capsule::CloseSession {
        code: 0x2A,
        message: "bye",
    };
    let drain = Capsule::DrainSession;
    let open = Capsule::Stream {
        stream_id: StreamId::new(0x1_0000_0000).expect("stream id"),
        fin: false,
        data: b"abc",
    };
    let finished = Capsule::Stream {
        stream_id: StreamId::new(3).expect("stream id"),
        fin: true,
        data: b"",
    };

    for capsule in [close, drain, open, finished] {
        let mut buffer = [0u8; 64];
        let written = capsule.encode(&mut buffer).expect("encode capsule");
        assert_eq!(written, Encode::encoded_len(&capsule));
        assert_eq!(written, capsule.encoded_len());

        let (decoded, consumed) =
            Capsule::decode(&buffer[..written], 4096).expect("decode capsule");
        assert_eq!(decoded, capsule);
        assert_eq!(consumed, written);

        // Framing is a type varint followed by a payload-length varint.
        let (capsule_type, type_len) = varint::decode(&buffer[..written]).expect("capsule type");
        let (payload_len, len_len) =
            varint::decode(&buffer[type_len..written]).expect("capsule length");
        let payload_len = usize::try_from(payload_len).expect("fits usize");
        assert_eq!(type_len + len_len + payload_len, written);

        if let Capsule::CloseSession { .. } = capsule {
            assert_eq!(capsule_type, WT_CLOSE_SESSION);
            assert_eq!(payload_len, 4 + "bye".len());
            let body = type_len + len_len;
            assert_eq!(&buffer[body..body + 4], &0x2A_u32.to_be_bytes());
            assert_eq!(&buffer[body + 4..written], b"bye");
        }
        if let Capsule::DrainSession = capsule {
            assert_eq!(capsule_type, WT_DRAIN_SESSION);
            assert_eq!(payload_len, 0);
        }
        if let Capsule::Stream { fin, .. } = capsule {
            let expected = if fin { WT_STREAM_FIN } else { WT_STREAM_NO_FIN };
            assert_eq!(capsule_type, expected);
            // The payload starts with the stream ID varint.
            let (stream_id, _) =
                varint::decode(&buffer[type_len + len_len..written]).expect("stream id varint");
            assert!(stream_id <= StreamId::MAX);
        }
    }

    // The declared maximum-length close message still parses.
    let message = "x".repeat(MAX_CLOSE_MESSAGE_LEN);
    let capsule = Capsule::CloseSession {
        code: 0,
        message: &message,
    };
    let mut buffer = [0u8; 1032];
    let written = capsule.encode(&mut buffer).expect("encode max message");
    let (decoded, consumed) =
        Capsule::decode(&buffer[..written], 4096).expect("decode max message");
    assert_eq!(decoded, capsule);
    assert_eq!(consumed, written);
}

#[test]
fn m3_h7_unknown_capsule_ignored() {
    // Unknown type 0x21 with a 3-byte payload, then a WT_DRAIN_SESSION capsule.
    let bytes = [0x21, 0x03, 0xAA, 0xBB, 0xCC, 0x80, 0x00, 0x78, 0xAE, 0x00];
    let (unknown, consumed) = Capsule::decode(&bytes, 64).expect("unknown capsule");
    assert_eq!(consumed, 5);
    assert_eq!(
        unknown,
        Capsule::Unknown {
            capsule_type: 0x21,
            payload: &[0xAA, 0xBB, 0xCC],
        }
    );

    // The unknown capsule re-encodes verbatim; it was not silently dropped.
    let mut output = [0u8; 16];
    let written = unknown.encode(&mut output).expect("re-encode unknown");
    assert_eq!(&output[..written], &bytes[..consumed]);

    // The caller skips it and immediately reads the next capsule.
    let (next, next_consumed) = Capsule::decode(&bytes[consumed..], 64).expect("next capsule");
    assert_eq!(next, Capsule::DrainSession);
    assert_eq!(next_consumed, 5);
}

#[test]
fn m3_h7_oversize_rejected() {
    // Type 0x01 with a 600-byte declared payload and no body.
    assert_eq!(
        Capsule::decode(&[0x01, 0x42, 0x58], 512),
        Err(CapsuleError::TooLarge { max_len: 512 })
    );
    // The same bytes under a larger limit are truncated rather than oversized.
    assert_eq!(
        Capsule::decode(&[0x01, 0x42, 0x58], 1024),
        Err(CapsuleError::Truncated)
    );
    // Declared length inside the limit but beyond the input.
    assert_eq!(
        Capsule::decode(&[0x01, 0x0A, 0xAA, 0xBB], 1024),
        Err(CapsuleError::Truncated)
    );
    // Truncated framing: no type, then no length.
    assert_eq!(Capsule::decode(&[], 1024), Err(CapsuleError::Truncated));
    assert_eq!(Capsule::decode(&[0x01], 1024), Err(CapsuleError::Truncated));

    // WT_CLOSE_SESSION message longer than 1024 bytes.
    let mut bytes = [0u8; 1040];
    let type_len = varint::encode(WT_CLOSE_SESSION, &mut bytes).expect("type");
    let message_len = MAX_CLOSE_MESSAGE_LEN + 1;
    let payload_len = 4 + message_len;
    let len_len = varint::encode(
        u64::try_from(payload_len).expect("fits"),
        &mut bytes[type_len..],
    )
    .expect("length");
    let body = type_len + len_len;
    bytes[body..body + 4].copy_from_slice(&0_u32.to_be_bytes());
    let total = body + payload_len;
    assert_eq!(
        Capsule::decode(&bytes[..total], 4096),
        Err(CapsuleError::Malformed)
    );

    // Invalid UTF-8 in the close message.
    let mut bytes = [0u8; 16];
    let type_len = varint::encode(WT_CLOSE_SESSION, &mut bytes).expect("type");
    let len_len = varint::encode(5, &mut bytes[type_len..]).expect("length");
    let body = type_len + len_len;
    bytes[body..body + 4].copy_from_slice(&0_u32.to_be_bytes());
    bytes[body + 4] = 0xFF;
    let total = body + 5;
    assert_eq!(
        Capsule::decode(&bytes[..total], 4096),
        Err(CapsuleError::Malformed)
    );

    // WT_DRAIN_SESSION must have an empty payload.
    let mut bytes = [0u8; 16];
    let type_len = varint::encode(WT_DRAIN_SESSION, &mut bytes).expect("type");
    let len_len = varint::encode(1, &mut bytes[type_len..]).expect("length");
    let body = type_len + len_len;
    bytes[body] = 0x00;
    let total = body + 1;
    assert_eq!(
        Capsule::decode(&bytes[..total], 4096),
        Err(CapsuleError::Malformed)
    );

    // WT_CLOSE_SESSION without room for the 32-bit error code.
    let mut bytes = [0u8; 16];
    let type_len = varint::encode(WT_CLOSE_SESSION, &mut bytes).expect("type");
    let len_len = varint::encode(3, &mut bytes[type_len..]).expect("length");
    let body = type_len + len_len;
    bytes[body..body + 3].copy_from_slice(&[0x00, 0x00, 0x00]);
    let total = body + 3;
    assert_eq!(
        Capsule::decode(&bytes[..total], 4096),
        Err(CapsuleError::Malformed)
    );

    // WT_STREAM with an empty payload has no stream ID varint.
    let mut bytes = [0u8; 16];
    let type_len = varint::encode(WT_STREAM_NO_FIN, &mut bytes).expect("type");
    let len_len = varint::encode(0, &mut bytes[type_len..]).expect("length");
    let total = type_len + len_len;
    assert_eq!(
        Capsule::decode(&bytes[..total], 4096),
        Err(CapsuleError::Malformed)
    );

    // Encoding into a too-small buffer is rejected.
    let capsule = Capsule::CloseSession {
        code: 1,
        message: "x",
    };
    assert_eq!(
        capsule.encode(&mut [0u8; 4]),
        Err(CapsuleError::OutputTooSmall)
    );
}

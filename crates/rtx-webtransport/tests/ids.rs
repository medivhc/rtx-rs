//! `M3-H6` evidence: session and stream identifier round trips, rejection of
//! invalid identifiers, and exact values above `u32::MAX` (no `usize`
//! truncation on 32-bit targets).

use rtx_webtransport::ids::{IdError, QuarterStreamId, SessionId, StreamId};
use rtx_wire::varint::{self, MAX_VARINT};
use rtx_wire::{Decode, Encode, WireError};

#[test]
fn m3_h6_session_and_stream_id_round_trip() {
    for id in [0u64, 4, 8, 4092, 0x1_0000_0000, 0xFFFF_FFFC] {
        let session = SessionId::new(id).expect("client bidirectional stream");
        assert_eq!(session.get(), id);
        assert_eq!(session.quarter().stream_id(), id);
        assert_eq!(session.quarter().get(), id >> 2);
    }

    for id in [0u64, 1, 2, 3, 16_383, MAX_VARINT] {
        let stream = StreamId::new(id).expect("62-bit stream id");
        assert_eq!(stream.get(), id);
    }
    assert_eq!(StreamId::MAX, MAX_VARINT);

    let cases = [0u64, 1, 63, 64, QuarterStreamId::MAX];
    for quarter in cases {
        let id = QuarterStreamId::new(quarter).expect("quarter in range");
        assert_eq!(id.get(), quarter);
        assert_eq!(id.stream_id(), quarter << 2);
        assert_eq!(id.encoded_len(), varint::encoded_len(quarter));

        let mut buffer = [0u8; 8];
        let written = id.encode(&mut buffer).expect("encode quarter");
        let (decoded, consumed) = QuarterStreamId::decode(&buffer[..written]).expect("decode");
        assert_eq!(decoded, id);
        assert_eq!(consumed, written);
    }
    assert_eq!(QuarterStreamId::MAX, MAX_VARINT >> 2);

    // Derivation from stream IDs and reconstruction back to them.
    for stream in [0u64, 4, 8, 0x1_0000_0000] {
        let quarter = QuarterStreamId::from_stream_id(stream).expect("aligned stream id");
        assert_eq!(quarter.stream_id(), stream);
        assert_eq!(quarter, SessionId::new(stream).expect("session").quarter());
    }

    // Encoding uses the shared `rtx-wire` varint: the bytes are identical.
    let id = QuarterStreamId::new(0x1_0000_0000).expect("quarter");
    let mut shared = [0u8; 8];
    let shared_len = varint::encode(id.get(), &mut shared).expect("shared varint");
    let mut encoded = [0u8; 8];
    let encoded_len = id.encode(&mut encoded).expect("id encode");
    assert_eq!(encoded[..encoded_len], shared[..shared_len]);
}

#[test]
fn m3_h6_invalid_id_rejected() {
    for id in [1u64, 2, 3, 5] {
        assert_eq!(
            SessionId::new(id),
            Err(IdError::NotClientBidirectional),
            "stream id {id}"
        );
    }
    assert_eq!(SessionId::new(MAX_VARINT + 1), Err(IdError::OutOfRange));
    assert_eq!(SessionId::new(u64::MAX), Err(IdError::OutOfRange));
    assert_eq!(StreamId::new(MAX_VARINT + 1), Err(IdError::OutOfRange));
    assert_eq!(StreamId::new(u64::MAX), Err(IdError::OutOfRange));
    assert_eq!(
        QuarterStreamId::new(QuarterStreamId::MAX + 1),
        Err(IdError::OutOfRange)
    );
    assert_eq!(
        QuarterStreamId::from_stream_id(2),
        Err(IdError::NotQuarterAligned)
    );
    assert_eq!(
        QuarterStreamId::from_stream_id(6),
        Err(IdError::NotQuarterAligned)
    );
    assert_eq!(
        QuarterStreamId::from_stream_id(MAX_VARINT + 1),
        Err(IdError::OutOfRange)
    );

    // A decodable varint outside the 60-bit quarter space is rejected.
    assert_eq!(
        QuarterStreamId::decode(&[0xFF; 8]),
        Err(IdError::OutOfRange)
    );
    // Truncated input and short output surface the varint error.
    assert_eq!(
        QuarterStreamId::decode(&[0x40]),
        Err(IdError::Wire(WireError::UnexpectedEnd))
    );
    let quarter = QuarterStreamId::new(64).expect("quarter");
    assert_eq!(
        quarter.encode(&mut [0u8; 1]),
        Err(IdError::Wire(WireError::OutputTooSmall))
    );
}

#[test]
fn m3_h6_no_usize_truncation() {
    // Every value here is above `u32::MAX` and must survive exactly.
    let big_stream = 0x1_0000_0004u64;
    assert!(big_stream > u64::from(u32::MAX));
    let stream = StreamId::new(big_stream).expect("stream");
    assert_eq!(stream.get(), big_stream);

    let big_session = 0x1_0000_0000u64;
    assert!(big_session > u64::from(u32::MAX));
    let session = SessionId::new(big_session).expect("session");
    assert_eq!(session.get(), big_session);
    assert_eq!(session.quarter().get(), big_session >> 2);
    assert_eq!(session.quarter().stream_id(), big_session);

    let quarter = session.quarter();
    let mut buffer = [0u8; 8];
    let written = quarter.encode(&mut buffer).expect("encode quarter");
    let (decoded, consumed) = QuarterStreamId::decode(&buffer[..written]).expect("decode quarter");
    assert_eq!(decoded, quarter);
    assert_eq!(consumed, written);

    let direct = QuarterStreamId::new(0x1_0000_0000).expect("quarter > u32::MAX");
    assert!(direct.get() > u64::from(u32::MAX));
    assert_eq!(direct.stream_id(), 0x4_0000_0000);

    // The wrappers hold `u64`, not `usize`.
    assert_eq!(core::mem::size_of::<SessionId>(), 8);
    assert_eq!(core::mem::size_of::<StreamId>(), 8);
    assert_eq!(core::mem::size_of::<QuarterStreamId>(), 8);
}

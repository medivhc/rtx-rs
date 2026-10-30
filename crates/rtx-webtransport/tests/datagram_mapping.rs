//! `M3-H8` evidence: HTTP Datagram mapping round trip, rejection of a quarter
//! stream ID that belongs to another session, malformed payload rejection, and
//! the caller-supplied size bound.

use rtx_webtransport::datagram::{self, DatagramError};
use rtx_webtransport::ids::SessionId;

#[test]
fn m3_h8_datagram_mapping_round_trip() {
    let session = SessionId::new(0x1_0000_0000).expect("session");
    let payload = b"webtransport payload";
    let mut buffer = [0u8; 64];
    let written = datagram::encode(session, payload, 1200, &mut buffer).expect("encode datagram");
    assert_eq!(written, session.quarter().encoded_len() + payload.len());

    let (decoded, consumed) =
        datagram::decode(&buffer[..written], session, 1200).expect("decode datagram");
    assert_eq!(consumed, written);
    assert_eq!(decoded.session(), session);
    assert_eq!(decoded.payload(), payload);

    // The payload borrows the input buffer instead of copying it.
    let header_len = session.quarter().encoded_len();
    let expected = &buffer[header_len..written];
    assert_eq!(decoded.payload().as_ptr(), expected.as_ptr());

    // An empty WebTransport payload is still a valid datagram.
    let written = datagram::encode(session, b"", 1200, &mut buffer).expect("encode empty");
    let (decoded, consumed) =
        datagram::decode(&buffer[..written], session, 1200).expect("decode empty");
    assert_eq!(decoded.payload(), []);
    assert_eq!(consumed, written);

    // Both directions honour the caller-supplied negotiated limit exactly.
    let at_limit = 1 + payload.len();
    let limit_session = SessionId::new(4).expect("session");
    let written =
        datagram::encode(limit_session, payload, at_limit, &mut buffer).expect("encode at limit");
    assert_eq!(written, at_limit);
    assert_eq!(
        datagram::encode(limit_session, payload, at_limit - 1, &mut buffer),
        Err(DatagramError::TooLarge {
            max_len: at_limit - 1
        })
    );
    assert_eq!(
        datagram::decode(&buffer[..written], limit_session, at_limit - 1),
        Err(DatagramError::TooLarge {
            max_len: at_limit - 1
        })
    );
}

#[test]
fn m3_h8_wrong_session_rejected() {
    let session = SessionId::new(4).expect("session");
    let other = SessionId::new(8).expect("other session");
    let mut buffer = [0u8; 16];
    let written = datagram::encode(session, b"x", 1200, &mut buffer).expect("encode");
    assert_eq!(
        datagram::decode(&buffer[..written], other, 1200),
        Err(DatagramError::WrongSession)
    );
}

#[test]
fn m3_h8_malformed_rejected() {
    let session = SessionId::new(4).expect("session");
    // Empty payload: no quarter stream ID at all.
    assert_eq!(
        datagram::decode(&[], session, 1200),
        Err(DatagramError::Malformed)
    );
    // Truncated two-byte varint.
    assert_eq!(
        datagram::decode(&[0x40], session, 1200),
        Err(DatagramError::Malformed)
    );
    // Decodable varint outside the 60-bit quarter stream ID space.
    assert_eq!(
        datagram::decode(&[0xFF; 8], session, 1200),
        Err(DatagramError::Malformed)
    );
    // A well-formed quarter for another session is a session error.
    assert_eq!(
        datagram::decode(&[0x02, 0x00], session, 1200),
        Err(DatagramError::WrongSession)
    );
    // A small output buffer is reported explicitly.
    assert_eq!(
        datagram::encode(session, b"x", 1200, &mut [0u8; 1]),
        Err(DatagramError::OutputTooSmall)
    );
}

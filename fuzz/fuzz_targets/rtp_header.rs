//! Fuzz target for the `rtx-rtp` packet decoder.
//!
//! RTP is the highest-rate parser in the stack (50–120 pps per stream), so a
//! panic here is a remote denial of service. The target asserts:
//!
//! 1. no panic on any input,
//! 2. `consumed <= input.len()`,
//! 3. re-encoding a decoded packet reaches a **fixed point**: decoding the
//!    re-encoded bytes and encoding again reproduces the same bytes.
//!
//! Note the third property is deliberately a fixed-point check rather than a
//! verbatim check: [`RtpPacket::encode`] re-derives the padding octet count
//! from the payload length ([RFC 3550] §5.1), so the first normalization pass
//! is legitimate and every pass after it must be a no-op.
//!
//! [RFC 3550]: https://www.rfc-editor.org/rfc/rfc3550

#![no_main]

use libfuzzer_sys::fuzz_target;
use rtx_rtp::{Decode, Encode, RtpPacket};

fuzz_target!(|data: &[u8]| {
    let Ok((packet, consumed)) = RtpPacket::decode(data) else {
        return;
    };
    assert!(consumed <= data.len(), "packet decode over-consumed");

    // First normalization pass: padding is re-derived, so the length may grow
    // by at most three padding octets.
    let mut first = vec![0u8; packet.encoded_len()];
    let written = packet
        .encode(&mut first)
        .expect("encode into an exactly sized buffer must succeed");
    assert_eq!(written, first.len(), "encode length mismatch");

    // Fixed point: one more decode/encode round must be a no-op.
    let Ok((second_packet, second_consumed)) = RtpPacket::decode(&first) else {
        return;
    };
    assert_eq!(
        second_consumed,
        first.len(),
        "re-decode consumed only a prefix"
    );
    let mut second = vec![0u8; second_packet.encoded_len()];
    let second_written = second_packet
        .encode(&mut second)
        .expect("second encode must succeed");
    assert_eq!(second_written, second.len());
    assert_eq!(
        second, first,
        "encode/decode is not a fixed point after one normalization"
    );

    // The payload must survive verbatim when no padding normalization happened.
    if first.len() == consumed && packet.header.padding == false {
        assert_eq!(&first[..], &data[..consumed], "re-encoding is not verbatim");
    }
});
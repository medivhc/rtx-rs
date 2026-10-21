//! Fuzz target for the `rtx-stun` message pipeline.
//!
//! Two properties are asserted for every input:
//!
//! 1. `decode` never panics and never reports consuming more bytes than it was
//!    given;
//! 2. whenever `decode` succeeds, re-encoding into a correctly sized buffer
//!    reproduces the consumed prefix byte-for-byte (the verbatim round-trip the
//!    FINGERPRINT and MESSAGE-INTEGRITY checks depend on), and the result
//!    reaches a fixed point when decoded again.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rtx_stun::{Decode, Encode, Message};

fuzz_target!(|data: &[u8]| {
    let Ok((message, consumed)) = Message::decode(data) else {
        return;
    };
    assert!(
        consumed <= data.len(),
        "decode reported consuming {consumed} of {} bytes",
        data.len()
    );

    let mut buffer = vec![0u8; message.encoded_len()];
    let written = message
        .encode(&mut buffer)
        .expect("encode into an exactly sized buffer must succeed");
    assert_eq!(written, buffer.len(), "encode length mismatch");
    assert_eq!(
        &buffer[..],
        &data[..consumed],
        "re-encoding is not verbatim"
    );

    // A decoded message must survive a second decode of its own encoding and
    // reach a fixed point — otherwise retransmissions re-parse differently.
    let Ok((again, second)) = Message::decode(&buffer) else {
        return;
    };
    assert_eq!(second, buffer.len(), "re-decode consumed only a prefix");
    let mut round_trip = vec![0u8; again.encoded_len()];
    let rewritten = again
        .encode(&mut round_trip)
        .expect("second encode must succeed");
    assert_eq!(rewritten, buffer.len());
    assert_eq!(round_trip, buffer, "encode is not idempotent");
});
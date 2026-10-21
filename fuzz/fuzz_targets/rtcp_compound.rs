//! Fuzz target for the `rtx-rtcp` compound dispatcher.
//!
//! RTCP arrives on the same socket as RTP and is fully attacker-controlled in
//! a WebRTC endpoint. The target asserts:
//!
//! 1. `RtcpPacket::decode` never panics,
//! 2. `consumed` is always strictly positive — a zero-length sub-packet would
//!    make the compound walk loop forever,
//! 3. every decoded sub-packet re-encodes to exactly its consumed length,
//! 4. `CompoundPacket::decode` is all-or-nothing: a compound is accepted only
//!    if every element parses and the walk consumes the input exactly.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rtx_rtcp::{CompoundPacket, Decode, Encode, RtcpPacket};

fuzz_target!(|data: &[u8]| {
    // --- single sub-packet ---
    if let Ok((packet, consumed)) = RtcpPacket::decode(data) {
        assert!(consumed <= data.len(), "rtcp decode over-consumed");
        assert!(consumed > 0, "rtcp decode must make progress");

        let mut buffer = vec![0u8; packet.encoded_len()];
        let written = packet
            .encode(&mut buffer)
            .expect("encode into an exactly sized buffer must succeed");
        assert_eq!(written, consumed, "re-encode length differs from decode");

        // Decoding the re-encoded bytes must yield the same packet.
        if let Ok((again, second)) = RtcpPacket::decode(&buffer) {
            assert_eq!(second, consumed);
            assert_eq!(again, packet, "re-decode produced a different packet");
        }
    }

    // --- compound walk ---
    let Ok((compound, consumed)) = CompoundPacket::decode(data) else {
        return;
    };
    assert_eq!(consumed, data.len(), "compound must consume all of its input");

    // Walk the compound independently: every element must decode and the
    // offsets must tile the input exactly.
    let mut offset = 0usize;
    while offset < data.len() {
        let Ok((packet, step)) = RtcpPacket::decode(&data[offset..]) else {
            break;
        };
        assert!(step > 0, "compound walk stalled at offset {offset}");
        let mut buffer = vec![0u8; packet.encoded_len()];
        assert_eq!(
            packet.encode(&mut buffer).expect("encode"),
            step,
            "sub-packet at offset {offset} re-encoded to a different length"
        );
        offset += step;
    }
    assert_eq!(offset, data.len(), "compound walk did not tile the input");
});
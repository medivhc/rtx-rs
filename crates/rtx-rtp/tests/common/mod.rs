//! Shared fixtures for the rtx-rtp integration suite.
//!
//! Follows the `EasyTier` `test_support` pattern: a deterministic LCG
//! (no `rand` dev-dependency), leak-based builders for the zero-copy
//! packet structs and verbatim round-trip assertions over the public
//! [`Decode`]/[`Encode`] contract.

#![allow(dead_code)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]

use rtx_rtp::header::Header;
use rtx_rtp::packet::RtpPacket;
use rtx_wire::{Decode, Encode, WireError};

/// Deterministic xorshift64* generator (no `rand` dev-dependency).
#[derive(Debug)]
pub struct Lcg {
    state: u64,
}

impl Lcg {
    /// Seeds the generator; a zero seed is mapped to a non-zero state.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    /// Advances the generator and returns the next 64-bit output.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Returns the next output truncated to 8 bits.
    #[allow(clippy::cast_possible_truncation)]
    pub fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    /// Returns a value below `bound`.
    pub fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64()).unwrap_or(0) % bound
    }
}

/// Leaks a byte vector into a `'static` slice for the borrowed
/// header regions.
#[must_use]
pub fn leak(bytes: Vec<u8>) -> &'static [u8] {
    Box::leak(bytes.into_boxed_slice())
}

/// Encodes one packet into a fresh vector.
#[must_use]
pub fn encode_packet(packet: &RtpPacket<'_>) -> Vec<u8> {
    let mut out = vec![0u8; packet.encoded_len()];
    let written = packet.encode(&mut out).expect("encode rtp packet");
    assert_eq!(written, out.len(), "encoded_len must match the writer");
    out
}

/// Encodes one header into a fresh vector.
///
/// [`Header`] exposes no public [`Encode`] impl (encoding is validated
/// through [`RtpPacket`]), so the header is wrapped in an empty-payload
/// packet — byte-identical to a bare header on the wire.
#[must_use]
pub fn encode_header(header: &Header<'_>) -> Vec<u8> {
    let packet = RtpPacket {
        header: *header,
        payload: b"",
    };
    encode_packet(&packet)
}

/// Asserts `bytes` decodes to one packet that re-encodes verbatim.
#[must_use]
pub fn assert_packet_verbatim(bytes: &[u8]) -> RtpPacket<'_> {
    let (packet, consumed) = RtpPacket::decode(bytes).expect("decode rtp packet");
    assert_eq!(consumed, bytes.len(), "decode must consume every byte");
    let mut out = vec![0u8; packet.encoded_len()];
    let written = packet.encode(&mut out).expect("re-encode rtp packet");
    assert_eq!(written, out.len());
    assert_eq!(out, bytes, "re-encode must be verbatim");
    packet
}

/// Error kind helper used by the robustness tables.
#[must_use]
pub fn err(bytes: &[u8]) -> Option<WireError> {
    RtpPacket::decode(bytes).err()
}

/// Error kind helper for the header layer.
#[must_use]
pub fn header_err(bytes: &[u8]) -> Option<WireError> {
    Header::decode(bytes).err()
}

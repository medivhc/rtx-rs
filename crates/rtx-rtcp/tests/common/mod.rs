//! Shared fixtures for the rtx-rtcp integration suite.
//!
//! Follows the `EasyTier` `test_support` pattern: deterministic builders for
//! every modelled packet type, a compound concatenator and verbatim
//! assertions — all zero-copy friendly and free of third-party test
//! dependencies.

#![allow(dead_code)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]

use rtx_rtcp::reception_report::ReceptionReport;
use rtx_rtcp::{CompoundPacket, RtcpPacket};
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

    /// Returns the next output truncated to 16 bits.
    #[allow(clippy::cast_possible_truncation)]
    pub fn next_u16(&mut self) -> u16 {
        (self.next_u64() >> 16) as u16
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

    /// Fills `buf` with generator output.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = self.next_u8();
        }
    }
}

/// Encodes one packet into a fresh vector.
#[must_use]
pub fn encode_rtcp(packet: &RtcpPacket<'_>) -> Vec<u8> {
    let mut out = vec![0u8; packet.encoded_len()];
    let written = packet.encode(&mut out).expect("encode rtcp packet");
    assert_eq!(written, out.len(), "encoded_len must match the writer");
    out
}

/// Concatenates encoded packets into one compound datagram.
#[must_use]
pub fn compound(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

/// Builds one 24-byte reception report block.
#[must_use]
pub fn report_block(
    ssrc: u32,
    fraction_lost: u8,
    total_lost: u32,
    highest_sequence: u32,
    jitter: u32,
    last_sr: u32,
    delay_since_last_sr: u32,
) -> [u8; 24] {
    let report = ReceptionReport {
        ssrc,
        fraction_lost,
        total_lost,
        highest_sequence,
        jitter,
        last_sr,
        delay_since_last_sr,
    };
    let mut out = [0u8; 24];
    let written = report.encode(&mut out).expect("24-byte report block");
    assert_eq!(written, 24);
    out
}

/// Builds one SDES chunk: SSRC + items + terminator + zero padding.
#[must_use]
pub fn sdes_chunk(ssrc: u32, items: &[(u8, &[u8])]) -> Vec<u8> {
    let mut chunk = ssrc.to_be_bytes().to_vec();
    for (typ, text) in items {
        chunk.push(*typ);
        chunk.push(u8::try_from(text.len()).expect("item fits u8"));
        chunk.extend_from_slice(text);
    }
    chunk.push(0); // end of item list
    while chunk.len() % 4 != 0 {
        chunk.push(0);
    }
    chunk
}

/// Builds one 4-byte Generic NACK pair (packet id + bitmask).
#[must_use]
pub fn nack_pair(packet_id: u16, lost_packets: u16) -> [u8; 4] {
    let mut out = [0u8; 4];
    out[0..2].copy_from_slice(&packet_id.to_be_bytes());
    out[2..4].copy_from_slice(&lost_packets.to_be_bytes());
    out
}

/// Builds one 4-byte SLI entry (first | number | picture).
#[must_use]
pub fn sli_entry(first: u16, number: u16, picture: u8) -> [u8; 4] {
    let raw = (u32::from(first & 0x1FFF) << 19)
        | (u32::from(number & 0x1FFF) << 6)
        | u32::from(picture & 0x3F);
    raw.to_be_bytes()
}

/// Builds one 8-byte FIR entry (ssrc + sequence + reserved).
#[must_use]
pub fn fir_entry(ssrc: u32, sequence_number: u8) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&ssrc.to_be_bytes());
    out[4] = sequence_number;
    out
}

/// Asserts `bytes` decodes to one packet that re-encodes verbatim.
pub fn assert_packet_verbatim(bytes: &[u8]) -> RtcpPacket<'_> {
    let (packet, consumed) = RtcpPacket::decode(bytes).expect("decode rtcp packet");
    assert_eq!(consumed, bytes.len(), "decode must consume every byte");
    assert_eq!(encode_rtcp(&packet), bytes, "re-encode must be verbatim");
    packet
}

/// Wraps bytes in a compound and asserts the walk is verbatim.
pub fn assert_compound_verbatim(bytes: &[u8]) -> CompoundPacket<'_> {
    let (compound, consumed) = CompoundPacket::decode(bytes).expect("decode compound");
    assert_eq!(consumed, bytes.len());
    assert_eq!(compound.data(), bytes);
    compound
}

/// Error kind helper used by the robustness tables.
#[must_use]
pub fn err(bytes: &[u8]) -> Option<WireError> {
    RtcpPacket::decode(bytes).err()
}

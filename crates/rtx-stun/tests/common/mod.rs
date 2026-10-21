//! Shared fixtures for the rtx-stun integration suite.
//!
//! Follows the `EasyTier` `test_support` pattern: one deterministic builder
//! toolkit — no `rand` dependency, no global state, no network — reused by
//! the themed integration files: the message pipeline, the ICE and TURN
//! protocol scenarios, the robustness suite and the cross-crate bridge
//! against `rtx-core`.

#![allow(dead_code)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]

use rtx_stun::attributes::AttrType;
use rtx_stun::integrity::MessageIntegrity;
use rtx_stun::message::{MESSAGE_HEADER_SIZE, Message, MessageType, MessageWriter, TransactionId};
use rtx_stun::{Decode, Encode, WireError};

/// Deterministic xorshift64* generator.
///
/// The suite deliberately avoids a `rand` dev-dependency: reproducibility
/// beats statistical strength for fuzz-shaped tests, and the workspace
/// keeps zero third-party dependencies.
#[derive(Debug)]
pub struct Lcg {
    state: u64,
}

impl Lcg {
    /// Seeds the generator; a zero seed is mapped to a non-zero state so
    /// the generator can never stick at zero.
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

    /// Returns a value below `bound` (rejection-free modulo).
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

/// A transaction id of `tag` repeated twelve times.
#[must_use]
pub fn tx(tag: u8) -> TransactionId {
    TransactionId([tag; 12])
}

/// Padding bytes a value of `len` occupies on the wire.
#[must_use]
pub const fn padded(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

/// Runs `f` against a fresh writer over `buf` and returns the message
/// length (header included).
pub fn build(
    buf: &mut [u8],
    typ: MessageType,
    transaction_id: TransactionId,
    f: impl FnOnce(&mut MessageWriter<'_>) -> Result<(), WireError>,
) -> Result<usize, WireError> {
    let mut writer = MessageWriter::new(buf, typ, transaction_id)?;
    f(&mut writer)?;
    Ok(writer.written())
}

/// Encodes a decoded message into a fresh vector.
#[must_use]
pub fn encode_msg(msg: &Message<'_>) -> Vec<u8> {
    let mut out = vec![0u8; msg.encoded_len()];
    let written = msg.encode(&mut out).expect("message re-encode");
    assert_eq!(written, out.len(), "encoded_len must match the writer");
    out
}

/// XOR-fold MAC over `key` plus every input part — the same fake the
/// unit tests use, so integration expectations line up with them.
// `unnecessary_wraps`: the signature must match `MacFn`, which can fail.
#[allow(clippy::unnecessary_wraps)]
pub fn mock_mac(key: &[u8], input: &[&[u8]], output: &mut [u8]) -> Result<(), WireError> {
    output.fill(0);
    for (index, &byte) in key
        .iter()
        .chain(input.iter().flat_map(|part| part.iter()))
        .enumerate()
    {
        output[index % output.len()] ^= byte;
    }
    Ok(())
}

/// A `MESSAGE-INTEGRITY` signer over `KEY`.
#[must_use]
pub fn signer() -> MessageIntegrity<'static> {
    MessageIntegrity::new_raw(b"password", mock_mac)
}

/// Asserts `msg` decodes from `bytes` and re-encodes to the same bytes.
pub fn assert_verbatim(bytes: &[u8]) -> Message<'_> {
    let (msg, consumed) = Message::decode(bytes).expect("decode");
    assert_eq!(consumed, bytes.len(), "decode must consume every byte");
    assert_eq!(encode_msg(&msg), bytes, "re-encode must be verbatim");
    msg
}

/// Standard header size constant re-export for the test files.
pub const HEADER: usize = MESSAGE_HEADER_SIZE;

/// Attribute type helper for ad-hoc types used by the fuzzers.
#[must_use]
pub const fn attr(value: u16) -> AttrType {
    AttrType(value)
}

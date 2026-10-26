//! Shared fixtures for the `rtx-dtls` integration suite.
//!
//! Deterministic only: no network, no system clock, no `rand`.

#![allow(dead_code)]

pub mod handshake;

use rtx_crypto::AeadAlgorithm;
use rtx_crypto_rustcrypto::RustCryptoProvider;
use rtx_dtls::{
    ContentType, DatagramMeta, IpAddr, Record, RecordCipher, RecordHeader, SequenceNumber,
    SocketAddr, Timestamp,
};

pub const KEY_128: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];
pub const KEY_256: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];
pub const FIXED_IV: [u8; 4] = [0x7A, 0x7B, 0x7C, 0x7D];

pub fn cipher(algorithm: AeadAlgorithm) -> RecordCipher {
    let key: &[u8] = match algorithm {
        AeadAlgorithm::Aes128Gcm => &KEY_128,
        AeadAlgorithm::Aes256Gcm => &KEY_256,
    };
    RecordCipher::new(algorithm, key, &FIXED_IV).expect("valid key and IV")
}

pub fn provider() -> RustCryptoProvider {
    RustCryptoProvider::new()
}

pub fn meta(now: u64) -> DatagramMeta {
    DatagramMeta {
        now: Timestamp::from_micros(now),
        source: SocketAddr::new(IpAddr::V4([192, 0, 2, 1]), 40_000),
        destination: SocketAddr::new(IpAddr::V4([192, 0, 2, 2]), 40_001),
        ecn: None,
    }
}

pub fn datagram(now: u64, payload: &[u8]) -> rtx_dtls::Input<'_> {
    rtx_dtls::Input::Datagram {
        meta: meta(now),
        payload,
    }
}

pub fn plaintext_wire(sequence: u64, content: &[u8]) -> Vec<u8> {
    let header = RecordHeader {
        content_type: ContentType::ApplicationData,
        epoch: 0,
        sequence_number: SequenceNumber::from_u64(sequence).expect("48-bit"),
        fragment_len: content.len(),
    };
    let mut output = vec![0u8; rtx_dtls::RECORD_HEADER_LEN + content.len()];
    Record {
        header,
        fragment: content,
    }
    .encode(&mut output)
    .expect("encode plaintext");
    output
}

pub fn protected_wire(
    algorithm: AeadAlgorithm,
    epoch: u16,
    sequence: u64,
    content: &[u8],
) -> Vec<u8> {
    let cipher = cipher(algorithm);
    let mut output =
        vec![0u8; rtx_dtls::RECORD_HEADER_LEN + rtx_dtls::AEAD_OVERHEAD + content.len()];
    let written = cipher
        .seal(
            &provider(),
            ContentType::ApplicationData,
            epoch,
            SequenceNumber::from_u64(sequence).expect("48-bit"),
            content,
            &mut output,
        )
        .expect("seal protected");
    assert_eq!(written, output.len());
    output
}

/// Deterministic xorshift64* generator.
#[derive(Debug)]
pub struct Lcg {
    state: u64,
}

impl Lcg {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.state = value;
        value.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn fill(&mut self, output: &mut [u8]) {
        for chunk in output.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
        }
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        self.fill(&mut bytes);
        bytes
    }
}

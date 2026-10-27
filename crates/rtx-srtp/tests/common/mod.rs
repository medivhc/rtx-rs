//! Shared fixtures for the rtx-srtp integration suite.

#![allow(dead_code)]

use rtx_crypto_rustcrypto::RustCryptoProvider;
use rtx_rtp::{Encode, Header, RtpPacket};
use rtx_srtp::{
    AUTH_TAG_LEN, PROFILE_AES128_CM_HMAC_SHA1_80, ReceiverContext, SESSION_KEY_LEN,
    SESSION_SALT_LEN, SenderContext,
};

/// `SSRC` used by the sender and receiver fixtures.
pub const SSRC: u32 = 0xDEAD_BEEF;
/// Session key used by every fixture.
pub const KEY: [u8; SESSION_KEY_LEN] = [0x11; SESSION_KEY_LEN];
/// Session salt used by every fixture.
pub const SALT: [u8; SESSION_SALT_LEN] = [0x22; SESSION_SALT_LEN];

pub type Provider = RustCryptoProvider;

/// Sender context for [`SSRC`].
pub fn sender() -> SenderContext<Provider> {
    sender_for(SSRC)
}

/// Sender context for `ssrc`.
pub fn sender_for(ssrc: u32) -> SenderContext<Provider> {
    SenderContext::new(
        RustCryptoProvider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        KEY,
        SALT,
        ssrc,
    )
    .expect("supported profile")
}

/// Receiver context for [`SSRC`].
pub fn receiver() -> ReceiverContext<Provider> {
    receiver_for(SSRC)
}

/// Receiver context for `ssrc`.
pub fn receiver_for(ssrc: u32) -> ReceiverContext<Provider> {
    ReceiverContext::new(
        RustCryptoProvider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        KEY,
        SALT,
        ssrc,
    )
    .expect("supported profile")
}

/// Encodes an `RTP` packet with two `CSRC` entries, an optional RFC 8285
/// one-byte extension and optional padding.
pub fn rtp(ssrc: u32, sequence: u16, padding: bool, extension: bool) -> Vec<u8> {
    let csrc = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];
    let extension_data = [0x10, 0xAA, 0x00, 0x00];
    let payload = [0x98, 0x36, 0xBE, 0x88, 0x9E];
    let header = Header {
        version: 2,
        padding,
        extension,
        marker: true,
        payload_type: 96,
        sequence_number: sequence,
        timestamp: 0x0102_0304,
        ssrc,
        csrc: &csrc,
        extension_profile: if extension { 0xBEDE } else { 0 },
        extension_data: if extension { &extension_data } else { &[] },
    };
    encode(&header, &payload)
}

/// Encodes a bare `RTP` packet: 12-byte fixed header and no payload.
pub fn minimal_rtp(ssrc: u32, sequence: u16) -> Vec<u8> {
    let header = Header {
        version: 2,
        padding: false,
        extension: false,
        marker: false,
        payload_type: 96,
        sequence_number: sequence,
        timestamp: 0,
        ssrc,
        csrc: &[],
        extension_profile: 0,
        extension_data: &[],
    };
    encode(&header, &[])
}

fn encode(header: &Header<'_>, payload: &[u8]) -> Vec<u8> {
    let packet = RtpPacket {
        header: *header,
        payload,
    };
    let mut bytes = vec![0u8; packet.encoded_len()];
    let written = packet.encode(&mut bytes).expect("encode RTP");
    bytes.truncate(written);
    bytes
}

/// Protects `rtp`, returning exactly `rtp.len() + 10` bytes.
pub fn protect(sender: &mut SenderContext<Provider>, rtp: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; rtp.len() + AUTH_TAG_LEN];
    let written = sender.protect(rtp, &mut output).expect("protect");
    assert_eq!(written, rtp.len() + AUTH_TAG_LEN);
    output
}

/// Unprotects `srtp`, returning the cleartext packet.
pub fn unprotect(receiver: &mut ReceiverContext<Provider>, srtp: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; srtp.len() - AUTH_TAG_LEN];
    let written = receiver.unprotect(srtp, &mut output).expect("unprotect");
    assert_eq!(written, srtp.len() - AUTH_TAG_LEN);
    output
}

/// Deterministic xorshift64* generator (no `rand` dependency).
#[derive(Debug)]
pub struct Lcg {
    state: u64,
}

impl Lcg {
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

    #[allow(clippy::cast_possible_truncation)]
    pub fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    pub fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.next_u8()).collect()
    }
}

/// Decodes an uppercase hex literal into a fixed-size array.
pub fn hex<const N: usize>(input: &str) -> [u8; N] {
    assert_eq!(input.len(), N * 2, "hex literal length");
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&input[offset..offset + 2], 16).expect("hex digit");
    }
    output
}

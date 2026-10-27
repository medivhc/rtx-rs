//! `DTLS-SRTP` media path: export, `RFC 3711` section 4.3 derivation,
//! `RFC 5764` section 4.2 direction mapping and `SRTP` protection.
//!
//! This is a caller-level composition test. It proves that the public
//! `rtx-dtls` exporter and the public `rtx-srtp` constructors can be wired
//! together; it does not claim that a stock `libsrtp`/`OpenSSL` peer would
//! interoperate.
//!
//! The NACK section at the end is likewise a caller-level cross-check: the
//! feedback packet is encoded and decoded by `rtx-rtcp` outside `SRTP`. It is
//! **not** protected by `SRTCP`; no `SRTCP` transform exists in this crate yet
//! (R3-3). The test only shows that the feedback packet and the media path
//! share the same `SSRC` and sequence-number space.

use rtx_crypto_rustcrypto::RustCryptoProvider;
use rtx_dtls::{SRTP_PROFILE_AES128_CM_HMAC_SHA1_80, SrtpKeyingMaterial};
use rtx_rtcp::{Decode, Encode, Nack, NackPair, PacketType};
use rtx_rtp::{Header, RtpPacket};
use rtx_srtp::{
    AUTH_TAG_LEN, DirectionalMasterKeys, Error, PROFILE_AES128_CM_HMAC_SHA1_80, ReceiverContext,
    Role, SenderContext, map_directions,
};

/// Fixed `DTLS` master secret for this test. These values are intentionally
/// different from the constants used by the `rtx-dtls` unit tests.
const MASTER_SECRET_HEX: &str = "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF";
const CLIENT_RANDOM_HEX: &str = "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF";
const SERVER_RANDOM_HEX: &str = "909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF";

/// `SSRC` the client's `SRTP` sender protects and the server's receiver owns.
const CLIENT_SSRC: u32 = 0x0BAD_1DEA;
/// `SSRC` the server's `SRTP` sender protects and the client's receiver owns.
const SERVER_SSRC: u32 = 0x0FEE_D000;

type Provider = RustCryptoProvider;

fn hex<const N: usize>(input: &str) -> [u8; N] {
    assert_eq!(input.len(), N * 2, "hex literal length");
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&input[offset..offset + 2], 16).expect("hex digit");
    }
    output
}

/// Exports the fixed `DTLS-SRTP` keying material through the public API.
fn export() -> SrtpKeyingMaterial {
    SrtpKeyingMaterial::export(
        &Provider::new(),
        SRTP_PROFILE_AES128_CM_HMAC_SHA1_80,
        &hex::<48>(MASTER_SECRET_HEX),
        &hex::<32>(CLIENT_RANDOM_HEX),
        &hex::<32>(SERVER_RANDOM_HEX),
    )
    .expect("export DTLS-SRTP keying material")
}

/// Maps one `rtx-dtls` export into the local send/receive master pairs.
fn directions(role: Role, material: &SrtpKeyingMaterial) -> DirectionalMasterKeys {
    map_directions(
        role,
        *material.client_write_key(),
        *material.client_write_salt(),
        *material.server_write_key(),
        *material.server_write_salt(),
    )
}

fn sender_from(material: &DirectionalMasterKeys, ssrc: u32) -> SenderContext<Provider> {
    SenderContext::from_master(
        Provider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        *material.send_key(),
        *material.send_salt(),
        ssrc,
    )
    .expect("sender from master material")
}

fn receiver_from(material: &DirectionalMasterKeys, ssrc: u32) -> ReceiverContext<Provider> {
    ReceiverContext::from_master(
        Provider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        *material.receive_key(),
        *material.receive_salt(),
        ssrc,
    )
    .expect("receiver from master material")
}

/// An `RTP` packet with two `CSRC` entries and one RFC 8285 one-byte
/// extension element, so the encrypted region starts at the end of the full
/// header rather than at byte 12.
fn rtp(ssrc: u32, sequence: u16) -> Vec<u8> {
    let csrc = [0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0B];
    let extension_data = [0x10, 0xAA, 0x00, 0x00];
    let payload = [0x98, 0x36, 0xBE, 0x88, 0x9E, 0x01, 0x02, 0x03];
    let header = Header {
        version: 2,
        padding: false,
        extension: true,
        marker: true,
        payload_type: 111,
        sequence_number: sequence,
        timestamp: 0x1020_3040,
        ssrc,
        csrc: &csrc,
        extension_profile: 0xBEDE,
        extension_data: &extension_data,
    };
    let packet = RtpPacket {
        header,
        payload: &payload,
    };
    let mut bytes = vec![0u8; packet.encoded_len()];
    let written = packet.encode(&mut bytes).expect("encode RTP");
    bytes.truncate(written);
    bytes
}

fn protect(sender: &mut SenderContext<Provider>, packet: &[u8]) -> Vec<u8> {
    let mut protected = vec![0u8; packet.len() + AUTH_TAG_LEN];
    let written = sender.protect(packet, &mut protected).expect("protect");
    assert_eq!(written, packet.len() + AUTH_TAG_LEN);
    protected
}

fn unprotect(receiver: &mut ReceiverContext<Provider>, protected: &[u8]) -> Vec<u8> {
    let mut cleartext = vec![0u8; protected.len() - AUTH_TAG_LEN];
    let written = receiver
        .unprotect(protected, &mut cleartext)
        .expect("unprotect");
    assert_eq!(written, cleartext.len());
    cleartext
}

// SRTP-DTLS-000 — differential vector from libsrtp 2.5.0. The expected bytes
// were produced by `srtp_protect` with the RFC 3711 Appendix B.3 master
// key/salt, SSRC 0xDEADBEEF, sequence number 0x1234 and a zeroed 16-byte
// payload, then reproduced here through `from_master`. Equality covers the
// §4.3 derivation (`k_e`, `k_a`, `k_s`), the §4.1.1 counter block, the §4.2
// tag and the §3.1 header layout. It is a derivation/protection differential,
// not an end-to-end interoperability claim.
#[test]
fn libsrtp_protected_packet_vector_matches() {
    const EXPECTED: &str =
        "8060123401020304DEADBEEF1E172FEE760E463D222D143B8B04E44C6C16D7E5EEF32ECE8573";

    let mut sender = SenderContext::from_master(
        Provider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        hex::<16>("E1F97A0D3E018BE0D64FA32C06DE4139"),
        hex::<14>("0EC675AD498AFEEBB6960B3AABE6"),
        0xDEAD_BEEF,
    )
    .expect("sender from master material");

    let mut packet = vec![0u8; 28];
    packet[0] = 0x80;
    packet[1] = 96;
    packet[2..4].copy_from_slice(&0x1234_u16.to_be_bytes());
    packet[4..8].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
    packet[8..12].copy_from_slice(&0xDEAD_BEEF_u32.to_be_bytes());

    assert_eq!(protect(&mut sender, &packet), hex::<38>(EXPECTED));
}

// SRTP-DTLS-001 — export → §4.2 direction mapping → §4.3 derivation →
// protect/unprotect round trip in both directions, with `CSRC` and an
// extension block, byte-exact.
#[test]
fn dtls_srtp_bidirectional_media_roundtrip() {
    let material = export();
    assert_eq!(material.profile(), SRTP_PROFILE_AES128_CM_HMAC_SHA1_80);
    assert_eq!(
        SRTP_PROFILE_AES128_CM_HMAC_SHA1_80,
        PROFILE_AES128_CM_HMAC_SHA1_80
    );

    let client = directions(Role::Client, &material);
    let server = directions(Role::Server, &material);

    // RFC 5764 section 4.2: a client sends client_write and receives
    // server_write; a server is the mirror image.
    assert_eq!(client.send_key(), material.client_write_key());
    assert_eq!(client.send_salt(), material.client_write_salt());
    assert_eq!(client.receive_key(), material.server_write_key());
    assert_eq!(client.receive_salt(), material.server_write_salt());
    assert_eq!(server.send_key(), material.server_write_key());
    assert_eq!(server.send_salt(), material.server_write_salt());
    assert_eq!(server.receive_key(), material.client_write_key());
    assert_eq!(server.receive_salt(), material.client_write_salt());

    let mut client_sender = sender_from(&client, CLIENT_SSRC);
    let mut server_receiver = receiver_from(&server, CLIENT_SSRC);
    let mut server_sender = sender_from(&server, SERVER_SSRC);
    let mut client_receiver = receiver_from(&client, SERVER_SSRC);

    // Client -> server.
    let client_packet = rtp(CLIENT_SSRC, 10);
    let protected = protect(&mut client_sender, &client_packet);
    assert_eq!(protected.len(), client_packet.len() + AUTH_TAG_LEN);
    // 12-byte fixed header + two CSRCs (8) + extension header and data (8).
    let enc_start = 12 + 4 * 2 + (4 + 4);
    assert_eq!(
        &protected[..enc_start],
        &client_packet[..enc_start],
        "full header stays cleartext (RFC 3711 §3.1)"
    );
    assert_ne!(
        &protected[enc_start..client_packet.len()],
        &client_packet[enc_start..],
        "payload is encrypted"
    );
    assert_eq!(unprotect(&mut server_receiver, &protected), client_packet);
    assert_eq!(client_sender.ssrc(), CLIENT_SSRC);
    assert_eq!(server_receiver.ssrc(), CLIENT_SSRC);

    // Server -> client.
    let server_packet = rtp(SERVER_SSRC, 20);
    let protected = protect(&mut server_sender, &server_packet);
    assert_eq!(protected.len(), server_packet.len() + AUTH_TAG_LEN);
    assert_eq!(
        &protected[..enc_start],
        &server_packet[..enc_start],
        "full header stays cleartext (RFC 3711 §3.1)"
    );
    assert_ne!(
        &protected[enc_start..server_packet.len()],
        &server_packet[enc_start..],
        "payload is encrypted"
    );
    assert_eq!(unprotect(&mut client_receiver, &protected), server_packet);
    assert_eq!(server_sender.ssrc(), SERVER_SSRC);
    assert_eq!(client_receiver.ssrc(), SERVER_SSRC);
}

// SRTP-DTLS-002 — a receiver wired to the opposite direction's master
// material (client_write and server_write swapped) must fail authentication
// and leave the caller's output buffer untouched (R3-1 tag-failure semantics).
#[test]
fn swapped_direction_material_fails_authentication_without_side_effects() {
    let material = export();
    let client = directions(Role::Client, &material);
    let server = directions(Role::Server, &material);

    // Client -> server packets are protected with client_write. A receiver
    // that swapped the direction pairs feeds server_write instead.
    let mut client_sender = sender_from(&client, CLIENT_SSRC);
    let client_packet = rtp(CLIENT_SSRC, 30);
    let protected = protect(&mut client_sender, &client_packet);

    let mut wrong_receiver = ReceiverContext::from_master(
        Provider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        *server.send_key(),
        *server.send_salt(),
        CLIENT_SSRC,
    )
    .expect("swapped receiver");
    let mut output = vec![0xA5_u8; client_packet.len()];
    assert_eq!(
        wrong_receiver.unprotect(&protected, &mut output),
        Err(Error::AuthenticationFailed)
    );
    assert!(
        output.iter().all(|&byte| byte == 0xA5),
        "a failed authentication must not write to the output buffer"
    );

    // The same bytes authenticate with the right receive-direction material,
    // so the failure above is key-direction, not packet corruption.
    let mut server_receiver = receiver_from(&server, CLIENT_SSRC);
    assert_eq!(unprotect(&mut server_receiver, &protected), client_packet);

    // Server -> client packets are protected with server_write. A receiver
    // that swapped the direction pairs feeds client_write instead.
    let mut server_sender = sender_from(&server, SERVER_SSRC);
    let server_packet = rtp(SERVER_SSRC, 40);
    let protected = protect(&mut server_sender, &server_packet);

    let mut wrong_receiver = ReceiverContext::from_master(
        Provider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        *client.send_key(),
        *client.send_salt(),
        SERVER_SSRC,
    )
    .expect("swapped receiver");
    let mut output = vec![0x5A_u8; server_packet.len()];
    assert_eq!(
        wrong_receiver.unprotect(&protected, &mut output),
        Err(Error::AuthenticationFailed)
    );
    assert!(output.iter().all(|&byte| byte == 0x5A));

    let mut client_receiver = receiver_from(&client, SERVER_SSRC);
    assert_eq!(unprotect(&mut client_receiver, &protected), server_packet);
}

// SRTP-DTLS-003 — caller-level RTCP feedback linkage: a Generic NACK names
// the dropped media sequence number and the same media `SSRC` the SRTP
// context protects. The NACK is handled as cleartext RTCP; it never passes
// through `protect` and no SRTCP transform exists yet (R3-3).
#[test]
fn rtcp_nack_feedback_shares_the_srtp_media_ssrc_and_sequence_space() {
    let material = export();
    let client = directions(Role::Client, &material);
    let server = directions(Role::Server, &material);

    let mut client_sender = sender_from(&client, CLIENT_SSRC);
    let mut server_receiver = receiver_from(&server, CLIENT_SSRC);

    // Sequence number 102 is intentionally never sent.
    let mut delivered = Vec::new();
    for sequence in [100_u16, 101, 103] {
        let packet = rtp(CLIENT_SSRC, sequence);
        let protected = protect(&mut client_sender, &packet);
        delivered.push((sequence, unprotect(&mut server_receiver, &protected)));
    }
    assert_eq!(
        delivered
            .iter()
            .map(|(sequence, _)| *sequence)
            .collect::<Vec<_>>(),
        vec![100, 101, 103]
    );
    assert_eq!(
        client_sender.ssrc(),
        server_receiver.ssrc(),
        "sender and receiver share one media SSRC"
    );

    // Generic NACK (RFC 4585 §6.2.1) for the missing sequence number. The
    // feedback sender is the server; the media source is the client.
    let missing = 102_u16;
    let pair = NackPair::new(missing);
    let pair_bytes = [
        pair.packet_id.to_be_bytes()[0],
        pair.packet_id.to_be_bytes()[1],
        pair.lost_packets.to_be_bytes()[0],
        pair.lost_packets.to_be_bytes()[1],
    ];
    let nack = Nack {
        sender_ssrc: SERVER_SSRC,
        media_ssrc: CLIENT_SSRC,
        nacks: &pair_bytes,
    };
    let mut encoded = vec![0u8; nack.encoded_len()];
    let written = nack.encode(&mut encoded).expect("encode NACK");
    assert_eq!(written, nack.encoded_len());
    assert_eq!(
        written, 16,
        "NACK is exactly its RTCP wire size: no SRTP tag"
    );

    // The NACK is not protected by SRTP: these are plain RTCP header fields.
    let header = nack.header();
    assert_eq!(header.packet_type, PacketType::Tsfb);
    assert_eq!(header.count, rtx_rtcp::nack::FMT_NACK);

    let (decoded, consumed) = Nack::decode(&encoded).expect("decode NACK");
    assert_eq!(consumed, encoded.len());
    assert_eq!(decoded.sender_ssrc, SERVER_SSRC);
    assert_eq!(
        decoded.media_ssrc,
        client_sender.ssrc(),
        "feedback and SRTP media share one SSRC space"
    );
    let mut reported = Vec::new();
    for pair in decoded.pairs() {
        reported.extend(pair.packet_ids());
    }
    assert_eq!(reported, vec![missing]);
    assert!(
        delivered.iter().all(|(sequence, _)| *sequence != missing),
        "the reported sequence number was indeed dropped"
    );
}

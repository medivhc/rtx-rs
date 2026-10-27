//! `SRTCP` integration: `DTLS-SRTP` export → `RFC 5764` section 4.2 direction
//! mapping → `RFC 3711` section 4.3.2 derivation → section 3.4 protection.
//!
//! This is a caller-level composition test over the public APIs of `rtx-dtls`,
//! `rtx-rtcp` and `rtx-srtp`. It proves that a compound RTCP packet survives
//! the SRTCP wire format byte for byte, that the derived keys and the
//! direction mapping are wired together, and that tampering, a swapped
//! direction and a replay are all rejected.
//!
//! The `libsrtp` vector is a differential check of the SRTCP transform, not an
//! end-to-end interoperability claim with stock `libsrtp`.

use rtx_crypto_rustcrypto::RustCryptoProvider;
use rtx_dtls::{SRTP_PROFILE_AES128_CM_HMAC_SHA1_80, SrtpKeyingMaterial};
use rtx_rtcp::{CompoundPacket, Encode, SenderReport, SourceDescription};
use rtx_srtp::{
    DirectionalMasterKeys, Error, PROFILE_AES128_CM_HMAC_SHA1_80, Role, SESSION_AUTH_KEY_LEN,
    SESSION_KEY_LEN, SESSION_SALT_LEN, SRTCP_OVERHEAD, SrtcpReceiverContext, SrtcpSenderContext,
    map_directions,
};

type Provider = RustCryptoProvider;

/// Fixed `DTLS` master secret for this test. Deliberately different from the
/// constants used by the `rtx-dtls` unit tests and by the R3-2 SRTP test.
const MASTER_SECRET_HEX: &str = "7172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0";
const CLIENT_RANDOM_HEX: &str = "B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0";
const SERVER_RANDOM_HEX: &str = "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";

/// `SSRC` of the client's RTCP stream.
const CLIENT_SSRC: u32 = 0x0BAD_1DEA;
/// `SSRC` of the server's RTCP stream.
const SERVER_SSRC: u32 = 0x0FEE_D000;

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

fn sender_from(material: &DirectionalMasterKeys, ssrc: u32) -> SrtcpSenderContext<Provider> {
    SrtcpSenderContext::from_master(
        Provider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        *material.send_key(),
        *material.send_salt(),
        ssrc,
    )
    .expect("SRTCP sender from master material")
}

fn receiver_from(material: &DirectionalMasterKeys, ssrc: u32) -> SrtcpReceiverContext<Provider> {
    SrtcpReceiverContext::from_master(
        Provider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        *material.receive_key(),
        *material.receive_salt(),
        ssrc,
    )
    .expect("SRTCP receiver from master material")
}

/// Builds a valid compound RTCP packet: a sender report followed by an SDES
/// packet carrying a CNAME (`RFC 3550` section 6.1).
fn compound(ssrc: u32) -> Vec<u8> {
    let report = SenderReport {
        ssrc,
        ntp_time: 0x0000_0001_0000_0002,
        rtp_time: 0x0000_0003,
        packet_count: 0x0000_0004,
        octet_count: 0x0000_0005,
        report_blocks: &[],
        profile_extensions: &[],
    };
    let mut report_bytes = vec![0u8; report.encoded_len()];
    let written = report.encode(&mut report_bytes).expect("encode SR");
    assert_eq!(written, report_bytes.len());

    let cname = b"rtx@example";
    let mut body = Vec::new();
    body.extend_from_slice(&ssrc.to_be_bytes());
    body.push(1);
    body.push(u8::try_from(cname.len()).expect("CNAME length"));
    body.extend_from_slice(cname);
    body.push(0);
    while body.len() % 4 != 0 {
        body.push(0);
    }
    let sdes = SourceDescription { body: &body };
    let mut sdes_bytes = vec![0u8; sdes.encoded_len()];
    let written = sdes.encode(&mut sdes_bytes).expect("encode SDES");
    assert_eq!(written, sdes_bytes.len());

    let mut packet = report_bytes;
    packet.extend_from_slice(&sdes_bytes);
    CompoundPacket::new(&packet)
        .validate()
        .expect("valid compound RTCP packet");
    packet
}

fn protect(sender: &mut SrtcpSenderContext<Provider>, packet: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; packet.len() + SRTCP_OVERHEAD];
    let written = sender.protect(packet, &mut output).expect("SRTCP protect");
    assert_eq!(written, output.len());
    output
}

fn unprotect(receiver: &mut SrtcpReceiverContext<Provider>, packet: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; packet.len() - SRTCP_OVERHEAD];
    let written = receiver
        .unprotect(packet, &mut output)
        .expect("SRTCP unprotect");
    assert_eq!(written, output.len());
    output
}

/// Reads the 31-bit SRTCP index from the wire, ignoring the E-flag.
fn index_of(packet: &[u8]) -> u32 {
    let at = packet.len() - SRTCP_OVERHEAD;
    u32::from_be_bytes([packet[at], packet[at + 1], packet[at + 2], packet[at + 3]]) & 0x7FFF_FFFF
}

/// True when the E-flag is set.
fn encrypted_flag(packet: &[u8]) -> bool {
    packet[packet.len() - SRTCP_OVERHEAD] & 0x80 != 0
}

// SRTP-SRTCP-IT-001 — export → direction mapping → section 4.3.2 derivation →
// section 3.4 protect/unprotect in both directions, byte-exact. The compound
// packet contains a sender report and an SDES CNAME.
#[test]
fn dtls_export_and_direction_mapping_roundtrip_compound_rtcp() {
    let material = export();
    assert_eq!(material.profile(), SRTP_PROFILE_AES128_CM_HMAC_SHA1_80);
    assert_eq!(
        SRTP_PROFILE_AES128_CM_HMAC_SHA1_80,
        PROFILE_AES128_CM_HMAC_SHA1_80
    );
    assert_eq!(
        material.client_write_key().len()
            + material.server_write_key().len()
            + material.client_write_salt().len()
            + material.server_write_salt().len(),
        60,
        "RFC 5764 section 4.2 exports 2 * (16 + 14) bytes"
    );

    let client = directions(Role::Client, &material);
    let server = directions(Role::Server, &material);

    // RFC 5764 section 4.2: a client sends client_write and receives
    // server_write; a server is the mirror image. The same mapping feeds the
    // SRTCP contexts.
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
    let client_packet = compound(CLIENT_SSRC);
    let protected = protect(&mut client_sender, &client_packet);
    assert_eq!(protected.len(), client_packet.len() + SRTCP_OVERHEAD);
    assert_eq!(
        &protected[..8],
        &client_packet[..8],
        "the first RTCP header and SSRC stay cleartext (RFC 3711 §3.4)"
    );
    assert_ne!(
        &protected[8..client_packet.len()],
        &client_packet[8..],
        "octet 9 to the end of the compound packet is encrypted"
    );
    assert!(encrypted_flag(&protected));
    assert_eq!(index_of(&protected), 0, "the first SRTCP index is zero");
    assert_eq!(unprotect(&mut server_receiver, &protected), client_packet);
    assert_eq!(client_sender.ssrc(), CLIENT_SSRC);
    assert_eq!(server_receiver.ssrc(), CLIENT_SSRC);

    // Server -> client.
    let server_packet = compound(SERVER_SSRC);
    let protected = protect(&mut server_sender, &server_packet);
    assert_eq!(
        &protected[..8],
        &server_packet[..8],
        "the first RTCP header and SSRC stay cleartext (RFC 3711 §3.4)"
    );
    assert_eq!(unprotect(&mut client_receiver, &protected), server_packet);
    assert_eq!(server_sender.ssrc(), SERVER_SSRC);
    assert_eq!(client_receiver.ssrc(), SERVER_SSRC);
}

// SRTP-SRTCP-IT-002 — differential vector from libsrtp 2.5.0. The expected
// bytes were produced by `srtp_protect_rtcp` with the RFC 3711 Appendix B.3
// master key/salt, SSRC 0xDEADBEEF and the 52-byte compound packet built
// above. libsrtp increments its RTCP counter before use, so its first packet
// carries index 1; this crate follows RFC 3711 section 3.4 and starts at 0,
// so the second packet protected here (index 1) is compared. Equality covers
// the section 4.3.2 SRTCP labels, the section 4.1.1 counter block, the
// section 3.4 encrypted/authenticated portions and the E-flag/index encoding.
#[test]
fn libsrtp_srtcp_protected_vector_matches() {
    const EXPECTED: &str = "80C80006DEADBEEF1FFA1594870F8D8EF1F18915ACD0E676F22FF133140FB007FB29709321B42B4F32AAD0FEBF98705AB8A01EAB80000001835F3BE65D851DB4888A";

    let mut sender = SrtcpSenderContext::from_master(
        Provider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        hex::<16>("E1F97A0D3E018BE0D64FA32C06DE4139"),
        hex::<14>("0EC675AD498AFEEBB6960B3AABE6"),
        0xDEAD_BEEF,
    )
    .expect("SRTCP sender from master material");

    let packet = compound(0xDEAD_BEEF);
    assert_eq!(packet.len(), 52);
    let first = protect(&mut sender, &packet);
    assert_eq!(index_of(&first), 0, "RFC 3711 §3.4 starts at index 0");

    let second = protect(&mut sender, &packet);
    assert_eq!(index_of(&second), 1);
    assert_eq!(second, hex::<66>(EXPECTED));
}

// SRTP-SRTCP-IT-003 (reverse proof a) — tampering the ciphertext or the tag
// returns AuthenticationFailed and leaves the caller's output untouched.
#[test]
fn tampered_ciphertext_and_tag_fail_authentication_without_output() {
    let material = export();
    let client = directions(Role::Client, &material);
    let server = directions(Role::Server, &material);
    let mut sender = sender_from(&client, CLIENT_SSRC);
    let packet = compound(CLIENT_SSRC);
    let protected = protect(&mut sender, &packet);

    for (name, position) in [
        ("ciphertext", 8),
        ("tag", protected.len() - 1),
        ("index", protected.len() - SRTCP_OVERHEAD + 3),
    ] {
        let mut tampered = protected.clone();
        tampered[position] ^= 0x01;
        let mut receiver = receiver_from(&server, CLIENT_SSRC);
        let mut output = vec![0xA5_u8; packet.len()];
        assert_eq!(
            receiver.unprotect(&tampered, &mut output),
            Err(Error::AuthenticationFailed),
            "tampered {name}"
        );
        assert!(
            output.iter().all(|&byte| byte == 0xA5),
            "tampered {name} must not write the output buffer"
        );
    }
}

// SRTP-SRTCP-IT-004 (reverse proof b) — swapped direction material fails
// authentication; the correct material accepts the same bytes.
#[test]
fn swapped_direction_material_fails_authentication() {
    let material = export();
    let client = directions(Role::Client, &material);
    let server = directions(Role::Server, &material);

    // Client -> server bytes are protected with client_write. A receiver that
    // swapped the pairs feeds server_write (= client.receive) instead.
    let mut client_sender = sender_from(&client, CLIENT_SSRC);
    let client_packet = compound(CLIENT_SSRC);
    let protected = protect(&mut client_sender, &client_packet);

    let mut wrong_receiver = SrtcpReceiverContext::from_master(
        Provider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        *server.send_key(),
        *server.send_salt(),
        CLIENT_SSRC,
    )
    .expect("swapped receiver");
    let mut output = vec![0x5A_u8; client_packet.len()];
    assert_eq!(
        wrong_receiver.unprotect(&protected, &mut output),
        Err(Error::AuthenticationFailed)
    );
    assert!(output.iter().all(|&byte| byte == 0x5A));

    // The same bytes authenticate with the right receive-direction material.
    let mut server_receiver = receiver_from(&server, CLIENT_SSRC);
    assert_eq!(unprotect(&mut server_receiver, &protected), client_packet);

    // Server -> client, mirrored.
    let mut server_sender = sender_from(&server, SERVER_SSRC);
    let server_packet = compound(SERVER_SSRC);
    let protected = protect(&mut server_sender, &server_packet);

    let mut wrong_receiver = SrtcpReceiverContext::from_master(
        Provider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        *client.send_key(),
        *client.send_salt(),
        SERVER_SSRC,
    )
    .expect("swapped receiver");
    let mut output = vec![0xA5_u8; server_packet.len()];
    assert_eq!(
        wrong_receiver.unprotect(&protected, &mut output),
        Err(Error::AuthenticationFailed)
    );
    assert!(output.iter().all(|&byte| byte == 0xA5));

    let mut client_receiver = receiver_from(&client, SERVER_SSRC);
    assert_eq!(unprotect(&mut client_receiver, &protected), server_packet);
}

// SRTP-SRTCP-IT-005 (reverse proof c) — replaying the same authenticated
// packet (same SRTCP index) is rejected without touching the output.
#[test]
fn replayed_srtcp_packet_is_rejected() {
    let material = export();
    let client = directions(Role::Client, &material);
    let server = directions(Role::Server, &material);
    let mut sender = sender_from(&client, CLIENT_SSRC);
    let mut receiver = receiver_from(&server, CLIENT_SSRC);

    let packet = compound(CLIENT_SSRC);
    let protected = protect(&mut sender, &packet);
    assert_eq!(unprotect(&mut receiver, &protected), packet);

    let mut output = vec![0x3C_u8; packet.len()];
    assert_eq!(
        receiver.unprotect(&protected, &mut output),
        Err(Error::Replay)
    );
    assert!(output.iter().all(|&byte| byte == 0x3C));

    // A later packet is still accepted, so the receiver is not wedged.
    let next = protect(&mut sender, &packet);
    assert_eq!(index_of(&next), 1);
    assert_eq!(unprotect(&mut receiver, &next), packet);
}

// SRTP-SRTCP-IT-006 — one sender increments the wire index by exactly one per
// protected packet; the E-flag is set because this crate always encrypts.
#[test]
fn wire_index_increments_by_one() {
    let material = export();
    let client = directions(Role::Client, &material);
    let mut sender = sender_from(&client, CLIENT_SSRC);
    let packet = compound(CLIENT_SSRC);

    let first = protect(&mut sender, &packet);
    let second = protect(&mut sender, &packet);
    let third = protect(&mut sender, &packet);
    assert_eq!(index_of(&first), 0);
    assert_eq!(index_of(&second), 1);
    assert_eq!(index_of(&third), 2);
    for protected in [&first, &second, &third] {
        assert!(encrypted_flag(protected));
    }
}

// SRTP-SRTCP-IT-007 — the direct session-material constructor round-trips the
// same compound packet. Unlike `from_master`, `new` takes the three SRTCP
// session values and performs no derivation.
#[test]
fn direct_session_material_roundtrip() {
    const ENCRYPTION_KEY: [u8; SESSION_KEY_LEN] = [0x0A; SESSION_KEY_LEN];
    const AUTHENTICATION_KEY: [u8; SESSION_AUTH_KEY_LEN] = [0x0B; SESSION_AUTH_KEY_LEN];
    const SALT: [u8; SESSION_SALT_LEN] = [0x0C; SESSION_SALT_LEN];

    let packet = compound(CLIENT_SSRC);
    let mut sender = SrtcpSenderContext::new(
        Provider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        ENCRYPTION_KEY,
        AUTHENTICATION_KEY,
        SALT,
        CLIENT_SSRC,
    )
    .expect("SRTCP sender from session material");
    let mut receiver = SrtcpReceiverContext::new(
        Provider::new(),
        PROFILE_AES128_CM_HMAC_SHA1_80,
        ENCRYPTION_KEY,
        AUTHENTICATION_KEY,
        SALT,
        CLIENT_SSRC,
    )
    .expect("SRTCP receiver from session material");

    let protected = protect(&mut sender, &packet);
    assert_eq!(unprotect(&mut receiver, &protected), packet);
}

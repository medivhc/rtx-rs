//! End-to-end protection scenarios over the public API.
//!
//! The packets exercise the `CSRC`, header-extension and `RTP` padding paths;
//! the authenticated region covers the cleartext fixed header plus the whole
//! encrypted suffix.

mod common;

use common::{
    KEY, SSRC, hex, minimal_rtp, protect, receiver, receiver_for, rtp, sender, sender_for,
    unprotect,
};
use rtx_crypto::Aes128BlockProvider;
use rtx_crypto_rustcrypto::RustCryptoProvider;
use rtx_srtp::{
    AUTH_TAG_LEN, Error, FIXED_HEADER_LEN, PROFILE_AES128_CM_HMAC_SHA1_80, ReceiverContext,
    SenderContext,
};

// SRTP-RT-001 — CSRC list, header extension and padding survive a round trip
// byte for byte, while the cleartext fixed header is copied verbatim.
#[test]
fn roundtrip_with_csrc_extension_and_padding() {
    let original = rtp(SSRC, 7, true, true);
    let mut sender = sender();
    let protected = protect(&mut sender, &original);

    assert_eq!(protected.len(), original.len() + AUTH_TAG_LEN);
    assert_eq!(
        &protected[..FIXED_HEADER_LEN],
        &original[..FIXED_HEADER_LEN],
        "fixed header must stay cleartext"
    );
    assert_ne!(
        &protected[FIXED_HEADER_LEN..original.len()],
        &original[FIXED_HEADER_LEN..],
        "CSRC/extension/payload/padding must be encrypted"
    );

    let mut receiver = receiver();
    assert_eq!(unprotect(&mut receiver, &protected), original);
    assert_eq!(receiver.rollover_counter(), 0);
    assert_eq!(sender.rollover_counter(), 0);
}

// SRTP-RT-002 — a minimal 12-byte RTP packet round-trips to 22 bytes.
#[test]
fn roundtrip_minimal_packet() {
    let original = minimal_rtp(SSRC, 0);
    assert_eq!(original.len(), FIXED_HEADER_LEN);

    let mut sender = sender();
    let protected = protect(&mut sender, &original);
    assert_eq!(protected.len(), FIXED_HEADER_LEN + AUTH_TAG_LEN);

    let mut receiver = receiver();
    assert_eq!(unprotect(&mut receiver, &protected), original);
}

// SRTP-RT-003 — no CSRC and no extension, only payload and padding.
#[test]
fn roundtrip_payload_with_padding() {
    let original = rtp(SSRC, 42, true, false);
    let mut sender = sender();
    let protected = protect(&mut sender, &original);
    let mut receiver = receiver();
    assert_eq!(unprotect(&mut receiver, &protected), original);
}

// SRTP-RT-004 — a tampered tag is rejected and the output stays untouched.
#[test]
fn tampered_tag_is_rejected_without_touching_output() {
    let original = rtp(SSRC, 3, false, true);
    let mut sender = sender();
    let mut protected = protect(&mut sender, &original);
    let tag_start = protected.len() - 1;
    protected[tag_start] ^= 0x01;

    let mut receiver = receiver();
    let mut output = vec![0x5A_u8; original.len()];
    let before = output.clone();
    assert_eq!(
        receiver.unprotect(&protected, &mut output),
        Err(Error::AuthenticationFailed)
    );
    assert_eq!(output, before);
}

// SRTP-RT-005 — a tampered ciphertext byte is rejected.
#[test]
fn tampered_ciphertext_is_rejected() {
    let original = rtp(SSRC, 4, false, false);
    let mut sender = sender();
    let mut protected = protect(&mut sender, &original);
    protected[FIXED_HEADER_LEN] ^= 0x80;

    let mut receiver = receiver();
    let mut output = vec![0u8; original.len()];
    assert_eq!(
        receiver.unprotect(&protected, &mut output),
        Err(Error::AuthenticationFailed)
    );
}

// SRTP-RT-006 — the tag covers the cleartext fixed header too.
#[test]
fn tampered_header_is_rejected() {
    let original = rtp(SSRC, 5, false, false);
    let mut sender = sender();
    let mut protected = protect(&mut sender, &original);
    protected[1] ^= 0x01; // payload type bit

    let mut receiver = receiver();
    let mut output = vec![0u8; original.len()];
    assert_eq!(
        receiver.unprotect(&protected, &mut output),
        Err(Error::AuthenticationFailed)
    );
}

// SRTP-RT-007 — both directions reject a packet from another SSRC.
#[test]
fn wrong_ssrc_is_rejected_in_both_directions() {
    let original = rtp(SSRC, 6, false, false);

    let mut wrong_sender = sender_for(SSRC + 1);
    let mut output = vec![0u8; original.len() + AUTH_TAG_LEN];
    assert_eq!(
        wrong_sender.protect(&original, &mut output),
        Err(Error::WrongSsrc {
            expected: SSRC + 1,
            found: SSRC,
        })
    );

    let mut sender = sender();
    let protected = protect(&mut sender, &original);
    let mut wrong_receiver = receiver_for(SSRC + 1);
    let mut plaintext = vec![0u8; original.len()];
    assert_eq!(
        wrong_receiver.unprotect(&protected, &mut plaintext),
        Err(Error::WrongSsrc {
            expected: SSRC + 1,
            found: SSRC,
        })
    );
}

// SRTP-RT-008 — only profile 0x0001 is accepted, at construction time.
#[test]
fn unsupported_profile_is_explicit() {
    for profile in [0x0000_u16, 0x0002, 0x0007, 0xFFFF] {
        let sender: Result<SenderContext<RustCryptoProvider>, Error> =
            SenderContext::new(RustCryptoProvider::new(), profile, KEY, common::SALT, SSRC);
        assert_eq!(sender.err(), Some(Error::UnsupportedProfile(profile)));

        let receiver: Result<ReceiverContext<RustCryptoProvider>, Error> =
            ReceiverContext::new(RustCryptoProvider::new(), profile, KEY, common::SALT, SSRC);
        assert_eq!(receiver.err(), Some(Error::UnsupportedProfile(profile)));
    }
}

// SRTP-RT-009 — output sizing is validated before any write.
#[test]
fn output_too_small_never_writes() {
    let original = rtp(SSRC, 8, false, true);
    let mut sender = sender();
    let mut short = vec![0xA5_u8; original.len() + AUTH_TAG_LEN - 1];
    let before = short.clone();
    assert_eq!(
        sender.protect(&original, &mut short),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(short, before);

    let protected = protect(&mut sender, &original);
    let mut receiver = receiver();
    let mut short = vec![0xA5_u8; original.len() - 1];
    let before = short.clone();
    assert_eq!(
        receiver.unprotect(&protected, &mut short),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(short, before);
}

// SRTP-RT-010 — context Debug output redacts the session material.
#[test]
fn debug_redacts_session_material() {
    let sender = sender();
    assert_eq!(sender.ssrc(), SSRC);
    let sender_text = format!("{sender:?}");
    assert!(sender_text.contains("<redacted>"));
    assert!(sender_text.contains("SenderContext"));

    let receiver = receiver();
    assert_eq!(receiver.ssrc(), SSRC);
    let receiver_text = format!("{receiver:?}");
    assert!(receiver_text.contains("<redacted>"));
    assert!(receiver_text.contains("ReceiverContext"));
}

// SRTP-AES-001 — the provider's raw AES-128 block matches FIPS-197 appendix
// C.1, which is the primitive AES-CM is built on.
#[test]
fn provider_aes128_block_matches_fips197() {
    let provider = RustCryptoProvider::new();
    let key = hex::<16>("000102030405060708090A0B0C0D0E0F");
    let mut block = hex::<16>("00112233445566778899AABBCCDDEEFF");
    provider
        .encrypt_aes128_block(&key, &mut block)
        .expect("AES-128 block");
    assert_eq!(block, hex::<16>("69C4E0D86A7B0430D8CDB78070B4C55A"));
}

// SRTP-RT-011 — the profile constant is the RFC 3711/5764 value.
#[test]
fn profile_constant_is_rfc_value() {
    assert_eq!(PROFILE_AES128_CM_HMAC_SHA1_80, 0x0001);
}

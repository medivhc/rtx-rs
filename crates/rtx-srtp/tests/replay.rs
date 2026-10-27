//! Replay-window and rollover-counter scenarios.
//!
//! Delivery order is explicit: each test protects a sequence of packets with
//! one sender context and then feeds them to one receiver in the order named.

mod common;

use common::{SSRC, protect, receiver, rtp, sender, unprotect};
use rtx_srtp::Error;

// SRTP-REPLAY-101 — a duplicate is rejected and does not write the output.
#[test]
fn duplicate_packet_is_replay() {
    let original = rtp(SSRC, 1, false, true);
    let mut sender = sender();
    let protected = protect(&mut sender, &original);

    let mut receiver = receiver();
    assert_eq!(unprotect(&mut receiver, &protected), original);

    let mut output = vec![0xC3_u8; original.len()];
    let before = output.clone();
    assert_eq!(
        receiver.unprotect(&protected, &mut output),
        Err(Error::Replay)
    );
    assert_eq!(output, before);
}

// SRTP-REPLAY-102 — reordering inside the 64-index window is accepted once.
#[test]
fn reordering_inside_the_window_is_accepted_once() {
    let mut sender = sender();
    let mut packets = Vec::new();
    // The sender must protect in send order; only delivery is reordered.
    for sequence in [9_u16, 10, 11, 12] {
        let original = rtp(SSRC, sequence, false, false);
        let protected = protect(&mut sender, &original);
        packets.push((original, protected));
    }

    let mut receiver = receiver();
    for index in [1_usize, 3, 2, 0] {
        assert_eq!(
            &unprotect(&mut receiver, &packets[index].1),
            &packets[index].0
        );
    }

    // The 11-packet was accepted; a second copy is a replay.
    assert_eq!(
        receiver.unprotect(&packets[2].1, &mut vec![0u8; packets[2].0.len()]),
        Err(Error::Replay)
    );
}

// SRTP-REPLAY-103 — an index older than the window is TooOld, not Replay.
#[test]
fn packet_below_the_window_is_too_old() {
    let mut sender = sender();
    let old = rtp(SSRC, 0, false, false);
    let old_protected = protect(&mut sender, &old);
    let new = rtp(SSRC, 100, false, false);
    let new_protected = protect(&mut sender, &new);

    let mut receiver = receiver();
    assert_eq!(unprotect(&mut receiver, &new_protected), new);

    let mut output = vec![0x7E_u8; old.len()];
    let before = output.clone();
    assert_eq!(
        receiver.unprotect(&old_protected, &mut output),
        Err(Error::TooOld)
    );
    assert_eq!(output, before);
}

// SRTP-REPLAY-104 — the sender advances its ROC on 65535 -> 0 and the receiver
// estimates ROC+1 (RFC 3711 Appendix A), then ROC-1 for a late packet.
#[test]
fn rollover_counter_roundtrip_in_both_directions() {
    let mut sender = sender();
    let mut packets = Vec::new();
    for sequence in [65_534_u16, 65_535, 0] {
        let original = rtp(SSRC, sequence, false, false);
        let protected = protect(&mut sender, &original);
        packets.push((original, protected));
    }
    assert_eq!(sender.rollover_counter(), 1);

    let mut receiver = receiver();
    // 65535 establishes ROC = 0 and s_l = 65535.
    assert_eq!(unprotect(&mut receiver, &packets[1].1), packets[1].0);
    assert_eq!(receiver.rollover_counter(), 0);

    // 0 moves the receiver to ROC = 1 (ROC+1 estimate).
    assert_eq!(unprotect(&mut receiver, &packets[2].1), packets[2].0);
    assert_eq!(receiver.rollover_counter(), 1);

    // The late 65534 comes from ROC = 0 (ROC-1 estimate) and is still in the
    // replay window, so it is delivered without moving s_l/ROC.
    assert_eq!(unprotect(&mut receiver, &packets[0].1), packets[0].0);
    assert_eq!(receiver.rollover_counter(), 1);

    // A second late copy is a replay.
    assert_eq!(
        receiver.unprotect(&packets[0].1, &mut vec![0u8; packets[0].0.len()]),
        Err(Error::Replay)
    );
    // So is a second copy of the post-wrap packet.
    assert_eq!(
        receiver.unprotect(&packets[2].1, &mut vec![0u8; packets[2].0.len()]),
        Err(Error::Replay)
    );
}

// SRTP-REPLAY-105 — after the wrap the sender keeps ROC = 1 for ordinary
// sequence numbers, and the receiver agrees.
#[test]
fn post_wrap_packets_stay_in_the_new_roc() {
    let mut sender = sender();
    let before_wrap = rtp(SSRC, 65_535, false, false);
    let before_wrap_protected = protect(&mut sender, &before_wrap);
    let after_wrap = rtp(SSRC, 0, false, false);
    let after_wrap_protected = protect(&mut sender, &after_wrap);
    let next = rtp(SSRC, 1, false, false);
    let next_protected = protect(&mut sender, &next);
    assert_eq!(sender.rollover_counter(), 1);

    let mut receiver = receiver();
    assert_eq!(
        unprotect(&mut receiver, &before_wrap_protected),
        before_wrap
    );
    assert_eq!(unprotect(&mut receiver, &after_wrap_protected), after_wrap);
    assert_eq!(unprotect(&mut receiver, &next_protected), next);
    assert_eq!(receiver.rollover_counter(), 1);
}

// SRTP-REPLAY-106 — a 64-index jump discards the bitmap: the old index becomes
// TooOld, while the boundary index is still accepted.
#[test]
fn window_boundary_is_64_indices() {
    let mut sender = sender();
    let first = rtp(SSRC, 0, false, false);
    let first_protected = protect(&mut sender, &first);
    let boundary = rtp(SSRC, 1, false, false);
    let boundary_protected = protect(&mut sender, &boundary);
    let jump = rtp(SSRC, 64, false, false);
    let jump_protected = protect(&mut sender, &jump);

    let mut receiver = receiver();
    assert_eq!(unprotect(&mut receiver, &first_protected), first);
    assert_eq!(unprotect(&mut receiver, &jump_protected), jump);

    assert_eq!(
        receiver.unprotect(&first_protected, &mut vec![0u8; first.len()]),
        Err(Error::TooOld)
    );
    assert_eq!(unprotect(&mut receiver, &boundary_protected), boundary);
}

// SRTP-AUTH-107 — a stale s_l makes Appendix A guess ROC = 0 for a ROC = 1
// packet. The tag covers the ROC, so the packet fails authentication instead
// of decrypting into garbage with the wrong epoch's keystream.
#[test]
fn stale_roc_estimate_is_authentication_failure() {
    let initial = rtp(SSRC, 0, false, false);
    let mut sender = sender();
    let initial_protected = protect(&mut sender, &initial);

    let mut receiver = receiver();
    assert_eq!(unprotect(&mut receiver, &initial_protected), initial);
    assert_eq!(receiver.rollover_counter(), 0);

    // Advance the sender to ROC = 1 and produce sequence 6 inside that ROC.
    let mut protected_packets = Vec::new();
    for sequence in [65_535_u16, 0, 1, 2, 3, 4, 5, 6] {
        protected_packets.push(protect(&mut sender, &rtp(SSRC, sequence, false, false)));
    }
    assert_eq!(sender.rollover_counter(), 1);
    let last_protected = protected_packets.pop().expect("final packet");

    // The receiver still has s_l = 0 and ROC = 0, so it guesses ROC = 0 and
    // index 6, which is fresh. Without ROC in the tag this would return Ok.
    let mut output = vec![0x5A_u8; initial.len()];
    let before = output.clone();
    assert_eq!(
        receiver.unprotect(&last_protected, &mut output),
        Err(Error::AuthenticationFailed)
    );
    assert_eq!(output, before);
    assert_eq!(receiver.rollover_counter(), 0);
}

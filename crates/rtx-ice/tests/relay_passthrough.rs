//! R4-2-F2: relay pass-through consistency tests.
//!
//! These tests pin the relay candidate contract of `docs/ice-turn-decision.md`
//! §2.B, §3 and §4 using only public API that already exists: a relay
//! candidate carries the relayed transport address in both `address` and
//! `base`, enters the tables through the existing add APIs, pairs, produces
//! checks whose `source` is the relayed address, and nominates — no new API
//! and no TURN implementation is needed or added.
//!
//! There are no sockets: every datagram is an encoded event payload handed
//! back to the checklist with a caller-supplied `DatagramMeta`, which is what
//! a caller does after de-encapsulating a TURN Data indication
//! (`source` = peer, `destination` = local relayed address).

use rtx_core::{DatagramMeta, Input, IpAddr, ProtocolMachine, SocketAddr, Timestamp};
use rtx_ice::{
    COMPONENT_RTP, Candidate, CandidatePair, CandidateType, Checklist, ChecklistState, Event,
    IceError, MAX_STUN_MESSAGE_SIZE, PairState, Role, Transport,
};
use rtx_stun::message::{BINDING_SUCCESS, MessageWriter, TransactionId};

/// Local relayed transport address: `address` and `base` of the local relay
/// candidate (§2.B of the decision: base is the relayed address itself).
const LOCAL_RELAYED: SocketAddr = SocketAddr::new(IpAddr::V4([203, 0, 113, 9]), 3_478);
/// Remote relayed transport address: `address` and `base` of the remote relay
/// candidate.
const REMOTE_RELAYED: SocketAddr = SocketAddr::new(IpAddr::V4([198, 51, 100, 7]), 4_000);
/// A local TURN control socket address. No candidate ever carries it as
/// `base`; it only serves as the negative-control destination for the
/// response-matching assertion in §2.B point 3.
const LOCAL_TURN_SOCKET: SocketAddr = SocketAddr::new(IpAddr::V4([10, 0, 0, 1]), 5_000);
const T0: Timestamp = Timestamp::from_micros(1_000_000);
const ONE_MICRO: rtx_core::Duration = rtx_core::Duration::from_micros(1);
const TIE_CONTROLLING: u64 = 0x0123_4567_89AB_CDEF;

/// Builds a relay candidate with `address == base == relayed`, the contract
/// `docs/ice-turn-decision.md` §2.B and §4.3 pin.
fn relay(relayed: SocketAddr) -> Candidate {
    Candidate::new(
        CandidateType::Relay,
        COMPONENT_RTP,
        Transport::Udp,
        relayed,
        Some(relayed),
    )
    .expect("relay candidate with address == base")
}

fn single_relay_pair(role: Role) -> Checklist {
    let mut checklist = Checklist::new(role, TIE_CONTROLLING);
    checklist
        .add_local_candidate(relay(LOCAL_RELAYED))
        .expect("local relay candidate");
    checklist
        .add_remote_candidate(relay(REMOTE_RELAYED))
        .expect("remote relay candidate");
    assert_eq!(checklist.generate_pairs().expect("relay-relay pair"), 1);
    checklist
}

fn deliver(
    checklist: &mut Checklist,
    now: Timestamp,
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
) -> Result<(), IceError> {
    checklist.handle_input(Input::Datagram {
        meta: DatagramMeta {
            now,
            source,
            destination,
            ecn: None,
        },
        payload,
    })
}

fn drain(checklist: &mut Checklist) -> Vec<Event> {
    let mut events = Vec::new();
    while let Some(event) = checklist.poll_event() {
        events.push(event);
    }
    events
}

fn sends(events: &[Event]) -> Vec<Event> {
    events
        .iter()
        .copied()
        .filter(|event| matches!(event, Event::SendCheck { .. }))
        .collect()
}

/// Encodes a Binding success response carrying no attributes, which is
/// enough for the transaction-id/source/destination match.
fn success_response(transaction_id: TransactionId) -> ([u8; MAX_STUN_MESSAGE_SIZE], usize) {
    let mut message = [0u8; MAX_STUN_MESSAGE_SIZE];
    let length = MessageWriter::new(&mut message, BINDING_SUCCESS, transaction_id)
        .expect("encode success response")
        .written();
    (message, length)
}

/// §2.B, §3 and §4.3: `address = base = relayed` enters the existing tables,
/// pairs, and the pair preserves both addresses through the existing public
/// API — the caller supplies relayed candidates, the crate needs no new API.
#[test]
fn relay_address_equals_base_pairs_without_new_api() {
    let mut checklist = Checklist::new(Role::Controlling, TIE_CONTROLLING);
    checklist
        .add_local_candidate(relay(LOCAL_RELAYED))
        .expect("local relay candidate");
    checklist
        .add_remote_candidate(relay(REMOTE_RELAYED))
        .expect("remote relay candidate");
    assert_eq!(checklist.local_candidate_count(), 1);
    assert_eq!(checklist.remote_candidate_count(), 1);

    assert_eq!(checklist.generate_pairs().expect("relay-relay pair"), 1);
    assert_eq!(checklist.pair_count(), 1);

    let pair: CandidatePair = checklist.pair(0).expect("relay-relay pair");
    assert_eq!(pair.local().typ(), CandidateType::Relay);
    assert_eq!(pair.remote().typ(), CandidateType::Relay);
    assert_eq!(pair.local().address(), LOCAL_RELAYED);
    assert_eq!(pair.local().base(), LOCAL_RELAYED);
    assert_eq!(pair.remote().address(), REMOTE_RELAYED);
    assert_eq!(pair.remote().base(), REMOTE_RELAYED);
    assert_eq!(pair.state(), PairState::Frozen);
    assert!(!pair.is_nominated());
}

/// §2.B argument 2: `SendCheck.source` is `pair.local().base()`, so a relay
/// check reports the relayed address the caller maps back to its allocation.
/// §2.B argument 3: a success response matches only when delivered with
/// `destination` equal to that relayed base — not the local TURN socket.
/// Nomination then completes over the same relayed pair.
#[test]
fn relay_check_event_source_is_relayed_address() {
    let mut checklist = single_relay_pair(Role::Controlling);
    checklist.start(T0).expect("start");

    let check = sends(&drain(&mut checklist)).remove(0);
    let pair = checklist.pair(0).expect("relay-relay pair");
    assert_eq!(check.source(), Some(LOCAL_RELAYED));
    assert_eq!(check.source(), Some(pair.local().base()));
    assert_eq!(check.destination(), Some(REMOTE_RELAYED));
    assert_eq!(check.nominated(), Some(false));
    let transaction_id = check.transaction_id().expect("check transaction id");
    let (response, length) = success_response(transaction_id);

    // Negative control: a de-encapsulated response attributed to the local
    // TURN control socket instead of the relayed address must not match.
    deliver(
        &mut checklist,
        T0 + ONE_MICRO,
        REMOTE_RELAYED,
        LOCAL_TURN_SOCKET,
        &response[..length],
    )
    .expect("mismatched response is ignored");
    assert!(drain(&mut checklist).is_empty());
    assert_eq!(
        checklist.pair(0).expect("pair").state(),
        PairState::InProgress
    );

    // The same response with `destination = relayed address` matches and the
    // controlling agent moves on to nominate the succeeded relay pair.
    deliver(
        &mut checklist,
        T0 + ONE_MICRO,
        REMOTE_RELAYED,
        LOCAL_RELAYED,
        &response[..length],
    )
    .expect("relayed response matches");
    let events = drain(&mut checklist);
    assert!(events.contains(&Event::CheckSucceeded { pair: 0 }));
    let nomination = sends(&events).remove(0);
    assert_eq!(nomination.source(), Some(LOCAL_RELAYED));
    assert_eq!(nomination.destination(), Some(REMOTE_RELAYED));
    assert_eq!(nomination.nominated(), Some(true));

    let (response, length) = success_response(
        nomination
            .transaction_id()
            .expect("nomination check transaction id"),
    );
    deliver(
        &mut checklist,
        T0 + ONE_MICRO,
        REMOTE_RELAYED,
        LOCAL_RELAYED,
        &response[..length],
    )
    .expect("nomination response matches");
    let events = drain(&mut checklist);
    assert!(events.contains(&Event::PairNominated { pair: 0 }));
    assert!(events.contains(&Event::ChecklistCompleted { pair: 0 }));
    assert_eq!(checklist.state(), ChecklistState::Completed);

    let nominated = checklist.nominated_pair().expect("nominated relay pair");
    assert!(nominated.is_nominated());
    assert_eq!(nominated.local().address(), LOCAL_RELAYED);
    assert_eq!(nominated.local().base(), LOCAL_RELAYED);
    assert_eq!(nominated.remote().address(), REMOTE_RELAYED);
    assert_eq!(nominated.remote().base(), REMOTE_RELAYED);
}

/// §4.3: candidates are added before `start`; afterwards both add APIs reject
/// relay candidates with `AlreadyStarted` and leave the tables unchanged, so a
/// TURN allocation must complete before `start`.
#[test]
fn relay_add_after_start_rejected() {
    let mut checklist = single_relay_pair(Role::Controlling);
    checklist.start(T0).expect("start");
    let _ = drain(&mut checklist);

    assert_eq!(
        checklist.add_local_candidate(relay(LOCAL_TURN_SOCKET)),
        Err(IceError::AlreadyStarted)
    );
    assert_eq!(
        checklist.add_remote_candidate(relay(LOCAL_TURN_SOCKET)),
        Err(IceError::AlreadyStarted)
    );
    assert_eq!(checklist.local_candidate_count(), 1);
    assert_eq!(checklist.remote_candidate_count(), 1);
}

/// Regression anchor only: a relay candidate without a base is still rejected
/// by `Candidate::new`. The full base-rule coverage stays in
/// `tests/ice_checklist.rs`.
#[test]
fn relay_missing_base_still_rejected() {
    assert_eq!(
        Candidate::new(
            CandidateType::Relay,
            COMPONENT_RTP,
            Transport::Udp,
            LOCAL_RELAYED,
            None
        ),
        Err(IceError::MissingBaseAddress)
    );
}

//! ICE checklist integration tests: formulas, pair ordering, a two-machine
//! dialogue, loss/retransmission, role conflicts and consent freshness.
//!
//! There are no sockets: every datagram is the encoded event payload passed
//! straight into the peer machine.

#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]

use rtx_core::{DatagramMeta, Duration, Input, IpAddr, ProtocolMachine, SocketAddr, Timestamp};
use rtx_ice::{
    COMPONENT_RTP, Candidate, CandidatePair, CandidateType, Checklist, ChecklistState, Event,
    INITIAL_RTO, IceError, MAX_ICE_CANDIDATES, MAX_RETRANSMISSIONS, MAX_RTO, MAX_STUN_MESSAGE_SIZE,
    PairState, Role, Transport, pair_priority,
};
use rtx_stun::attributes::{
    ATTR_ICE_CONTROLLED, ATTR_ICE_CONTROLLING, ATTR_PRIORITY, ATTR_USE_CANDIDATE,
    ATTR_XORMAPPED_ADDRESS, AttrType,
};
use rtx_stun::message::{
    BINDING_REQUEST, BINDING_SUCCESS, CLASS_INDICATION, CLASS_REQUEST, MAGIC_COOKIE,
    METHOD_ALLOCATE, METHOD_BINDING, Message, MessageType, TransactionId,
};
use rtx_stun::{Decode, WireError};

const A1: SocketAddr = SocketAddr::new(IpAddr::V4([10, 0, 0, 1]), 5_000);
const A2: SocketAddr = SocketAddr::new(IpAddr::V4([10, 0, 0, 1]), 5_001);
const B1: SocketAddr = SocketAddr::new(IpAddr::V4([10, 0, 0, 2]), 6_000);
const B2: SocketAddr = SocketAddr::new(IpAddr::V4([10, 0, 0, 2]), 6_001);
const C1: SocketAddr = SocketAddr::new(IpAddr::V4([10, 0, 0, 3]), 7_000);
const T0: Timestamp = Timestamp::from_micros(1_000_000);
const TIE_CONTROLLING: u64 = 0x0123_4567_89AB_CDEF;
const TIE_CONTROLLED: u64 = 0xFEDC_BA98_7654_3210;
const ONE_MICRO: Duration = Duration::from_micros(1);

fn host(address: SocketAddr) -> Candidate {
    Candidate::new(
        CandidateType::Host,
        COMPONENT_RTP,
        Transport::Udp,
        address,
        None,
    )
    .expect("host candidate")
}

fn srflx(address: SocketAddr, base: SocketAddr) -> Candidate {
    Candidate::new(
        CandidateType::ServerReflexive,
        COMPONENT_RTP,
        Transport::Udp,
        address,
        Some(base),
    )
    .expect("server-reflexive candidate")
}

fn peer_reflexive(address: SocketAddr, base: SocketAddr) -> Candidate {
    Candidate::new(
        CandidateType::PeerReflexive,
        COMPONENT_RTP,
        Transport::Udp,
        address,
        Some(base),
    )
    .expect("peer-reflexive candidate")
}

fn relay(address: SocketAddr, base: SocketAddr) -> Candidate {
    Candidate::new(
        CandidateType::Relay,
        COMPONENT_RTP,
        Transport::Udp,
        address,
        Some(base),
    )
    .expect("relay candidate")
}

fn meta(now: Timestamp, source: SocketAddr, destination: SocketAddr) -> DatagramMeta {
    DatagramMeta {
        now,
        source,
        destination,
        ecn: None,
    }
}

fn deliver(
    checklist: &mut Checklist,
    now: Timestamp,
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
) -> Result<(), IceError> {
    checklist.handle_input(Input::Datagram {
        meta: meta(now, source, destination),
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

fn responses(events: &[Event]) -> Vec<Event> {
    events
        .iter()
        .copied()
        .filter(|event| matches!(event, Event::SendResponse { .. }))
        .collect()
}

fn decode(event: &Event) -> Message<'_> {
    Message::decode(event.payload().expect("transmit event"))
        .expect("decode event payload")
        .0
}

fn machine_with(
    role: Role,
    tie_breaker: u64,
    local: &[SocketAddr],
    remote: &[SocketAddr],
) -> Checklist {
    let mut checklist = Checklist::new(role, tie_breaker);
    for &address in local {
        checklist
            .add_local_candidate(host(address))
            .expect("local candidate");
    }
    for &address in remote {
        checklist
            .add_remote_candidate(host(address))
            .expect("remote candidate");
    }
    checklist.generate_pairs().expect("generate pairs");
    checklist
}

fn duo() -> (Checklist, Checklist) {
    (
        machine_with(Role::Controlling, TIE_CONTROLLING, &[A1, A2], &[B1, B2]),
        machine_with(Role::Controlled, TIE_CONTROLLED, &[B1, B2], &[A1, A2]),
    )
}

fn single_pair(role: Role, tie_breaker: u64) -> Checklist {
    match role {
        Role::Controlling => machine_with(role, tie_breaker, &[A1], &[B1]),
        Role::Controlled => machine_with(role, tie_breaker, &[B1], &[A1]),
    }
}

/// Runs the complete regular-nomination dialogue and returns both machines.
fn complete_duo() -> (Checklist, Checklist) {
    let (mut controller, mut controllee) = duo();
    let mut now = T0;
    controller.start(now).expect("start controlling");
    controllee.start(now).expect("start controlled");

    let controller_check = sends(&drain(&mut controller)).remove(0);
    let controllee_check = sends(&drain(&mut controllee)).remove(0);
    assert_eq!(controller_check.pair().expect("pair"), 0);
    assert_eq!(controllee_check.pair().expect("pair"), 0);

    now += ONE_MICRO;
    deliver(
        &mut controllee,
        now,
        A1,
        B1,
        controller_check.payload().expect("check payload"),
    )
    .expect("controlled receives controlling check");
    let controllee_response = responses(&drain(&mut controllee)).remove(0);

    deliver(
        &mut controller,
        now,
        B1,
        A1,
        controllee_check.payload().expect("check payload"),
    )
    .expect("controlling receives controlled check");
    let controller_response = responses(&drain(&mut controller)).remove(0);

    now += ONE_MICRO;
    deliver(
        &mut controller,
        now,
        B1,
        A1,
        controllee_response.payload().expect("response payload"),
    )
    .expect("controlling receives its response");
    let controller_settled = drain(&mut controller);
    assert!(
        controller_settled
            .iter()
            .any(|event| matches!(event, Event::CheckSucceeded { pair: 0 })),
        "controlling pair must succeed"
    );
    let nomination = sends(&controller_settled)
        .into_iter()
        .find(|event| {
            matches!(
                event,
                Event::SendCheck {
                    nominated: true,
                    ..
                }
            )
        })
        .expect("controlling nominates the succeeded pair");

    deliver(
        &mut controllee,
        now,
        A1,
        B1,
        controller_response.payload().expect("response payload"),
    )
    .expect("controlled receives its response");
    assert!(
        drain(&mut controllee)
            .iter()
            .any(|event| matches!(event, Event::CheckSucceeded { pair: 0 })),
        "controlled pair must succeed before nomination"
    );

    now += ONE_MICRO;
    deliver(
        &mut controllee,
        now,
        nomination.source().expect("nomination source"),
        nomination.destination().expect("nomination destination"),
        nomination.payload().expect("nomination payload"),
    )
    .expect("controlled receives nomination");
    let controllee_completed = drain(&mut controllee);
    let nomination_response = responses(&controllee_completed)
        .into_iter()
        .find(|event| {
            matches!(
                event,
                Event::SendResponse {
                    accepted_nomination: true,
                    ..
                }
            )
        })
        .expect("controlled accepts the nomination");
    assert!(
        controllee_completed
            .iter()
            .any(|event| matches!(event, Event::ChecklistCompleted { pair: 0 })),
        "controlled completes"
    );

    now += ONE_MICRO;
    deliver(
        &mut controller,
        now,
        B1,
        A1,
        nomination_response.payload().expect("response payload"),
    )
    .expect("controlling receives the nomination response");
    let controller_completed = drain(&mut controller);
    assert!(
        controller_completed
            .iter()
            .any(|event| matches!(event, Event::ChecklistCompleted { pair: 0 })),
        "controlling completes"
    );
    (controller, controllee)
}

fn build_request(
    transaction_id: TransactionId,
    priority: u32,
    role_attribute: Option<AttrType>,
    tie_breaker: u64,
    use_candidate: bool,
) -> Vec<u8> {
    let mut buffer = [0u8; 64];
    let mut writer =
        rtx_stun::message::MessageWriter::new(&mut buffer, BINDING_REQUEST, transaction_id)
            .expect("writer");
    writer
        .push(ATTR_PRIORITY, &priority.to_be_bytes())
        .expect("priority");
    if let Some(attribute) = role_attribute {
        writer
            .push(attribute, &tie_breaker.to_be_bytes())
            .expect("role");
    }
    if use_candidate {
        writer.push(ATTR_USE_CANDIDATE, &[]).expect("use-candidate");
    }
    let length = writer.written();
    buffer[..length].to_vec()
}

fn build_indication(transaction_id: TransactionId) -> Vec<u8> {
    let mut buffer = [0u8; 32];
    let writer = rtx_stun::message::MessageWriter::new(
        &mut buffer,
        MessageType::new(METHOD_BINDING, CLASS_INDICATION),
        transaction_id,
    )
    .expect("writer");
    let length = writer.written();
    buffer[..length].to_vec()
}

// ---- FORMULAS -----------------------------------------------------------

#[test]
fn host_priority_follows_rfc_8445_126_type_preference() {
    // (126 << 24) + (65535 << 8) + (256 - 1) = 0x7EFF_FFFF.
    assert_eq!(host(A1).priority(), 0x7EFF_FFFF);
}

#[test]
fn stun_ice_003_anchor_value_is_the_peer_reflexive_priority() {
    // The STUN-ICE-003 comment writes 0x6EFF_FFFF as a host priority, but
    // 0x6E = 110 is the RFC 8445 §5.1.2.2 peer-reflexive preference. The
    // anchor numeric value is preserved here for the type it belongs to.
    assert_eq!(peer_reflexive(A1, B1).priority(), 0x6EFF_FFFF);
}

#[test]
fn type_preferences_are_strictly_decreasing() {
    let host_priority = host(A1).priority();
    let peer_priority = peer_reflexive(A1, B1).priority();
    let server_priority = srflx(A1, B1).priority();
    let relay_priority = relay(A1, B1).priority();

    assert!(host_priority > peer_priority);
    assert!(peer_priority > server_priority);
    assert!(server_priority > relay_priority);
    assert_eq!(server_priority, 0x64FF_FFFF);
    assert_eq!(relay_priority, 0x00FF_FFFF);
    assert_eq!(host(A1).typ().type_preference(), 126);
    assert_eq!(peer_reflexive(A1, B1).typ().type_preference(), 110);
    assert_eq!(srflx(A1, B1).typ().type_preference(), 100);
    assert_eq!(relay(A1, B1).typ().type_preference(), 0);
}

#[test]
fn component_and_base_rules_are_enforced() {
    let component = rtx_ice::Component::new(2).expect("component 2");
    assert_eq!(
        Candidate::new(CandidateType::Host, component, Transport::Udp, A1, None),
        Err(IceError::UnsupportedComponent(2))
    );
    assert_eq!(rtx_ice::Component::new(0), None);
    assert_eq!(rtx_ice::Component::new(257), None);
    assert_eq!(
        rtx_ice::Component::new(256).map(rtx_ice::Component::value),
        Some(256)
    );
    assert_eq!(rtx_ice::Component::RTP.value(), 1);
    assert_eq!(COMPONENT_RTP.value(), 1);

    assert_eq!(
        Candidate::new(
            CandidateType::Host,
            COMPONENT_RTP,
            Transport::Udp,
            A1,
            Some(B1)
        ),
        Err(IceError::BaseAddressMismatch)
    );
    let host_with_same_base = Candidate::new(
        CandidateType::Host,
        COMPONENT_RTP,
        Transport::Udp,
        A1,
        Some(A1),
    )
    .expect("host base may repeat its address");
    assert_eq!(host_with_same_base.base(), A1);
    assert_eq!(host(A1).base(), A1);
    assert_eq!(
        Candidate::new(
            CandidateType::ServerReflexive,
            COMPONENT_RTP,
            Transport::Udp,
            A1,
            None
        ),
        Err(IceError::MissingBaseAddress)
    );
    let reflexive = srflx(A1, B1);
    assert_eq!(reflexive.base(), B1);
    assert_eq!(reflexive.address(), A1);
    assert_eq!(reflexive.transport(), Transport::Udp);
    assert_eq!(host(A1).component(), COMPONENT_RTP);
}

#[test]
fn foundation_is_deterministic_and_depends_on_type_base_and_transport() {
    assert_eq!(host(A1).foundation(), host(A1).foundation());
    assert_ne!(host(A1).foundation(), host(A2).foundation());
    assert_ne!(host(A1).foundation(), srflx(A1, A1).foundation());
    assert_ne!(srflx(A1, A1).foundation(), srflx(A1, A2).foundation());

    let v6 = SocketAddr::new(
        IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        5_000,
    );
    let v6_candidate = host(v6);
    assert_eq!(v6_candidate.foundation(), host(v6).foundation());
    assert_ne!(v6_candidate.foundation(), host(A1).foundation());
}

#[test]
fn pair_priority_matches_rfc_8445_and_is_role_consistent() {
    let controlling_priority = 0x7EFF_FFFFu32;
    let controlled_priority = 0x64FF_FFFFu32;
    // G > D: minimum is D, maximum is G, tie-break is +1.
    let expected =
        (u64::from(controlled_priority) << 32) + (u64::from(controlling_priority) << 1) + 1;
    assert_eq!(
        pair_priority(controlling_priority, controlled_priority, Role::Controlling),
        expected
    );
    assert_eq!(
        pair_priority(controlled_priority, controlling_priority, Role::Controlled),
        expected
    );

    // G < D: the controlling candidate is the minimum, tie-break is 0.
    let expected = (u64::from(controlled_priority) << 32) + (u64::from(controlling_priority) << 1);
    assert_eq!(
        pair_priority(controlled_priority, controlling_priority, Role::Controlling),
        expected
    );
}

#[test]
fn pair_priority_is_identical_on_both_agents() {
    let (controller, controllee) = duo();
    let controlling_pair = controller.pair(0).expect("pair");
    let controlled_pair = controllee.pair(0).expect("pair");
    assert_eq!(
        controlling_pair.local().address(),
        controlled_pair.remote().address()
    );
    assert_eq!(
        controlling_pair.remote().address(),
        controlled_pair.local().address()
    );
    assert_eq!(controlling_pair.priority(), controlled_pair.priority());
}

#[test]
fn pair_table_orders_by_priority_and_dedupes_address_pairs() {
    let mut checklist = Checklist::new(Role::Controlling, TIE_CONTROLLING);
    // The low-priority relay pair is created first so the higher-priority
    // host pairs must be inserted ahead of it.
    checklist
        .add_local_candidate(relay(
            SocketAddr::new(IpAddr::V4([203, 0, 113, 9]), 3_478),
            A1,
        ))
        .expect("relay local");
    checklist.add_local_candidate(host(A1)).expect("host local");
    checklist
        .add_remote_candidate(host(B1))
        .expect("host remote");
    checklist
        .add_remote_candidate(srflx(
            SocketAddr::new(IpAddr::V4([198, 51, 100, 7]), 4_000),
            B1,
        ))
        .expect("server-reflexive remote");
    assert_eq!(checklist.generate_pairs().expect("pairs"), 4);

    let pairs: Vec<CandidatePair> = checklist.pairs().collect();
    assert_eq!(pairs.len(), 4);
    for window in pairs.windows(2) {
        assert!(
            window[0].priority() >= window[1].priority(),
            "pairs must be ordered by decreasing priority"
        );
    }
    // host-host, host-srflx, relay-host, relay-srflx.
    assert_eq!(pairs[0].local().address(), A1);
    assert_eq!(pairs[0].remote().address(), B1);
    assert_eq!(pairs[0].local().typ(), CandidateType::Host);
    assert_eq!(pairs[1].remote().typ(), CandidateType::ServerReflexive);
    assert_eq!(pairs[2].local().typ(), CandidateType::Relay);
    assert_eq!(pairs[3].local().typ(), CandidateType::Relay);
    assert_eq!(pairs[3].remote().typ(), CandidateType::ServerReflexive);

    // Generating again adds nothing; duplicate candidate addresses collapse
    // to one address pair.
    assert_eq!(checklist.generate_pairs().expect("no-op"), 0);
    let mut duplicated = Checklist::new(Role::Controlling, TIE_CONTROLLING);
    duplicated.add_local_candidate(host(A1)).expect("first");
    duplicated
        .add_local_candidate(host(A1))
        .expect("duplicate local");
    duplicated.add_remote_candidate(host(B1)).expect("remote");
    duplicated
        .add_remote_candidate(host(B1))
        .expect("duplicate remote");
    assert_eq!(duplicated.generate_pairs().expect("dedup"), 1);
    assert_eq!(duplicated.pair_count(), 1);
}

// ---- TWO-MACHINE DIALOGUE ----------------------------------------------

#[test]
fn duo_completes_with_the_highest_priority_usable_pair_nominated() {
    let (mut controller, controllee) = complete_duo();

    assert_eq!(controller.state(), ChecklistState::Completed);
    assert_eq!(controllee.state(), ChecklistState::Completed);
    controller
        .start(T0)
        .expect("a completed checklist ignores later starts");
    assert_eq!(controller.state(), ChecklistState::Completed);

    let controlling_nominated = controller.nominated_pair().expect("controlling nomination");
    let controlled_nominated = controllee.nominated_pair().expect("controlled nomination");
    assert!(controlling_nominated.is_nominated());
    assert!(controlled_nominated.is_nominated());

    // The same physical pair, seen from both roles.
    assert_eq!(controlling_nominated.local().address(), A1);
    assert_eq!(controlling_nominated.remote().address(), B1);
    assert_eq!(controlled_nominated.local().address(), B1);
    assert_eq!(controlled_nominated.remote().address(), A1);
    assert_eq!(
        controlling_nominated.priority(),
        controlled_nominated.priority()
    );

    // The nominated pair is the first (highest-priority) pair on each side.
    let controlling_first = controller.pairs().next().expect("first pair");
    let controlled_first = controllee.pairs().next().expect("first pair");
    assert_eq!(
        controlling_nominated.local().address(),
        controlling_first.local().address()
    );
    assert_eq!(
        controlling_nominated.remote().address(),
        controlling_first.remote().address()
    );
    assert_eq!(
        controlled_nominated.local().address(),
        controlled_first.local().address()
    );
    assert_eq!(
        controlled_nominated.remote().address(),
        controlled_first.remote().address()
    );
}

#[test]
fn controlled_ignores_nomination_before_the_pair_succeeds() {
    let mut controllee = single_pair(Role::Controlled, TIE_CONTROLLED);
    controllee.start(T0).expect("start");
    let check = sends(&drain(&mut controllee)).remove(0);

    // A nomination arrives while the pair is In-Progress.
    let nomination = build_request(
        TransactionId([0xAA; 12]),
        0x7EFF_FFFF,
        Some(ATTR_ICE_CONTROLLING),
        TIE_CONTROLLING,
        true,
    );
    let now = T0 + ONE_MICRO;
    deliver(&mut controllee, now, A1, B1, &nomination).expect("nomination accepted as a request");
    let events = drain(&mut controllee);
    let response = responses(&events).remove(0);
    assert!(matches!(
        response,
        Event::SendResponse {
            accepted_nomination: false,
            ..
        }
    ));
    assert_eq!(controllee.state(), ChecklistState::Running);
    assert_eq!(
        controllee.pair(0).expect("pair").state(),
        PairState::InProgress
    );
    assert!(!controllee.pair(0).expect("pair").is_nominated());

    // The real success response to the earlier check must not resurrect the
    // ignored nomination.
    let mut buffer = [0u8; 64];
    let writer = rtx_stun::message::MessageWriter::new(
        &mut buffer,
        BINDING_SUCCESS,
        check.transaction_id().expect("check transaction"),
    )
    .expect("writer");
    let length = writer.written();
    deliver(&mut controllee, now + ONE_MICRO, A1, B1, &buffer[..length]).expect("response");
    let events = drain(&mut controllee);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::CheckSucceeded { pair: 0 }))
    );
    assert_eq!(controllee.state(), ChecklistState::Running);
    assert!(controllee.nominated_pair().is_none());
}

#[test]
fn lost_first_check_is_retransmitted_and_the_checklist_still_completes() {
    let (mut controller, mut controllee) = duo();
    let mut now = T0;
    controller.start(now).expect("start controlling");
    controllee.start(now).expect("start controlled");
    let dropped = sends(&drain(&mut controller)).remove(0);
    let controllee_check = sends(&drain(&mut controllee)).remove(0);

    // The controlled side's own check completes normally.
    now += ONE_MICRO;
    deliver(
        &mut controller,
        now,
        B1,
        A1,
        controllee_check.payload().expect("check payload"),
    )
    .expect("controlled check reaches controlling");
    let controller_response = responses(&drain(&mut controller)).remove(0);
    deliver(
        &mut controllee,
        now + ONE_MICRO,
        A1,
        B1,
        controller_response.payload().expect("response payload"),
    )
    .expect("response reaches controlled");
    assert!(
        drain(&mut controllee)
            .iter()
            .any(|event| matches!(event, Event::CheckSucceeded { pair: 0 }))
    );
    assert!(dropped.payload().is_some());

    // The dropped check is retransmitted by the timer, not by a sleep.
    assert_eq!(controller.next_wakeup(), Some(T0 + INITIAL_RTO));
    let retransmit_at = controller.next_wakeup().expect("timer");
    controller
        .handle_input(Input::Timeout(retransmit_at))
        .expect("timeout");
    let retransmissions = sends(&drain(&mut controller));
    assert_eq!(retransmissions.len(), 1);
    assert_eq!(
        retransmissions[0].transaction_id(),
        dropped.transaction_id()
    );
    assert_eq!(retransmissions[0].pair(), Some(0));

    now = retransmit_at + ONE_MICRO;
    deliver(
        &mut controllee,
        now,
        A1,
        B1,
        retransmissions[0].payload().expect("check payload"),
    )
    .expect("retransmission reaches controlled");
    let controllee_response = responses(&drain(&mut controllee)).remove(0);
    deliver(
        &mut controller,
        now + ONE_MICRO,
        B1,
        A1,
        controllee_response.payload().expect("response payload"),
    )
    .expect("retransmission response reaches controlling");

    let events = drain(&mut controller);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::CheckSucceeded { pair: 0 }))
    );
    let nomination = sends(&events)
        .into_iter()
        .find(|event| {
            matches!(
                event,
                Event::SendCheck {
                    nominated: true,
                    ..
                }
            )
        })
        .expect("nomination after retransmission");
    deliver(
        &mut controllee,
        now + Duration::from_micros(2),
        nomination.source().expect("nomination source"),
        nomination.destination().expect("nomination destination"),
        nomination.payload().expect("nomination payload"),
    )
    .expect("nomination reaches controlled");
    let controllee_events = drain(&mut controllee);
    let nomination_response = responses(&controllee_events)
        .into_iter()
        .find(|event| {
            matches!(
                event,
                Event::SendResponse {
                    accepted_nomination: true,
                    ..
                }
            )
        })
        .expect("nomination accepted");
    deliver(
        &mut controller,
        now + Duration::from_micros(3),
        B1,
        A1,
        nomination_response.payload().expect("response payload"),
    )
    .expect("nomination response reaches controlling");
    drain(&mut controller);

    assert_eq!(controller.state(), ChecklistState::Completed);
    assert_eq!(controllee.state(), ChecklistState::Completed);
}

#[test]
fn retransmission_exhaustion_fails_the_pair_and_moves_to_the_next_one() {
    let mut checklist = Checklist::new(Role::Controlling, TIE_CONTROLLING);
    checklist.add_local_candidate(host(A1)).expect("A1");
    checklist.add_local_candidate(host(A2)).expect("A2");
    checklist.add_remote_candidate(host(B1)).expect("B1");
    assert_eq!(checklist.generate_pairs().expect("pairs"), 2);
    checklist.start(T0).expect("start");
    let first = sends(&drain(&mut checklist)).remove(0);
    assert_eq!(first.pair(), Some(0));
    assert_eq!(checklist.next_wakeup(), Some(T0 + INITIAL_RTO));

    let mut next_rto = INITIAL_RTO.as_micros() * 2;
    for _ in 0..MAX_RETRANSMISSIONS {
        let deadline = checklist.next_wakeup().expect("timer");
        checklist
            .handle_input(Input::Timeout(deadline))
            .expect("retransmit");
        let retransmission = sends(&drain(&mut checklist)).remove(0);
        assert_eq!(retransmission.transaction_id(), first.transaction_id());
        assert_eq!(retransmission.pair(), Some(0));
        assert_eq!(retransmission.nominated(), Some(false));
        assert_eq!(
            checklist.next_wakeup(),
            Some(deadline + Duration::from_micros(next_rto))
        );
        next_rto = core::cmp::min(next_rto * 2, MAX_RTO.as_micros());
    }

    let final_deadline = checklist.next_wakeup().expect("final wait");
    checklist
        .handle_input(Input::Timeout(final_deadline))
        .expect("fail the pair");
    let events = drain(&mut checklist);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::CheckFailed { pair: 0 }))
    );
    let next_check = sends(&events).remove(0);
    assert_eq!(next_check.pair(), Some(1), "the checklist must move on");
    assert_eq!(
        checklist.pair(0).expect("pair 0").state(),
        PairState::Failed
    );
    assert_eq!(
        checklist.pair(1).expect("pair 1").state(),
        PairState::InProgress
    );
    assert_eq!(checklist.state(), ChecklistState::Running);
    assert!(
        checklist.next_wakeup().is_some(),
        "the table must not stall"
    );
}

#[test]
fn error_response_fails_the_pair_and_finishes_an_exhausted_checklist() {
    let mut checklist = single_pair(Role::Controlling, TIE_CONTROLLING);
    checklist.start(T0).expect("start");
    let check = sends(&drain(&mut checklist)).remove(0);

    let mut buffer = [0u8; 32];
    let writer = rtx_stun::message::MessageWriter::new(
        &mut buffer,
        MessageType::new(METHOD_BINDING, rtx_stun::message::CLASS_ERROR_RESPONSE),
        check.transaction_id().expect("check transaction"),
    )
    .expect("writer");
    let length = writer.written();
    deliver(&mut checklist, T0 + ONE_MICRO, B1, A1, &buffer[..length]).expect("error response");
    let events = drain(&mut checklist);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::CheckFailed { pair: 0 }))
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::ChecklistFailed))
    );
    assert_eq!(checklist.state(), ChecklistState::Failed);
    assert_eq!(checklist.pair(0).expect("pair").state(), PairState::Failed);
}

// ---- ROLE CONFLICT ------------------------------------------------------

#[test]
fn role_conflicts_return_typed_errors_and_do_not_touch_the_table() {
    let mut controlled = single_pair(Role::Controlled, TIE_CONTROLLED);
    let transaction_id = TransactionId([0x77; 12]);
    let before = controlled.pair(0).expect("pair");

    // RFC 8445 §7.3.1.1: a controlled agent rejects ICE-CONTROLLED.
    let conflict = build_request(
        transaction_id,
        0x7EFF_FFFF,
        Some(ATTR_ICE_CONTROLLED),
        TIE_CONTROLLING,
        false,
    );
    assert_eq!(
        deliver(&mut controlled, T0, A1, B1, &conflict),
        Err(IceError::RoleConflict(transaction_id))
    );
    assert_eq!(controlled.state(), ChecklistState::Running);
    assert_eq!(controlled.pair(0).expect("pair"), before);
    assert_eq!(drain(&mut controlled), [] as [rtx_ice::Event; 0]);

    // The complementary case: a controlling agent rejects ICE-CONTROLLING.
    let mut controller = single_pair(Role::Controlling, TIE_CONTROLLING);
    let conflict = build_request(
        transaction_id,
        0x7EFF_FFFF,
        Some(ATTR_ICE_CONTROLLING),
        TIE_CONTROLLED,
        false,
    );
    assert_eq!(
        deliver(&mut controller, T0, B1, A1, &conflict),
        Err(IceError::RoleConflict(transaction_id))
    );
    assert_eq!(controller.pair(0).expect("pair").state(), PairState::Frozen);

    // Both attributes at once are also a conflict.
    let both = {
        let mut writer_buffer = [0u8; 64];
        let mut writer = rtx_stun::message::MessageWriter::new(
            &mut writer_buffer,
            BINDING_REQUEST,
            transaction_id,
        )
        .expect("writer");
        writer
            .push(ATTR_ICE_CONTROLLING, &TIE_CONTROLLING.to_be_bytes())
            .expect("controlling");
        writer
            .push(ATTR_ICE_CONTROLLED, &TIE_CONTROLLED.to_be_bytes())
            .expect("controlled");
        writer
            .push(ATTR_PRIORITY, &0x7EFF_FFFFu32.to_be_bytes())
            .expect("priority");
        let length = writer.written();
        writer_buffer[..length].to_vec()
    };
    assert_eq!(
        deliver(&mut controlled, T0, A1, B1, &both),
        Err(IceError::RoleConflict(transaction_id))
    );
    assert_eq!(drain(&mut controlled), [] as [rtx_ice::Event; 0]);
}

#[test]
fn a_matching_role_pair_is_not_a_conflict() {
    // Controlled receiving ICE-CONTROLLING is the normal dialogue; the
    // task's role-conflict sentence lists this pair twice, but the RFC
    // §7.3.1.1 conflict is the same-role case tested above.
    let mut controlled = single_pair(Role::Controlled, TIE_CONTROLLED);
    let request = build_request(
        TransactionId([0x31; 12]),
        0x7EFF_FFFF,
        Some(ATTR_ICE_CONTROLLING),
        TIE_CONTROLLING,
        false,
    );
    deliver(&mut controlled, T0, A1, B1, &request).expect("normal check");
    let response = responses(&drain(&mut controlled)).remove(0);
    assert_eq!(response.destination(), Some(A1));
    assert!(matches!(
        response,
        Event::SendResponse {
            accepted_nomination: false,
            ..
        }
    ));
    let message = decode(&response);
    assert_eq!(message.typ, BINDING_SUCCESS);
    assert_eq!(message.transaction_id, TransactionId([0x31; 12]));
    let mapped = message.get(ATTR_XORMAPPED_ADDRESS).expect("mapped address");
    let address =
        rtx_stun::xoraddr::XorMappedAddress::from_value(mapped.value, message.transaction_id)
            .expect("unmask");
    assert_eq!(address.ip, A1.ip);
    assert_eq!(address.port, A1.port);
}

// ---- WIRE FORMAT AND TRANSACTION IDS -----------------------------------

#[test]
fn checks_and_nominations_carry_rfc_8445_attributes_and_deterministic_ids() {
    let (mut controller, mut controllee) = duo();
    controller.start(T0).expect("start controlling");
    controllee.start(T0).expect("start controlled");
    let controller_check = sends(&drain(&mut controller)).remove(0);
    let controllee_check = sends(&drain(&mut controllee)).remove(0);
    let _ = controllee_check;

    let request = decode(&controller_check);
    assert_eq!(request.typ, BINDING_REQUEST);
    assert_eq!(&request.transaction_id.0[..4], b"RTX!");
    assert_eq!(
        u64::from_be_bytes(
            request.transaction_id.0[4..]
                .try_into()
                .expect("eight-byte counter")
        ),
        1
    );
    assert!(request.contains(ATTR_ICE_CONTROLLING));
    assert!(!request.contains(ATTR_ICE_CONTROLLED));
    assert!(!request.contains(ATTR_USE_CANDIDATE));
    let priority = request.get(ATTR_PRIORITY).expect("priority");
    assert_eq!(
        u32::from_be_bytes(priority.value.try_into().expect("four bytes")),
        0x7EFF_FFFF
    );
    let role = request.get(ATTR_ICE_CONTROLLING).expect("role");
    assert_eq!(
        u64::from_be_bytes(role.value.try_into().expect("eight bytes")),
        TIE_CONTROLLING
    );

    // Complete one check so the controlling side nominates.
    let now = T0 + ONE_MICRO;
    deliver(
        &mut controllee,
        now,
        A1,
        B1,
        controller_check.payload().expect("payload"),
    )
    .expect("check");
    let response = responses(&drain(&mut controllee)).remove(0);
    deliver(
        &mut controller,
        now,
        B1,
        A1,
        response.payload().expect("payload"),
    )
    .expect("response");
    let nomination = sends(&drain(&mut controller))
        .into_iter()
        .find(|event| {
            matches!(
                event,
                Event::SendCheck {
                    nominated: true,
                    ..
                }
            )
        })
        .expect("nomination");
    let message = decode(&nomination);
    assert!(message.contains(ATTR_PRIORITY));
    assert!(message.contains(ATTR_ICE_CONTROLLING));
    let use_candidate = message.get(ATTR_USE_CANDIDATE).expect("use-candidate");
    assert_eq!(use_candidate.length, 0, "USE-CANDIDATE is empty");
    assert_eq!(
        u64::from_be_bytes(
            message.transaction_id.0[4..]
                .try_into()
                .expect("eight-byte counter")
        ),
        2
    );
}

// ---- INBOUND DECODE ERRORS ---------------------------------------------

#[test]
fn malformed_or_unexpected_inbound_messages_are_typed_errors() {
    let mut controlled = single_pair(Role::Controlled, TIE_CONTROLLED);

    assert_eq!(
        deliver(&mut controlled, T0, A1, B1, &[0u8; 19]),
        Err(IceError::NotStunMessage)
    );

    let mut truncated = [0u8; 20];
    truncated[0..2].copy_from_slice(&BINDING_REQUEST.value().to_be_bytes());
    truncated[2..4].copy_from_slice(&8u16.to_be_bytes());
    truncated[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    assert_eq!(
        deliver(&mut controlled, T0, A1, B1, &truncated),
        Err(IceError::Decode(WireError::UnexpectedEnd))
    );

    let mut allocate = [0u8; 20];
    let writer = rtx_stun::message::MessageWriter::new(
        &mut allocate,
        MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST),
        TransactionId([0x41; 12]),
    )
    .expect("writer");
    let length = writer.written();
    assert_eq!(
        deliver(&mut controlled, T0, A1, B1, &allocate[..length]),
        Err(IceError::UnexpectedMessage)
    );

    let mut no_priority = [0u8; 64];
    let mut writer = rtx_stun::message::MessageWriter::new(
        &mut no_priority,
        BINDING_REQUEST,
        TransactionId([0x42; 12]),
    )
    .expect("writer");
    writer
        .push(ATTR_ICE_CONTROLLING, &TIE_CONTROLLING.to_be_bytes())
        .expect("role");
    let length = writer.written();
    assert_eq!(
        deliver(&mut controlled, T0, A1, B1, &no_priority[..length]),
        Err(IceError::MissingPriority)
    );

    let mut short_priority = [0u8; 64];
    let mut writer = rtx_stun::message::MessageWriter::new(
        &mut short_priority,
        BINDING_REQUEST,
        TransactionId([0x43; 12]),
    )
    .expect("writer");
    writer.push(ATTR_PRIORITY, &[1, 2, 3]).expect("priority");
    writer
        .push(ATTR_ICE_CONTROLLING, &TIE_CONTROLLING.to_be_bytes())
        .expect("role");
    let length = writer.written();
    assert_eq!(
        deliver(&mut controlled, T0, A1, B1, &short_priority[..length]),
        Err(IceError::InvalidAttribute)
    );

    let mut long_use_candidate = [0u8; 64];
    let mut writer = rtx_stun::message::MessageWriter::new(
        &mut long_use_candidate,
        BINDING_REQUEST,
        TransactionId([0x44; 12]),
    )
    .expect("writer");
    writer
        .push(ATTR_PRIORITY, &0x7EFF_FFFFu32.to_be_bytes())
        .expect("priority");
    writer
        .push(ATTR_ICE_CONTROLLING, &TIE_CONTROLLING.to_be_bytes())
        .expect("role");
    writer
        .push(ATTR_USE_CANDIDATE, &[0])
        .expect("use-candidate");
    let length = writer.written();
    assert_eq!(
        deliver(&mut controlled, T0, A1, B1, &long_use_candidate[..length]),
        Err(IceError::InvalidAttribute)
    );

    let unknown_local = build_request(
        TransactionId([0x45; 12]),
        0x7EFF_FFFF,
        Some(ATTR_ICE_CONTROLLING),
        TIE_CONTROLLING,
        false,
    );
    assert_eq!(
        deliver(&mut controlled, T0, A1, C1, &unknown_local),
        Err(IceError::UnknownLocalCandidate)
    );
    assert_eq!(controlled.state(), ChecklistState::Running);
    assert_eq!(drain(&mut controlled), [] as [rtx_ice::Event; 0]);
}

#[test]
fn unmatched_late_and_mismatched_responses_are_ignored() {
    let mut controller = single_pair(Role::Controlling, TIE_CONTROLLING);
    controller.start(T0).expect("start");
    let check = sends(&drain(&mut controller)).remove(0);

    // No transaction in flight? Start one, then send unrelated responses.
    let mut buffer = [0u8; 64];
    let writer = rtx_stun::message::MessageWriter::new(
        &mut buffer,
        BINDING_SUCCESS,
        TransactionId([0x55; 12]),
    )
    .expect("writer");
    let length = writer.written();
    assert_eq!(
        deliver(&mut controller, T0 + ONE_MICRO, B1, A1, &buffer[..length]),
        Ok(())
    );
    assert_eq!(
        controller.pair(0).expect("pair").state(),
        PairState::InProgress
    );

    // Matching transaction id but wrong source is ignored.
    let writer = rtx_stun::message::MessageWriter::new(
        &mut buffer,
        BINDING_SUCCESS,
        check.transaction_id().expect("check transaction"),
    )
    .expect("writer");
    let length = writer.written();
    assert_eq!(
        deliver(&mut controller, T0 + ONE_MICRO, C1, A1, &buffer[..length]),
        Ok(())
    );
    assert_eq!(
        controller.pair(0).expect("pair").state(),
        PairState::InProgress
    );
    assert!(controller.next_wakeup().is_some());

    // A late response after the transaction already failed is ignored.
    let mut exhausted = single_pair(Role::Controlling, TIE_CONTROLLING);
    exhausted.start(T0).expect("start");
    let _ = sends(&drain(&mut exhausted)).remove(0);
    for _ in 0..=MAX_RETRANSMISSIONS {
        let deadline = exhausted.next_wakeup().expect("timer");
        exhausted
            .handle_input(Input::Timeout(deadline))
            .expect("retransmit or fail");
        drain(&mut exhausted);
    }
    assert_eq!(exhausted.pair(0).expect("pair").state(), PairState::Failed);
    let writer = rtx_stun::message::MessageWriter::new(
        &mut buffer,
        BINDING_SUCCESS,
        TransactionId([0x55; 12]),
    )
    .expect("writer");
    let length = writer.written();
    assert_eq!(
        deliver(
            &mut exhausted,
            T0 + Duration::from_millis(60_000),
            B1,
            A1,
            &buffer[..length]
        ),
        Ok(())
    );
}

// ---- CONSENT ------------------------------------------------------------

#[test]
fn consent_starts_at_nomination_and_refreshes_only_on_the_nominated_pair() {
    let timeout = Duration::from_millis(15_000);
    let (mut controller, controllee) = complete_duo();
    assert_eq!(controller.state(), ChecklistState::Completed);
    assert_eq!(controllee.state(), ChecklistState::Completed);

    // Within the window the consent is fresh; strictly after it is stale.
    assert!(!controller.is_consent_stale(T0, timeout));
    assert!(!controller.is_consent_stale(T0 + timeout, timeout));
    assert!(controller.is_consent_stale(T0 + timeout + Duration::from_millis(1), timeout));
    assert!(!controllee.is_consent_stale(T0 + timeout, timeout));
    assert!(controllee.is_consent_stale(T0 + timeout + Duration::from_millis(1), timeout));

    // An indication from a non-nominated remote address does not refresh.
    let stale_at = T0 + timeout + Duration::from_millis(1);
    let indication = build_indication(TransactionId([0xD1; 12]));
    deliver(&mut controller, stale_at, B2, A1, &indication).expect("indication");
    assert!(controller.is_consent_stale(stale_at, timeout));

    // An indication on the nominated pair refreshes the timestamp.
    deliver(&mut controller, stale_at, B1, A1, &indication).expect("indication");
    assert!(!controller.is_consent_stale(stale_at, timeout));
    assert!(!controller.is_consent_stale(stale_at + timeout, timeout));
    assert!(controller.is_consent_stale(stale_at + timeout + Duration::from_micros(1), timeout));

    // No nominated pair: the query is not applicable, so it is never stale.
    let fresh = single_pair(Role::Controlling, 1);
    assert!(!fresh.is_consent_stale(T0 + Duration::from_millis(3_600_000), timeout));
}

// ---- FAILURE AND BOUNDARY PATHS ---------------------------------------

#[test]
fn empty_checklist_start_fails_explicitly() {
    let mut checklist = Checklist::new(Role::Controlling, TIE_CONTROLLING);
    checklist.start(T0).expect("start");
    assert_eq!(checklist.state(), ChecklistState::Failed);
    assert!(checklist.next_wakeup().is_none());
    let events = drain(&mut checklist);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::ChecklistFailed))
    );
    checklist
        .start(T0 + ONE_MICRO)
        .expect("a terminal checklist ignores later starts");
    assert_eq!(checklist.state(), ChecklistState::Failed);
}

#[test]
fn tables_freeze_after_start() {
    let mut checklist = single_pair(Role::Controlling, TIE_CONTROLLING);
    checklist.start(T0).expect("start");
    drain(&mut checklist);
    assert_eq!(
        checklist.add_local_candidate(host(A2)),
        Err(IceError::AlreadyStarted)
    );
    assert_eq!(
        checklist.add_remote_candidate(host(B2)),
        Err(IceError::AlreadyStarted)
    );
    assert_eq!(checklist.generate_pairs(), Err(IceError::AlreadyStarted));
}

#[test]
fn a_full_event_queue_rejects_input_without_mutating_state() {
    let mut checklist = single_pair(Role::Controlling, TIE_CONTROLLING);
    checklist.start(T0).expect("start");
    // Do not drain: the initial transmit stays queued.
    for _ in 0..MAX_RETRANSMISSIONS {
        let deadline = checklist.next_wakeup().expect("timer");
        checklist
            .handle_input(Input::Timeout(deadline))
            .expect("retransmit");
    }
    assert_eq!(
        checklist.pair(0).expect("pair").state(),
        PairState::InProgress
    );
    let deadline = checklist.next_wakeup().expect("timer");
    assert_eq!(
        checklist.handle_input(Input::Timeout(deadline)),
        Err(IceError::EventQueueFull)
    );
    assert_eq!(
        checklist.pair(0).expect("pair").state(),
        PairState::InProgress
    );

    // Draining lets the terminal timeout complete.
    let queued = drain(&mut checklist);
    assert_eq!(queued.len(), 8);
    checklist
        .handle_input(Input::Timeout(deadline))
        .expect("terminal timeout");
    let events = drain(&mut checklist);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::CheckFailed { pair: 0 }))
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::ChecklistFailed))
    );
}

#[test]
fn configuration_errors_are_explicit() {
    assert_eq!(
        Candidate::new(
            CandidateType::Host,
            COMPONENT_RTP,
            Transport::Udp,
            A1,
            Some(B1)
        ),
        Err(IceError::BaseAddressMismatch)
    );
    assert_eq!(
        Candidate::new(
            CandidateType::Relay,
            COMPONENT_RTP,
            Transport::Udp,
            A1,
            None
        ),
        Err(IceError::MissingBaseAddress)
    );
}

// ---- TRIGGERED CHECKS AND REQUEST PATH BOUNDS -------------------------

#[test]
fn unknown_pair_request_learns_a_peer_reflexive_candidate_and_triggers_a_check() {
    let mut controlled = Checklist::new(Role::Controlled, TIE_CONTROLLED);
    controlled.add_local_candidate(host(B1)).expect("local");
    assert_eq!(controlled.remote_candidate_count(), 0);
    assert_eq!(controlled.pair_count(), 0);

    let request = build_request(
        TransactionId([0xB1; 12]),
        0x7EFF_FFFF,
        Some(ATTR_ICE_CONTROLLING),
        TIE_CONTROLLING,
        false,
    );
    deliver(&mut controlled, T0, C1, B1, &request).expect("unknown pair request");
    let response = responses(&drain(&mut controlled)).remove(0);
    assert!(matches!(
        response,
        Event::SendResponse {
            accepted_nomination: false,
            ..
        }
    ));

    assert_eq!(controlled.remote_candidate_count(), 1);
    let learned = controlled
        .remote_candidates()
        .next()
        .expect("learned candidate");
    assert_eq!(learned.typ(), CandidateType::PeerReflexive);
    assert_eq!(learned.address(), C1);
    assert_eq!(learned.base(), B1);
    assert_eq!(controlled.pair_count(), 1);
    let pair = controlled.pair(0).expect("learned pair");
    assert_eq!(pair.local().address(), B1);
    assert_eq!(pair.remote().address(), C1);
    assert_eq!(pair.state(), PairState::Frozen);
    assert!(!controlled.is_started());
    assert_eq!(controlled.role(), Role::Controlled);

    // The queued triggered check runs first when the checklist starts.
    controlled
        .start(T0 + ONE_MICRO)
        .expect("start from a trigger");
    assert!(controlled.is_started());
    let check = sends(&drain(&mut controlled)).remove(0);
    assert_eq!(check.pair(), Some(0));
    assert_eq!(check.source(), Some(B1));
    assert_eq!(check.destination(), Some(C1));
    assert_eq!(check.nominated(), Some(false));
    assert_eq!(
        controlled.pair(0).expect("pair").state(),
        PairState::InProgress
    );
}

#[test]
fn request_path_overflow_is_explicit_and_state_is_untouched() {
    // Pair table full: a request from a ninth remote candidate to an existing
    // local candidate would need a 65th pair.
    let mut pair_full = Checklist::new(Role::Controlled, TIE_CONTROLLED);
    for index in 0..8u16 {
        pair_full
            .add_local_candidate(host(SocketAddr::new(
                IpAddr::V4([10, 0, 0, 1]),
                10_000 + index,
            )))
            .expect("local");
        pair_full
            .add_remote_candidate(host(SocketAddr::new(
                IpAddr::V4([10, 0, 0, 2]),
                20_000 + index,
            )))
            .expect("remote");
    }
    assert_eq!(pair_full.generate_pairs().expect("64 pairs"), 64);
    let ninth_remote = SocketAddr::new(IpAddr::V4([10, 0, 0, 2]), 20_008);
    pair_full
        .add_remote_candidate(host(ninth_remote))
        .expect("ninth remote fits");
    let request = build_request(
        TransactionId([0xB2; 12]),
        0x7EFF_FFFF,
        Some(ATTR_ICE_CONTROLLING),
        TIE_CONTROLLING,
        false,
    );
    let destination = SocketAddr::new(IpAddr::V4([10, 0, 0, 1]), 10_000);
    assert_eq!(
        deliver(&mut pair_full, T0, ninth_remote, destination, &request),
        Err(IceError::PairTableFull)
    );
    assert_eq!(pair_full.pair_count(), 64);
    assert_eq!(pair_full.pair(0).expect("pair").state(), PairState::Frozen);

    // Remote candidate table full: the source is an unknown seventeenth
    // remote address.
    let mut candidate_full = Checklist::new(Role::Controlled, TIE_CONTROLLED);
    candidate_full.add_local_candidate(host(A1)).expect("local");
    for index in 0..MAX_ICE_CANDIDATES {
        candidate_full
            .add_remote_candidate(host(SocketAddr::new(
                IpAddr::V4([10, 0, 9, 1]),
                30_000 + u16::try_from(index).expect("fits"),
            )))
            .expect("remote");
    }
    assert_eq!(candidate_full.generate_pairs().expect("pairs"), 16);
    assert_eq!(
        deliver(&mut candidate_full, T0, C1, A1, &request),
        Err(IceError::CandidateTableFull)
    );
    assert_eq!(candidate_full.remote_candidate_count(), MAX_ICE_CANDIDATES);
    assert_eq!(candidate_full.pair_count(), 16);
}

#[test]
fn a_request_is_rejected_when_the_event_queue_is_full() {
    let mut checklist = single_pair(Role::Controlling, TIE_CONTROLLING);
    checklist.start(T0).expect("start");
    // Fill the eight-slot queue with the initial transmit and seven
    // retransmissions, then send a request without draining.
    for _ in 0..MAX_RETRANSMISSIONS {
        let deadline = checklist.next_wakeup().expect("timer");
        checklist
            .handle_input(Input::Timeout(deadline))
            .expect("retransmit");
    }
    let request = build_request(
        TransactionId([0xB3; 12]),
        0x7EFF_FFFF,
        Some(ATTR_ICE_CONTROLLED),
        TIE_CONTROLLED,
        false,
    );
    assert_eq!(
        deliver(&mut checklist, T0 + ONE_MICRO, B1, A1, &request),
        Err(IceError::EventQueueFull)
    );
    assert_eq!(
        checklist.pair(0).expect("pair").state(),
        PairState::InProgress
    );
    assert_eq!(drain(&mut checklist).len(), 8);
}

#[test]
fn early_and_empty_timeouts_are_no_ops() {
    let mut running = single_pair(Role::Controlling, TIE_CONTROLLING);
    running.start(T0).expect("start");
    let _ = sends(&drain(&mut running)).remove(0);
    let deadline = running.next_wakeup().expect("timer");
    running
        .handle_input(Input::Timeout(T0))
        .expect("early timeout");
    assert_eq!(running.next_wakeup(), Some(deadline));
    assert_eq!(drain(&mut running), [] as [rtx_ice::Event; 0]);

    let mut idle = Checklist::new(Role::Controlling, TIE_CONTROLLING);
    idle.handle_input(Input::Timeout(T0))
        .expect("no outstanding transaction");
    assert!(idle.next_wakeup().is_none());
    assert!(!idle.is_started());
}

#[test]
fn nomination_timeout_and_nomination_error_fail_the_checklist() {
    let timeout_failure = {
        let (mut controller, mut controllee) = (
            single_pair(Role::Controlling, TIE_CONTROLLING),
            single_pair(Role::Controlled, TIE_CONTROLLED),
        );
        controller.start(T0).expect("start controlling");
        controllee.start(T0).expect("start controlled");
        let check = sends(&drain(&mut controller)).remove(0);
        let _ = sends(&drain(&mut controllee)).remove(0);
        deliver(
            &mut controllee,
            T0 + ONE_MICRO,
            A1,
            B1,
            check.payload().expect("payload"),
        )
        .expect("check");
        let response = responses(&drain(&mut controllee)).remove(0);
        deliver(
            &mut controller,
            T0 + ONE_MICRO,
            B1,
            A1,
            response.payload().expect("payload"),
        )
        .expect("response");
        let nomination = sends(&drain(&mut controller))
            .into_iter()
            .find(|event| {
                matches!(
                    event,
                    Event::SendCheck {
                        nominated: true,
                        ..
                    }
                )
            })
            .expect("nomination");
        for _ in 0..=MAX_RETRANSMISSIONS {
            let deadline = controller.next_wakeup().expect("timer");
            controller
                .handle_input(Input::Timeout(deadline))
                .expect("retransmit or fail");
            drain(&mut controller);
        }
        assert_eq!(controller.state(), ChecklistState::Failed);
        assert!(controller.nominated_pair().is_none());
        assert_eq!(
            controller.pair(0).expect("pair").state(),
            PairState::Succeeded
        );
        assert_eq!(nomination.nominated(), Some(true));
        controller
    };
    assert_eq!(timeout_failure.state(), ChecklistState::Failed);

    let mut controller = single_pair(Role::Controlling, TIE_CONTROLLING);
    let mut controllee = single_pair(Role::Controlled, TIE_CONTROLLED);
    controller.start(T0).expect("start controlling");
    controllee.start(T0).expect("start controlled");
    let check = sends(&drain(&mut controller)).remove(0);
    let _ = sends(&drain(&mut controllee)).remove(0);
    deliver(
        &mut controllee,
        T0 + ONE_MICRO,
        A1,
        B1,
        check.payload().expect("payload"),
    )
    .expect("check");
    let response = responses(&drain(&mut controllee)).remove(0);
    deliver(
        &mut controller,
        T0 + ONE_MICRO,
        B1,
        A1,
        response.payload().expect("payload"),
    )
    .expect("response");
    let nomination = sends(&drain(&mut controller))
        .into_iter()
        .find(|event| {
            matches!(
                event,
                Event::SendCheck {
                    nominated: true,
                    ..
                }
            )
        })
        .expect("nomination");
    let mut buffer = [0u8; 32];
    let writer = rtx_stun::message::MessageWriter::new(
        &mut buffer,
        MessageType::new(METHOD_BINDING, rtx_stun::message::CLASS_ERROR_RESPONSE),
        nomination.transaction_id().expect("transaction"),
    )
    .expect("writer");
    let length = writer.written();
    deliver(
        &mut controller,
        T0 + Duration::from_micros(2),
        B1,
        A1,
        &buffer[..length],
    )
    .expect("nomination error");
    let events = drain(&mut controller);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::ChecklistFailed))
    );
    assert_eq!(controller.state(), ChecklistState::Failed);
    assert!(controller.nominated_pair().is_none());
}

#[test]
fn event_accessors_cover_every_variant() {
    let response = Event::SendResponse {
        destination: A1,
        pair: 3,
        transaction_id: TransactionId([0xE0; 12]),
        accepted_nomination: true,
        message: [0u8; MAX_STUN_MESSAGE_SIZE],
        message_len: 4,
    };
    assert_eq!(response.payload().map(<[u8]>::len), Some(4));
    assert_eq!(response.pair(), Some(3));
    assert_eq!(response.transaction_id(), Some(TransactionId([0xE0; 12])));
    assert_eq!(response.source(), None);
    assert_eq!(response.destination(), Some(A1));
    assert_eq!(response.nominated(), None);

    let succeeded = Event::CheckSucceeded { pair: 2 };
    assert_eq!(succeeded.pair(), Some(2));
    assert!(succeeded.payload().is_none());
    assert!(succeeded.transaction_id().is_none());
    assert!(succeeded.source().is_none());
    assert!(succeeded.destination().is_none());
    assert!(succeeded.nominated().is_none());

    let failed = Event::CheckFailed { pair: 2 };
    assert_eq!(failed.pair(), Some(2));
    let nominated = Event::PairNominated { pair: 2 };
    assert_eq!(nominated.pair(), Some(2));
    let completed = Event::ChecklistCompleted { pair: 2 };
    assert_eq!(completed.pair(), Some(2));
    let checklist_failed = Event::ChecklistFailed;
    assert_eq!(checklist_failed.pair(), None);
    assert!(checklist_failed.payload().is_none());
    assert!(checklist_failed.transaction_id().is_none());
    assert!(checklist_failed.source().is_none());
    assert!(checklist_failed.destination().is_none());
    assert!(checklist_failed.nominated().is_none());
}

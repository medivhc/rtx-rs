//! M4-R1 / M4-R2 resource-bound tests for `rtx-ice`.
//!
//! The gate names are fixed in `docs/m3-m4-gates.md`: these tests are the
//! evidence for `MAX_ICE_CANDIDATES` and `MAX_ICE_PAIRS`, and M4 reuses them.

use rtx_core::{IpAddr, SocketAddr};
use rtx_ice::{
    COMPONENT_RTP, Candidate, CandidatePair, CandidateType, Checklist, IceError,
    MAX_ICE_CANDIDATES, MAX_ICE_PAIRS, Role, Transport,
};

fn host(ip: [u8; 4], port: u16) -> Candidate {
    Candidate::new(
        CandidateType::Host,
        COMPONENT_RTP,
        Transport::Udp,
        SocketAddr::new(IpAddr::V4(ip), port),
        None,
    )
    .expect("host candidate")
}

// M4-R1 — a full candidate table rejects the new candidate explicitly and
// leaves every existing candidate byte-for-byte unchanged.
#[test]
fn m4_r01_max_ice_candidates_overflow_is_explicit() {
    let mut checklist = Checklist::new(Role::Controlling, 0x1111_2222_3333_4444);

    for index in 0..MAX_ICE_CANDIDATES {
        let port = 10_000 + u16::try_from(index).expect("index fits u16");
        checklist
            .add_local_candidate(host([10, 0, 0, 1], port))
            .expect("local candidate within the bound");
    }
    assert_eq!(checklist.local_candidate_count(), MAX_ICE_CANDIDATES);
    let before: Vec<Candidate> = checklist.local_candidates().collect();

    let rejected = host(
        [10, 0, 0, 1],
        10_000 + u16::try_from(MAX_ICE_CANDIDATES).expect("bound fits u16"),
    );
    assert_eq!(
        checklist.add_local_candidate(rejected),
        Err(IceError::CandidateTableFull)
    );
    let after: Vec<Candidate> = checklist.local_candidates().collect();
    assert_eq!(before, after, "existing local candidates must not change");
    assert_eq!(checklist.local_candidate_count(), MAX_ICE_CANDIDATES);

    // The remote table has its own independent budget.
    for index in 0..MAX_ICE_CANDIDATES {
        let port = 20_000 + u16::try_from(index).expect("index fits u16");
        checklist
            .add_remote_candidate(host([10, 0, 0, 2], port))
            .expect("remote candidate within the bound");
    }
    assert_eq!(checklist.remote_candidate_count(), MAX_ICE_CANDIDATES);
    let remote_before: Vec<Candidate> = checklist.remote_candidates().collect();
    assert_eq!(
        checklist.add_remote_candidate(host(
            [10, 0, 0, 2],
            20_000 + u16::try_from(MAX_ICE_CANDIDATES).expect("bound fits u16"),
        )),
        Err(IceError::CandidateTableFull)
    );
    assert_eq!(
        remote_before,
        checklist.remote_candidates().collect::<Vec<_>>(),
        "existing remote candidates must not change"
    );
}

// M4-R2 — a full pair table rejects the new generation atomically; every
// existing pair keeps its addresses, priority, state and nomination flag.
#[test]
fn m4_r02_max_ice_pairs_overflow_is_explicit() {
    let mut checklist = Checklist::new(Role::Controlling, 0xAAAA_BBBB_CCCC_DDDD);

    for index in 0..8u16 {
        checklist
            .add_local_candidate(host([10, 0, 0, 1], 10_000 + index))
            .expect("local candidate");
        checklist
            .add_remote_candidate(host([10, 0, 0, 2], 20_000 + index))
            .expect("remote candidate");
    }
    assert_eq!(checklist.generate_pairs().expect("8x8 pairs"), 64);
    assert_eq!(checklist.pair_count(), MAX_ICE_PAIRS);

    let before: Vec<CandidatePair> = (0..u16::try_from(MAX_ICE_PAIRS).expect("bound fits u16"))
        .filter_map(|index| checklist.pair(index))
        .collect();
    assert_eq!(before.len(), MAX_ICE_PAIRS);

    // A ninth remote candidate is allowed by the candidate table, but the
    // eight new pairs do not fit the pair table. The whole step is rejected.
    checklist
        .add_remote_candidate(host([10, 0, 0, 2], 20_008))
        .expect("remote candidate still fits");
    assert_eq!(checklist.generate_pairs(), Err(IceError::PairTableFull));
    assert_eq!(checklist.pair_count(), MAX_ICE_PAIRS);

    let after: Vec<CandidatePair> = (0..u16::try_from(MAX_ICE_PAIRS).expect("bound fits u16"))
        .filter_map(|index| checklist.pair(index))
        .collect();
    assert_eq!(before, after, "existing pairs must not change");
}

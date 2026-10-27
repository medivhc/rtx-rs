#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! Bounded ICE candidate/check tables and a sans-IO checklist state machine
//! ([RFC 8445]).
//!
//! This crate is the R4-1 slice of the `rtx-ice` layer. It owns candidate
//! bookkeeping and connectivity-check state; it owns no socket, reads no
//! clock, allocates nothing and never blocks. Every output is a [`Event`]
//! carrying bytes encoded with the public `rtx-stun` codec, and every input
//! is an [`rtx_core::Input`].
//!
//! [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
//!
//! # Implemented
//!
//! - [`Candidate`] records type, component, transport, address, base,
//!   priority and an opaque foundation. Component 1 (RTP) and UDP are the only
//!   accepted values.
//! - [`Checklist::add_local_candidate`] and
//!   [`Checklist::add_remote_candidate`] fill two independently bounded
//!   tables. Full tables reject the new candidate with
//!   [`IceError::CandidateTableFull`]; nothing is evicted or grown.
//! - [`Checklist::generate_pairs`] forms the deduplicated local x remote
//!   matrix, orders it by decreasing pair priority and bounds it by
//!   [`MAX_ICE_PAIRS`]. Overflow is explicit and atomic.
//! - [`Checklist`] implements [`rtx_core::ProtocolMachine`] and drives
//!   `Frozen`/`Waiting`/`In-Progress`/`Succeeded`/`Failed` pairs through
//!   Binding requests and responses.
//! - Retransmission is driven only by [`rtx_core::Input::Timeout`] and
//!   [`rtx_core::ProtocolMachine::next_wakeup`], with [`INITIAL_RTO`],
//!   [`MAX_RTO`] and [`MAX_RETRANSMISSIONS`] as constants.
//! - Regular nomination: the controlling side nominates a `Succeeded` pair
//!   with `USE-CANDIDATE`; the controlled side accepts only for a `Succeeded`
//!   pair. Aggressive nomination is not implemented.
//! - Minimal consent freshness: a valid Binding indication on the nominated
//!   pair refreshes a timestamp; [`Checklist::is_consent_stale`] answers the
//!   staleness query. The state machine never sends keepalives.
//!
//! # Explicitly not implemented
//!
//! - Socket candidate gathering, interface enumeration and STUN server
//!   discovery. Candidates enter through the add APIs; "gathering" in this
//!   order means filling these tables. Both belong to R4-2.
//! - TURN allocation, refresh and permissions. [`CandidateType::Relay`] is a
//!   type value only; R4-2 owns the TURN client.
//! - ICE restart, ICE-lite, aggressive nomination and foundation-based pair
//!   pruning. All pairs are unfrozen unconditionally at
//!   [`Checklist::start`].
//! - The RTCP component (component 2), TCP candidates and multihomed local
//!   preference selection ([RFC 8421]).
//! - `USERNAME` and `MESSAGE-INTEGRITY` validation. There is no shared
//!   credential context in this order, so inbound checks are processed
//!   without authentication and outbound checks carry no integrity
//!   attribute. **This crate does not claim an authenticated ICE agent.**
//! - `DTLS`/`SRTP` wiring, SDP parsing and the media path. Those belong to P6.
//!
//! [RFC 8421]: https://www.rfc-editor.org/rfc/rfc8421
//!
//! # Priorities
//!
//! [`Candidate::new`] applies the recommended formula of [RFC 8445]
//! §5.1.2.1:
//!
//! ```text
//! priority = (2^24) * (type preference) +
//!            (2^8)  * (local preference) +
//!            (2^0)  * (256 - component ID)
//! ```
//!
//! The type preferences are the §5.1.2.2 recommendations: host 126,
//! peer-reflexive 110, server-reflexive 100, relay 0. [`LOCAL_PREFERENCE`] is
//! 65535 and the component is 1, so a host candidate has priority
//! `(126 << 24) + (65535 << 8) + 255 = 0x7EFF_FFFF`.
//!
//! **Anchor note.** The `STUN-ICE-003` scenario in `rtx-stun` writes host
//! priority as `0x6EFF_FFFF = (110 << 24) + (65535 << 8) + 255`. Under
//! [RFC 8445] §5.1.2.2, 110 is the *peer-reflexive* type preference, not the
//! host value; `0x6EFF_FFFF` is therefore the peer-reflexive priority, and
//! this crate asserts exactly that in its tests. The task also requires host
//! 126 and strictly decreasing peer-reflexive/server-reflexive/relay
//! priorities, which cannot coexist with a host value derived from 110. This
//! crate follows the RFC table and records the difference instead of
//! inventing a second weighting.
//!
//! Pair priority follows [RFC 8445] §6.1.2.3:
//!
//! ```text
//! pair priority = 2^32 * MIN(G, D) + 2 * MAX(G, D) + (G > D ? 1 : 0)
//! ```
//!
//! `G` is the controlling candidate's priority and `D` the controlled
//! candidate's, so both agents compute the same number and the tie-break
//! always favours the controlling side. See [`pair_priority`].
//!
//! # Bounded tables
//!
//! | constant | value | unit | overflow |
//! |---|---|---|---|
//! | [`MAX_ICE_CANDIDATES`] | 16 per side | candidates | [`IceError::CandidateTableFull`], no eviction |
//! | [`MAX_ICE_PAIRS`] | 64 | pairs | [`IceError::PairTableFull`], no new pair, existing pairs untouched |
//!
//! `MAX_ICE_CANDIDATES` applies to the local table and to the remote table
//! independently, so one machine can hold at most 32 candidates. Both values
//! are Tier B choices, documented on the constants; the M4 resource budget
//! will pin them. The tables are fixed arrays plus a count: no `alloc`, no
//! `heapless`.
//!
//! # Checklist, checks and nomination
//!
//! [`Checklist::new`] fixes the role and the local tie-breaker. The role can
//! never change: a conflicting inbound request returns
//! [`IceError::RoleConflict`] with the request's transaction id, leaving the
//! tables untouched. Encoding the STUN 487 response is the caller's job.
//!
//! [`Checklist::start`] unfreezes every pair and starts the highest-priority
//! `Waiting` pair, or the oldest triggered check. An inbound Binding request
//! for an unknown pair creates a peer-reflexive remote candidate for the
//! observed source and queues a triggered check; this is the only automatic
//! candidate creation, everything else comes from the caller. Ordinary checks
//! run in pair-priority order and are serialized: at most one transaction is
//! outstanding, which keeps the Tier B timer state to one deadline. The
//! controlling side nominates the first `Succeeded` pair and stops probing
//! lower-priority pairs.
//!
//! Retransmission timing:
//!
//! - initial RTO [`INITIAL_RTO`] = 500 ms (RFC 8445 §14.3 minimum; RFC 5389
//!   §7.2.1 fixed-line recommendation);
//! - doubling, capped at [`MAX_RTO`] = 8 s;
//! - up to [`MAX_RETRANSMISSIONS`] = 7 retransmissions (RFC 5389 `Rc`);
//! - after the final wait, the pair becomes `Failed` and the next pair starts.
//!
//! A success response whose transaction id, source and destination match the
//! outstanding check marks the pair `Succeeded`. Mismatched or late
//! responses are ignored, never treated as a table failure.
//!
//! The controlling side nominates the highest-priority `Succeeded` pair by
//! sending `USE-CANDIDATE`; it completes when the matching success response
//! arrives. The controlled side marks the pair nominated and the checklist
//! `Completed` only when a `USE-CANDIDATE` request arrives for a pair that is
//! already `Succeeded`. All other nomination markers are ignored.
//!
//! # Consent
//!
//! On completion the nominated pair starts a consent timestamp. A Binding
//! indication received from the nominated pair's remote address refreshes it;
//! indications on other pairs do not. [`Checklist::is_consent_stale`] returns
//! `false` when no pair is nominated, `false` at exactly the timeout and
//! `true` strictly after it. Sending keepalives and choosing the timeout are
//! caller responsibilities.
//!
//! # Transaction ids
//!
//! Transaction ids come from an internal 64-bit counter, not randomness. The
//! first id is counter 1; bytes 0-3 are the fixed tag `RTX!` and bytes 4-11
//! are the counter in big-endian order. The counter wraps at `u64::MAX`. This
//! is deterministic for tests and reproducible across agents; it is **not**
//! cryptographic randomness and must be replaced before an authenticated
//! production deployment.
//!
//! # Events and caller responsibilities
//!
//! [`rtx_core::ProtocolMachine::poll_event`] yields one [`Event`] at a time:
//!
//! | event | meaning |
//! |---|---|
//! | [`Event::SendCheck`] | send the encoded Binding request from `source` to `destination` |
//! | [`Event::SendResponse`] | send the encoded Binding success response to `destination` |
//! | [`Event::CheckSucceeded`] | the pair's check succeeded |
//! | [`Event::CheckFailed`] | the pair's check failed |
//! | [`Event::PairNominated`] | the pair is nominated |
//! | [`Event::ChecklistCompleted`] | selection finished; the nominated pair is usable |
//! | [`Event::ChecklistFailed`] | no pair is available |
//!
//! Caller responsibility table:
//!
//! | responsibility | owner |
//! |---|---|
//! | Obtain local/remote candidates (sockets, STUN, TURN, signalling) | caller; R4-2 adds gathering |
//! | Fill the candidate tables | caller, through the add APIs |
//! | Encode and send every datagram | caller, from `Event::SendCheck`/`SendResponse` |
//! | Retransmit lost datagrams | crate schedules the resend event; caller sends it |
//! | Provide time | caller, as [`rtx_core::Timestamp`] in `Input::Timeout` and `DatagramMeta::now` |
//! | Encode the 487 response for [`IceError::RoleConflict`] | caller |
//! | Send consent keepalives | caller; the crate only records timestamps |
//! | Read the nominated pair and hand its addresses to the media layer | caller, after `ChecklistCompleted` |
//! | Authenticate checks (`USERNAME`/`MESSAGE-INTEGRITY`) | nobody in this order; explicit gap |
//!
//! # Split with R4-2
//!
//! R4-1 (this crate) stops at "tables filled by the caller". R4-2 owns socket
//! gathering, STUN server discovery, TURN allocation/refresh and the relay
//! candidate lifecycle. The relay type exists here only so R4-2 can insert
//! relay candidates without changing this API.

mod candidate;
mod checklist;
mod error;
mod pair;
mod role;

pub use candidate::{
    COMPONENT_RTP, Candidate, CandidateType, Component, LOCAL_PREFERENCE, Transport,
};
pub use checklist::{
    Checklist, ChecklistState, Event, INITIAL_RTO, MAX_EVENTS, MAX_ICE_CANDIDATES, MAX_ICE_PAIRS,
    MAX_RETRANSMISSIONS, MAX_RTO, MAX_STUN_MESSAGE_SIZE,
};
pub use error::IceError;
pub use pair::{CandidatePair, PairState, pair_priority};
pub use role::Role;

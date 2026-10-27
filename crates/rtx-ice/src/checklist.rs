//! The bounded candidate tables and the checklist state machine.

use rtx_core::{DatagramMeta, Duration, Input, ProtocolMachine, SocketAddr, Timestamp};
use rtx_stun::Decode;
use rtx_stun::attributes::{
    ATTR_ICE_CONTROLLED, ATTR_ICE_CONTROLLING, ATTR_PRIORITY, ATTR_USE_CANDIDATE,
    ATTR_XORMAPPED_ADDRESS,
};
use rtx_stun::message::{
    BINDING_REQUEST, BINDING_SUCCESS, CLASS_ERROR_RESPONSE, CLASS_INDICATION, CLASS_REQUEST,
    CLASS_SUCCESS_RESPONSE, METHOD_BINDING, Message, MessageWriter, TRANSACTION_ID_SIZE,
    TransactionId,
};
use rtx_stun::xoraddr::XorMappedAddress;

use crate::{
    COMPONENT_RTP, Candidate, CandidatePair, CandidateType, IceError, PairState, Role, Transport,
};

/// Maximum candidates held per side (local and remote each).
///
/// A checklist holds up to two tables, so at most `2 * MAX_ICE_CANDIDATES`
/// candidates exist per machine. The value is a Tier B bound, not an RFC
/// constant: it covers a dual-stack host plus a STUN-reflexive, peer-reflexive
/// and relay address for one component with room to spare, while keeping the
/// table a fixed array. The M4 resource-budget document will pin the final
/// value; this order only requires that the limit be explicit and testable.
pub const MAX_ICE_CANDIDATES: usize = 16;

/// Maximum candidate pairs in one checklist.
///
/// [RFC 8445] §6.1.2.5 suggests a configurable default of 100 pairs. This
/// order chooses 64: with the UDP/RTP-only scope and the serialized check
/// order, 64 is enough for 8x8 candidate matrices, and the smaller bound keeps
/// the fixed pair array suitable for Tier B. A full table rejects the whole
/// generation step; it never evicts a pair.
///
/// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
pub const MAX_ICE_PAIRS: usize = 64;

/// Maximum queued sans-IO events.
pub const MAX_EVENTS: usize = 8;

/// Bytes reserved for one encoded STUN message in an event.
///
/// A Binding request with `PRIORITY`, a role attribute and `USE-CANDIDATE`
/// occupies at most 20 + 8 + 16 + 4 = 48 bytes; a success response with
/// `XOR-MAPPED-ADDRESS` at most 20 + 24 = 44 bytes.
pub const MAX_STUN_MESSAGE_SIZE: usize = 64;

/// Initial retransmission timeout: 500 ms.
///
/// [RFC 8445] §14.3 requires an RTO of at least 500 ms; [RFC 5389] §7.2.1
/// recommends 500 ms for fixed-line access and doubling after each
/// retransmission.
///
/// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
/// [RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389
pub const INITIAL_RTO: Duration = Duration::from_millis(500);

/// Upper bound on the doubling backoff: 8 s.
///
/// [RFC 5389] §7.2.1 leaves the RTO configurable and shows an unbounded
/// doubling example. This order caps the interval at `2^4 * INITIAL_RTO` so a
/// Tier B machine never needs a timer beyond this constant. The cap is an
/// implementation bound, not an RFC-mandated value.
///
/// [RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389
pub const MAX_RTO: Duration = Duration::from_millis(8_000);

/// Retransmissions per check before the pair fails.
///
/// [RFC 5389] §7.2.1 names `Rc` with a default of 7. This order sends the
/// initial request plus seven retransmissions, then waits one more RTO before
/// declaring the transaction failed.
///
/// [RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389
pub const MAX_RETRANSMISSIONS: u32 = 7;

/// Fixed four-byte prefix of every generated transaction id.
const TRANSACTION_TAG: [u8; 4] = [b'R', b'T', b'X', b'!'];

/// Checklist state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChecklistState {
    /// Connectivity checks or nomination are still in progress.
    Running,
    /// A pair was nominated (controlled side) or the nomination succeeded
    /// (controlling side).
    Completed,
    /// Every pair failed, or nomination timed out.
    Failed,
}

/// One sans-IO output produced by the checklist.
///
/// The caller drains events with [`ProtocolMachine::poll_event`] and is
/// responsible for sending every datagram, retransmitting when the encoded
/// message is lost, and switching away from a failed pair. Events never
/// borrow caller memory: the encoded message lives in the event itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Send this encoded Binding request.
    SendCheck {
        /// Local base address to send from ([RFC 8445] §6.1.2.4).
        ///
        /// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
        source: SocketAddr,
        /// Remote candidate address to send to.
        destination: SocketAddr,
        /// Index of the pair this check belongs to.
        pair: u16,
        /// Transaction id carried by `message`.
        transaction_id: TransactionId,
        /// `true` when the request carries `USE-CANDIDATE`.
        nominated: bool,
        /// Encoded Binding request.
        message: [u8; MAX_STUN_MESSAGE_SIZE],
        /// Number of valid bytes in `message`.
        message_len: usize,
    },
    /// Send this encoded Binding success response.
    SendResponse {
        /// Address the request came from.
        destination: SocketAddr,
        /// Index of the pair the request matched.
        pair: u16,
        /// Transaction id echoed from the request.
        transaction_id: TransactionId,
        /// `true` when the request carried `USE-CANDIDATE` and the pair was
        /// already `Succeeded`.
        accepted_nomination: bool,
        /// Encoded Binding success response.
        message: [u8; MAX_STUN_MESSAGE_SIZE],
        /// Number of valid bytes in `message`.
        message_len: usize,
    },
    /// A check on `pair` produced a success response.
    CheckSucceeded { pair: u16 },
    /// A check on `pair` failed (timeout or error response).
    CheckFailed { pair: u16 },
    /// `pair` was nominated.
    PairNominated { pair: u16 },
    /// The checklist completed with `pair` nominated.
    ChecklistCompleted { pair: u16 },
    /// The checklist failed; no pair is nominated.
    ChecklistFailed,
}

impl Event {
    /// Returns the encoded STUN bytes for a transmit event.
    #[must_use]
    pub fn payload(&self) -> Option<&[u8]> {
        match self {
            Self::SendCheck {
                message,
                message_len,
                ..
            }
            | Self::SendResponse {
                message,
                message_len,
                ..
            } => Some(&message[..*message_len]),
            Self::CheckSucceeded { .. }
            | Self::CheckFailed { .. }
            | Self::PairNominated { .. }
            | Self::ChecklistCompleted { .. }
            | Self::ChecklistFailed => None,
        }
    }

    /// Returns the pair an event refers to, if any.
    #[must_use]
    pub fn pair(&self) -> Option<u16> {
        match self {
            Self::SendCheck { pair, .. }
            | Self::SendResponse { pair, .. }
            | Self::CheckSucceeded { pair }
            | Self::CheckFailed { pair }
            | Self::PairNominated { pair }
            | Self::ChecklistCompleted { pair } => Some(*pair),
            Self::ChecklistFailed => None,
        }
    }

    /// Returns the transaction id of a transmit event.
    #[must_use]
    pub fn transaction_id(&self) -> Option<TransactionId> {
        match self {
            Self::SendCheck { transaction_id, .. } | Self::SendResponse { transaction_id, .. } => {
                Some(*transaction_id)
            }
            Self::CheckSucceeded { .. }
            | Self::CheckFailed { .. }
            | Self::PairNominated { .. }
            | Self::ChecklistCompleted { .. }
            | Self::ChecklistFailed => None,
        }
    }

    /// Returns the local base address of a check transmit event.
    #[must_use]
    pub fn source(&self) -> Option<SocketAddr> {
        match self {
            Self::SendCheck { source, .. } => Some(*source),
            Self::SendResponse { .. }
            | Self::CheckSucceeded { .. }
            | Self::CheckFailed { .. }
            | Self::PairNominated { .. }
            | Self::ChecklistCompleted { .. }
            | Self::ChecklistFailed => None,
        }
    }

    /// Returns the destination address of a transmit event.
    #[must_use]
    pub fn destination(&self) -> Option<SocketAddr> {
        match self {
            Self::SendCheck { destination, .. } | Self::SendResponse { destination, .. } => {
                Some(*destination)
            }
            Self::CheckSucceeded { .. }
            | Self::CheckFailed { .. }
            | Self::PairNominated { .. }
            | Self::ChecklistCompleted { .. }
            | Self::ChecklistFailed => None,
        }
    }

    /// Returns `true`/`false` for a check transmit event, `None` otherwise.
    #[must_use]
    pub fn nominated(&self) -> Option<bool> {
        match self {
            Self::SendCheck { nominated, .. } => Some(*nominated),
            Self::SendResponse { .. }
            | Self::CheckSucceeded { .. }
            | Self::CheckFailed { .. }
            | Self::PairNominated { .. }
            | Self::ChecklistCompleted { .. }
            | Self::ChecklistFailed => None,
        }
    }
}

/// The ICE checklist for one component and one transport.
///
/// See the crate-level documentation for the implemented scope, the caller's
/// responsibilities and the explicit gaps.
#[derive(Debug)]
pub struct Checklist {
    role: Role,
    tie_breaker: u64,
    local: CandidateTable,
    remote: CandidateTable,
    pairs: PairTable,
    triggers: TriggerQueue,
    events: EventQueue,
    state: ChecklistState,
    started: bool,
    outstanding: Option<OutstandingCheck>,
    next_transaction: u64,
    nominated_pair: Option<u16>,
    consent_timestamp: Option<Timestamp>,
}

impl Checklist {
    /// Creates an empty checklist with a fixed role and local tie-breaker.
    ///
    /// `tie_breaker` is written into the outbound `ICE-CONTROLLING` or
    /// `ICE-CONTROLLED` attribute. It is caller-supplied so tests and
    /// runtimes remain deterministic; this crate never generates randomness.
    #[must_use]
    pub fn new(role: Role, tie_breaker: u64) -> Self {
        Self {
            role,
            tie_breaker,
            local: CandidateTable::new(),
            remote: CandidateTable::new(),
            pairs: PairTable::new(),
            triggers: TriggerQueue::new(),
            events: EventQueue::new(),
            state: ChecklistState::Running,
            started: false,
            outstanding: None,
            next_transaction: 0,
            nominated_pair: None,
            consent_timestamp: None,
        }
    }

    /// Returns the fixed role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Returns the checklist state.
    #[must_use]
    pub const fn state(&self) -> ChecklistState {
        self.state
    }

    /// Returns `true` once [`Checklist::start`] has run.
    #[must_use]
    pub const fn is_started(&self) -> bool {
        self.started
    }

    /// Adds one local candidate.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::CandidateTableFull`] when the local table is at
    /// [`MAX_ICE_CANDIDATES`], and [`IceError::AlreadyStarted`] after
    /// [`Checklist::start`].
    pub fn add_local_candidate(&mut self, candidate: Candidate) -> Result<(), IceError> {
        if self.started {
            return Err(IceError::AlreadyStarted);
        }
        self.local.push(candidate)
    }

    /// Adds one remote candidate.
    ///
    /// # Errors
    ///
    /// Same contract as [`Checklist::add_local_candidate`], on the remote
    /// table.
    pub fn add_remote_candidate(&mut self, candidate: Candidate) -> Result<(), IceError> {
        if self.started {
            return Err(IceError::AlreadyStarted);
        }
        self.remote.push(candidate)
    }

    /// Returns the number of local candidates.
    #[must_use]
    pub const fn local_candidate_count(&self) -> usize {
        self.local.len()
    }

    /// Returns the number of remote candidates.
    #[must_use]
    pub const fn remote_candidate_count(&self) -> usize {
        self.remote.len()
    }

    /// Iterates over local candidates in insertion order.
    pub fn local_candidates(&self) -> impl Iterator<Item = Candidate> + '_ {
        self.local.iter().copied()
    }

    /// Iterates over remote candidates in insertion order.
    pub fn remote_candidates(&self) -> impl Iterator<Item = Candidate> + '_ {
        self.remote.iter().copied()
    }

    /// Generates all unique local x remote pairs for the one component and
    /// transport, ordered by decreasing pair priority.
    ///
    /// The generation is atomic: when the new pairs do not fit
    /// [`MAX_ICE_PAIRS`], nothing is added and
    /// [`IceError::PairTableFull`] is returned.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::PairTableFull`] on overflow and
    /// [`IceError::AlreadyStarted`] after [`Checklist::start`].
    pub fn generate_pairs(&mut self) -> Result<usize, IceError> {
        if self.started {
            return Err(IceError::AlreadyStarted);
        }
        let mut planned: [Option<(SocketAddr, SocketAddr)>; MAX_ICE_PAIRS] = [None; MAX_ICE_PAIRS];
        let mut planned_len = 0;
        for local in self.local.iter() {
            for remote in self.remote.iter() {
                let key = (local.address(), remote.address());
                if self.pairs.contains_addresses(key.0, key.1) {
                    continue;
                }
                if planned[..planned_len].contains(&Some(key)) {
                    continue;
                }
                if self.pairs.len() + planned_len >= MAX_ICE_PAIRS {
                    return Err(IceError::PairTableFull);
                }
                planned[planned_len] = Some(key);
                planned_len += 1;
            }
        }

        let mut added = 0;
        for local in self.local.iter() {
            for remote in self.remote.iter() {
                if self
                    .pairs
                    .contains_addresses(local.address(), remote.address())
                {
                    continue;
                }
                self.pairs
                    .push(CandidatePair::new(*local, *remote, self.role))?;
                added += 1;
            }
        }
        Ok(added)
    }

    /// Returns the number of pairs.
    #[must_use]
    pub const fn pair_count(&self) -> usize {
        self.pairs.len()
    }

    /// Returns pair `index`.
    #[must_use]
    pub fn pair(&self, index: u16) -> Option<CandidatePair> {
        self.pairs.get(index).copied()
    }

    /// Iterates over pairs in decreasing priority order: the check order.
    pub fn pairs(&self) -> impl Iterator<Item = CandidatePair> + '_ {
        self.pairs.iter_in_order().copied()
    }

    /// Returns the nominated pair, if any.
    #[must_use]
    pub fn nominated_pair(&self) -> Option<CandidatePair> {
        self.nominated_pair
            .and_then(|index| self.pairs.get(index))
            .copied()
    }

    /// Returns `true` when consent on the nominated pair is older than
    /// `timeout`.
    ///
    /// A fresh nomination starts the consent timer at the completion
    /// timestamp. A valid Binding indication on the nominated pair refreshes
    /// it. With no nominated pair the query is not applicable and returns
    /// `false`; pairs that are not nominated never participate
    /// ([RFC 8445] §11).
    ///
    /// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
    #[must_use]
    pub fn is_consent_stale(&self, now: Timestamp, timeout: Duration) -> bool {
        if self.nominated_pair.is_none() {
            return false;
        }
        let Some(last) = self.consent_timestamp else {
            return true;
        };
        now.saturating_duration_since(last) > timeout
    }

    /// Starts connectivity checks at `now`.
    ///
    /// All `Frozen` pairs are unfrozen to `Waiting` (this order does no
    /// foundation-based freezing), then the highest-priority `Waiting` pair
    /// or the oldest triggered check is started.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::EventQueueFull`] when the event queue cannot hold
    /// the first transmit or the terminal failure event.
    pub fn start(&mut self, now: Timestamp) -> Result<(), IceError> {
        if self.state != ChecklistState::Running {
            return Ok(());
        }
        if self.started {
            // A previous start may have failed with `EventQueueFull`; after
            // draining, the same call retries the scheduler.
            return self.drive(now);
        }
        self.started = true;
        if self.pairs.is_empty() {
            return self.fail();
        }
        for pair in self.pairs.slots[..self.pairs.len].iter_mut().flatten() {
            if pair.state() == PairState::Frozen {
                pair.set_state(PairState::Waiting);
            }
        }
        self.drive(now)
    }

    fn handle_datagram(&mut self, meta: DatagramMeta, payload: &[u8]) -> Result<(), IceError> {
        if !rtx_stun::is_stun_message(payload) {
            return Err(IceError::NotStunMessage);
        }
        let (message, _) = Message::decode(payload).map_err(IceError::Decode)?;
        if message.typ.method != METHOD_BINDING {
            return Err(IceError::UnexpectedMessage);
        }
        if message.typ.class == CLASS_REQUEST {
            return self.handle_request(meta, &message);
        }
        if message.typ.class == CLASS_INDICATION {
            self.handle_indication(meta);
            return Ok(());
        }
        if message.typ.class == CLASS_SUCCESS_RESPONSE || message.typ.class == CLASS_ERROR_RESPONSE
        {
            return self.handle_response(meta, &message);
        }
        Err(IceError::UnexpectedMessage)
    }

    fn handle_request(
        &mut self,
        meta: DatagramMeta,
        message: &Message<'_>,
    ) -> Result<(), IceError> {
        let has_controlling = message.contains(ATTR_ICE_CONTROLLING);
        let has_controlled = message.contains(ATTR_ICE_CONTROLLED);
        // RFC 8445 §7.3.1.1: a controlling agent rejects ICE-CONTROLLING and
        // a controlled agent rejects ICE-CONTROLLED. A request carrying both
        // attributes necessarily hits one of those cases. This order keeps
        // its role and returns the 487 condition as an error.
        let conflict = match self.role {
            Role::Controlling => has_controlling,
            Role::Controlled => has_controlled,
        };
        if conflict {
            return Err(IceError::RoleConflict(message.transaction_id));
        }
        // PRIORITY is mandatory in a connectivity check (RFC 8445 §7.2.4).
        // The wire value is validated but the remote candidate's priority in
        // this order comes from the caller-filled candidate table; adopting
        // the wire value for learned peer-reflexive candidates is a gap.
        let _priority = parse_priority(message)?;
        let nomination = match message.get(ATTR_USE_CANDIDATE) {
            None => false,
            Some(attr) if attr.value.is_empty() => true,
            Some(_) => return Err(IceError::InvalidAttribute),
        };
        if self.events.remaining() < 3 {
            return Err(IceError::EventQueueFull);
        }

        let local_index = self
            .local
            .position(meta.destination)
            .ok_or(IceError::UnknownLocalCandidate)?;
        let local = self
            .local
            .get(local_index)
            .copied()
            .ok_or(IceError::UnknownLocalCandidate)?;
        let remote_index = self.remote.position(meta.source);
        let existing_pair = self.pairs.position(local.address(), meta.source);
        if existing_pair.is_none() {
            if self.pairs.len() == MAX_ICE_PAIRS {
                return Err(IceError::PairTableFull);
            }
            if remote_index.is_none() && self.remote.len() == MAX_ICE_CANDIDATES {
                return Err(IceError::CandidateTableFull);
            }
            if self.triggers.len() == MAX_ICE_PAIRS {
                return Err(IceError::TriggerQueueFull);
            }
        }

        let mut response = [0u8; MAX_STUN_MESSAGE_SIZE];
        let response_len = encode_response(&mut response, message.transaction_id, meta.source)?;
        if self.events.remaining() < 3 {
            return Err(IceError::EventQueueFull);
        }

        let remote = if let Some(index) = remote_index {
            self.remote
                .get(index)
                .copied()
                .ok_or(IceError::UnknownLocalCandidate)?
        } else {
            let candidate = Candidate::new(
                CandidateType::PeerReflexive,
                COMPONENT_RTP,
                Transport::Udp,
                meta.source,
                Some(local.base()),
            )?;
            self.remote.push(candidate)?;
            candidate
        };
        let pair_index = if let Some(index) = existing_pair {
            index
        } else {
            let index = self
                .pairs
                .push(CandidatePair::new(local, remote, self.role))?;
            self.triggers.push(index)?;
            index
        };

        let mut accepted_nomination = false;
        if nomination
            && self
                .pairs
                .get(pair_index)
                .is_some_and(|pair| pair.state() == PairState::Succeeded)
        {
            self.pairs.set_nominated(pair_index, true);
            self.nominated_pair = Some(pair_index);
            self.consent_timestamp = Some(meta.now);
            self.state = ChecklistState::Completed;
            self.cancel_outstanding();
            accepted_nomination = true;
        }

        self.events.push(Event::SendResponse {
            destination: meta.source,
            pair: pair_index,
            transaction_id: message.transaction_id,
            accepted_nomination,
            message: response,
            message_len: response_len,
        })?;
        if accepted_nomination {
            self.events
                .push(Event::PairNominated { pair: pair_index })?;
            self.events
                .push(Event::ChecklistCompleted { pair: pair_index })?;
        }
        self.drive(meta.now)?;
        Ok(())
    }

    fn handle_response(
        &mut self,
        meta: DatagramMeta,
        message: &Message<'_>,
    ) -> Result<(), IceError> {
        let Some(check) = self.outstanding else {
            // No transaction is in flight: a late or unsolicited response is
            // ignored, never an error.
            return Ok(());
        };
        if message.transaction_id != check.transaction_id {
            return Ok(());
        }
        let Some(pair) = self.pairs.get(check.pair) else {
            self.outstanding = None;
            return Ok(());
        };
        if pair.remote().address() != meta.source || pair.local().base() != meta.destination {
            return Ok(());
        }
        if self.events.remaining() < 3 {
            return Err(IceError::EventQueueFull);
        }

        if message.typ.class == CLASS_SUCCESS_RESPONSE {
            if check.nominated {
                self.pairs.set_nominated(check.pair, true);
                self.nominated_pair = Some(check.pair);
                self.consent_timestamp = Some(meta.now);
                self.state = ChecklistState::Completed;
                self.outstanding = None;
                self.events
                    .push(Event::PairNominated { pair: check.pair })?;
                self.events
                    .push(Event::ChecklistCompleted { pair: check.pair })?;
            } else {
                self.pairs.set_state(check.pair, PairState::Succeeded);
                self.outstanding = None;
                self.events
                    .push(Event::CheckSucceeded { pair: check.pair })?;
                self.drive(meta.now)?;
            }
            return Ok(());
        }

        // A matching error response fails the check (RFC 8445 §7.2.5.2.1).
        if check.nominated {
            self.outstanding = None;
            self.state = ChecklistState::Failed;
            self.events.push(Event::ChecklistFailed)?;
        } else {
            self.pairs.set_state(check.pair, PairState::Failed);
            self.outstanding = None;
            self.events.push(Event::CheckFailed { pair: check.pair })?;
            self.drive(meta.now)?;
        }
        Ok(())
    }

    fn handle_indication(&mut self, meta: DatagramMeta) {
        // Consent freshness is unauthenticated in this order. Only an
        // indication that arrives on the nominated pair refreshes the timer;
        // anything else is ignored.
        if let Some(index) = self.nominated_pair {
            if let Some(pair) = self.pairs.get(index) {
                if pair.remote().address() == meta.source && pair.local().base() == meta.destination
                {
                    self.consent_timestamp = Some(meta.now);
                }
            }
        }
    }

    fn handle_timeout(&mut self, now: Timestamp) -> Result<(), IceError> {
        let Some(check) = self.outstanding else {
            return Ok(());
        };
        if now < check.deadline {
            return Ok(());
        }
        if check.retransmissions < MAX_RETRANSMISSIONS {
            if self.events.remaining() < 1 {
                return Err(IceError::EventQueueFull);
            }
            let Some(pair) = self.pairs.get(check.pair) else {
                self.outstanding = None;
                return Ok(());
            };
            let doubled = check.rto + check.rto;
            let next_rto = if doubled > MAX_RTO { MAX_RTO } else { doubled };
            let mut message = [0u8; MAX_STUN_MESSAGE_SIZE];
            let message_len = self.encode_request(
                &mut message,
                check.transaction_id,
                pair.local().priority(),
                check.nominated,
            )?;
            self.events.push(Event::SendCheck {
                source: pair.local().base(),
                destination: pair.remote().address(),
                pair: check.pair,
                transaction_id: check.transaction_id,
                nominated: check.nominated,
                message,
                message_len,
            })?;
            self.outstanding = Some(OutstandingCheck {
                retransmissions: check.retransmissions + 1,
                rto: next_rto,
                deadline: now + next_rto,
                ..check
            });
            return Ok(());
        }

        if self.events.remaining() < 2 {
            return Err(IceError::EventQueueFull);
        }
        if check.nominated {
            self.outstanding = None;
            self.state = ChecklistState::Failed;
            self.events.push(Event::ChecklistFailed)?;
            return Ok(());
        }
        self.pairs.set_state(check.pair, PairState::Failed);
        self.outstanding = None;
        self.events.push(Event::CheckFailed { pair: check.pair })?;
        self.drive(now)
    }

    fn drive(&mut self, now: Timestamp) -> Result<(), IceError> {
        if !self.started || self.state != ChecklistState::Running || self.outstanding.is_some() {
            return Ok(());
        }
        // RFC 8445 §6.1.4.2 step 1: the triggered-check queue runs before the
        // ordinary Waiting order.
        while let Some(index) = self.triggers.pop() {
            let Some(pair) = self.pairs.get(index) else {
                continue;
            };
            if pair.state() == PairState::Succeeded || pair.state() == PairState::Failed {
                continue;
            }
            return self.send_check(index, now, false);
        }
        // The controlling agent nominates the highest-priority usable pair as
        // soon as one exists; it does not need to probe lower-priority pairs
        // first.
        if self.role == Role::Controlling {
            if let Some(index) = self.pairs.first_succeeded_un_nominated() {
                return self.send_check(index, now, true);
            }
        }
        if let Some(index) = self.pairs.first_waiting() {
            return self.send_check(index, now, false);
        }
        if self.pairs.all_failed() {
            return self.fail();
        }
        Ok(())
    }

    fn send_check(&mut self, index: u16, now: Timestamp, nominated: bool) -> Result<(), IceError> {
        let Some(pair) = self.pairs.get(index).copied() else {
            return Ok(());
        };
        if self.events.remaining() < 1 {
            return Err(IceError::EventQueueFull);
        }
        let transaction_id = self.next_transaction_id();
        let mut message = [0u8; MAX_STUN_MESSAGE_SIZE];
        let message_len = self.encode_request(
            &mut message,
            transaction_id,
            pair.local().priority(),
            nominated,
        )?;
        self.events.push(Event::SendCheck {
            source: pair.local().base(),
            destination: pair.remote().address(),
            pair: index,
            transaction_id,
            nominated,
            message,
            message_len,
        })?;
        if !nominated {
            self.pairs.set_state(index, PairState::InProgress);
        }
        self.outstanding = Some(OutstandingCheck {
            pair: index,
            transaction_id,
            nominated,
            retransmissions: 0,
            rto: INITIAL_RTO,
            deadline: now + INITIAL_RTO,
        });
        Ok(())
    }

    fn encode_request(
        &self,
        output: &mut [u8],
        transaction_id: TransactionId,
        priority: u32,
        nominated: bool,
    ) -> Result<usize, IceError> {
        let mut writer =
            MessageWriter::new(output, BINDING_REQUEST, transaction_id).map_err(IceError::Wire)?;
        // RFC 8445 §7.2.4: PRIORITY is mandatory; the role attribute follows
        // the local role; a regular nomination appends an empty
        // USE-CANDIDATE.
        writer
            .push(ATTR_PRIORITY, &priority.to_be_bytes())
            .map_err(IceError::Wire)?;
        let role_attribute = match self.role {
            Role::Controlling => ATTR_ICE_CONTROLLING,
            Role::Controlled => ATTR_ICE_CONTROLLED,
        };
        writer
            .push(role_attribute, &self.tie_breaker.to_be_bytes())
            .map_err(IceError::Wire)?;
        if nominated {
            writer
                .push(ATTR_USE_CANDIDATE, &[])
                .map_err(IceError::Wire)?;
        }
        Ok(writer.written())
    }

    fn next_transaction_id(&mut self) -> TransactionId {
        self.next_transaction = self.next_transaction.wrapping_add(1);
        let mut value = [0u8; TRANSACTION_ID_SIZE];
        value[..TRANSACTION_TAG.len()].copy_from_slice(&TRANSACTION_TAG);
        value[TRANSACTION_TAG.len()..].copy_from_slice(&self.next_transaction.to_be_bytes());
        TransactionId(value)
    }

    fn cancel_outstanding(&mut self) {
        if let Some(check) = self.outstanding.take() {
            if !check.nominated {
                self.pairs.set_state(check.pair, PairState::Waiting);
            }
        }
    }

    fn fail(&mut self) -> Result<(), IceError> {
        if self.events.remaining() < 1 {
            return Err(IceError::EventQueueFull);
        }
        self.state = ChecklistState::Failed;
        self.outstanding = None;
        self.events.push(Event::ChecklistFailed)
    }
}

impl ProtocolMachine for Checklist {
    type Input<'a> = Input<'a>;
    type Event = Event;
    type Error = IceError;

    fn handle_input(&mut self, input: Self::Input<'_>) -> Result<(), Self::Error> {
        match input {
            Input::Datagram { meta, payload } => self.handle_datagram(meta, payload),
            Input::Timeout(now) => self.handle_timeout(now),
        }
    }

    fn poll_event(&mut self) -> Option<Self::Event> {
        self.events.pop()
    }

    fn next_wakeup(&self) -> Option<Timestamp> {
        self.outstanding.map(|check| check.deadline)
    }
}

fn parse_priority(message: &Message<'_>) -> Result<u32, IceError> {
    let attribute = message
        .get(ATTR_PRIORITY)
        .ok_or(IceError::MissingPriority)?;
    let value: [u8; 4] = attribute
        .value
        .try_into()
        .map_err(|_| IceError::InvalidAttribute)?;
    Ok(u32::from_be_bytes(value))
}

fn encode_response(
    output: &mut [u8],
    transaction_id: TransactionId,
    observed: SocketAddr,
) -> Result<usize, IceError> {
    let mut writer =
        MessageWriter::new(output, BINDING_SUCCESS, transaction_id).map_err(IceError::Wire)?;
    XorMappedAddress::new(observed.ip, observed.port)
        .push_to(ATTR_XORMAPPED_ADDRESS, &mut writer)
        .map_err(IceError::Wire)?;
    Ok(writer.written())
}

#[derive(Debug, Clone, Copy)]
struct OutstandingCheck {
    pair: u16,
    transaction_id: TransactionId,
    nominated: bool,
    retransmissions: u32,
    rto: Duration,
    deadline: Timestamp,
}

#[derive(Debug)]
struct CandidateTable {
    slots: [Option<Candidate>; MAX_ICE_CANDIDATES],
    len: usize,
}

impl CandidateTable {
    const fn new() -> Self {
        Self {
            slots: [None; MAX_ICE_CANDIDATES],
            len: 0,
        }
    }

    const fn len(&self) -> usize {
        self.len
    }

    fn push(&mut self, candidate: Candidate) -> Result<(), IceError> {
        if self.len == MAX_ICE_CANDIDATES {
            return Err(IceError::CandidateTableFull);
        }
        self.slots[self.len] = Some(candidate);
        self.len += 1;
        Ok(())
    }

    fn get(&self, index: u16) -> Option<&Candidate> {
        self.slots.get(usize::from(index)).and_then(Option::as_ref)
    }

    fn iter(&self) -> impl Iterator<Item = &Candidate> {
        self.slots[..self.len].iter().filter_map(Option::as_ref)
    }

    fn position(&self, address: SocketAddr) -> Option<u16> {
        self.slots[..self.len]
            .iter()
            .position(|slot| slot.is_some_and(|candidate| candidate.address() == address))
            .and_then(|index| u16::try_from(index).ok())
    }
}

#[derive(Debug)]
struct PairTable {
    slots: [Option<CandidatePair>; MAX_ICE_PAIRS],
    order: [u16; MAX_ICE_PAIRS],
    len: usize,
}

impl PairTable {
    const fn new() -> Self {
        Self {
            slots: [None; MAX_ICE_PAIRS],
            order: [0; MAX_ICE_PAIRS],
            len: 0,
        }
    }

    const fn len(&self) -> usize {
        self.len
    }

    const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn get(&self, index: u16) -> Option<&CandidatePair> {
        self.slots.get(usize::from(index)).and_then(Option::as_ref)
    }

    fn set_state(&mut self, index: u16, state: PairState) {
        if let Some(pair) = self
            .slots
            .get_mut(usize::from(index))
            .and_then(Option::as_mut)
        {
            pair.set_state(state);
        }
    }

    fn set_nominated(&mut self, index: u16, nominated: bool) {
        if let Some(pair) = self
            .slots
            .get_mut(usize::from(index))
            .and_then(Option::as_mut)
        {
            pair.set_nominated(nominated);
        }
    }

    fn push(&mut self, pair: CandidatePair) -> Result<u16, IceError> {
        if self.len == MAX_ICE_PAIRS {
            return Err(IceError::PairTableFull);
        }
        let index = u16::try_from(self.len).map_err(|_| IceError::PairTableFull)?;
        self.slots[self.len] = Some(pair);
        // Insert into the descending-priority order. Equal priorities keep
        // their creation order, matching the "arbitrary" tie rule of
        // RFC 8445 §6.1.2.3 with a deterministic choice.
        let mut position = self.len;
        while position > 0 {
            let previous = self.order[position - 1];
            let previous_priority = self
                .get(previous)
                .map_or(0, |candidate_pair| candidate_pair.priority());
            if previous_priority >= pair.priority() {
                break;
            }
            position -= 1;
        }
        let mut cursor = self.len;
        while cursor > position {
            self.order[cursor] = self.order[cursor - 1];
            cursor -= 1;
        }
        self.order[position] = index;
        self.len += 1;
        Ok(index)
    }

    fn contains_addresses(&self, local: SocketAddr, remote: SocketAddr) -> bool {
        self.slots[..self.len]
            .iter()
            .flatten()
            .any(|pair| pair.local().address() == local && pair.remote().address() == remote)
    }

    fn position(&self, local: SocketAddr, remote: SocketAddr) -> Option<u16> {
        self.slots[..self.len]
            .iter()
            .position(|slot| {
                slot.is_some_and(|pair| {
                    pair.local().address() == local && pair.remote().address() == remote
                })
            })
            .and_then(|index| u16::try_from(index).ok())
    }

    fn first_waiting(&self) -> Option<u16> {
        self.order[..self.len].iter().copied().find(|&index| {
            self.get(index)
                .is_some_and(|pair| pair.state() == PairState::Waiting)
        })
    }

    fn first_succeeded_un_nominated(&self) -> Option<u16> {
        self.order[..self.len].iter().copied().find(|&index| {
            self.get(index)
                .is_some_and(|pair| pair.state() == PairState::Succeeded && !pair.is_nominated())
        })
    }

    fn all_failed(&self) -> bool {
        !self.is_empty()
            && self.slots[..self.len]
                .iter()
                .flatten()
                .all(|pair| pair.state() == PairState::Failed)
    }

    fn iter_in_order(&self) -> impl Iterator<Item = &CandidatePair> {
        self.order[..self.len]
            .iter()
            .filter_map(|&index| self.get(index))
    }
}

#[derive(Debug)]
struct TriggerQueue {
    entries: [u16; MAX_ICE_PAIRS],
    head: usize,
    len: usize,
}

impl TriggerQueue {
    const fn new() -> Self {
        Self {
            entries: [0; MAX_ICE_PAIRS],
            head: 0,
            len: 0,
        }
    }

    const fn len(&self) -> usize {
        self.len
    }

    fn push(&mut self, pair: u16) -> Result<(), IceError> {
        if self.contains(pair) {
            return Ok(());
        }
        if self.len == MAX_ICE_PAIRS {
            return Err(IceError::TriggerQueueFull);
        }
        let position = (self.head + self.len) % MAX_ICE_PAIRS;
        self.entries[position] = pair;
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<u16> {
        if self.len == 0 {
            return None;
        }
        let pair = self.entries[self.head];
        self.head = (self.head + 1) % MAX_ICE_PAIRS;
        self.len -= 1;
        Some(pair)
    }

    fn contains(&self, pair: u16) -> bool {
        (0..self.len).any(|offset| self.entries[(self.head + offset) % MAX_ICE_PAIRS] == pair)
    }
}

#[derive(Debug)]
struct EventQueue {
    slots: [Option<Event>; MAX_EVENTS],
    head: usize,
    len: usize,
}

impl EventQueue {
    const fn new() -> Self {
        Self {
            slots: [None; MAX_EVENTS],
            head: 0,
            len: 0,
        }
    }

    const fn remaining(&self) -> usize {
        MAX_EVENTS - self.len
    }

    fn push(&mut self, event: Event) -> Result<(), IceError> {
        if self.len == MAX_EVENTS {
            return Err(IceError::EventQueueFull);
        }
        let position = (self.head + self.len) % MAX_EVENTS;
        self.slots[position] = Some(event);
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<Event> {
        if self.len == 0 {
            return None;
        }
        let event = self.slots[self.head].take();
        self.head = (self.head + 1) % MAX_EVENTS;
        self.len -= 1;
        event
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::{COMPONENT_RTP, Candidate, CandidateType, Role, Transport};
    use rtx_core::IpAddr;

    fn host(octets: [u8; 4], port: u16) -> Candidate {
        Candidate::new(
            CandidateType::Host,
            COMPONENT_RTP,
            Transport::Udp,
            SocketAddr::new(IpAddr::V4(octets), port),
            None,
        )
        .expect("host candidate")
    }

    #[test]
    fn start_retry_after_a_full_event_queue_is_drained() {
        let mut checklist = Checklist::new(Role::Controlling, 1);
        checklist
            .add_local_candidate(host([10, 0, 0, 1], 5_000))
            .expect("local");
        checklist
            .add_remote_candidate(host([10, 0, 0, 2], 6_000))
            .expect("remote");
        checklist.generate_pairs().expect("pair");
        for _ in 0..MAX_EVENTS {
            checklist
                .events
                .push(Event::ChecklistFailed)
                .expect("queue has room");
        }
        assert_eq!(
            checklist.events.push(Event::ChecklistFailed),
            Err(IceError::EventQueueFull)
        );
        assert_eq!(
            checklist.start(Timestamp::ZERO),
            Err(IceError::EventQueueFull)
        );
        assert!(checklist.is_started());
        assert_eq!(checklist.state(), ChecklistState::Running);

        while checklist.poll_event().is_some() {}
        checklist
            .start(Timestamp::from_micros(1))
            .expect("retry after draining");
        assert!(matches!(
            checklist.poll_event(),
            Some(Event::SendCheck { pair: 0, .. })
        ));
        assert_eq!(
            checklist.pair(0).expect("pair").state(),
            PairState::InProgress
        );
    }

    #[test]
    fn pair_table_rejects_an_extra_pair_and_supports_order_queries() {
        let pair = CandidatePair::new(
            host([10, 0, 0, 1], 5_000),
            host([10, 0, 0, 2], 6_000),
            Role::Controlling,
        );
        let mut table = PairTable::new();
        assert!(table.is_empty());
        assert!(!table.all_failed());
        for _ in 0..MAX_ICE_PAIRS {
            assert!(table.push(pair).is_ok());
        }
        assert_eq!(table.push(pair), Err(IceError::PairTableFull));
        assert_eq!(table.len(), MAX_ICE_PAIRS);
        assert!(table.contains_addresses(pair.local().address(), pair.remote().address()));
        assert_eq!(
            table.position(pair.local().address(), pair.remote().address()),
            Some(0)
        );
        assert_eq!(
            table.position(
                SocketAddr::new(IpAddr::V4([10, 0, 0, 3]), 7_000),
                pair.remote().address()
            ),
            None
        );
        assert_eq!(table.first_waiting(), None);
        assert_eq!(table.first_succeeded_un_nominated(), None);
        table.set_state(0, PairState::Waiting);
        assert_eq!(table.first_waiting(), Some(0));
        for index in 0..MAX_ICE_PAIRS {
            let index = u16::try_from(index).expect("fits");
            table.set_state(index, PairState::Failed);
        }
        assert!(table.all_failed());
    }

    #[test]
    fn trigger_queue_wraps_deduplicates_and_reports_overflow() {
        let mut queue = TriggerQueue::new();
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.pop(), None);
        for index in 0..MAX_ICE_PAIRS {
            queue
                .push(u16::try_from(index).expect("fits"))
                .expect("room");
        }
        assert_eq!(queue.len(), MAX_ICE_PAIRS);
        assert_eq!(queue.push(0), Ok(()));
        let extra = u16::try_from(MAX_ICE_PAIRS).expect("fits");
        assert_eq!(queue.push(extra), Err(IceError::TriggerQueueFull));
        assert_eq!(queue.pop(), Some(0));
        queue.push(extra).expect("slot after the pop");
        assert!(queue.contains(extra));
        assert_eq!(queue.len(), MAX_ICE_PAIRS);
    }

    #[test]
    fn event_queue_reports_its_bound() {
        let mut queue = EventQueue::new();
        assert_eq!(queue.remaining(), MAX_EVENTS);
        for _ in 0..MAX_EVENTS {
            queue.push(Event::ChecklistFailed).expect("room");
        }
        assert_eq!(queue.remaining(), 0);
        assert_eq!(
            queue.push(Event::ChecklistFailed),
            Err(IceError::EventQueueFull)
        );
        for _ in 0..MAX_EVENTS {
            assert!(queue.pop().is_some());
        }
        assert!(queue.pop().is_none());
    }

    #[test]
    fn a_full_event_queue_rejects_the_terminal_failure_event() {
        let mut checklist = Checklist::new(Role::Controlling, 1);
        for _ in 0..MAX_EVENTS {
            checklist.events.push(Event::ChecklistFailed).expect("room");
        }
        assert_eq!(checklist.fail(), Err(IceError::EventQueueFull));
        assert_eq!(checklist.state(), ChecklistState::Running);
    }

    #[test]
    fn consent_is_stale_when_a_nomination_has_no_timestamp() {
        let mut checklist = Checklist::new(Role::Controlling, 1);
        checklist.nominated_pair = Some(0);
        assert!(checklist.is_consent_stale(Timestamp::ZERO, Duration::from_millis(1)));
    }
}

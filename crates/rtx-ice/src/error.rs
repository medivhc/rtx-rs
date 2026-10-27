//! Typed errors returned by the candidate tables and the checklist.

use rtx_stun::{TransactionId, WireError};

/// Everything this crate rejects explicitly.
///
/// A full candidate or pair table never evicts and never grows: the insert
/// that does not fit returns [`IceError::CandidateTableFull`] or
/// [`IceError::PairTableFull`] and leaves every existing entry untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceError {
    /// The local or remote candidate table is at
    /// [`crate::MAX_ICE_CANDIDATES`]; the new candidate was rejected.
    CandidateTableFull,
    /// The pair table is at [`crate::MAX_ICE_PAIRS`]; no pair was added.
    PairTableFull,
    /// The triggered-check queue is full; the inbound request was rejected.
    TriggerQueueFull,
    /// The event queue is full; drain it with `poll_event` and retry.
    EventQueueFull,
    /// Candidates and pairs are frozen once `start` has been called.
    AlreadyStarted,
    /// This crate implements component 1 (RTP) only.
    UnsupportedComponent(u16),
    /// A non-host candidate needs its base transport address.
    MissingBaseAddress,
    /// A host candidate's base must be its own address ([RFC 8445] §5.1.1).
    ///
    /// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
    BaseAddressMismatch,
    /// The datagram is too short or lacks the STUN magic cookie.
    NotStunMessage,
    /// [`rtx_stun::Decode::decode`] rejected the datagram.
    Decode(WireError),
    /// The message is not a Binding request, response, or indication.
    UnexpectedMessage,
    /// An inbound Binding request lacks the mandatory `PRIORITY` attribute.
    MissingPriority,
    /// An attribute value has the wrong length.
    InvalidAttribute,
    /// The peer's role attribute conflicts with this agent's fixed role.
    ///
    /// The transaction id is carried so the caller can encode the STUN 487
    /// (`Role Conflict`) error response; this crate does not fabricate
    /// response bytes ([RFC 8445] §7.3.1.1).
    ///
    /// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
    RoleConflict(TransactionId),
    /// No local candidate has the destination address of the datagram.
    UnknownLocalCandidate,
    /// A STUN message could not be encoded into the fixed event buffer.
    Wire(WireError),
}

//! Candidate pairs, pair states and the [RFC 8445] §6.1.2.3 priority.
//!
//! [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445

use crate::{Candidate, Role};

/// Candidate-pair state ([RFC 8445] §6.1.2.6).
///
/// Nomination is a flag on the pair, not a sixth state: §6.1.2.6 defines
/// exactly these five values, and a nominated pair remains `Succeeded`.
///
/// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PairState {
    /// No check has been sent and the pair cannot be checked yet.
    Frozen,
    /// No check has been sent, but the pair may be checked.
    Waiting,
    /// A check is outstanding.
    InProgress,
    /// A check produced a success response.
    Succeeded,
    /// A check failed (timeout or error response).
    Failed,
}

/// One candidate pair in the checklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidatePair {
    local: Candidate,
    remote: Candidate,
    priority: u64,
    state: PairState,
    nominated: bool,
}

impl CandidatePair {
    pub(crate) fn new(local: Candidate, remote: Candidate, role: Role) -> Self {
        Self {
            local,
            remote,
            priority: pair_priority(local.priority(), remote.priority(), role),
            state: PairState::Frozen,
            nominated: false,
        }
    }

    /// Returns the local candidate.
    #[must_use]
    pub const fn local(self) -> Candidate {
        self.local
    }

    /// Returns the remote candidate.
    #[must_use]
    pub const fn remote(self) -> Candidate {
        self.remote
    }

    /// Returns the pair priority.
    #[must_use]
    pub const fn priority(self) -> u64 {
        self.priority
    }

    /// Returns the pair state.
    #[must_use]
    pub const fn state(self) -> PairState {
        self.state
    }

    /// Returns `true` after a successful regular nomination.
    #[must_use]
    pub const fn is_nominated(self) -> bool {
        self.nominated
    }

    pub(crate) fn set_state(&mut self, state: PairState) {
        self.state = state;
    }

    pub(crate) fn set_nominated(&mut self, nominated: bool) {
        self.nominated = nominated;
    }
}

/// Computes the pair priority from [RFC 8445] §6.1.2.3:
///
/// ```text
/// pair priority = 2^32 * MIN(G, D) + 2 * MAX(G, D) + (G > D ? 1 : 0)
/// ```
///
/// `local_priority` and `remote_priority` are the two candidates' priorities;
/// `role` selects which one is `G` — the candidate offered by the controlling
/// agent. The `+1` tie-break therefore always favours the controlling
/// candidate and both agents compute the same value for the same pair.
///
/// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
#[must_use]
pub fn pair_priority(local_priority: u32, remote_priority: u32, role: Role) -> u64 {
    let (g, d) = match role {
        Role::Controlling => (local_priority, remote_priority),
        Role::Controlled => (remote_priority, local_priority),
    };
    let minimum = u64::from(g.min(d));
    let maximum = u64::from(g.max(d));
    let tie_break = u64::from(g > d);
    (minimum << 32) + (maximum << 1) + tie_break
}

//! The ICE agent role.

/// The role an ICE agent takes for one checklist ([RFC 8445] §6.1.1).
///
/// The role is fixed when the [`Checklist`] is constructed and never changes:
/// this crate does not implement the role-switch branch of the role-conflict
/// repair procedure. A conflicting inbound request is rejected with
/// [`crate::IceError::RoleConflict`] instead.
///
/// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
/// [`Checklist`]: crate::Checklist
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The agent nominates pairs and sends `ICE-CONTROLLING`.
    Controlling,
    /// The agent accepts nominations and sends `ICE-CONTROLLED`.
    Controlled,
}

//! Candidate types and the [RFC 8445] §5.1.2.1 priority formula.
//!
//! [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445

use rtx_core::SocketAddr;

use crate::IceError;

/// Local preference used for every candidate in this crate.
///
/// [RFC 8445] §5.1.2.1 defines `local preference` as an integer from 0 to
/// 65535 and recommends 65535 when there is a single IP address. This order
/// keeps one fixed value; multihomed uniqueness ([RFC 8421]) is not
/// implemented.
///
/// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
/// [RFC 8421]: https://www.rfc-editor.org/rfc/rfc8421
pub const LOCAL_PREFERENCE: u16 = 65_535;

/// The RTP component (component ID 1).
///
/// RTCP (component 2) is not implemented in this order; see
/// [`crate::Checklist`] documentation.
pub const COMPONENT_RTP: Component = Component::RTP;

/// A candidate's component, the data stream it serves.
///
/// [RFC 8445] §5.1.2.1 allows component IDs 1 through 256. Only
/// [`Component::RTP`] (1) is accepted by [`Candidate::new`] here.
///
/// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Component(u16);

impl Component {
    /// Component ID 1, the RTP component.
    pub const RTP: Self = Self(1);

    /// Creates a component from its wire ID, if it is in `1..=256`.
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        if value == 0 || value > 256 {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Returns the component ID.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// The transport protocol of a candidate.
///
/// Only UDP is implemented in this order ([RFC 8445] §5.1.1); TCP candidates
/// are not in scope.
///
/// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// UDP.
    Udp,
}

impl Transport {
    /// Discriminator mixed into the candidate foundation.
    ///
    /// The value is the IANA IP protocol number for UDP (17). It is not a
    /// wire field; it only keeps future transports from colliding in
    /// [`Candidate::foundation`].
    const fn code(self) -> u8 {
        match self {
            Self::Udp => 17,
        }
    }
}

/// A candidate type ([RFC 8445] §5.1.1).
///
/// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateType {
    /// A transport address on a local interface.
    Host,
    /// A translated address learned from a STUN server.
    ///
    /// This crate does not query a STUN server; the caller supplies the
    /// address. Server discovery belongs to R4-2.
    ServerReflexive,
    /// A translated address learned from an inbound connectivity check.
    PeerReflexive,
    /// A relayed address allocated by a TURN server.
    ///
    /// Relay is a type value only: this crate contains no TURN allocation or
    /// refresh logic. Both belong to R4-2.
    Relay,
}

impl CandidateType {
    /// The recommended type preference ([RFC 8445] §5.1.2.2).
    ///
    /// Host 126, peer-reflexive 110, server-reflexive 100, relay 0.
    ///
    /// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
    #[must_use]
    pub const fn type_preference(self) -> u32 {
        match self {
            Self::Host => 126,
            Self::PeerReflexive => 110,
            Self::ServerReflexive => 100,
            Self::Relay => 0,
        }
    }

    /// Discriminator mixed into the candidate foundation.
    const fn code(self) -> u8 {
        match self {
            Self::Host => 1,
            Self::ServerReflexive => 2,
            Self::PeerReflexive => 3,
            Self::Relay => 4,
        }
    }
}

/// One ICE candidate.
///
/// The priority and foundation are derived in [`Candidate::new`]; callers do
/// not supply them. `base` is the local transport address a check is sent
/// from: for a host candidate it is the candidate address itself, for the
/// reflexive and relay types it is the caller-supplied base ([RFC 8445]
/// §5.1.1, §6.1.2.4).
///
/// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Candidate {
    typ: CandidateType,
    component: Component,
    transport: Transport,
    address: SocketAddr,
    base: SocketAddr,
    priority: u32,
    foundation: u32,
}

impl Candidate {
    /// Builds a candidate and derives its priority and foundation.
    ///
    /// `base` must be `None` or the same address for a host candidate, and
    /// must be `Some` for every other type. Only component 1 (RTP) is
    /// accepted.
    ///
    /// # Errors
    ///
    /// Returns [`IceError::UnsupportedComponent`] when `component` is not
    /// [`COMPONENT_RTP`], [`IceError::MissingBaseAddress`] when a non-host
    /// candidate has no base, and [`IceError::BaseAddressMismatch`] when a
    /// host candidate's base differs from its address.
    pub fn new(
        typ: CandidateType,
        component: Component,
        transport: Transport,
        address: SocketAddr,
        base: Option<SocketAddr>,
    ) -> Result<Self, IceError> {
        if component != COMPONENT_RTP {
            return Err(IceError::UnsupportedComponent(component.value()));
        }
        let base = match typ {
            CandidateType::Host => match base {
                None => address,
                Some(base) if base == address => address,
                Some(_) => return Err(IceError::BaseAddressMismatch),
            },
            CandidateType::ServerReflexive
            | CandidateType::PeerReflexive
            | CandidateType::Relay => base.ok_or(IceError::MissingBaseAddress)?,
        };
        let priority = priority_for(typ, LOCAL_PREFERENCE, component.value());
        let foundation = foundation_for(typ, transport, base);
        Ok(Self {
            typ,
            component,
            transport,
            address,
            base,
            priority,
            foundation,
        })
    }

    /// Returns the candidate type.
    #[must_use]
    pub const fn typ(self) -> CandidateType {
        self.typ
    }

    /// Returns the component.
    #[must_use]
    pub const fn component(self) -> Component {
        self.component
    }

    /// Returns the transport.
    #[must_use]
    pub const fn transport(self) -> Transport {
        self.transport
    }

    /// Returns the candidate transport address.
    #[must_use]
    pub const fn address(self) -> SocketAddr {
        self.address
    }

    /// Returns the base transport address.
    #[must_use]
    pub const fn base(self) -> SocketAddr {
        self.base
    }

    /// Returns the priority computed by [RFC 8445] §5.1.2.1.
    ///
    /// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
    #[must_use]
    pub const fn priority(self) -> u32 {
        self.priority
    }

    /// Returns the opaque foundation derived from (type, base, transport).
    ///
    /// This is a 32-bit FNV-1a hash, not a network-visible string. It exists
    /// so a future foundation-based pruning pass can group pairs; this order
    /// performs no pruning and never compares foundations.
    #[must_use]
    pub const fn foundation(self) -> u32 {
        self.foundation
    }
}

/// Implements the recommended priority formula ([RFC 8445] §5.1.2.1):
///
/// ```text
/// priority = (2^24) * (type preference) +
///            (2^8)  * (local preference) +
///            (2^0)  * (256 - component ID)
/// ```
///
/// [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
fn priority_for(typ: CandidateType, local_preference: u16, component: u16) -> u32 {
    (typ.type_preference() << 24)
        + (u32::from(local_preference) << 8)
        + (256 - u32::from(component))
}

/// FNV-1a over (type, transport, base), used as the opaque foundation.
fn foundation_for(typ: CandidateType, transport: Transport, base: SocketAddr) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    hash = fnv1a(hash, &[typ.code(), transport.code()]);
    match base.ip {
        rtx_core::IpAddr::V4(octets) => {
            hash = fnv1a(hash, &[4]);
            hash = fnv1a(hash, &octets);
        }
        rtx_core::IpAddr::V6(octets) => {
            hash = fnv1a(hash, &[6]);
            hash = fnv1a(hash, &octets);
        }
    }
    fnv1a(hash, &base.port.to_be_bytes())
}

/// Folds `bytes` into `hash` with the FNV-1a 32-bit parameters.
fn fnv1a(mut hash: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

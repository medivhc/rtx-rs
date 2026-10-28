//! Stream identifiers, directions and events.

use quinn_proto::{Dir, StreamId as QuinnStreamId, VarInt};

/// Stream directionality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Data flows in both directions.
    Bi,
    /// Data flows only from the initiator.
    Uni,
}

impl Direction {
    pub(crate) fn from_dir(dir: Dir) -> Self {
        match dir {
            Dir::Bi => Self::Bi,
            Dir::Uni => Self::Uni,
        }
    }
}

/// QUIC stream identifier.
///
/// The facade keeps the wire identifier (as `u64`) and validates direction
/// and ordering rules before touching the connection. Values only originate
/// from [`crate::Endpoint`], so the encoded initiator/direction bits always
/// match the connection that produced them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u64);

impl StreamId {
    /// The raw QUIC stream identifier.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// The stream’s directionality, decoded from the identifier’s second
    /// least-significant bit.
    #[must_use]
    pub const fn direction(self) -> Direction {
        if self.0 & 0b10 == 0 {
            Direction::Bi
        } else {
            Direction::Uni
        }
    }

    /// The per-initiator, per-direction index (`id >> 2`).
    #[must_use]
    pub const fn index(self) -> u64 {
        self.0 >> 2
    }

    /// Whether this stream was initiated by the peer that sent it as a
    /// client (`id & 1 == 0`).
    pub(crate) const fn initiated_by_client(self) -> bool {
        self.0 & 1 == 0
    }

    /// Convert to the upstream identifier, rejecting values that cannot be
    /// encoded as a QUIC varint.
    pub(crate) fn to_quinn(self) -> Option<QuinnStreamId> {
        VarInt::from_u64(self.0).ok().map(QuinnStreamId::from)
    }
}

impl From<QuinnStreamId> for StreamId {
    fn from(id: QuinnStreamId) -> Self {
        Self(u64::from(id))
    }
}

/// Result of one [`crate::Endpoint::read_stream`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRead {
    /// Bytes were copied into the caller buffer.
    Data {
        /// Number of bytes copied.
        len: usize,
    },
    /// The peer finished the stream and all data has been delivered.
    Finished,
}

/// Application-visible stream events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamEvent {
    /// One or more new streams of a direction are available for accept.
    Opened {
        /// Directionality of the opened streams.
        direction: Direction,
    },
    /// The stream has data or an error to read.
    Readable {
        /// The readable stream.
        stream: StreamId,
    },
    /// A formerly write-blocked stream may accept data again.
    Writable {
        /// The writable stream.
        stream: StreamId,
    },
    /// The peer finished receiving all data on this stream.
    Finished {
        /// The finished stream.
        stream: StreamId,
    },
    /// The peer asked us to stop sending.
    Stopped {
        /// The stopped stream.
        stream: StreamId,
        /// Application error code supplied by the peer.
        error_code: u64,
    },
    /// New stream credits are available for opening.
    Available {
        /// Directionality for which credit increased.
        direction: Direction,
    },
}

#[cfg(test)]
mod tests {
    use super::{Direction, StreamId};
    use quinn_proto::{Dir, Side, StreamId as QuinnStreamId};

    fn id(side: Side, dir: Dir, index: u64) -> StreamId {
        StreamId::from(QuinnStreamId::new(side, dir, index))
    }

    #[test]
    fn identifier_bits_decode_direction_and_index() {
        let client_bi = id(Side::Client, Dir::Bi, 0);
        assert_eq!(client_bi.direction(), Direction::Bi);
        assert_eq!(client_bi.index(), 0);
        assert!(client_bi.initiated_by_client());

        let client_uni_second = id(Side::Client, Dir::Uni, 1);
        assert_eq!(client_uni_second.direction(), Direction::Uni);
        assert_eq!(client_uni_second.index(), 1);
        assert!(client_uni_second.initiated_by_client());

        let server_bi = id(Side::Server, Dir::Bi, 0);
        assert_eq!(server_bi.direction(), Direction::Bi);
        assert!(!server_bi.initiated_by_client());
    }
}

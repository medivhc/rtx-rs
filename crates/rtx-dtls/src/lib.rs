#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! DTLS 1.2 record layer (RFC 6347 section 4.1), Sans-IO and allocation-free.
//!
//! This crate freezes the record-layer contract that the later DTLS handshake
//! engine builds on:
//!
//! - [`Record`] / [`RecordHeader`] encode and decode the 13-byte DTLS 1.2
//!   header (`content_type`, version `{254, 253}`, epoch, 48-bit sequence
//!   number, length) with strict bounds checking;
//! - [`RecordCipher`] seals and opens AEAD-protected records through
//!   [`rtx_crypto::AeadProvider`], with caller-owned output buffers and no
//!   allocation. Nonce construction (RFC 5116) and sequence ownership stay in
//!   this layer;
//! - [`ReplayWindow`] is the 64-record sliding replay bitmap;
//! - [`RecordMachine`] implements [`rtx_core::ProtocolMachine`], consuming
//!   [`rtx_core::Input::Datagram`] / [`rtx_core::Input::Timeout`] and emitting
//!   [`RecordEvent`]s. Time is only the injected [`rtx_core::Timestamp`]; the
//!   crate never reads a system clock and never performs I/O.
//!
//! # Scope
//!
//! Only the record layer is implemented. Handshake messages, the key schedule
//! / HKDF, certificates and SRTP are out of scope; a later change adds the
//! handshake on top of this contract. DTLS 1.3 (RFC 9147) is **not**
//! implemented: this crate accepts exactly the DTLS 1.2 record version
//! `{254, 253}` and rejects every other version, including DTLS 1.0 and 1.3.
//! DTLS 1.3 remains a tracked gap for a separate crate.
//!
//! # Record protection
//!
//! A protected record carries an 8-byte explicit nonce, the ciphertext and a
//! 16-byte GCM tag. The explicit nonce is `epoch || sequence_number`; the
//! AEAD nonce is `fixed_iv (4) || epoch (2) || sequence_number (6)`. The
//! additional data is `epoch || sequence_number || type || version ||
//! plaintext_length` (RFC 5246 section 6.2.3.3 order, not wire-header order).
//!
//! # Failure semantics
//!
//! Every decoder validates before indexing or writing. Truncated, oversized,
//! wrong-version, wrong-content-type and length-mismatched inputs return a
//! [`RecordError`]; none of them panics, and none touches a caller-owned
//! output buffer before its structural checks pass. Replayed and out-of-window
//! records return distinct errors ([`RecordError::Replay`] and
//! [`RecordError::TooOld`]).
//!
//! # Example
//!
//! ```ignore
//! use rtx_dtls::{RecordEncoder, RecordMachine, ContentType, Input};
//!
//! let mut encoder = RecordEncoder::new(0);
//! let mut wire = [0u8; 64];
//! let written = encoder
//!     .seal_plaintext(ContentType::ApplicationData, b"hello", &mut wire)?;
//! let mut machine = RecordMachine::<256, _>::new(provider);
//! machine.handle_input(Input::Datagram {
//!     meta,
//!     payload: &wire[..written],
//! })?;
//! let event = machine.poll_event().expect("one event");
//! assert_eq!(event.plaintext(), b"hello");
//! ```

mod cipher;
mod error;
mod machine;
mod record;
mod replay;

pub use cipher::{AEAD_NONCE_LEN, FIXED_IV_LEN, RecordCipher};
pub use error::RecordError;
pub use machine::{EVENT_QUEUE_CAPACITY, RecordEncoder, RecordEvent, RecordMachine};
pub use record::{
    AEAD_EXPLICIT_NONCE_LEN, AEAD_OVERHEAD, AEAD_TAG_LEN, ContentType, DTLS12_VERSION,
    MAX_FRAGMENT_LEN, MAX_PLAINTEXT_LEN, RECORD_HEADER_LEN, Record, RecordHeader,
    SEQUENCE_NUMBER_MAX, SequenceNumber,
};
pub use replay::{REPLAY_WINDOW_SIZE, ReplayWindow};

pub use rtx_core::{DatagramMeta, Input, IpAddr, ProtocolMachine, SocketAddr, Timestamp};
pub use rtx_crypto::{AeadAlgorithm, AeadProvider, CryptoError};

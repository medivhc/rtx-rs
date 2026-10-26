#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! DTLS 1.2 record layer and minimal handshake (RFC 6347), Sans-IO and
//! allocation-free.
//!
//! This crate freezes the DTLS 1.2 contract that later media and connection
//! layers build on:
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
//!   [`RecordEvent`]s;
//! - [`HandshakeMachine`] implements [`rtx_core::ProtocolMachine`] for the
//!   minimal DTLS 1.2 profile (X25519 ECDHE, Ed25519 signatures,
//!   ECDHE-ECDSA-AES128-GCM-SHA256, `use_srtp` 0x0001), emits
//!   [`HandshakeEvent::Established`] with RFC 5764 keying material and owns
//!   handshake retransmission. The state table and export contract are frozen
//!   in `HANDSHAKE.md`;
//! - [`SrtpKeyingMaterial`] exports the DTLS-SRTP master keys and salts with
//!   the `EXTRACTOR-dtls_srtp` label.
//!
//! Time is only the injected [`rtx_core::Timestamp`]; the crate never reads a
//! system clock and never performs I/O.
//!
//! # Scope
//!
//! Only DTLS 1.2 is implemented. DTLS 1.3 (RFC 9147), HKDF, X.509 parsing and
//! certificate-chain validation, `HelloVerifyRequest`/cookies, handshake
//! fragmentation/reassembly, renegotiation, Extended Master Secret and SRTP
//! media handling are **not** implemented. The handshake does not send a
//! Certificate message: the peer's raw Ed25519 public key is provisioned out
//! of band and only the `ServerKeyExchange` signature is verified.
//!
//! This profile is deliberately not wire-interoperable with a stock OpenSSL
//! DTLS 1.2 handshake; `HANDSHAKE.md` records the differential gaps instead of
//! claiming interoperability. DTLS 1.3 and certificate validation remain
//! tracked gaps for separate crates.
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
//! [`RecordError::TooOld`]). Handshake failures are terminal: the machine
//! moves to [`HandshakeState::Failed`], drops the ephemeral key and zeroizes
//! its key-schedule buffers.

mod cipher;
mod error;
mod handshake;
mod handshake_error;
mod handshake_message;
mod keyschedule;
mod machine;
mod record;
mod replay;
mod srtp;

pub use cipher::{AEAD_NONCE_LEN, FIXED_IV_LEN, RecordCipher};
pub use error::RecordError;
pub use handshake::{
    HandshakeConfig, HandshakeEvent, HandshakeMachine, HandshakeState, MAX_HANDSHAKE_RECORD_LEN,
    Role,
};
pub use handshake_error::{HandshakeError, SrtpExportError};
pub use handshake_message::{
    ClientHelloInfo, HANDSHAKE_HEADER_LEN, HandshakeMessage, HandshakeType,
    MAX_HANDSHAKE_MESSAGE_LEN, OfferedAlgorithms, decode_handshake_message, parse_client_hello,
};
pub use keyschedule::FINISHED_VERIFY_DATA_LEN;
pub use machine::{EVENT_QUEUE_CAPACITY, RecordEncoder, RecordEvent, RecordMachine};
pub use record::{
    AEAD_EXPLICIT_NONCE_LEN, AEAD_OVERHEAD, AEAD_TAG_LEN, ContentType, DTLS12_VERSION,
    MAX_FRAGMENT_LEN, MAX_PLAINTEXT_LEN, RECORD_HEADER_LEN, Record, RecordHeader,
    SEQUENCE_NUMBER_MAX, SequenceNumber,
};
pub use replay::{REPLAY_WINDOW_SIZE, ReplayWindow};
pub use srtp::{
    DTLS_SRTP_EXPORTER_LABEL, SRTP_EXPORT_LEN, SRTP_MASTER_KEY_LEN, SRTP_MASTER_SALT_LEN,
    SRTP_PROFILE_AES128_CM_HMAC_SHA1_80, SrtpKeyingMaterial,
};

pub use rtx_core::{DatagramMeta, Input, IpAddr, ProtocolMachine, SocketAddr, Timestamp};
pub use rtx_crypto::{AeadAlgorithm, AeadProvider, CryptoError};

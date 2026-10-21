#![cfg_attr(not(feature = "std"), no_std)]
//! Wire codec for the Session Traversal Utilities for NAT (`STUN`).
//!
//! This crate decodes and encodes STUN messages as defined by [RFC 5389],
//! together with the attributes TURN ([RFC 5766]), ICE ([RFC 8445]) and the
//! NAT behaviour discovery extensions ([RFC 5780]) add, on top of the
//! allocation-free [`rtx_wire`] codec contract ([`Decode`] and [`Encode`]).
//!
//! Decoding is zero-copy: [`Message`] borrows its attribute
//! region directly from the input slice and every attribute is validated
//! eagerly, so a decoded message is always well-formed. Re-encoding a decoded
//! message reproduces its bytes verbatim.
//!
//! Building a message goes through [`MessageWriter`],
//! which writes into a caller-owned buffer: attributes are appended in order,
//! and the two attributes whose value covers the message itself —
//! `MESSAGE-INTEGRITY` and `FINGERPRINT` — are therefore appended last.
//!
//! [RFC 5389]: https://www.rfc-editor.org/rfc/rfc5389
//! [RFC 5766]: https://www.rfc-editor.org/rfc/rfc5766
//! [RFC 8445]: https://www.rfc-editor.org/rfc/rfc8445
//! [RFC 5780]: https://www.rfc-editor.org/rfc/rfc5780
//!
//! # Message layout
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|     STUN Message Type     |         Message Length        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Magic Cookie                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                     Transaction ID (96 bits)                  |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Attributes                           |
//! |                          ....  ....                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Each attribute is a Type-Length-Value unit padded to a 32-bit boundary,
//! see [`attributes`].

pub mod addr;
pub mod attributes;
pub mod error_code;
pub mod fingerprint;
pub mod integrity;
pub mod message;
pub mod textattrs;
pub mod uattrs;
pub mod xoraddr;

pub use attributes::{ATTRIBUTE_HEADER_SIZE, AttrType, RawAttribute};
pub use fingerprint::{
    FINGERPRINT_SIZE, FINGERPRINT_XOR_VALUE, check as check_fingerprint, fingerprint_value,
    push_fingerprint,
};
pub use integrity::{MESSAGE_INTEGRITY_SIZE, MacFn, MessageIntegrity};
pub use message::{
    MAGIC_COOKIE, MESSAGE_HEADER_SIZE, Message, MessageClass, MessageType, MessageWriter, Method,
    TRANSACTION_ID_SIZE, TransactionId, is_stun_message,
};
pub use rtx_wire::{Decode, Encode, WireError};

//! Sans-IO DTLS 1.2 record machine.
//!
//! [`RecordMachine`] implements [`rtx_core::ProtocolMachine`]: it consumes
//! [`rtx_core::Input::Datagram`] and [`rtx_core::Input::Timeout`] values and
//! yields [`RecordEvent`]s. It never touches sockets, Tokio or a system clock;
//! the only time source is the [`rtx_core::Timestamp`] carried by the input.
//!
//! The machine owns the replay window and, when protected records are
//! configured, the read cipher. [`RecordEncoder`] owns the matching outbound
//! epoch and 48-bit sequence number. Both sides derive AEAD nonces from the
//! record header, so a provider never manages a nonce.
//!
//! # Datagram contract
//!
//! One datagram may carry several records back to back (RFC 6347 section 4.1)
//! and the machine walks them all. Records are processed in order until one
//! fails; a failure returns an error and leaves already-accepted records in
//! the event queue. A datagram that straddles an epoch change is not accepted
//! as a unit: the caller installs the cipher between datagrams. At most
//! [`EVENT_QUEUE_CAPACITY`] events are queued; a record that would overflow
//! the queue returns
//! [`RecordError::EventQueueFull`](crate::RecordError::EventQueueFull) without
//! consuming its sequence number.
//!
//! # Event payloads
//!
//! [`RecordEvent`] carries the decrypted fragment inline in a fixed
//! `[u8; N]` array, so the machine needs no allocator and no lifetime tied to
//! the input datagram. `N` must be at least the largest protected fragment
//! minus the 8-byte explicit nonce (equal to the plaintext length plus the
//! 16-byte tag); unprotected records only need `N >= plaintext length`. A
//! record that does not fit is rejected with
//! [`RecordError::OutputTooSmall`](crate::RecordError::OutputTooSmall).

use rtx_core::{Input, ProtocolMachine, Timestamp};
use rtx_crypto::AeadProvider;

use crate::cipher::RecordCipher;
use crate::error::RecordError;
use crate::record::{
    AEAD_EXPLICIT_NONCE_LEN, AEAD_OVERHEAD, ContentType, MAX_PLAINTEXT_LEN, Record, RecordHeader,
    SequenceNumber,
};
use crate::replay::ReplayWindow;

/// Number of [`RecordEvent`]s the machine can queue.
pub const EVENT_QUEUE_CAPACITY: usize = 4;

/// One accepted record, with its plaintext copied into fixed storage.
///
/// The payload is owned by the event, so it stays valid after the input
/// datagram borrow ends. `Debug` deliberately prints only metadata.
#[derive(Clone, Copy)]
pub struct RecordEvent<const N: usize> {
    header: RecordHeader,
    plaintext_len: usize,
    plaintext: [u8; N],
}

impl<const N: usize> RecordEvent<N> {
    fn new(header: RecordHeader) -> Self {
        Self {
            header,
            plaintext_len: 0,
            plaintext: [0; N],
        }
    }

    /// Header of the accepted record, with the wire fragment length.
    #[must_use]
    pub const fn header(&self) -> RecordHeader {
        self.header
    }

    /// Content type of the accepted record.
    #[must_use]
    pub const fn content_type(&self) -> ContentType {
        self.header.content_type
    }

    /// Epoch of the accepted record.
    #[must_use]
    pub const fn epoch(&self) -> u16 {
        self.header.epoch
    }

    /// Sequence number of the accepted record.
    #[must_use]
    pub const fn sequence_number(&self) -> SequenceNumber {
        self.header.sequence_number
    }

    /// Decrypted fragment. Empty for an empty record.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext[..self.plaintext_len]
    }
}

impl<const N: usize> core::fmt::Debug for RecordEvent<N> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RecordEvent")
            .field("header", &self.header)
            .field("plaintext_len", &self.plaintext_len)
            .finish_non_exhaustive()
    }
}

/// Sans-IO DTLS 1.2 record layer.
///
/// Construct with [`RecordMachine::new`] for epoch-0 plaintext records, then
/// call [`RecordMachine::install_cipher`] when the peer's `ChangeCipherSpec`
/// has been accepted to switch the read path to AEAD protection.
pub struct RecordMachine<const N: usize, P: AeadProvider> {
    provider: P,
    cipher: Option<RecordCipher>,
    read_epoch: u16,
    replay: ReplayWindow,
    events: [Option<RecordEvent<N>>; EVENT_QUEUE_CAPACITY],
    event_head: usize,
    event_len: usize,
    now: Timestamp,
}

impl<const N: usize, P: AeadProvider> RecordMachine<N, P> {
    /// Creates a machine that accepts unprotected epoch-0 records.
    #[must_use]
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            cipher: None,
            read_epoch: 0,
            replay: ReplayWindow::new(),
            events: [None; EVENT_QUEUE_CAPACITY],
            event_head: 0,
            event_len: 0,
            now: Timestamp::ZERO,
        }
    }

    /// Switches the read path to `cipher` for `read_epoch`.
    ///
    /// The replay window is reset because sequence numbers restart at zero in
    /// every epoch (RFC 6347 section 4.1). Events already queued are kept.
    pub fn install_cipher(&mut self, cipher: RecordCipher, read_epoch: u16) {
        self.cipher = Some(cipher);
        self.read_epoch = read_epoch;
        self.replay.reset();
    }

    /// Epoch the read path currently expects.
    #[must_use]
    pub const fn read_epoch(&self) -> u16 {
        self.read_epoch
    }

    /// Last `Timestamp` supplied by a datagram or timeout input.
    #[must_use]
    pub const fn now(&self) -> Timestamp {
        self.now
    }

    fn process_record(&mut self, record: Record<'_>) -> Result<(), RecordError> {
        let header = record.header;
        if let Some(cipher) = &self.cipher {
            if header.epoch != self.read_epoch {
                return Err(if header.epoch < self.read_epoch {
                    RecordError::StaleEpoch
                } else {
                    RecordError::UnexpectedEpoch
                });
            }
            if header.fragment_len < AEAD_OVERHEAD {
                return Err(RecordError::CiphertextTooShort);
            }
            // `N` holds ciphertext plus tag while the provider decrypts in
            // place, so it must cover the wire fragment minus the nonce.
            if header.fragment_len - AEAD_EXPLICIT_NONCE_LEN > N {
                return Err(RecordError::OutputTooSmall);
            }
            self.ensure_event_space()?;
            self.replay.check(header.sequence_number)?;
            let mut event = RecordEvent::new(header);
            let opened = cipher.open(&self.provider, &record, &mut event.plaintext)?;
            event.plaintext_len = opened;
            self.replay.accept(header.sequence_number)?;
            self.push_event(event);
        } else {
            if header.epoch != 0 {
                return Err(RecordError::UnexpectedEpoch);
            }
            if header.fragment_len > MAX_PLAINTEXT_LEN {
                return Err(RecordError::RecordTooLong);
            }
            if header.fragment_len > N {
                return Err(RecordError::OutputTooSmall);
            }
            self.ensure_event_space()?;
            self.replay.check(header.sequence_number)?;
            let mut event = RecordEvent::new(header);
            event.plaintext[..header.fragment_len].copy_from_slice(record.fragment);
            event.plaintext_len = header.fragment_len;
            self.replay.accept(header.sequence_number)?;
            self.push_event(event);
        }
        Ok(())
    }

    fn ensure_event_space(&self) -> Result<(), RecordError> {
        if self.event_len == EVENT_QUEUE_CAPACITY {
            Err(RecordError::EventQueueFull)
        } else {
            Ok(())
        }
    }

    fn push_event(&mut self, event: RecordEvent<N>) {
        let index = (self.event_head + self.event_len) % EVENT_QUEUE_CAPACITY;
        self.events[index] = Some(event);
        self.event_len += 1;
    }
}

impl<const N: usize, P: AeadProvider> core::fmt::Debug for RecordMachine<N, P> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RecordMachine")
            .field("protected", &self.cipher.is_some())
            .field("read_epoch", &self.read_epoch)
            .field("replay_highest", &self.replay.highest())
            .field("queued_events", &self.event_len)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl<const N: usize, P: AeadProvider + 'static> ProtocolMachine for RecordMachine<N, P> {
    type Input<'a>
        = Input<'a>
    where
        Self: 'a;
    type Event = RecordEvent<N>;
    type Error = RecordError;

    fn handle_input(&mut self, input: Self::Input<'_>) -> Result<(), Self::Error> {
        match input {
            Input::Datagram { meta, payload } => {
                self.now = meta.now;
                if payload.is_empty() {
                    return Err(RecordError::UnexpectedEnd);
                }
                let mut remaining = payload;
                while !remaining.is_empty() {
                    let (record, consumed) = Record::decode_prefix(remaining)?;
                    self.process_record(record)?;
                    remaining = remaining
                        .get(consumed..)
                        .ok_or(RecordError::UnexpectedEnd)?;
                }
                Ok(())
            }
            Input::Timeout(at) => {
                self.now = at;
                Ok(())
            }
        }
    }

    fn poll_event(&mut self) -> Option<Self::Event> {
        if self.event_len == 0 {
            return None;
        }
        let event = self.events[self.event_head].take();
        self.event_head = (self.event_head + 1) % EVENT_QUEUE_CAPACITY;
        self.event_len -= 1;
        event
    }

    fn next_wakeup(&self) -> Option<Timestamp> {
        // A record layer owns no timer; retransmission lives in the handshake
        // layer that will sit above this machine.
        None
    }
}

/// Outbound epoch and 48-bit sequence-number owner.
///
/// Every successful seal consumes exactly one sequence number; a rejected
/// seal leaves the counter unchanged. [`RecordEncoder::set_epoch`] resets the
/// counter to zero, as required when `ChangeCipherSpec` advances the epoch.
#[derive(Debug, Clone)]
pub struct RecordEncoder {
    epoch: u16,
    next_sequence: u64,
}

impl RecordEncoder {
    /// Creates an encoder whose first record uses sequence number zero.
    #[must_use]
    pub const fn new(epoch: u16) -> Self {
        Self {
            epoch,
            next_sequence: 0,
        }
    }

    /// Epoch written into protected records.
    #[must_use]
    pub const fn epoch(&self) -> u16 {
        self.epoch
    }

    /// Sequence number the next successful seal will use, or `None` when the
    /// 48-bit space is exhausted.
    #[must_use]
    pub const fn next_sequence(&self) -> Option<SequenceNumber> {
        SequenceNumber::from_u64(self.next_sequence)
    }

    /// Switches epoch and restarts the sequence number at zero.
    pub fn set_epoch(&mut self, epoch: u16) {
        self.epoch = epoch;
        self.next_sequence = 0;
    }

    /// Encodes an unprotected record, consuming one sequence number.
    ///
    /// Only epoch 0 may send unprotected records.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::UnexpectedEpoch`] when the encoder epoch is not
    /// zero, [`RecordError::SequenceExhausted`] when the 48-bit space is
    /// exhausted, and the framing errors of [`Record::encode`] (including
    /// [`RecordError::OutputTooSmall`]). The sequence number advances only on
    /// success.
    pub fn seal_plaintext(
        &mut self,
        content_type: ContentType,
        fragment: &[u8],
        output: &mut [u8],
    ) -> Result<usize, RecordError> {
        if self.epoch != 0 {
            return Err(RecordError::UnexpectedEpoch);
        }
        let sequence_number = self.take_sequence()?;
        let header = RecordHeader {
            content_type,
            epoch: 0,
            sequence_number,
            fragment_len: fragment.len(),
        };
        let written = Record { header, fragment }.encode(output)?;
        self.advance();
        Ok(written)
    }

    /// Encodes an AEAD-protected record, consuming one sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::SequenceExhausted`] when the 48-bit space is
    /// exhausted and the errors of [`RecordCipher::seal`]. The sequence
    /// number advances only on success.
    pub fn seal_protected<P: AeadProvider + ?Sized>(
        &mut self,
        provider: &P,
        cipher: &RecordCipher,
        content_type: ContentType,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, RecordError> {
        let sequence_number = self.take_sequence()?;
        let written = cipher.seal(
            provider,
            content_type,
            self.epoch,
            sequence_number,
            plaintext,
            output,
        )?;
        self.advance();
        Ok(written)
    }

    fn take_sequence(&self) -> Result<SequenceNumber, RecordError> {
        SequenceNumber::from_u64(self.next_sequence).ok_or(RecordError::SequenceExhausted)
    }

    fn advance(&mut self) {
        self.next_sequence += 1;
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use rtx_core::{DatagramMeta, IpAddr, SocketAddr};
    use rtx_crypto::{AeadAlgorithm, CryptoError};

    use crate::record::{
        AEAD_TAG_LEN, DTLS12_VERSION, MAX_FRAGMENT_LEN, RECORD_HEADER_LEN, SEQUENCE_NUMBER_MAX,
    };

    const KEY: [u8; 16] = [0x33; 16];
    const FIXED_IV: [u8; 4] = [0x44; 4];
    const CAPACITY: usize = 256;

    fn meta(now: u64) -> DatagramMeta {
        DatagramMeta {
            now: Timestamp::from_micros(now),
            source: SocketAddr::new(IpAddr::V4([10, 0, 0, 1]), 5_000),
            destination: SocketAddr::new(IpAddr::V4([10, 0, 0, 2]), 6_000),
            ecn: None,
        }
    }

    fn datagram_at(now: u64, payload: &[u8]) -> Input<'_> {
        Input::Datagram {
            meta: meta(now),
            payload,
        }
    }

    fn datagram(payload: &[u8]) -> Input<'_> {
        datagram_at(1_000, payload)
    }

    /// Minimal in-place AEAD: XOR keystream plus a fixed tag.
    #[derive(Debug, Default)]
    struct XorAead;

    impl AeadProvider for XorAead {
        fn seal_in_place(
            &self,
            _algorithm: AeadAlgorithm,
            _key: &[u8],
            _nonce: &[u8],
            _aad: &[u8],
            payload_and_tag: &mut [u8],
            plaintext_len: usize,
        ) -> Result<usize, CryptoError> {
            let needed = plaintext_len
                .checked_add(AEAD_TAG_LEN)
                .ok_or(CryptoError::OutputTooSmall)?;
            if payload_and_tag.len() < needed {
                return Err(CryptoError::OutputTooSmall);
            }
            let (payload, tag) = payload_and_tag.split_at_mut(plaintext_len);
            for byte in payload.iter_mut() {
                *byte ^= 0x5A;
            }
            tag[..AEAD_TAG_LEN].fill(0xAB);
            Ok(needed)
        }

        fn open_in_place(
            &self,
            _algorithm: AeadAlgorithm,
            _key: &[u8],
            _nonce: &[u8],
            _aad: &[u8],
            ciphertext_and_tag: &mut [u8],
        ) -> Result<usize, CryptoError> {
            if ciphertext_and_tag.len() < AEAD_TAG_LEN {
                return Err(CryptoError::OutputTooSmall);
            }
            let split = ciphertext_and_tag.len() - AEAD_TAG_LEN;
            let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(split);
            if tag.iter().any(|&byte| byte != 0xAB) {
                return Err(CryptoError::AuthenticationFailed);
            }
            for byte in ciphertext.iter_mut() {
                *byte ^= 0x5A;
            }
            Ok(split)
        }
    }

    fn cipher() -> RecordCipher {
        RecordCipher::new(AeadAlgorithm::Aes128Gcm, &KEY, &FIXED_IV).expect("cipher")
    }

    fn machine() -> RecordMachine<CAPACITY, XorAead> {
        RecordMachine::new(XorAead)
    }

    fn plaintext_wire(sequence: u64, content: &[u8]) -> Vec<u8> {
        let mut encoder = RecordEncoder::new(0);
        encoder.next_sequence = sequence;
        let mut output = vec![0u8; RECORD_HEADER_LEN + content.len()];
        let written = encoder
            .seal_plaintext(ContentType::ApplicationData, content, &mut output)
            .expect("seal plaintext");
        assert_eq!(written, output.len());
        output
    }

    fn protected_wire(epoch: u16, sequence: u64, content: &[u8]) -> Vec<u8> {
        let mut encoder = RecordEncoder::new(epoch);
        encoder.next_sequence = sequence;
        let mut output = vec![0u8; RECORD_HEADER_LEN + AEAD_OVERHEAD + content.len()];
        let written = encoder
            .seal_protected(
                &XorAead,
                &cipher(),
                ContentType::Handshake,
                content,
                &mut output,
            )
            .expect("seal protected");
        assert_eq!(written, output.len());
        output
    }

    fn protected_machine() -> RecordMachine<CAPACITY, XorAead> {
        let mut machine = machine();
        machine.install_cipher(cipher(), 1);
        machine
    }

    // DTLS-MACHINE-001 — one plaintext datagram becomes one event.
    #[test]
    fn plaintext_datagram_yields_event() {
        let mut machine = machine();
        let wire = plaintext_wire(0, b"hello");
        machine
            .handle_input(datagram_at(7_000, &wire))
            .expect("handle");
        assert_eq!(machine.now(), Timestamp::from_micros(7_000));
        assert_eq!(machine.read_epoch(), 0);
        let event = machine.poll_event().expect("event");
        assert_eq!(event.content_type(), ContentType::ApplicationData);
        assert_eq!(event.epoch(), 0);
        assert_eq!(event.sequence_number(), SequenceNumber::ZERO);
        assert_eq!(event.header().fragment_len, 5);
        assert_eq!(event.plaintext(), b"hello");
        assert!(machine.poll_event().is_none());
        assert!(machine.next_wakeup().is_none());
        assert!(!format!("{machine:?}").is_empty());
        assert!(format!("{event:?}").contains("plaintext_len"));
    }

    // DTLS-MACHINE-002 — timeouts update injected time only.
    #[test]
    fn timeout_updates_time_without_event() {
        let mut machine = machine();
        assert_eq!(machine.now(), Timestamp::ZERO);
        machine
            .handle_input(Input::Timeout(Timestamp::from_micros(42)))
            .expect("timeout");
        assert_eq!(machine.now(), Timestamp::from_micros(42));
        assert!(machine.poll_event().is_none());
        assert!(machine.next_wakeup().is_none());
    }

    // DTLS-MACHINE-003 — empty and truncated datagrams are rejected.
    #[test]
    fn empty_and_truncated_datagrams_are_rejected() {
        assert_eq!(
            machine().handle_input(datagram(&[])),
            Err(RecordError::UnexpectedEnd)
        );
        let wire = plaintext_wire(0, b"truncated");
        for len in 0..wire.len() {
            let mut layer = machine();
            assert_eq!(
                layer.handle_input(datagram(&wire[..len])),
                Err(RecordError::UnexpectedEnd),
                "truncated to {len}"
            );
            assert!(layer.poll_event().is_none());
        }
        let mut layer = machine();
        layer.handle_input(datagram(&wire)).expect("full datagram");
        assert_eq!(layer.poll_event().expect("event").plaintext(), b"truncated");
    }

    // DTLS-MACHINE-004 — several records in one datagram are all delivered.
    #[test]
    fn coalesced_records_fill_the_queue() {
        let mut datagram_bytes = Vec::new();
        for (sequence, content) in [(0u64, &b"one"[..]), (1, b"two"), (2, b"three")] {
            datagram_bytes.extend_from_slice(&plaintext_wire(sequence, content));
        }
        let mut machine = machine();
        machine
            .handle_input(datagram(&datagram_bytes))
            .expect("coalesced");
        for expected in [&b"one"[..], &b"two"[..], &b"three"[..]] {
            assert_eq!(machine.poll_event().expect("event").plaintext(), expected);
        }
        assert!(machine.poll_event().is_none());
    }

    // DTLS-MACHINE-005 — the fourth record fits, the fifth reports a full
    // queue without consuming its sequence number.
    #[test]
    fn event_queue_is_bounded_and_recovers() {
        let mut datagram_bytes = Vec::new();
        for sequence in 0..5u64 {
            datagram_bytes.extend_from_slice(&plaintext_wire(
                sequence,
                &[u8::try_from(sequence).expect("small")],
            ));
        }
        let mut machine = machine();
        assert_eq!(
            machine.handle_input(datagram(&datagram_bytes)),
            Err(RecordError::EventQueueFull)
        );
        for sequence in 0..4u64 {
            let event = machine.poll_event().expect("queued event");
            assert_eq!(event.sequence_number().as_u64(), sequence);
        }
        assert!(machine.poll_event().is_none());

        let fifth = plaintext_wire(4, &[4]);
        machine.handle_input(datagram(&fifth)).expect("retry fifth");
        assert_eq!(
            machine
                .poll_event()
                .expect("fifth")
                .sequence_number()
                .as_u64(),
            4
        );
    }

    // DTLS-MACHINE-006 — duplicate and out-of-window records are distinct
    // errors.
    #[test]
    fn replay_and_too_old_are_distinguishable() {
        let mut machine = machine();
        machine
            .handle_input(datagram(&plaintext_wire(0, b"zero")))
            .expect("first");
        assert!(machine.poll_event().is_some());
        assert_eq!(
            machine.handle_input(datagram(&plaintext_wire(0, b"zero"))),
            Err(RecordError::Replay)
        );
        machine
            .handle_input(datagram(&plaintext_wire(100, b"far")))
            .expect("far ahead");
        assert!(machine.poll_event().is_some());
        assert_eq!(
            machine.handle_input(datagram(&plaintext_wire(0, b"zero"))),
            Err(RecordError::TooOld)
        );
        assert!(machine.poll_event().is_none());
    }

    // DTLS-MACHINE-007 — plaintext mode accepts epoch 0 only.
    #[test]
    fn plaintext_mode_rejects_other_epochs() {
        let header = RecordHeader {
            content_type: ContentType::Handshake,
            epoch: 1,
            sequence_number: SequenceNumber::ZERO,
            fragment_len: 0,
        };
        let mut wire = [0u8; RECORD_HEADER_LEN];
        Record {
            header,
            fragment: &[],
        }
        .encode(&mut wire)
        .expect("encode");
        let mut machine = machine();
        assert_eq!(
            machine.handle_input(datagram(&wire)),
            Err(RecordError::UnexpectedEpoch)
        );
        assert!(machine.poll_event().is_none());
    }

    // DTLS-MACHINE-008 — event capacity and the 2^14 plaintext bound.
    #[test]
    fn plaintext_capacity_and_length_bounds() {
        let mut small = RecordMachine::<4, XorAead>::new(XorAead);
        assert_eq!(
            small.handle_input(datagram(&plaintext_wire(0, b"12345"))),
            Err(RecordError::OutputTooSmall)
        );
        assert!(small.poll_event().is_none());

        let mut large = RecordMachine::<{ MAX_PLAINTEXT_LEN + 1 }, XorAead>::new(XorAead);
        let oversized = plaintext_wire(0, &vec![0u8; MAX_PLAINTEXT_LEN + 1]);
        assert_eq!(
            large.handle_input(datagram(&oversized)),
            Err(RecordError::RecordTooLong)
        );
        let maximum = plaintext_wire(0, &vec![0u8; MAX_PLAINTEXT_LEN]);
        large.handle_input(datagram(&maximum)).expect("maximum");
        assert_eq!(
            large.poll_event().expect("event").plaintext().len(),
            MAX_PLAINTEXT_LEN
        );
    }

    // DTLS-MACHINE-009 — protected roundtrip through the encoder and machine.
    #[test]
    fn protected_roundtrip_delivers_plaintext() {
        let mut machine = protected_machine();
        let wire = protected_wire(1, 0, b"protected payload");
        machine.handle_input(datagram(&wire)).expect("protected");
        let event = machine.poll_event().expect("event");
        assert_eq!(event.content_type(), ContentType::Handshake);
        assert_eq!(event.epoch(), 1);
        assert_eq!(event.sequence_number(), SequenceNumber::ZERO);
        assert_eq!(event.plaintext(), b"protected payload");
        assert_eq!(
            machine.handle_input(datagram(&wire)),
            Err(RecordError::Replay)
        );
    }

    // DTLS-MACHINE-010 — stale and future epochs are rejected.
    #[test]
    fn protected_epoch_checks() {
        let mut machine = protected_machine();
        assert_eq!(machine.read_epoch(), 1);
        assert_eq!(
            machine.handle_input(datagram(&protected_wire(0, 9, b"stale"))),
            Err(RecordError::StaleEpoch)
        );
        assert_eq!(
            machine.handle_input(datagram(&protected_wire(2, 9, b"future"))),
            Err(RecordError::UnexpectedEpoch)
        );
        assert!(machine.poll_event().is_none());
    }

    // DTLS-MACHINE-011 — epoch-1 records need an installed cipher.
    #[test]
    fn protected_record_without_cipher_is_rejected() {
        let wire = protected_wire(1, 0, b"no cipher");
        let mut machine = machine();
        assert_eq!(
            machine.handle_input(datagram(&wire)),
            Err(RecordError::UnexpectedEpoch)
        );
        assert!(machine.poll_event().is_none());
    }

    // DTLS-MACHINE-012 — authentication failure leaves the replay window
    // untouched, so a retransmitted good record is still accepted.
    #[test]
    fn authentication_failure_does_not_advance_replay() {
        let mut machine = protected_machine();
        let mut wire = protected_wire(1, 0, b"authentic");
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        assert_eq!(
            machine.handle_input(datagram(&wire)),
            Err(RecordError::AuthenticationFailed)
        );
        assert!(machine.poll_event().is_none());

        let good = protected_wire(1, 0, b"authentic");
        machine.handle_input(datagram(&good)).expect("retry good");
        assert_eq!(
            machine.poll_event().expect("event").plaintext(),
            b"authentic"
        );
    }

    // DTLS-MACHINE-013 — a tampered explicit nonce is rejected before the
    // provider runs and does not consume the sequence number.
    #[test]
    fn invalid_explicit_nonce_does_not_advance_replay() {
        let mut machine = protected_machine();
        let mut wire = protected_wire(1, 0, b"nonce");
        wire[RECORD_HEADER_LEN] ^= 0xFF;
        assert_eq!(
            machine.handle_input(datagram(&wire)),
            Err(RecordError::InvalidExplicitNonce)
        );
        assert!(machine.poll_event().is_none());
        machine
            .handle_input(datagram(&protected_wire(1, 0, b"nonce")))
            .expect("retry");
        assert_eq!(machine.poll_event().expect("event").plaintext(), b"nonce");
    }

    // DTLS-MACHINE-014 — `N` must cover ciphertext plus tag, not just the
    // plaintext length.
    #[test]
    fn protected_event_capacity_covers_tag() {
        let mut machine = RecordMachine::<8, XorAead>::new(XorAead);
        machine.install_cipher(cipher(), 1);
        let wire = protected_wire(1, 0, b"payload");
        assert_eq!(
            machine.handle_input(datagram(&wire)),
            Err(RecordError::OutputTooSmall)
        );
        assert!(machine.poll_event().is_none());
    }

    // DTLS-MACHINE-015 — installing a cipher resets a replay window that had
    // already seen epoch-0 sequence numbers.
    #[test]
    fn install_cipher_resets_the_replay_window() {
        let mut machine = machine();
        machine
            .handle_input(datagram(&plaintext_wire(0, b"ccs")))
            .expect("epoch zero");
        assert!(machine.poll_event().is_some());
        machine.install_cipher(cipher(), 1);
        machine
            .handle_input(datagram(&protected_wire(1, 0, b"encrypted")))
            .expect("epoch one sequence zero");
        assert_eq!(
            machine.poll_event().expect("event").plaintext(),
            b"encrypted"
        );
    }

    // DTLS-MACHINE-016 — the wire fragment limit is enforced before framing.
    #[test]
    fn oversized_declared_length_is_rejected() {
        let mut header = [0u8; RECORD_HEADER_LEN];
        header[0] = ContentType::ApplicationData.to_u8();
        header[1..3].copy_from_slice(&DTLS12_VERSION);
        header[11..13].copy_from_slice(
            &u16::try_from(MAX_FRAGMENT_LEN + 1)
                .expect("fits")
                .to_be_bytes(),
        );
        let mut machine = RecordMachine::<{ MAX_FRAGMENT_LEN + 1 }, XorAead>::new(XorAead);
        assert_eq!(
            machine.handle_input(datagram(&header)),
            Err(RecordError::RecordTooLong)
        );
    }

    // DTLS-ENCODER-001 — sequence numbers increase per record and epoch
    // changes restart them.
    #[test]
    fn encoder_tracks_epoch_and_sequence() {
        let mut encoder = RecordEncoder::new(0);
        assert_eq!(encoder.epoch(), 0);
        assert_eq!(encoder.next_sequence(), Some(SequenceNumber::ZERO));
        let mut output = [0u8; RECORD_HEADER_LEN + 1];
        encoder
            .seal_plaintext(ContentType::Alert, b"a", &mut output)
            .expect("first");
        assert_eq!(
            encoder.next_sequence(),
            Some(SequenceNumber::from_u64(1).expect("in range"))
        );
        encoder
            .seal_plaintext(ContentType::Alert, b"a", &mut output)
            .expect("second");
        assert_eq!(
            encoder.next_sequence(),
            Some(SequenceNumber::from_u64(2).expect("in range"))
        );

        encoder.set_epoch(1);
        assert_eq!(encoder.epoch(), 1);
        assert_eq!(encoder.next_sequence(), Some(SequenceNumber::ZERO));
    }

    // DTLS-ENCODER-002 — failures do not consume a sequence number.
    #[test]
    fn encoder_failures_keep_the_sequence() {
        let mut encoder = RecordEncoder::new(0);
        let mut small = [0u8; RECORD_HEADER_LEN];
        assert_eq!(
            encoder.seal_plaintext(ContentType::ApplicationData, b"x", &mut small),
            Err(RecordError::OutputTooSmall)
        );
        assert_eq!(encoder.next_sequence(), Some(SequenceNumber::ZERO));

        let mut protected_small = [0u8; RECORD_HEADER_LEN];
        assert_eq!(
            encoder.seal_protected(
                &XorAead,
                &cipher(),
                ContentType::ApplicationData,
                b"x",
                &mut protected_small
            ),
            Err(RecordError::OutputTooSmall)
        );
        assert_eq!(encoder.next_sequence(), Some(SequenceNumber::ZERO));
    }

    // DTLS-ENCODER-003 — plaintext encoding is limited to epoch 0.
    #[test]
    fn encoder_plaintext_requires_epoch_zero() {
        let mut encoder = RecordEncoder::new(1);
        let mut output = [0u8; RECORD_HEADER_LEN];
        assert_eq!(
            encoder.seal_plaintext(ContentType::Alert, b"", &mut output),
            Err(RecordError::UnexpectedEpoch)
        );
    }

    // DTLS-ENCODER-004 — the 48-bit sequence space is exhausted exactly once.
    #[test]
    fn encoder_sequence_space_exhaustion() {
        let mut encoder = RecordEncoder::new(0);
        encoder.next_sequence = SEQUENCE_NUMBER_MAX;
        assert_eq!(encoder.next_sequence(), Some(SequenceNumber::MAX));
        let mut output = [0u8; RECORD_HEADER_LEN];
        encoder
            .seal_plaintext(ContentType::Alert, b"", &mut output)
            .expect("last sequence number");
        assert_eq!(encoder.next_sequence(), None);
        assert_eq!(
            encoder.seal_plaintext(ContentType::Alert, b"", &mut output),
            Err(RecordError::SequenceExhausted)
        );

        encoder.next_sequence = SEQUENCE_NUMBER_MAX + 1;
        assert_eq!(
            encoder.seal_plaintext(ContentType::Alert, b"", &mut output),
            Err(RecordError::SequenceExhausted)
        );
    }

    // DTLS-ENCODER-005 — protected sealing advances the encoder and produces a
    // record the machine accepts.
    #[test]
    fn encoder_protected_seal_advances_sequence() {
        let mut encoder = RecordEncoder::new(2);
        let cipher = cipher();
        let mut output = vec![0u8; RECORD_HEADER_LEN + AEAD_OVERHEAD + 4];
        let written = encoder
            .seal_protected(
                &XorAead,
                &cipher,
                ContentType::ApplicationData,
                b"data",
                &mut output,
            )
            .expect("seal");
        assert_eq!(written, output.len());
        assert_eq!(
            encoder.next_sequence(),
            Some(SequenceNumber::from_u64(1).expect("in range"))
        );
        let record = Record::decode_protected(&output).expect("record");
        assert_eq!(record.header.epoch, 2);
        assert_eq!(record.header.sequence_number, SequenceNumber::ZERO);
    }
}

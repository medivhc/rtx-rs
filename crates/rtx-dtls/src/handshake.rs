//! Sans-IO DTLS 1.2 handshake state machine for the minimal profile.
//!
//! The machine implements [`rtx_core::ProtocolMachine`]: it consumes
//! [`rtx_core::Input::Datagram`] and [`rtx_core::Input::Timeout`] values,
//! never performs I/O, never reads a clock and never allocates. Time is only
//! the injected [`rtx_core::Timestamp`].
//!
//! The state table, key schedule, DTLS-SRTP export contract and test-vector
//! sources are frozen in `HANDSHAKE.md` in this crate. The profile is:
//!
//! - DTLS 1.2, X25519 ECDHE, Ed25519 signatures;
//! - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B);
//! - `SRTP_AES128_CM_HMAC_SHA1_80` (`use_srtp` 0x0001, empty MKI);
//! - no Certificate message: the peer's raw Ed25519 public key is provisioned
//!   out of band and the `ServerKeyExchange` signature is verified strictly.
//!
//! Outbound records are produced by [`HandshakeMachine::poll_transmit`], one
//! record per call. Retransmissions keep the original handshake
//! `message_seq` and message bytes but always use fresh record sequence
//! numbers. Once established, the machine emits
//! [`HandshakeEvent::Established`] carrying the RFC 5764 keying material.

use rtx_core::{Duration, Input, ProtocolMachine, Timestamp};
use rtx_crypto::{
    AeadAlgorithm, CryptoError, CryptoProvider, HashAlgorithm, KeyExchangeAlgorithm,
    KeyExchangeProvider, SignatureAlgorithm, SignatureProvider,
};
use zeroize::{Zeroize, Zeroizing};

use crate::cipher::RecordCipher;
use crate::error::RecordError;
use crate::handshake_error::HandshakeError;
use crate::handshake_message::{
    HandshakeMessage, HandshakeType, MAX_HANDSHAKE_MESSAGE_LEN, OfferedAlgorithms,
    build_client_hello_body, build_client_key_exchange_body, build_server_hello_body,
    build_server_key_exchange_body, decode_handshake_message, encode_handshake_message,
    parse_client_hello, parse_client_key_exchange, parse_finished, parse_server_hello,
    parse_server_hello_done, parse_server_key_exchange,
};
use crate::keyschedule::{
    MasterSecret, derive_key_block, derive_master_secret, finished_verify_data,
};
use crate::machine::RecordEncoder;
use crate::record::{AEAD_OVERHEAD, AEAD_TAG_LEN, ContentType, RECORD_HEADER_LEN, Record};
use crate::replay::ReplayWindow;
use crate::srtp::{SRTP_PROFILE_AES128_CM_HMAC_SHA1_80, SrtpKeyingMaterial};

/// Number of handshake messages one flight can hold. The largest flight is
/// `ClientKeyExchange` + `ChangeCipherSpec` + Finished (three items).
const FLIGHT_ITEMS: usize = 4;
/// Fixed transcript buffer.
const TRANSCRIPT_CAPACITY: usize = 1024;
/// Largest plaintext a protected inbound record can reveal (message plus tag).
const RECORD_BUFFER_LEN: usize = MAX_HANDSHAKE_MESSAGE_LEN + AEAD_TAG_LEN;
/// Largest record `poll_transmit` can produce.
pub const MAX_HANDSHAKE_RECORD_LEN: usize =
    RECORD_HEADER_LEN + AEAD_OVERHEAD + MAX_HANDSHAKE_MESSAGE_LEN;

/// Which side of the handshake this machine drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The client sends `ClientHello` first.
    Client,
    /// The server waits for `ClientHello` and signs `ServerKeyExchange`.
    Server,
}

/// Observable handshake state.
///
/// See the state table in `HANDSHAKE.md` for the accepted inputs and outputs
/// of every state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakeState {
    /// Server waiting for the first `ClientHello`.
    WaitClientHello,
    /// Client waiting for `ServerHello`.
    WaitServerHello,
    /// Client waiting for `ServerKeyExchange`.
    WaitServerKeyExchange,
    /// Client waiting for `ServerHello`Done.
    WaitServerHelloDone,
    /// Server waiting for `ClientKeyExchange`.
    WaitClientKeyExchange,
    /// Server waiting for the client CCS and Finished.
    WaitClientFinished,
    /// Client waiting for the server CCS and Finished.
    WaitServerFinished,
    /// Both Finished messages verified.
    Established,
    /// Terminal failure; every further input returns [`HandshakeError::Failed`].
    Failed,
}

/// Configuration for a [`HandshakeMachine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeConfig {
    /// Client or server role.
    pub role: Role,
    /// Provisioned Ed25519 public key of the server (client only).
    pub peer_public_key: Option<[u8; 32]>,
    /// Initial retransmission interval.
    pub initial_retransmit: Duration,
    /// Upper bound for the doubling retransmission interval.
    pub max_retransmit: Duration,
    /// Number of retransmissions before a waiting handshake aborts.
    pub max_retransmissions: u8,
}

impl HandshakeConfig {
    /// Client configuration with the provisioned server public key.
    #[must_use]
    pub const fn client(peer_public_key: [u8; 32]) -> Self {
        Self {
            role: Role::Client,
            peer_public_key: Some(peer_public_key),
            initial_retransmit: Duration::from_millis(1_000),
            max_retransmit: Duration::from_millis(60_000),
            max_retransmissions: 6,
        }
    }

    /// Server configuration. A signing key must be supplied to
    /// [`HandshakeMachine::new`].
    #[must_use]
    pub const fn server() -> Self {
        Self {
            role: Role::Server,
            peer_public_key: None,
            initial_retransmit: Duration::from_millis(1_000),
            max_retransmit: Duration::from_millis(60_000),
            max_retransmissions: 6,
        }
    }
}

/// Event produced by the handshake layer.
#[derive(Debug)]
pub enum HandshakeEvent {
    /// Both Finished messages verified; the handshake is complete.
    Established {
        /// RFC 5764 DTLS-SRTP master keys and salts.
        keying_material: SrtpKeyingMaterial,
    },
}

#[derive(Clone, Copy)]
struct FlightItem {
    content_type: ContentType,
    epoch: u16,
    payload_len: usize,
    payload: [u8; MAX_HANDSHAKE_MESSAGE_LEN],
}

impl FlightItem {
    const fn empty() -> Self {
        Self {
            content_type: ContentType::Handshake,
            epoch: 0,
            payload_len: 0,
            payload: [0; MAX_HANDSHAKE_MESSAGE_LEN],
        }
    }
}

struct Flight {
    items: [FlightItem; FLIGHT_ITEMS],
    len: usize,
    next: usize,
}

impl Flight {
    const fn new() -> Self {
        Self {
            items: [FlightItem::empty(); FLIGHT_ITEMS],
            len: 0,
            next: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
        self.next = 0;
    }

    fn push(
        &mut self,
        content_type: ContentType,
        epoch: u16,
        payload: &[u8],
    ) -> Result<(), HandshakeError> {
        if self.len == FLIGHT_ITEMS || payload.len() > MAX_HANDSHAKE_MESSAGE_LEN {
            return Err(HandshakeError::FlightFull);
        }
        let mut item = FlightItem::empty();
        item.content_type = content_type;
        item.epoch = epoch;
        item.payload_len = payload.len();
        item.payload[..payload.len()].copy_from_slice(payload);
        self.items[self.len] = item;
        self.len += 1;
        Ok(())
    }
}

impl core::fmt::Debug for Flight {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Flight")
            .field("len", &self.len)
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

/// Sans-IO DTLS 1.2 handshake machine.
///
/// The profile caps a handshake message at [`MAX_HANDSHAKE_MESSAGE_LEN`] and
/// keeps the transcript in a fixed 1024-byte buffer, so the machine allocates
/// nothing. Inbound datagrams must not exceed the record-layer limits;
/// outbound buffers must hold at least [`MAX_HANDSHAKE_RECORD_LEN`] bytes.
/// The server's signing-key handle is a `&'static` reference, which lets the
/// machine implement [`ProtocolMachine`] without a lifetime parameter.
pub struct HandshakeMachine<P: CryptoProvider>
where
    <P as SignatureProvider>::PrivateKey: 'static,
{
    provider: P,
    role: Role,
    state: HandshakeState,
    config: HandshakeConfig,
    now: Timestamp,
    own_random: [u8; 32],
    peer_random: [u8; 32],
    own_public: [u8; 32],
    ephemeral: Option<<P as KeyExchangeProvider>::PrivateKey>,
    signing_key: Option<&'static <P as SignatureProvider>::PrivateKey>,
    peer_public_key: Option<[u8; 32]>,
    transcript: [u8; TRANSCRIPT_CAPACITY],
    transcript_len: usize,
    next_send_seq: u16,
    next_recv_seq: u16,
    master_secret: Option<MasterSecret>,
    client_write_cipher: Option<RecordCipher>,
    server_write_cipher: Option<RecordCipher>,
    read_cipher: Option<RecordCipher>,
    read_epoch: u16,
    replay: ReplayWindow,
    epoch0_encoder: RecordEncoder,
    epoch1_encoder: RecordEncoder,
    flight: Flight,
    deadline: Option<Timestamp>,
    retransmit_interval: Duration,
    retransmissions: u8,
    event: Option<HandshakeEvent>,
}

impl<P: CryptoProvider> HandshakeMachine<P>
where
    <P as SignatureProvider>::PrivateKey: 'static,
{
    /// Creates a machine.
    ///
    /// The client queues its `ClientHello` immediately (drain
    /// [`HandshakeMachine::poll_transmit`]); the server waits for `ClientHello`.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError::InvalidConfig`] for zero timers or an initial
    /// interval above the cap, [`HandshakeError::MissingPeerPublicKey`] for a
    /// client without a provisioned peer key,
    /// [`HandshakeError::MissingSigningKey`] for a server without a signing
    /// handle, and [`HandshakeError::Crypto`] when random generation or the
    /// ephemeral X25519 key generation fails.
    pub fn new(
        provider: P,
        config: HandshakeConfig,
        signing_key: Option<&'static <P as SignatureProvider>::PrivateKey>,
    ) -> Result<Self, HandshakeError> {
        if config.initial_retransmit.as_micros() == 0
            || config.max_retransmit.as_micros() == 0
            || config.initial_retransmit > config.max_retransmit
        {
            return Err(HandshakeError::InvalidConfig);
        }
        if config.role == Role::Client && config.peer_public_key.is_none() {
            return Err(HandshakeError::MissingPeerPublicKey);
        }
        if config.role == Role::Server && signing_key.is_none() {
            return Err(HandshakeError::MissingSigningKey);
        }

        let mut own_random = [0u8; 32];
        provider.fill_random(&mut own_random)?;

        let mut own_public = [0u8; 32];
        let (ephemeral, written) =
            provider.generate_key(KeyExchangeAlgorithm::X25519, &mut own_public)?;
        if written != 32 {
            return Err(HandshakeError::Crypto(CryptoError::BackendFailure));
        }

        let mut machine = Self {
            provider,
            role: config.role,
            state: if config.role == Role::Client {
                HandshakeState::WaitServerHello
            } else {
                HandshakeState::WaitClientHello
            },
            config,
            now: Timestamp::ZERO,
            own_random,
            peer_random: [0; 32],
            own_public,
            ephemeral: Some(ephemeral),
            signing_key,
            peer_public_key: config.peer_public_key,
            transcript: [0; TRANSCRIPT_CAPACITY],
            transcript_len: 0,
            next_send_seq: 0,
            next_recv_seq: 0,
            master_secret: None,
            client_write_cipher: None,
            server_write_cipher: None,
            read_cipher: None,
            read_epoch: 0,
            replay: ReplayWindow::new(),
            epoch0_encoder: RecordEncoder::new(0),
            epoch1_encoder: RecordEncoder::new(1),
            flight: Flight::new(),
            deadline: None,
            retransmit_interval: config.initial_retransmit,
            retransmissions: 0,
            event: None,
        };
        if machine.role == Role::Client {
            machine.queue_client_hello()?;
        }
        Ok(machine)
    }

    /// Current handshake state.
    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    /// Role this machine drives.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Returns `true` once both Finished messages verified.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.state, HandshakeState::Established)
    }

    /// Emits the next queued record into `output`, returning its length.
    ///
    /// `output` must hold at least [`MAX_HANDSHAKE_RECORD_LEN`] bytes. The
    /// caller drains this method until it returns `None`, then arms the timer
    /// from [`ProtocolMachine::next_wakeup`].
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError::Failed`] after a previous failure, record
    /// errors of [`RecordEncoder`] when `output` is too short, and the
    /// crypto/record failures of the AEAD path. A too-small `output` leaves
    /// the flight intact for a retry; every other error is terminal and moves
    /// the machine to [`HandshakeState::Failed`].
    pub fn poll_transmit(&mut self, output: &mut [u8]) -> Result<Option<usize>, HandshakeError> {
        let result = self.poll_transmit_inner(output);
        if let Err(error) = &result {
            if !matches!(error, HandshakeError::Record(RecordError::OutputTooSmall)) {
                self.fail();
            }
        }
        result
    }

    fn poll_transmit_inner(&mut self, output: &mut [u8]) -> Result<Option<usize>, HandshakeError> {
        if self.state == HandshakeState::Failed {
            return Err(HandshakeError::Failed);
        }
        if self.flight.next >= self.flight.len {
            return Ok(None);
        }
        let item = self.flight.items[self.flight.next];
        let written = match item.epoch {
            0 => self.epoch0_encoder.seal_plaintext(
                item.content_type,
                &item.payload[..item.payload_len],
                output,
            )?,
            1 => {
                let cipher = match self.role {
                    Role::Client => self.client_write_cipher.as_ref(),
                    Role::Server => self.server_write_cipher.as_ref(),
                }
                .ok_or(HandshakeError::KeyMaterialUnavailable)?;
                self.epoch1_encoder.seal_protected(
                    &self.provider,
                    cipher,
                    item.content_type,
                    &item.payload[..item.payload_len],
                    output,
                )?
            }
            _ => return Err(HandshakeError::Crypto(CryptoError::BackendFailure)),
        };
        self.flight.next += 1;
        if self.flight.next == self.flight.len {
            self.deadline = Some(self.now + self.retransmit_interval);
        }
        Ok(Some(written))
    }

    fn queue_client_hello(&mut self) -> Result<(), HandshakeError> {
        let mut body = [0u8; 128];
        let body_len = build_client_hello_body(&mut body, &self.own_random)?;
        self.queue_message(HandshakeType::ClientHello, &body[..body_len], 0)?;
        self.retransmit_interval = self.config.initial_retransmit;
        self.retransmissions = 0;
        self.deadline = None;
        Ok(())
    }

    fn queue_server_flight(&mut self) -> Result<(), HandshakeError> {
        let mut body = [0u8; 128];
        let body_len = build_server_hello_body(&mut body, &self.own_random)?;
        self.queue_message(HandshakeType::ServerHello, &body[..body_len], 0)?;

        let (client_random, server_random) = self.randoms();
        let mut params = [0u8; 36];
        params[0] = 3;
        params[1..3].copy_from_slice(&crate::handshake_message::GROUP_X25519.to_be_bytes());
        params[3] = 32;
        params[4..].copy_from_slice(&self.own_public);

        let mut signed = Zeroizing::new([0u8; 100]);
        signed[..32].copy_from_slice(&client_random);
        signed[32..64].copy_from_slice(&server_random);
        signed[64..].copy_from_slice(&params);

        let signing_key = self.signing_key.ok_or(HandshakeError::MissingSigningKey)?;
        let mut signature = [0u8; 64];
        let written = self.provider.sign(
            SignatureAlgorithm::Ed25519,
            signing_key,
            &signed[..],
            &mut signature,
        )?;
        if written != 64 {
            return Err(HandshakeError::Crypto(CryptoError::BackendFailure));
        }

        let body_len = build_server_key_exchange_body(&mut body, &params, &signature)?;
        self.queue_message(HandshakeType::ServerKeyExchange, &body[..body_len], 0)?;
        self.queue_message(HandshakeType::ServerHelloDone, &[], 0)?;
        self.retransmit_interval = self.config.initial_retransmit;
        self.retransmissions = 0;
        self.deadline = None;
        Ok(())
    }

    fn queue_client_flight(&mut self) -> Result<(), HandshakeError> {
        let mut body = [0u8; 128];
        let body_len = build_client_key_exchange_body(&mut body, &self.own_public)?;
        self.queue_message(HandshakeType::ClientKeyExchange, &body[..body_len], 0)?;
        self.queue_ccs()?;
        self.queue_local_finished(false)?;
        self.retransmit_interval = self.config.initial_retransmit;
        self.retransmissions = 0;
        self.deadline = None;
        Ok(())
    }

    fn queue_server_final_flight(&mut self) -> Result<(), HandshakeError> {
        self.queue_ccs()?;
        self.queue_local_finished(true)?;
        self.retransmit_interval = self.config.initial_retransmit;
        self.retransmissions = 0;
        self.deadline = None;
        Ok(())
    }

    fn queue_ccs(&mut self) -> Result<(), HandshakeError> {
        self.flight.push(ContentType::ChangeCipherSpec, 0, &[1])
    }

    fn queue_local_finished(&mut self, server_role: bool) -> Result<(), HandshakeError> {
        let hash = self.transcript_hash()?;
        let master = self
            .master_secret
            .as_ref()
            .ok_or(HandshakeError::KeyMaterialUnavailable)?;
        let verify_data = finished_verify_data(&self.provider, master, server_role, &hash)?;
        self.queue_message(HandshakeType::Finished, &verify_data, 1)
    }

    fn queue_message(
        &mut self,
        message_type: HandshakeType,
        body: &[u8],
        epoch: u16,
    ) -> Result<(), HandshakeError> {
        let mut raw = [0u8; MAX_HANDSHAKE_MESSAGE_LEN];
        let written = encode_handshake_message(&mut raw, message_type, self.next_send_seq, body)?;
        self.append_transcript(&raw[..written])?;
        self.flight
            .push(ContentType::Handshake, epoch, &raw[..written])?;
        self.next_send_seq = self.next_send_seq.wrapping_add(1);
        Ok(())
    }

    fn transcript_hash(&self) -> Result<[u8; 32], HandshakeError> {
        let mut hash = [0u8; 32];
        let written = self.provider.digest(
            HashAlgorithm::Sha256,
            &self.transcript[..self.transcript_len],
            &mut hash,
        )?;
        if written != 32 {
            return Err(HandshakeError::Crypto(CryptoError::BackendFailure));
        }
        Ok(hash)
    }

    fn append_transcript(&mut self, bytes: &[u8]) -> Result<(), HandshakeError> {
        let end = self
            .transcript_len
            .checked_add(bytes.len())
            .ok_or(HandshakeError::TranscriptTooLong)?;
        if end > TRANSCRIPT_CAPACITY {
            return Err(HandshakeError::TranscriptTooLong);
        }
        self.transcript[self.transcript_len..end].copy_from_slice(bytes);
        self.transcript_len = end;
        Ok(())
    }

    fn randoms(&self) -> ([u8; 32], [u8; 32]) {
        match self.role {
            Role::Client => (self.own_random, self.peer_random),
            Role::Server => (self.peer_random, self.own_random),
        }
    }

    fn begin_progress(&mut self) {
        self.flight.clear();
        self.deadline = None;
        self.retransmissions = 0;
        self.retransmit_interval = self.config.initial_retransmit;
    }

    /// Keeps the last completed flight retransmittable while waiting for the
    /// peer's next flight. Used after `ClientKeyExchange` and after receiving
    /// the peer's CCS: a CCS is not handshake progress and must not cancel the
    /// retransmission timer (RFC 6347 section 4.2.4).
    fn retain_flight_for_retransmit(&mut self) {
        if self.flight.len == 0 {
            return;
        }
        if self.flight.next < self.flight.len {
            // The flight is still being emitted; do not mark it sent.
            self.deadline = None;
            return;
        }
        self.deadline = Some(self.now + self.config.initial_retransmit);
        self.retransmissions = 0;
        self.retransmit_interval = self.config.initial_retransmit;
    }

    fn resend_last_flight(&mut self) {
        if self.flight.len == 0 {
            return;
        }
        if self.state == HandshakeState::Established {
            // The established server's final-flight responses count against
            // the same retransmission budget instead of resetting it forever.
            if self.retransmissions >= self.config.max_retransmissions {
                return;
            }
            self.retransmissions = self.retransmissions.saturating_add(1);
        } else {
            self.retransmissions = 0;
        }
        self.flight.next = 0;
        self.deadline = None;
    }

    fn handle_timeout(&mut self, at: Timestamp) -> Result<(), HandshakeError> {
        self.now = at;
        let Some(deadline) = self.deadline else {
            return Ok(());
        };
        if at < deadline {
            return Ok(());
        }
        if self.flight.len == 0 {
            self.deadline = None;
            return Ok(());
        }
        if self.retransmissions >= self.config.max_retransmissions {
            self.deadline = None;
            if self.state == HandshakeState::Established {
                self.flight.clear();
                return Ok(());
            }
            return Err(HandshakeError::Timeout);
        }
        self.retransmissions = self.retransmissions.saturating_add(1);
        self.retransmit_interval = core::cmp::min(
            self.retransmit_interval + self.retransmit_interval,
            self.config.max_retransmit,
        );
        self.deadline = Some(at + self.retransmit_interval);
        self.flight.next = 0;
        Ok(())
    }

    fn handle_datagram(&mut self, payload: &[u8]) -> Result<(), HandshakeError> {
        if self.state == HandshakeState::Established {
            self.handle_established_datagram(payload);
            return Ok(());
        }
        let mut remaining = payload;
        if remaining.is_empty() {
            return Err(HandshakeError::Record(RecordError::UnexpectedEnd));
        }
        while !remaining.is_empty() {
            let (record, consumed) = Record::decode_prefix(remaining)?;
            self.process_record(&record)?;
            remaining = remaining
                .get(consumed..)
                .ok_or(HandshakeError::Record(RecordError::UnexpectedEnd))?;
        }
        Ok(())
    }

    /// Handles datagrams after establishment. Application data and alerts are
    /// outside this handshake machine and are ignored. A retransmitted
    /// handshake flight from the peer triggers a bounded retransmission of the
    /// local final flight (RFC 6347 section 4.2.4); a replay of the exact same
    /// record is treated the same way. Record errors are ignored here so a
    /// stray packet cannot tear down an established handshake.
    fn handle_established_datagram(&mut self, payload: &[u8]) {
        let mut remaining = payload;
        while !remaining.is_empty() {
            let Ok((record, consumed)) = Record::decode_prefix(remaining) else {
                return;
            };
            if record.header.content_type == ContentType::Handshake {
                match self.replay.check(record.header.sequence_number) {
                    Err(RecordError::Replay | RecordError::TooOld) => {
                        self.resend_last_flight();
                    }
                    _ => {
                        let _ = self.process_record(&record);
                    }
                }
            }
            let Some(rest) = remaining.get(consumed..) else {
                return;
            };
            remaining = rest;
        }
    }

    fn process_record(&mut self, record: &Record<'_>) -> Result<(), HandshakeError> {
        let header = record.header;
        if header.epoch > self.read_epoch {
            return Err(HandshakeError::Record(RecordError::UnexpectedEpoch));
        }
        if header.epoch < self.read_epoch {
            return Ok(());
        }
        match self.replay.check(header.sequence_number) {
            Err(RecordError::Replay | RecordError::TooOld) => return Ok(()),
            Err(error) => return Err(HandshakeError::Record(error)),
            Ok(()) => {}
        }

        let mut plaintext = [0u8; RECORD_BUFFER_LEN];
        let plaintext_len = if let Some(cipher) = &self.read_cipher {
            if header.fragment_len < AEAD_OVERHEAD {
                return Err(HandshakeError::Record(RecordError::CiphertextTooShort));
            }
            let ciphertext_len = header.fragment_len - 8;
            if ciphertext_len > RECORD_BUFFER_LEN {
                return Err(HandshakeError::Record(RecordError::OutputTooSmall));
            }
            cipher.open(&self.provider, record, &mut plaintext)?
        } else {
            if header.fragment_len > MAX_HANDSHAKE_MESSAGE_LEN {
                return Err(HandshakeError::Record(RecordError::RecordTooLong));
            }
            plaintext[..header.fragment_len].copy_from_slice(record.fragment);
            header.fragment_len
        };
        self.replay.accept(header.sequence_number)?;

        match header.content_type {
            ContentType::Handshake => self.process_handshake(&plaintext[..plaintext_len]),
            ContentType::ChangeCipherSpec => {
                self.process_change_cipher_spec(&plaintext[..plaintext_len])
            }
            ContentType::Alert => Err(HandshakeError::PeerAlert),
            ContentType::ApplicationData => Err(HandshakeError::UnexpectedRecord),
        }
    }

    fn process_change_cipher_spec(&mut self, payload: &[u8]) -> Result<(), HandshakeError> {
        if self.read_epoch != 0
            || payload != [1]
            || !matches!(
                self.state,
                HandshakeState::WaitServerFinished | HandshakeState::WaitClientFinished
            )
        {
            return Err(HandshakeError::UnexpectedChangeCipherSpec);
        }
        let cipher = match self.role {
            Role::Client => self.server_write_cipher.take(),
            Role::Server => self.client_write_cipher.take(),
        }
        .ok_or(HandshakeError::KeyMaterialUnavailable)?;
        self.read_cipher = Some(cipher);
        self.read_epoch = 1;
        self.replay.reset();
        // CCS is not handshake progress: keep the last flight and reset the
        // retransmission timer instead of cancelling them. A lost Finished
        // must still be recoverable by retransmission, and a peer that never
        // completes must drive the state machine to Timeout.
        self.retain_flight_for_retransmit();
        Ok(())
    }

    fn process_handshake(&mut self, raw: &[u8]) -> Result<(), HandshakeError> {
        let message = decode_handshake_message(raw)?;
        if message.message_seq < self.next_recv_seq {
            self.resend_last_flight();
            return Ok(());
        }
        if message.message_seq > self.next_recv_seq {
            return Err(HandshakeError::UnexpectedMessageSequence {
                expected: self.next_recv_seq,
                received: message.message_seq,
            });
        }

        match (self.state, message.message_type) {
            (HandshakeState::WaitClientHello, HandshakeType::ClientHello) => {
                self.on_client_hello(&message)
            }
            (HandshakeState::WaitServerHello, HandshakeType::ServerHello) => {
                self.on_server_hello(&message)
            }
            (HandshakeState::WaitServerKeyExchange, HandshakeType::ServerKeyExchange) => {
                self.on_server_key_exchange(&message)
            }
            (HandshakeState::WaitServerHelloDone, HandshakeType::ServerHelloDone) => {
                self.on_server_hello_done(&message)
            }
            (HandshakeState::WaitClientKeyExchange, HandshakeType::ClientKeyExchange) => {
                self.on_client_key_exchange(&message)
            }
            (
                HandshakeState::WaitServerFinished | HandshakeState::WaitClientFinished,
                HandshakeType::Finished,
            ) => self.on_finished(&message),
            _ => Err(HandshakeError::UnexpectedMessage),
        }
    }

    fn accept_message(&mut self) {
        self.next_recv_seq = self.next_recv_seq.wrapping_add(1);
    }

    fn on_client_hello(&mut self, message: &HandshakeMessage<'_>) -> Result<(), HandshakeError> {
        let info = parse_client_hello(message)?;
        if !info.offers.contains(OfferedAlgorithms::REQUIRED) {
            return Err(HandshakeError::NoCommonAlgorithm);
        }
        self.begin_progress();
        self.append_transcript(message.raw)?;
        self.accept_message();
        self.peer_random = info.random;
        self.state = HandshakeState::WaitClientKeyExchange;
        self.queue_server_flight()?;
        Ok(())
    }

    fn on_server_hello(&mut self, message: &HandshakeMessage<'_>) -> Result<(), HandshakeError> {
        let random = parse_server_hello(message.body)?;
        self.begin_progress();
        self.append_transcript(message.raw)?;
        self.accept_message();
        self.peer_random = random;
        self.state = HandshakeState::WaitServerKeyExchange;
        Ok(())
    }

    fn on_server_key_exchange(
        &mut self,
        message: &HandshakeMessage<'_>,
    ) -> Result<(), HandshakeError> {
        let info = parse_server_key_exchange(message.body)?;
        let peer_public_key = self
            .peer_public_key
            .ok_or(HandshakeError::MissingPeerPublicKey)?;
        let (client_random, server_random) = self.randoms();
        let mut signed = Zeroizing::new([0u8; 100]);
        signed[..32].copy_from_slice(&client_random);
        signed[32..64].copy_from_slice(&server_random);
        signed[64..].copy_from_slice(&info.params);
        match self.provider.verify(
            SignatureAlgorithm::Ed25519,
            &peer_public_key,
            &signed[..],
            &info.signature,
        ) {
            Ok(()) => {}
            Err(CryptoError::InvalidSignature) => return Err(HandshakeError::InvalidSignature),
            Err(error) => return Err(HandshakeError::Crypto(error)),
        }

        let shared_secret = self.agree(&info.params[4..])?;
        self.derive_keys(&shared_secret)?;

        self.begin_progress();
        self.append_transcript(message.raw)?;
        self.accept_message();
        self.state = HandshakeState::WaitServerHelloDone;
        Ok(())
    }

    fn on_server_hello_done(
        &mut self,
        message: &HandshakeMessage<'_>,
    ) -> Result<(), HandshakeError> {
        parse_server_hello_done(message.body)?;
        self.begin_progress();
        self.append_transcript(message.raw)?;
        self.accept_message();
        self.queue_client_flight()?;
        self.state = HandshakeState::WaitServerFinished;
        Ok(())
    }

    fn on_client_key_exchange(
        &mut self,
        message: &HandshakeMessage<'_>,
    ) -> Result<(), HandshakeError> {
        let peer_public_key = parse_client_key_exchange(message.body)?;
        let shared_secret = self.agree(&peer_public_key)?;
        self.derive_keys(&shared_secret)?;

        self.append_transcript(message.raw)?;
        self.accept_message();
        self.retain_flight_for_retransmit();
        self.state = HandshakeState::WaitClientFinished;
        Ok(())
    }

    fn on_finished(&mut self, message: &HandshakeMessage<'_>) -> Result<(), HandshakeError> {
        let received = parse_finished(message.body)?;
        let hash = self.transcript_hash()?;
        let master = self
            .master_secret
            .as_ref()
            .ok_or(HandshakeError::KeyMaterialUnavailable)?;
        let server_role = self.role == Role::Client;
        let expected = finished_verify_data(&self.provider, master, server_role, &hash)?;
        if !constant_time_eq(&received, &expected) {
            return Err(HandshakeError::FinishedMismatch);
        }

        self.begin_progress();
        self.append_transcript(message.raw)?;
        self.accept_message();

        if self.role == Role::Server {
            self.state = HandshakeState::Established;
            self.queue_server_final_flight()?;
        } else {
            self.state = HandshakeState::Established;
        }
        self.emit_established()?;
        Ok(())
    }

    fn agree(
        &mut self,
        peer_public_key: &[u8],
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, HandshakeError> {
        let ephemeral = self
            .ephemeral
            .as_ref()
            .ok_or(HandshakeError::KeyMaterialUnavailable)?;
        let mut shared_secret = Zeroizing::new([0u8; 32]);
        let result = self.provider.agree(
            KeyExchangeAlgorithm::X25519,
            ephemeral,
            peer_public_key,
            &mut shared_secret[..],
        );
        self.ephemeral = None;
        let written = match result {
            Ok(written) => written,
            Err(CryptoError::InvalidKey) => return Err(HandshakeError::ZeroSharedSecret),
            Err(error) => return Err(HandshakeError::Crypto(error)),
        };
        if written != 32 || shared_secret.iter().all(|&byte| byte == 0) {
            return Err(HandshakeError::ZeroSharedSecret);
        }
        Ok(shared_secret)
    }

    fn derive_keys(&mut self, shared_secret: &[u8; 32]) -> Result<(), HandshakeError> {
        let (client_random, server_random) = self.randoms();
        let master = derive_master_secret(
            &self.provider,
            shared_secret,
            &client_random,
            &server_random,
        )?;
        let key_block = derive_key_block(&self.provider, &master, &client_random, &server_random)?;

        let client_cipher = RecordCipher::new(
            AeadAlgorithm::Aes128Gcm,
            &key_block.client_write_key,
            &key_block.client_write_iv,
        )?;
        let server_cipher = RecordCipher::new(
            AeadAlgorithm::Aes128Gcm,
            &key_block.server_write_key,
            &key_block.server_write_iv,
        )?;
        self.client_write_cipher = Some(client_cipher);
        self.server_write_cipher = Some(server_cipher);
        self.master_secret = Some(master);
        Ok(())
    }

    fn emit_established(&mut self) -> Result<(), HandshakeError> {
        let (client_random, server_random) = self.randoms();
        let master = self
            .master_secret
            .as_ref()
            .ok_or(HandshakeError::KeyMaterialUnavailable)?;
        let material = SrtpKeyingMaterial::export(
            &self.provider,
            SRTP_PROFILE_AES128_CM_HMAC_SHA1_80,
            master.as_bytes(),
            &client_random,
            &server_random,
        )?;
        self.event = Some(HandshakeEvent::Established {
            keying_material: material,
        });
        self.master_secret = None;
        self.deadline = None;
        Ok(())
    }

    fn fail(&mut self) {
        self.state = HandshakeState::Failed;
        self.ephemeral = None;
        self.master_secret = None;
        self.client_write_cipher = None;
        self.server_write_cipher = None;
        self.read_cipher = None;
        self.flight.clear();
        self.deadline = None;
        self.event = None;
        self.transcript.zeroize();
        self.transcript_len = 0;
        self.own_random.zeroize();
        self.peer_random.zeroize();
        self.own_public.zeroize();
    }
}

impl<P: CryptoProvider> core::fmt::Debug for HandshakeMachine<P>
where
    <P as SignatureProvider>::PrivateKey: 'static,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HandshakeMachine")
            .field("role", &self.role)
            .field("state", &self.state)
            .field("transcript_len", &self.transcript_len)
            .field("next_send_seq", &self.next_send_seq)
            .field("next_recv_seq", &self.next_recv_seq)
            .field("queued_records", &(self.flight.len - self.flight.next))
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl<P: CryptoProvider> Drop for HandshakeMachine<P>
where
    <P as SignatureProvider>::PrivateKey: 'static,
{
    fn drop(&mut self) {
        self.ephemeral = None;
        self.master_secret = None;
        self.transcript.zeroize();
        self.own_random.zeroize();
        self.peer_random.zeroize();
        self.own_public.zeroize();
    }
}

impl<P: CryptoProvider + 'static> ProtocolMachine for HandshakeMachine<P>
where
    <P as SignatureProvider>::PrivateKey: 'static,
{
    type Input<'a>
        = Input<'a>
    where
        Self: 'a;
    type Event = HandshakeEvent;
    type Error = HandshakeError;

    fn handle_input(&mut self, input: Self::Input<'_>) -> Result<(), Self::Error> {
        if self.state == HandshakeState::Failed {
            return Err(HandshakeError::Failed);
        }
        let result = match input {
            Input::Datagram { meta, payload } => {
                self.now = meta.now;
                self.handle_datagram(payload)
            }
            Input::Timeout(at) => self.handle_timeout(at),
        };
        if result.is_err() {
            self.fail();
        }
        result
    }

    fn poll_event(&mut self) -> Option<Self::Event> {
        self.event.take()
    }

    fn next_wakeup(&self) -> Option<Timestamp> {
        if self.state == HandshakeState::Failed
            || self.flight.len == 0
            || self.flight.next < self.flight.len
        {
            None
        } else {
            self.deadline
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    // DTLS-HS-UNIT-001 — the fixed flight enforces its item bound and payload
    // bound without panicking, and its Debug redacts the payloads.
    #[test]
    fn flight_queue_bounds() {
        let mut flight = Flight::new();
        assert!(format!("{flight:?}").contains("Flight"));
        for _ in 0..FLIGHT_ITEMS {
            flight
                .push(ContentType::Handshake, 0, &[0u8; 4])
                .expect("item fits");
        }
        assert_eq!(
            flight.push(ContentType::Handshake, 0, &[0u8; 4]),
            Err(HandshakeError::FlightFull)
        );
        flight.clear();
        assert_eq!(flight.len, 0);
        assert_eq!(
            flight.push(
                ContentType::Handshake,
                0,
                &[0u8; MAX_HANDSHAKE_MESSAGE_LEN + 1]
            ),
            Err(HandshakeError::FlightFull)
        );
    }

    // DTLS-HS-UNIT-002 — constant-time comparison handles length mismatch,
    // equality and a one-bit difference.
    #[test]
    fn constant_time_comparison() {
        assert!(!constant_time_eq(b"short", b"longer"));
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"samf"));
        assert!(constant_time_eq(&[], &[]));
    }
}

# DTLS 1.2 handshake + DTLS-SRTP export contract (R2-2)

Status: frozen contract for the code in this crate. The implementation in
`src/handshake*.rs`, `src/keyschedule.rs` and `src/srtp.rs` must match this
document; tests pin the table and the derivation vectors.

Scope: one minimal DTLS 1.2 (RFC 6347) handshake profile with X25519 ECDHE,
Ed25519 signatures, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B) and
`SRTP_AES128_CM_HMAC_SHA1_80` (0x0001). The engine is Sans-IO, allocation-free,
never reads a system clock, never touches Tokio, and implements
`rtx_core::ProtocolMachine`.

## 1. State table

`HandshakeMachine::poll_transmit` writes one DTLS record per call. A flight is
queued by the transition that produces it; the runtime drains
`poll_transmit` until it returns `None`, then arms the timer returned by
`next_wakeup`.

| State | Role | Accepts | Emits on accept | Timer |
|---|---|---|---|---|
| `WaitClientHello` | server | `ClientHello` (message_seq 0) | `ServerHello` (seq 0), `ServerKeyExchange` (seq 1), `ServerHelloDone` (seq 2), all epoch 0 | none until the server flight is queued |
| `WaitServerHello` | client | `ServerHello` (message_seq 0) | none | resend `ClientHello` until the server flight arrives |
| `WaitServerKeyExchange` | client | `ServerKeyExchange` (message_seq 1); signature verified against the provisioned peer key | none | resend disabled: the peer owns the last flight |
| `WaitServerHelloDone` | client | `ServerHelloDone` (message_seq 2) | `ClientKeyExchange` (seq 1, epoch 0), `ChangeCipherSpec` (epoch 0), `Finished` (seq 2, epoch 1) | resend the client flight |
| `WaitClientKeyExchange` | server | `ClientKeyExchange` (message_seq 1) | none (keys derived; server waits for the client CCS) | resend the server flight |
| `WaitClientFinished` | server | `ChangeCipherSpec` (epoch 0), then `Finished` (message_seq 2, epoch 1) | `ChangeCipherSpec` (epoch 0), `Finished` (seq 3, epoch 1) after verifying the client Finished | resend the server flight while waiting; receiving CCS keeps the flight and timer, and budget exhaustion reaches `Timeout` → `Failed` |
| `WaitServerFinished` | client | `ChangeCipherSpec` (epoch 0), then `Finished` (message_seq 3, epoch 1) | `HandshakeEvent::Established` after verifying the server Finished | resend the client flight (including its Finished) until the server Finished arrives; receiving CCS does not cancel it |
| `Established` | both | application data and alerts are ignored; a retransmitted peer handshake flight is processed | server resends its final flight within the retry budget; client has no further handshake output | server keeps a final-flight timer; client has none |
| `Failed` | both | nothing; every input returns `HandshakeError::Failed` | none | none |

Message sequence numbers are per sender: each side starts at 0 and increments
only for its own handshake messages. ChangeCipherSpec is not a handshake
message and has no `message_seq`.

The machine owns the crypto provider and borrows the server's signing-key
handle as a `&'static` reference. That is what lets `HandshakeMachine`
implement `ProtocolMachine` without a lifetime parameter that would make the
trait's `Input<'_>` unusable. Client machines pass `None`; server machines
must provide a static handle (a hardware slot id, a provider constant, or a
key stored in a long-lived connection object).

Additional transitions:

- A handshake message with `message_seq < expected` is a retransmission: it is
  not appended to the transcript, and the machine re-queues its own last
  flight (if any) without advancing state.
- A handshake message with `message_seq > expected` aborts with
  `UnexpectedMessageSequence`.
- A record that fails replay/too-old/stale-epoch classification is ignored.
  Every other record error aborts.
- `ChangeCipherSpec` is **not** handshake progress: receiving it does not
  cancel the last flight or its retransmission timer. A peer that stops after
  CCS is driven to `Timeout` → `Failed` after the retry budget.
- Any error moves the machine to `Failed`, drops the ephemeral key handle and
  zeroizes master-secret/key-schedule buffers. There is no recovery path.

## 2. Record-layer contract

R2-1's record API is reused as-is; no record API signature is changed.

- Handshake messages are sent one per record; a record fragment that contains
  more than one message, a partial message, or a DTLS handshake fragment
  (`fragment_offset != 0` or `fragment_length != length`) is rejected.
  Fragmentation/reassembly is a recorded gap.
- Handshake messages before `ChangeCipherSpec` use record epoch 0 and are
  unprotected. `ChangeCipherSpec` is an epoch-0 record whose payload is `[1]`.
  `Finished` and later records use epoch 1 and are protected by
  `RecordCipher`.
- A datagram may carry several records. The machine walks them in order and
  installs the read cipher between records, so a CCS and a Finished in one
  datagram are handled correctly, provided CCS precedes Finished. A protected
  epoch-1 record that arrives before CCS is rejected rather than buffered
  (recorded as a gap in section 7).
- Record sequence numbers are owned by two `RecordEncoder`s (epoch 0 and
  epoch 1); retransmissions always use fresh record sequence numbers while
  keeping the original handshake `message_seq` and bytes.
- The read side uses R2-1's `ReplayWindow`; replay/too-old records are dropped.
- Outbound record plaintext capacity is
  `MAX_HANDSHAKE_MESSAGE_LEN = 512`; `poll_transmit` therefore needs at least
  `RECORD_HEADER_LEN + AEAD_OVERHEAD + 512 = 549` bytes.

## 3. Handshake message contract

The 12-byte DTLS handshake header is
`type (1) || length (3) || message_seq (2) || fragment_offset (3) ||
fragment_length (3)`.

- Message sequence numbers start at 0 on each side and increase by one per
  distinct handshake message. CCS is not a handshake message.
- The transcript is the concatenation of the complete handshake messages
  (including their 12-byte DTLS headers) in send/receive order. CCS is
  excluded. The transcript is kept in a fixed 1024-byte buffer; overflow is
  `TranscriptTooLong`.
- Finished `verify_data` is
  `PRF(master_secret, "client finished" | "server finished",
  Hash(handshake_messages))[0..12]`, where the hash is SHA-256 and the
  transcript excludes the Finished being computed.

Profile:

- version: DTLS 1.2 `{254, 253}`;
- cipher suite: 0xC02B (ECDHE-ECDSA-AES128-GCM-SHA256);
- key exchange: X25519 (supported_groups 0x001D);
- signature: Ed25519 (signature_algorithms 0x0807); strict Ed25519
  verification of the `(public_key, message, signature)` triple, with the
  signed message `client_random || server_random || ServerECDHParams`;
- SRTP: use_srtp extension, profile 0x0001, MKI length 0.

`ServerKeyExchange` signs `client_random || server_random || ServerECDHParams`
(32 + 32 + 36 bytes). `Finished` carries exactly 12 bytes.

## 4. Key schedule

DTLS 1.2 uses the **TLS 1.2 PRF** (RFC 5246 section 5), not HKDF. HKDF belongs
to DTLS 1.3 and is out of scope. The PRF is `P_SHA256` implemented through
`HmacProvider`; every PRF call below uses SHA-256.

| Step | Label | Seed | Output |
|---|---|---|---|
| master secret | `"master secret"` | `client_random || server_random` | 48 bytes |
| key block | `"key expansion"` | `server_random || client_random` | 40 bytes |
| client Finished | `"client finished"` | `Hash(handshake_messages)` | 12 bytes |
| server Finished | `"server finished"` | `Hash(handshake_messages)` | 12 bytes |
| DTLS-SRTP | `"EXTRACTOR-dtls_srtp"` | `client_random || server_random` | 60 bytes |

Key block split for AES-128-GCM:

```
client_write_key   = key_block[0..16]
server_write_key   = key_block[16..32]
client_write_IV    = key_block[32..36]   // RFC 5288 fixed IV / salt
server_write_IV    = key_block[36..40]
```

Handoff to R2-1:

- client: write cipher = `(client_write_key, client_write_IV)`, read cipher =
  `(server_write_key, server_write_IV)`;
- server: write cipher = `(server_write_key, server_write_IV)`, read cipher =
  `(client_write_key, client_write_IV)`;
- both are `RecordCipher::new(AeadAlgorithm::Aes128Gcm, key, iv)`; explicit
  nonce and AAD remain owned by R2-1. No key/salt is passed anywhere else.

The ephemeral X25519 private-key handle is dropped immediately after the
shared secret is derived, on success and on every failure path. The shared
secret, master secret and key block are zeroized with `zeroize`; the SRTP
keying material is zeroized when dropped.

## 5. DTLS-SRTP export interface (RFC 5764 section 4.2)

```rust
pub const SRTP_PROFILE_AES128_CM_HMAC_SHA1_80: u16 = 0x0001;
pub const SRTP_MASTER_KEY_LEN: usize = 16;
pub const SRTP_MASTER_SALT_LEN: usize = 14;
pub const SRTP_EXPORT_LEN: usize = 60; // 2 * (key_len + salt_len)
pub const DTLS_SRTP_EXPORTER_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp";

impl SrtpKeyingMaterial {
    pub fn export<P: HmacProvider>(
        provider: &P,
        profile: u16,
        master_secret: &[u8; 48],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Result<Self, SrtpExportError>;
}
```

Export layout:

```
keying_material          = PRF(master_secret, "EXTRACTOR-dtls_srtp",
                               client_random || server_random)[0..60]
client_write_key         = keying_material[0..16]
server_write_key         = keying_material[16..32]
client_write_salt        = keying_material[32..46]
server_write_salt        = keying_material[46..60]
```

Failure semantics:

- an unknown/unsupported profile returns `SrtpExportError::UnsupportedProfile`
  before any PRF call;
- an HMAC failure, a short/long HMAC result or any provider failure returns
  `SrtpExportError::Crypto` and no keying material;
- export failure aborts the handshake (`HandshakeError::SrtpExport`), falls
  back to nothing, and never reuses a previous key set;
- master key/salt lengths are fixed by the profile; there is no truncation or
  padding path.

## 6. Test vectors and sources

| Vector | Source | Where |
|---|---|---|
| PRF master secret / key block / DTLS-SRTP export | OpenSSL 3.0.13 `openssl kdf ... TLS1-PRF`, command recorded in `src/keyschedule.rs` tests | `keyschedule.rs`, `srtp.rs` unit tests |
| ClientHello bytes | `openssl s_server -dtls1_2 -listen -use_srtp SRTP_AES128_CM_SHA1_80 -msg` receiving `openssl s_client -dtls1_2` on 2026-10-27; raw message in `tests/handshake_openssl.rs` | parse + server negotiation test |
| Full handshake and failures | RFC 6347 / RFC 5246 / RFC 5764 semantics, deterministic provider | `tests/handshake_scenarios.rs` |
| Retransmission, timeout, malformed input, replay | RFC 6347 section 4.2.4, deterministic inputs | unit + integration tests |

Differential limitations, recorded rather than hidden:

- OpenSSL's first DTLS ClientHello is carried in a record with version
  `{254, 255}` (DTLS 1.0 compatibility). R2-1 deliberately rejects that
  version, so the OpenSSL vector is parsed at the handshake-message layer and
  re-wrapped in `{254, 253}` for the negotiation test. The record-layer
  differential fails and is claimed as a gap, not as interoperability.
- The captured OpenSSL ServerHello path uses an X.509 certificate and a
  different signature algorithm; this profile sends no Certificate message and
  uses a provisioned raw Ed25519 peer key. Full wire interoperability with
  OpenSSL is **not** claimed.
- Export bytes are compared against OpenSSL's `TLS1-PRF` KDF; the handshake
  itself is not compared against a live OpenSSL SRTP exporter.

## 7. Explicit non-goals and gaps

- DTLS 1.3 (RFC 9147), HKDF, cipher-suite agility.
- X.509 parsing, certificate-chain validation, name matching, Certificate /
  CertificateRequest / CertificateVerify messages.
- HelloVerifyRequest, stateless cookies and session resumption.
- Handshake fragmentation/reassembly; one message per record only.
- Extended Master Secret (RFC 7627), renegotiation, alerts beyond aborting,
  application-data forwarding after establishment.
- Final-flight acknowledgement: there is no handshake-level ACK. The server
  retransmits its final flight for a bounded retry budget, and after
  establishment it responds to a peer's retransmitted final flight with the
  same bounded budget. Once the budget is exhausted it stops responding; the
  peer still has its own `Timeout` → `Failed` exit.
- CCS/Finished reordering: a protected epoch-1 record received before CCS is
  rejected with `RecordError::UnexpectedEpoch`; it is not buffered. CCS must be
  processed first. Loss of CCS or Finished is handled by the retransmission
  timer, not by reordering support.
- `RecordCipher` (owned by R2-1) drops its AEAD key and fixed IV without an
  explicit zeroization hook. This PR zeroizes the master secret, key block,
  shared secret and SRTP material, but cannot change R2-1's record type; that
  residual is recorded as an R2-1 limitation rather than silently claimed.
- Changes to R2-1's record API, provider traits, CI, or any crate outside
  `rtx-dtls`.

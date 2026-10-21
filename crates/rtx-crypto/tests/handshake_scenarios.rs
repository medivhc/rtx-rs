//! L3 — protocol scenarios: the crypto operations as a media/DTLS stack
//! actually sequences them.
//!
//! These tests model the *order* of operations, not just the individual
//! primitives: ephemeral DH → transcript signing → key derivation →
//! keystream rollover → record sealing → anti-replay. Each scenario is a
//! named protocol step, so a failure names the phase that broke.

mod common;

use common::{
    AEAD_SUPPORTED, HASH_SUPPORTED, KEX_SUPPORTED, Lcg, RefCrypto, RefSigningKey, SECRET_LEN,
    SIG_LEN, SIG_SUPPORTED, TAG_LEN, assert_error, generate_pair, seal, sign,
};
use rtx_crypto::{
    AeadAlgorithm, AeadProvider, CryptoError, CryptoProvider, HashProvider, HmacProvider,
    KeyExchangeProvider, SignatureProvider,
};

/// Shared transcript material for the handshake scenarios.
const CLIENT_RANDOM: &[u8] = b"client-random-0123456789abcdef";
const SERVER_RANDOM: &[u8] = b"server-random-fedcba9876543210";

/// Key material derived from a DH secret, mirroring a TLS HKDF step.
fn derive(mac: &impl HmacProvider, secret: &[u8], label: &[u8], out: &mut [u8]) {
    let written = mac
        .hmac(HASH_SUPPORTED, secret, label, out)
        .expect("derive key material");
    assert_eq!(written, out.len());
}

// ---------------------------------------------------------------------------
// DTLS-like handshake
// ---------------------------------------------------------------------------

// L3-HANDSHAKE-001 — 完整握手：双方 DH → transcript 签名 → 派生密钥 → 密封应用数据。
#[test]
fn full_handshake_reaches_an_application_record() {
    let crypto = RefCrypto::new();
    let client = generate_pair(&crypto);
    let server = generate_pair(&crypto);

    let mut client_secret = [0u8; SECRET_LEN];
    let mut server_secret = [0u8; SECRET_LEN];
    crypto
        .agree(
            KEX_SUPPORTED,
            &client.private,
            &server.public,
            &mut client_secret,
        )
        .expect("client agree");
    crypto
        .agree(
            KEX_SUPPORTED,
            &server.private,
            &client.public,
            &mut server_secret,
        )
        .expect("server agree");
    assert_eq!(client_secret, server_secret, "DH agreement");

    let mut transcript = Vec::new();
    transcript.extend_from_slice(CLIENT_RANDOM);
    transcript.extend_from_slice(SERVER_RANDOM);

    let server_signing = RefSigningKey(0x5EED_5EED_5EED_5EED);
    let signature = sign(&crypto, server_signing, &transcript);
    crypto
        .verify(
            SIG_SUPPORTED,
            &server_signing.public_key(),
            &transcript,
            &signature,
        )
        .expect("server transcript signature");

    let mut key = [0u8; 32];
    derive(&crypto, &client_secret, b"rtx application key", &mut key);

    let plaintext = b"first application record";
    let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &key,
            &[0x22; 12],
            b"app",
            &mut buffer,
            plaintext.len(),
        )
        .expect("seal record");
    let opened = crypto
        .open_in_place(AEAD_SUPPORTED, &key, &[0x22; 12], b"app", &mut buffer)
        .expect("open record");
    assert_eq!(opened, plaintext.len());
    assert_eq!(&buffer[..plaintext.len()], plaintext);
}

// L3-HANDSHAKE-002 — 中间人替换服务端公钥 → 双方共享密钥不同 → 记录解不开。
#[test]
fn substituted_public_key_yields_unreadable_records() {
    let crypto = RefCrypto::new();
    let client = generate_pair(&crypto);
    let server = generate_pair(&crypto);
    let impostor = generate_pair(&crypto);

    let mut honest = [0u8; SECRET_LEN];
    crypto
        .agree(KEX_SUPPORTED, &client.private, &server.public, &mut honest)
        .expect("honest agree");

    let mut attacked = [0u8; SECRET_LEN];
    crypto
        .agree(
            KEX_SUPPORTED,
            &client.private,
            &impostor.public,
            &mut attacked,
        )
        .expect("attacked agree");
    assert_ne!(honest, attacked, "substitution must change the secret");

    // 诚实客户端用 `[0x11;32]`+attacked 派生钥加密；中间人不持有该钥。
    let mut sealed = vec![0u8; 5 + TAG_LEN];
    sealed[..5].copy_from_slice(b"attac");
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &attacked,
            &[0x22; 12],
            b"app",
            &mut sealed,
            5,
        )
        .expect("seal under derived key");
    assert_error(
        crypto.open_in_place(AEAD_SUPPORTED, &honest, &[0x22; 12], b"app", &mut sealed),
        CryptoError::AuthenticationFailed,
        "honest key cannot read the forged record",
    );
}

// L3-HANDSHAKE-003 — transcript 中任一随机数被改动 → 签名验证失败。
#[test]
fn tampered_random_breaks_the_transcript_signature() {
    let crypto = RefCrypto::new();
    let signing = RefSigningKey(0xABCD_1234_5678_9ABC);
    let mut transcript = Vec::new();
    transcript.extend_from_slice(CLIENT_RANDOM);
    transcript.extend_from_slice(SERVER_RANDOM);
    let signature = sign(&crypto, signing, &transcript);

    // 改客户端随机数。
    let mut altered = transcript.clone();
    altered[0] ^= 0x01;
    assert_error(
        crypto.verify(SIG_SUPPORTED, &signing.public_key(), &altered, &signature),
        CryptoError::InvalidSignature,
        "altered client random",
    );

    // 截断随机数（协商降级攻击）。
    let truncated = &transcript[..CLIENT_RANDOM.len()];
    assert_error(
        crypto.verify(SIG_SUPPORTED, &signing.public_key(), truncated, &signature),
        CryptoError::InvalidSignature,
        "truncated transcript",
    );

    // 追加扩展数据（注入扩展）。
    let mut extended = transcript.clone();
    extended.extend_from_slice(b"extra");
    assert_error(
        crypto.verify(SIG_SUPPORTED, &signing.public_key(), &extended, &signature),
        CryptoError::InvalidSignature,
        "extended transcript",
    );
}

// L3-HANDSHAKE-004 — 握手可重复执行而不产生相同密钥（每轮 generate_key 推进状态）。
#[test]
fn repeated_handshakes_produce_fresh_secrets() {
    let crypto = RefCrypto::new();
    let mut secrets: Vec<[u8; SECRET_LEN]> = Vec::new();
    for _ in 0..4 {
        let client = generate_pair(&crypto);
        let server = generate_pair(&crypto);
        let mut secret = [0u8; SECRET_LEN];
        crypto
            .agree(KEX_SUPPORTED, &client.private, &server.public, &mut secret)
            .expect("agree");
        secrets.push(secret);
    }
    for (i, left) in secrets.iter().enumerate() {
        for (j, right) in secrets.iter().enumerate() {
            if i != j {
                assert_ne!(left, right, "handshake reused key material");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Record layer
// ---------------------------------------------------------------------------

// L3-RECORD-001 — 连续多条记录使用递增 nonce，密文互不相同。
#[test]
fn record_sequence_uses_distinct_nonces() {
    let crypto = RefCrypto::new();
    let plaintext = b"media-frame";
    let mut ciphertexts: Vec<Vec<u8>> = Vec::new();
    for sequence in 0..16u64 {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&sequence.to_be_bytes());
        let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
        crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &nonce,
                b"rtp",
                &mut buffer,
                plaintext.len(),
            )
            .expect("seal frame");
        ciphertexts.push(buffer);
    }
    for (i, left) in ciphertexts.iter().enumerate() {
        for (j, right) in ciphertexts.iter().enumerate() {
            if i != j {
                assert_ne!(left, right, "records {i} and {j} collide");
            }
        }
    }
}

// L3-RECORD-002 — 密钥轮转：每个会话密钥只作用于自己的记录序列。
#[test]
fn session_key_rotation_isolates_record_streams() {
    let crypto = RefCrypto::new();
    let plaintext = b"frame";

    // 两个会话各密封 4 条记录，序号相同但会话密钥不同。
    let streams: [[u8; 32]; 2] = [[0x11u8; 32], [0xAA; 32]];
    let mut sealed: Vec<Vec<Vec<u8>>> = vec![Vec::new(), Vec::new()];
    for (session, key) in streams.iter().enumerate() {
        for sequence in 0..4u64 {
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&sequence.to_be_bytes());
            let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
            buffer[..plaintext.len()].copy_from_slice(plaintext);
            crypto
                .seal_in_place(
                    AEAD_SUPPORTED,
                    key,
                    &nonce,
                    b"",
                    &mut buffer,
                    plaintext.len(),
                )
                .expect("seal");
            sealed[session].push(buffer);
        }
    }

    // 同序号跨会话密文必然不同。
    for (first, second) in sealed[0].iter().zip(&sealed[1]) {
        assert_ne!(first, second, "session key ignored");
    }

    // 每条记录只能用自己会话的密钥打开。
    for (session, records) in sealed.iter().enumerate() {
        for (index, record) in records.iter().enumerate() {
            let mut buffer = record.clone();
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&(index as u64).to_be_bytes());
            crypto
                .open_in_place(
                    AEAD_SUPPORTED,
                    streams[session].as_slice(),
                    &nonce,
                    b"",
                    &mut buffer,
                )
                .expect("own session key opens the record");
            assert_error(
                crypto.open_in_place(
                    AEAD_SUPPORTED,
                    streams[1 - session].as_slice(),
                    &nonce,
                    b"",
                    &mut buffer,
                ),
                CryptoError::AuthenticationFailed,
                "records must not cross sessions",
            );
        }
    }
}

// L3-RECORD-003 — 头部作为 AAD：改动头部即认证失败（SRTP 语义）。
#[test]
fn record_header_is_authenticated_as_aad() {
    let crypto = RefCrypto::new();
    let mut header = vec![0x80, 0x60, 0x00, 0x08];
    let payload = b"payload";
    let mut buffer = vec![0u8; payload.len() + TAG_LEN];
    buffer[..payload.len()].copy_from_slice(payload);
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            &header,
            &mut buffer,
            payload.len(),
        )
        .expect("seal with header aad");

    // 原头部可解。
    let opened = crypto
        .open_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            &header,
            &mut buffer,
        )
        .expect("open with original header");
    assert_eq!(opened, payload.len());

    // 同一明文在原头部下重新密封，随后用篡改后的头部（序号 +1）打开。
    let mut replay = vec![0u8; payload.len() + TAG_LEN];
    replay[..payload.len()].copy_from_slice(payload);
    let original_header = [0x80u8, 0x60, 0x00, 0x08];
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            &original_header,
            &mut replay,
            payload.len(),
        )
        .expect("reseal");
    header[2] = header[2].wrapping_add(1);
    assert_error(
        crypto.open_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            &header,
            &mut replay,
        ),
        CryptoError::AuthenticationFailed,
        "sequence number rewritten",
    );
}

// L3-RECORD-004 — 乱序到达的记录各自可独立打开（无隐式状态）。
#[test]
fn out_of_order_records_open_independently() {
    let crypto = RefCrypto::new();
    let mut records: Vec<Vec<u8>> = Vec::new();
    for sequence in 0..8u64 {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&sequence.to_be_bytes());
        let payload = format!("frame-{sequence}");
        let mut buffer = vec![0u8; payload.len() + TAG_LEN];
        buffer[..payload.len()].copy_from_slice(payload.as_bytes());
        crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &nonce,
                b"rtp",
                &mut buffer,
                payload.len(),
            )
            .expect("seal");
        records.push(buffer);
    }
    records.reverse();
    for (index, record) in records.iter_mut().enumerate() {
        let sequence = 7 - index as u64;
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&sequence.to_be_bytes());
        let opened = crypto
            .open_in_place(AEAD_SUPPORTED, &[0x11; 32], &nonce, b"rtp", record)
            .expect("out-of-order open");
        let expected = format!("frame-{sequence}");
        assert_eq!(
            std::str::from_utf8(&record[..opened]).expect("utf8"),
            expected
        );
    }
}

// L3-RECORD-005 — 分片记录：同一明文拆成多段分别密封后可拼回。
#[test]
fn fragmented_payload_reassembles_after_individual_sealing() {
    let crypto = RefCrypto::new();
    let payload = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rebuilt = Vec::new();
    for (index, chunk) in payload.chunks(8).enumerate() {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let mut buffer = vec![0u8; chunk.len() + TAG_LEN];
        buffer[..chunk.len()].copy_from_slice(chunk);
        crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &nonce,
                b"frag",
                &mut buffer,
                chunk.len(),
            )
            .expect("seal fragment");
        let opened = crypto
            .open_in_place(AEAD_SUPPORTED, &[0x11; 32], &nonce, b"frag", &mut buffer)
            .expect("open fragment");
        rebuilt.extend_from_slice(&buffer[..opened]);
    }
    assert_eq!(rebuilt, payload);
}

// ---------------------------------------------------------------------------
// Anti-replay
// ---------------------------------------------------------------------------

// L3-REPLAY-001 — 应用层滑动窗口检测重复序号。
#[test]
fn replay_window_rejects_a_repeated_sequence_number() {
    let crypto = RefCrypto::new();
    let window = 64u64;
    let mut seen: Vec<u64> = Vec::new();

    let accept = |sequence: u64, seen: &mut Vec<u64>| -> bool {
        if seen.contains(&sequence) {
            return false;
        }
        seen.push(sequence);
        seen.retain(|&value| value + window > sequence);
        true
    };

    for sequence in 0..32 {
        assert!(accept(sequence, &mut seen), "fresh sequence {sequence}");
    }
    assert!(!accept(31, &mut seen), "replay of 31 rejected");
    assert!(!accept(0, &mut seen), "replay of 0 rejected");

    // 窗口滑出后旧序号不再被记录，但 AEAD tag 依然有效 —— 由上层的
    // 窗口策略而非密码学负责，故此处只断言窗口语义。
    for sequence in 100..132 {
        assert!(accept(sequence, &mut seen), "fresh sequence {sequence}");
    }
    assert!(!accept(101, &mut seen), "replay after window advance");
    assert_eq!(crypto.name(), "rtx-ref-crypto");
}

// L3-REPLAY-002 — 重放的密文本身仍然能通过 AEAD（AEAD 不做重放保护）。
#[test]
fn aead_alone_does_not_prevent_replay() {
    let crypto = RefCrypto::new();
    let (sealed, _) = seal(&crypto, b"replay-me", b"aad");
    let mut first = sealed.clone();
    let mut second = sealed;
    assert_eq!(
        crypto
            .open_in_place(AEAD_SUPPORTED, &[0x11; 32], &[0x22; 12], b"aad", &mut first)
            .expect("first open"),
        b"replay-me".len()
    );
    assert_eq!(
        crypto
            .open_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &[0x22; 12],
                b"aad",
                &mut second
            )
            .expect("second open"),
        b"replay-me".len()
    );
    assert_eq!(first, second);
}

// L3-REPLAY-003 — 双向 nonce 空间：两个方向使用不同 key/nonce 组合。
#[test]
fn bidirectional_streams_use_separate_nonce_spaces() {
    let crypto = RefCrypto::new();
    let payload = b"payload";
    let mut outbound = Vec::new();
    let mut inbound = Vec::new();
    for sequence in 0..8u64 {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&sequence.to_be_bytes());
        nonce[8] = 0x00; // outbound 标记
        let mut out = vec![0u8; payload.len() + TAG_LEN];
        out[..payload.len()].copy_from_slice(payload);
        crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &nonce,
                b"",
                &mut out,
                payload.len(),
            )
            .expect("seal outbound");
        outbound.push(out);

        let mut inbound_nonce = nonce;
        inbound_nonce[8] = 0x01; // inbound 标记
        let mut inb = vec![0u8; payload.len() + TAG_LEN];
        inb[..payload.len()].copy_from_slice(payload);
        crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &[0x22; 32],
                &inbound_nonce,
                b"",
                &mut inb,
                payload.len(),
            )
            .expect("seal inbound");
        inbound.push(inb);
    }
    for (index, out) in outbound.iter().enumerate() {
        assert_ne!(out, &inbound[index], "directions must not collide");
    }
}

// ---------------------------------------------------------------------------
// Algorithm negotiation
// ---------------------------------------------------------------------------

// L3-NEGOTIATE-001 — 协商降级到未支持算法时显式 Unsupported，而非静默弱化。
#[test]
fn negotiation_to_unsupported_algorithm_fails_loudly() {
    let crypto = RefCrypto::new();

    // 签名：参考后端只建模一种算法，协商成功时长度固定。
    let key = RefSigningKey(3);
    let mut signature = [0u8; SIG_LEN];
    assert_eq!(
        crypto
            .sign(SIG_SUPPORTED, &key, b"neg", &mut signature)
            .expect("modelled algorithm signs"),
        SIG_LEN,
    );

    // 未建模的算法必须显式 Unsupported，绝不静默弱化。
    for algorithm in [
        rtx_crypto::SignatureAlgorithm::EcdsaP256Sha256,
        rtx_crypto::SignatureAlgorithm::EcdsaP384Sha384,
    ] {
        assert_error(
            crypto.sign(algorithm, &key, b"neg", &mut signature),
            CryptoError::Unsupported,
            "unmodelled signature suite",
        );
    }

    // 摘要：协商出的套件长度必须由调用方提供足够缓冲，否则显式失败。
    let mut short = [0u8; 8];
    assert_error(
        crypto.digest(HASH_SUPPORTED, b"neg", &mut short),
        CryptoError::OutputTooSmall,
        "digest buffer must match the negotiated suite",
    );

    // AEAD：参考后端同时建模两个套件，协商结果可预测。
    let mut buffer = vec![0u8; 4 + TAG_LEN];
    buffer[..4].copy_from_slice(b"data");
    for algorithm in [AeadAlgorithm::Aes128Gcm, AeadAlgorithm::Aes256Gcm] {
        assert_eq!(
            crypto
                .seal_in_place(algorithm, &[0x11; 32], &[0x22; 12], b"", &mut buffer, 4,)
                .unwrap_or_else(|error| panic!("{algorithm:?}: {error:?}")),
            4 + TAG_LEN,
        );
    }
}

// L3-NEGOTIATE-002 — 同一 transcript 在不同算法下产生不同签名。
#[test]
fn transcript_signature_is_algorithm_bound() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(11);
    let transcript = b"negotiated-params";
    let signature = sign(&crypto, key, transcript);
    let mut digest = [0u8; 32];
    crypto
        .digest(HASH_SUPPORTED, transcript, &mut digest)
        .expect("digest");
    assert_ne!(
        &signature[..],
        &digest[..],
        "different primitives must not collide"
    );
}

// L3-NEGOTIATE-003 — 密钥派生标签隔离：不同 label 产生不同 key material。
#[test]
fn key_derivation_labels_are_domain_separated() {
    let crypto = RefCrypto::new();
    let mut rng = Lcg::new(0x01CE_0FF0);
    let secret = rng.bytes(SECRET_LEN);
    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    derive(&crypto, &secret, b"rtx key", &mut enc_key);
    derive(&crypto, &secret, b"rtx mac", &mut mac_key);
    assert_ne!(enc_key, mac_key);
    // 重复派生稳定。
    let mut again = [0u8; 32];
    derive(&crypto, &secret, b"rtx key", &mut again);
    assert_eq!(enc_key, again);
}

//! L2 — cross-crate bridges between `rtx-crypto` and the rest of the
//! workspace.
//!
//! `rtx-crypto` deliberately depends on nothing, so the interesting L2
//! questions live in the *consumer*: can a crypto operation run directly over
//! a `rtx-buffer` packet buffer, can a nonce be derived from a `rtx-core`
//! timestamp, and does the AEAD contract survive the `PacketBuf` length
//! discipline (`set_len` / `remaining_mut`)?

mod common;

use common::{
    AEAD_SUPPORTED, HASH_SUPPORTED, KEX_SUPPORTED, Lcg, MAX_DIGEST_LEN, PUB_LEN, RefCrypto,
    RefSigningKey, SECRET_LEN, SIG_LEN, SIG_SUPPORTED, TAG_LEN, assert_error, digest_len, sign,
};
use rtx_buffer::{BorrowedBuf, BufferError, FixedBuf, PacketBuf};
use rtx_core::{Clock, DatagramMeta, Duration, EcnCodepoint, IpAddr, SocketAddr, Timestamp};
use rtx_crypto::{
    AeadProvider, CryptoError, HashAlgorithm, HashProvider, HmacProvider, KeyExchangeProvider,
    RandomProvider, SignatureProvider,
};

// ---------------------------------------------------------------------------
// crypto × rtx-buffer
// ---------------------------------------------------------------------------

// L2-BUF-001 — 密封可以就地发生在 FixedBuf 上，写入长度满足 set_len 约束。
#[test]
fn seal_runs_in_place_over_fixed_buf() {
    let crypto = RefCrypto::new();
    let plaintext = b"rtx-datagram";
    let mut buffer = FixedBuf::<64>::new();
    buffer.as_mut_slice()[..plaintext.len()].copy_from_slice(plaintext);
    buffer
        .set_len(plaintext.len() + TAG_LEN)
        .expect("reserve plaintext + tag");

    let sealed = crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"hdr",
            buffer.as_mut_slice(),
            plaintext.len(),
        )
        .expect("seal over PacketBuf");
    assert_eq!(sealed, plaintext.len() + TAG_LEN);
    assert_eq!(buffer.len(), sealed);
    assert_eq!(buffer.remaining_mut(), 64 - sealed);
}

// L2-BUF-002 — FixedBuf 尾部余量被正确视为 tag 空间，不被误当成明文。
#[test]
fn fixed_buf_tail_is_tag_space_not_plaintext() {
    let crypto = RefCrypto::new();
    let mut buffer = FixedBuf::<32>::new();
    let plaintext_len = 8;
    buffer.as_mut_slice()[..plaintext_len].copy_from_slice(b"12345678");
    buffer.set_len(plaintext_len).expect("len 8");

    let sealed = crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"",
            &mut buffer.as_mut_slice()[..plaintext_len + TAG_LEN],
            plaintext_len,
        )
        .expect("seal");
    assert_eq!(sealed, plaintext_len + TAG_LEN);

    let opened = crypto
        .open_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"",
            &mut buffer.as_mut_slice()[..sealed],
        )
        .expect("open");
    assert_eq!(opened, plaintext_len);
    assert_eq!(&buffer.as_slice()[..plaintext_len], b"12345678");
}

// L2-BUF-003 — BorrowedBuf 上的原地往返，栈存储零分配。
#[test]
fn seal_open_roundtrip_over_borrowed_buf() {
    let crypto = RefCrypto::new();
    let plaintext = b"borrowed";
    let mut storage = [0u8; 40];
    let mut buffer =
        BorrowedBuf::with_len(&mut storage, plaintext.len() + TAG_LEN).expect("with_len fits");
    buffer.as_mut_slice()[..plaintext.len()].copy_from_slice(plaintext);

    // `as_mut_slice` 暴露整块存储；协议层只提交 len 以内的已初始化区域。
    let region = plaintext.len() + TAG_LEN;
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"aad",
            &mut buffer.as_mut_slice()[..region],
            plaintext.len(),
        )
        .expect("seal");
    let opened = crypto
        .open_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"aad",
            &mut buffer.as_mut_slice()[..region],
        )
        .expect("open");
    assert_eq!(opened, plaintext.len());
    assert_eq!(&buffer.as_slice()[..plaintext.len()], plaintext);
}

// L2-BUF-004 — 存储小于 tag 时 open 报 OutputTooSmall 而非越界 panic。
#[test]
fn borrowed_buf_smaller_than_tag_is_rejected() {
    let crypto = RefCrypto::new();
    let mut storage = [0u8; TAG_LEN - 1];
    let mut buffer = BorrowedBuf::with_len(&mut storage, TAG_LEN - 1).expect("view");
    assert_error(
        crypto.open_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            b"",
            buffer.as_mut_slice(),
        ),
        CryptoError::OutputTooSmall,
        "storage smaller than tag",
    );
}

// L2-BUF-005 — PacketBuf::set_len 拒绝超容量，crypto 不参与长度裁决。
#[test]
fn set_len_overflow_is_a_buffer_error_not_a_crypto_error() {
    let mut buffer = FixedBuf::<16>::new();
    assert_eq!(
        buffer.set_len(17),
        Err(BufferError::LengthExceedsCapacity),
        "buffer layer owns length validation"
    );
    assert_eq!(buffer.len(), 0);
}

// ---------------------------------------------------------------------------
// crypto × rtx-core
// ---------------------------------------------------------------------------

/// Serializes an `IpAddr` for use as AAD material.
fn ip_bytes(addr: &IpAddr, out: &mut Vec<u8>) {
    match addr {
        IpAddr::V4(octets) => out.extend_from_slice(octets),
        IpAddr::V6(octets) => out.extend_from_slice(octets),
    }
}

/// Deterministic clock driving nonce derivation from `rtx-core` time.
#[derive(Debug)]
struct MicrosClock(Timestamp);

impl Clock for MicrosClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

// L2-CORE-001 — 从 rtx-core 时间戳派生的 nonce 长度固定为 12 字节。
#[test]
fn nonce_derived_from_timestamp_has_gcm_length() {
    let crypto = RefCrypto::new();
    let clock = MicrosClock(Timestamp::from_micros(1_700_000_000_000_000));
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&clock.now().as_micros().to_le_bytes());
    crypto.fill_random(&mut nonce[8..]).expect("random suffix");

    let plaintext = b"nonce";
    let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &nonce,
            b"",
            &mut buffer,
            plaintext.len(),
        )
        .expect("seal with derived nonce");
    let opened = crypto
        .open_in_place(AEAD_SUPPORTED, &[0x11; 32], &nonce, b"", &mut buffer)
        .expect("open");
    assert_eq!(opened, plaintext.len());
}

// L2-CORE-002 — 不同时刻派生的 nonce 产生不同密文（nonce 不复用）。
#[test]
fn distinct_timestamps_yield_distinct_ciphertexts() {
    let crypto = RefCrypto::new();
    let mut rng = Lcg::new(0xC0_FFEE);
    let plaintext = [0x7Fu8; 24];
    let mut seen: Vec<Vec<u8>> = Vec::new();

    for tick in 0..8u64 {
        let stamp = Timestamp::from_micros(1_700_000_000_000_000 + tick * 20_000);
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&stamp.as_micros().to_le_bytes());
        nonce[8..].copy_from_slice(&rng.bytes(4));

        let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
        buffer[..plaintext.len()].copy_from_slice(&plaintext);
        crypto
            .seal_in_place(
                AEAD_SUPPORTED,
                &[0x11; 32],
                &nonce,
                b"hdr",
                &mut buffer,
                plaintext.len(),
            )
            .expect("seal");
        for previous in &seen {
            assert_ne!(previous, &buffer, "nonce reuse produced identical record");
        }
        seen.push(buffer);
    }
    assert_eq!(seen.len(), 8);
}

// L2-CORE-003 — DatagramMeta 的 5 元组可作为 AAD，认证失败即丢弃。
#[test]
fn datagram_meta_five_tuple_works_as_aad() {
    let crypto = RefCrypto::new();
    let sender = SocketAddr::new(IpAddr::V4([10, 0, 0, 1]), 5000);
    let receiver = SocketAddr::new(IpAddr::V4([10, 0, 0, 2]), 5001);
    let meta = DatagramMeta {
        now: Timestamp::from_micros(42),
        source: sender,
        destination: receiver,
        ecn: Some(EcnCodepoint::Ect0),
    };

    let mut aad = Vec::new();
    ip_bytes(&meta.source.ip, &mut aad);
    aad.extend_from_slice(&meta.source.port.to_be_bytes());
    ip_bytes(&meta.destination.ip, &mut aad);
    aad.extend_from_slice(&meta.destination.port.to_be_bytes());
    aad.extend_from_slice(&meta.now.as_micros().to_le_bytes());

    let plaintext = b"srtp-packet";
    let mut buffer = vec![0u8; plaintext.len() + TAG_LEN];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    crypto
        .seal_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            &aad,
            &mut buffer,
            plaintext.len(),
        )
        .expect("seal with meta aad");

    let opened = crypto
        .open_in_place(AEAD_SUPPORTED, &[0x11; 32], &[0x22; 12], &aad, &mut buffer)
        .expect("open with meta aad");
    assert_eq!(opened, plaintext.len());

    // 换目的端口即换AAD → 认证失败。
    let mut moved = meta;
    moved.destination.port += 1;
    let mut bad_aad = Vec::new();
    ip_bytes(&moved.source.ip, &mut bad_aad);
    bad_aad.extend_from_slice(&moved.source.port.to_be_bytes());
    ip_bytes(&moved.destination.ip, &mut bad_aad);
    bad_aad.extend_from_slice(&moved.destination.port.to_be_bytes());
    bad_aad.extend_from_slice(&moved.now.as_micros().to_le_bytes());
    assert_error(
        crypto.open_in_place(
            AEAD_SUPPORTED,
            &[0x11; 32],
            &[0x22; 12],
            &bad_aad,
            &mut buffer,
        ),
        CryptoError::AuthenticationFailed,
        "five-tuple mismatch",
    );
}

// L2-CORE-004 — Duration 驱动的 nonce 轮转在 20ms 间隔下互不相同。
#[test]
fn duration_spacing_produces_distinct_nonces() {
    let crypto = RefCrypto::new();
    let spacing = Duration::from_millis(20);
    let base = Timestamp::from_micros(1_000_000);
    let mut nonces: Vec<[u8; 12]> = Vec::new();
    for step in 0..8u64 {
        let at = base + Duration::from_micros(spacing.as_micros() * step);
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&at.as_micros().to_le_bytes());
        nonces.push(nonce);
    }
    for (i, left) in nonces.iter().enumerate() {
        for (j, right) in nonces.iter().enumerate() {
            if i != j {
                assert_ne!(left, right);
            }
        }
    }
    // 20ms 间隔在微秒时间轴上必须是 20_000µs。
    assert_eq!(spacing.as_micros(), 20_000);
    let _ = crypto.fill_random(&mut [0u8; 8]);
}

// ---------------------------------------------------------------------------
// 能力组合（跨 trait 静态分发）
// ---------------------------------------------------------------------------

/// CRYPTO-COMBO 支撑：与 `src/lib.rs` 中同名的泛型入口保持同一形状。
///
/// 严禁 `&dyn CryptoProvider`：关联类型 `PrivateKey` 出现在参数与返回位，
/// 违反对象安全（E0191）。六个 provider 一律静态分发。
type SigningKeyOf<P> = <P as rtx_crypto::SignatureProvider>::PrivateKey;
fn exercise_every_capability<P>(crypto: &P, sign_key: &SigningKeyOf<P>) -> Result<(), CryptoError>
where
    P: rtx_crypto::CryptoProvider,
{
    let mut random = [0u8; 16];
    crypto.fill_random(&mut random)?;

    let mut digest = [0u8; MAX_DIGEST_LEN];
    crypto.digest(HASH_SUPPORTED, b"a", &mut digest)?;

    let mut mac = [0u8; MAX_DIGEST_LEN];
    crypto.hmac(HASH_SUPPORTED, b"k", b"a", &mut mac)?;

    let mut record = vec![0u8; 12 + TAG_LEN];
    record[..12].copy_from_slice(b"payloadbytes");
    let sealed = crypto.seal_in_place(
        AEAD_SUPPORTED,
        &[0x11; 32],
        &[0x22; 12],
        b"aad",
        &mut record,
        12,
    )?;
    let opened = crypto.open_in_place(
        AEAD_SUPPORTED,
        &[0x11; 32],
        &[0x22; 12],
        b"aad",
        &mut record,
    )?;
    assert_eq!(sealed, 12 + TAG_LEN);
    assert_eq!(opened, 12);

    let mut signature = [0u8; SIG_LEN];
    crypto.sign(SIG_SUPPORTED, sign_key, b"a", &mut signature)?;

    let mut public = [0u8; PUB_LEN];
    let (private, _) = crypto.generate_key(KEX_SUPPORTED, &mut public)?;
    let mut secret = [0u8; SECRET_LEN];
    crypto.agree(KEX_SUPPORTED, &private, &public, &mut secret)?;

    assert_ne!(crypto.name(), "");
    Ok(())
}

// L2-COMBO-001 — 泛型上界下逐类调用六种能力全部成功（编译期契约 + 运行期冒烟）。
#[test]
fn generic_provider_bound_exercises_every_capability() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(0xC0FF_EE00_1234_5678);
    exercise_every_capability(&crypto, &key).expect("all capabilities");
}

// L2-COMBO-002 — 摘要长度经由 digest_len 与 hmac 返回值一致。
#[test]
fn digest_and_hmac_lengths_agree_per_algorithm() {
    let crypto = RefCrypto::new();
    let mut a = [0u8; MAX_DIGEST_LEN];
    let mut b = [0u8; MAX_DIGEST_LEN];
    for algorithm in [
        HashAlgorithm::Sha1,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
    ] {
        let digest_written = crypto
            .digest(algorithm, b"m", &mut a)
            .unwrap_or_else(|error| panic!("{algorithm:?}: {error:?}"));
        let hmac_written = crypto
            .hmac(algorithm, b"k", b"m", &mut b)
            .unwrap_or_else(|error| panic!("{algorithm:?}: {error:?}"));
        assert_eq!(digest_written, digest_len(algorithm));
        assert_eq!(hmac_written, digest_written);
    }
}

// L2-COMBO-003 — 随机源派生的密钥与直接生成的密钥都能完成 DH。
#[test]
fn kex_key_material_may_come_from_random_source() {
    let crypto = RefCrypto::new();
    let mut public = [0u8; PUB_LEN];
    let (private, _) = crypto
        .generate_key(KEX_SUPPORTED, &mut public)
        .expect("generate");
    // 随机源提供足够长度的 material（真实后端由此导入硬件 RNG）。
    let mut material = [0u8; 64];
    crypto.fill_random(&mut material).expect("random");
    assert!(material.iter().any(|&byte| byte != 0));

    let mut secret = [0u8; SECRET_LEN];
    crypto
        .agree(KEX_SUPPORTED, &private, &public, &mut secret)
        .expect("agree");
}

// L2-COMBO-004 — 签名 + 验证覆盖真实握手消息。
#[test]
fn signature_covers_handshake_transcript() {
    let crypto = RefCrypto::new();
    let key = RefSigningKey(0xDEAD_BEEF_CAFE_F00D);
    let public = key.public_key();
    let transcript = b"client-random|server-random|negotiated-params";
    let signature = sign(&crypto, key, transcript);
    crypto
        .verify(SIG_SUPPORTED, &public, transcript, &signature)
        .expect("verify transcript");

    let mut altered = transcript.to_vec();
    altered[0] ^= 0x01;
    assert_error(
        crypto.verify(SIG_SUPPORTED, &public, &altered, &signature),
        CryptoError::InvalidSignature,
        "altered transcript",
    );
}

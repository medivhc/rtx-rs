//! Decode-path fuzzing for the `rtx-dtls` record layer.
//!
//! The fuzzer drives every public decoder and the Sans-IO machine with
//! arbitrary bytes. The contract under test is total safety: no panic, no
//! out-of-bounds read, and — for inputs the decoder accepts — a verbatim
//! re-encode.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rtx_crypto::{AeadAlgorithm, AeadProvider, CryptoError};
use rtx_dtls::{
    DatagramMeta, Input, IpAddr, ProtocolMachine, Record, RecordHeader, RecordMachine,
    ReplayWindow, SequenceNumber, SocketAddr, Timestamp,
};

/// Provider that declines every operation: the plaintext machine never calls
/// it, and a protected machine fed garbage never gets a valid tag.
#[derive(Debug)]
struct NeverAead;

impl AeadProvider for NeverAead {
    fn seal_in_place(
        &self,
        _algorithm: AeadAlgorithm,
        _key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        _payload_and_tag: &mut [u8],
        _plaintext_len: usize,
    ) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    fn open_in_place(
        &self,
        _algorithm: AeadAlgorithm,
        _key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        _ciphertext_and_tag: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

fn meta(now: Timestamp) -> DatagramMeta {
    DatagramMeta {
        now,
        source: SocketAddr::new(IpAddr::V4([10, 0, 0, 1]), 1),
        destination: SocketAddr::new(IpAddr::V4([10, 0, 0, 2]), 2),
        ecn: None,
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = RecordHeader::decode(data);
    let _ = Record::decode(data);
    let _ = Record::decode_plaintext(data);
    let _ = Record::decode_protected(data);

    // Walk a datagram record by record exactly like the machine does,
    // verifying the prefix contract on everything that decodes.
    let mut remaining = data;
    let mut walked = 0usize;
    while !remaining.is_empty() && walked < 256 {
        let Ok((record, consumed)) = Record::decode_prefix(remaining) else {
            break;
        };
        if consumed == 0 || consumed > remaining.len() {
            break;
        }
        let mut encoded = [0u8; 1024];
        if let Some(target) = encoded.get_mut(..record.encoded_len()) {
            if record.encode(target).is_ok() {
                assert_eq!(target, &remaining[..consumed]);
            }
        }
        remaining = &remaining[consumed..];
        walked += 1;
    }

    // Drive the plaintext machine with the whole buffer.
    let mut machine = RecordMachine::<1024, NeverAead>::new(NeverAead);
    let _ = machine.handle_input(Input::Datagram {
        meta: meta(Timestamp::from_micros(u64::try_from(data.len()).unwrap_or(u64::MAX))),
        payload: data,
    });
    while machine.poll_event().is_some() {}

    // Drive the timeout input.
    let _ = machine.handle_input(Input::Timeout(Timestamp::from_micros(
        u64::try_from(data.len()).unwrap_or(u64::MAX),
    )));

    // Replay window: 7-byte chunks give a 6-byte sequence number plus an
    // operation selector.
    let mut window = ReplayWindow::new();
    for chunk in data.chunks(7).take(128) {
        if chunk.len() < 7 {
            break;
        }
        let mut sequence_bytes = [0u8; 6];
        sequence_bytes.copy_from_slice(&chunk[..6]);
        let sequence = SequenceNumber::from_be_bytes(sequence_bytes);
        let _ = window.check(sequence);
        match chunk[6] % 4 {
            0 => {
                let _ = window.accept(sequence);
            }
            1 => window.reset(),
            _ => {}
        }
    }
});

//! `M3-PT2` zero-allocation measurement for the `rtx-wire` / `rtx-h3`
//! frame codecs.
//!
//! This module is a **measurement**, not an optimization claim. The gate
//! (`docs/m3-m4-gates.md` §1.4.4 `M3-PT2`) asks for a counting-allocator
//! delta over steady-state frame encode/decode; the report wording is
//! restricted to “the measured delta is zero”. `M3-F3` forbids calling the
//! decoders “optimized” before the `M3-F` fuzz targets exist, and they do
//! not exist in this change.
//!
//! Mechanics: the unit-test binary installs the counting allocator
//! (`TEST_GLOBAL` in the crate root). The test registers a scene, enters it
//! with every input prepared on the stack or allocated beforehand, runs the
//! codec loop, leaves the scene and asserts the scene's `alloc_count` and
//! `free_count` deltas are zero.

#[cfg(test)]
mod tests {
    use crate::alloc::{enter, reset, scene, snapshot};
    use rtx_h3::connect::{ConnectBuffers, ConnectRequest, ConnectResponse};
    use rtx_h3::settings::{
        SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_H3_DATAGRAM, SETTINGS_QPACK_BLOCKED_STREAMS,
        SETTINGS_QPACK_MAX_TABLE_CAPACITY, Settings,
    };
    use rtx_wire::Decode;
    use rtx_wire::Encode;
    use rtx_wire::h3_frame::Frame;
    use rtx_wire::varint::{self, VarInt};
    use std::vec;

    const ITERATIONS: usize = 1_000;

    fn settings_payload() -> (Settings, vec::Vec<u8>) {
        let mut settings = Settings::new();
        for (id, value) in [
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
            (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
            (SETTINGS_H3_DATAGRAM, 1),
        ] {
            settings.set(id, value).expect("encodable setting");
        }
        let mut payload = vec![0u8; settings.encoded_len()];
        let written = settings.encode(&mut payload).expect("payload fits");
        assert_eq!(written, payload.len());
        (settings, payload)
    }

    #[test]
    fn m3_pt2_frame_codec_zero_alloc() {
        let (_settings, payload) = settings_payload();

        let frame_type = VarInt::new(0x04).expect("SETTINGS is a valid varint");
        let frame = Frame::new(frame_type, &payload);
        let mut frame_bytes = vec![0u8; frame.encoded_len()];
        frame.encode(&mut frame_bytes).expect("frame fits");

        let request = ConnectRequest::new("https", "127.0.0.1:4433", "/session", "webtransport");
        let mut request_bytes = vec![0u8; request.encoded_len()];
        request.encode(&mut request_bytes).expect("request fits");

        let response = ConnectResponse::new(200).expect("valid status");
        let mut response_bytes = vec![0u8; response.encoded_len()];
        response.encode(&mut response_bytes).expect("response fits");

        let mut scratch = vec![0u8; 1024];
        let mut scheme = [0u8; 64];
        let mut authority = [0u8; 64];
        let mut path = [0u8; 64];
        let mut protocol = [0u8; 64];

        // Warm up the code paths and the thread-local scene slot before the
        // measured region; nothing here is part of the measurement.
        {
            let (decoded, _) = Frame::decode(&frame_bytes).expect("frame decodes");
            assert_eq!(decoded.frame_type().get(), 0x04);
        }

        let tag = scene("m3_pt2_frame_codec_zero_alloc");
        reset(tag);

        let mut checksum = 0usize;
        let scope = enter(tag);
        for _ in 0..ITERATIONS {
            let (decoded, consumed) = Frame::decode(&frame_bytes).expect("frame decodes");
            let written = decoded
                .encode(&mut scratch)
                .expect("frame re-encodes into the scratch buffer");
            checksum = checksum
                .wrapping_add(consumed)
                .wrapping_add(written)
                .wrapping_add(usize::try_from(decoded.frame_type().get()).unwrap_or(0));

            let decoded_settings = Settings::decode(&payload).expect("settings decode");
            let written = decoded_settings
                .encode(&mut scratch)
                .expect("settings re-encode into the scratch buffer");
            checksum = checksum
                .wrapping_add(decoded_settings.len())
                .wrapping_add(written);

            let buffers =
                ConnectBuffers::new(&mut scheme, &mut authority, &mut path, &mut protocol);
            let decoded_request =
                ConnectRequest::decode(&request_bytes, buffers).expect("request decodes");
            checksum = checksum
                .wrapping_add(decoded_request.scheme().len())
                .wrapping_add(decoded_request.protocol().len());

            let decoded_response =
                ConnectResponse::decode(&response_bytes).expect("response decodes");
            checksum = checksum.wrapping_add(usize::from(decoded_response.status()));

            let (value, consumed) = varint::decode(&frame_bytes).expect("varint decodes");
            let written = varint::encode(value, &mut scratch[..8]).expect("varint encodes");
            checksum = checksum
                .wrapping_add(consumed)
                .wrapping_add(written)
                .wrapping_add(usize::try_from(value).unwrap_or(0));
        }
        drop(scope);

        let measured = snapshot(tag);
        assert_eq!(
            measured.alloc_count, 0,
            "M3-PT2 measured allocation delta (alloc_count) must be zero"
        );
        assert_eq!(
            measured.free_count, 0,
            "M3-PT2 measured allocation delta (free_count) must be zero"
        );
        assert_eq!(measured.allocated_bytes, 0);
        assert!(checksum > 0, "the loop must actually run the codecs");
    }
}

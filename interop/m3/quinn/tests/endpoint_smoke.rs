//! Smoke test: an rtx-quic endpoint constructs without touching the network.

use rtx_quic::{Endpoint, EndpointConfig};

#[test]
fn rtx_quic_endpoint_creates() {
    let endpoint = Endpoint::new(EndpointConfig::new()).expect("rtx-quic endpoint");
    let _ = endpoint;
}

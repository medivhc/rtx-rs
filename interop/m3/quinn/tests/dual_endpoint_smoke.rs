//! Smoke test: an rtx-quic endpoint and a quinn upstream endpoint construct
//! without touching the network.

use std::net::SocketAddr;

use quinn::Endpoint as QuinnEndpoint;
use rtx_quic::{Endpoint as RtxEndpoint, EndpointConfig};

#[tokio::test]
async fn dual_endpoints_create() {
    let rtx = RtxEndpoint::new(EndpointConfig::new()).expect("rtx-quic endpoint");
    let _ = rtx;

    let bind_addr: SocketAddr = "[::1]:0".parse().expect("bind addr");
    let quinn = QuinnEndpoint::client(bind_addr).expect("quinn client endpoint");
    let _ = quinn;
}

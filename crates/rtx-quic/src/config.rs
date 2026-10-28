//! Endpoint and transport configuration.
//!
//! TLS material is accepted as DER bytes; no Rustls or `quinn-proto` type is
//! exposed. The provider is fixed to rustls + ring with TLS 1.3 only.

use std::fmt;
use std::sync::Arc;

use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{IdleTimeout, TransportConfig as QuinnTransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::error::EndpointError;
use crate::telemetry::{RecordingFactory, Telemetry};

/// Largest value representable by a QUIC varint.
const MAX_VARINT: u64 = (1 << 62) - 1;

/// Tunables copied into the peer-visible QUIC transport parameters and the
/// local buffers.
///
/// Defaults mirror the useful parts of `quinn-proto`’s defaults, except that
/// the connection-level receive window is an explicit 16 MiB instead of the
/// upstream “maximum varint” default (see the crate-level resource-budget
/// section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    /// Idle timeout in milliseconds; `None` disables it, `0` also disables it
    /// per RFC 9000. The effective timeout is the minimum of both peers.
    pub max_idle_timeout_millis: Option<u64>,
    /// Maximum concurrently open bidirectional streams the peer may open.
    pub max_concurrent_bidi_streams: u32,
    /// Maximum concurrently open unidirectional streams the peer may open.
    pub max_concurrent_uni_streams: u32,
    /// Per-stream receive window in bytes.
    pub stream_receive_window_bytes: u64,
    /// Connection-level receive window in bytes.
    pub connection_receive_window_bytes: u64,
    /// DATAGRAM receive buffer in bytes; `None` disables DATAGRAM support
    /// (and therefore stops advertising `max_datagram_frame_size`).
    pub datagram_receive_buffer_bytes: Option<usize>,
    /// DATAGRAM send buffer in bytes.
    pub datagram_send_buffer_bytes: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_idle_timeout_millis: Some(30_000),
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 100,
            stream_receive_window_bytes: 1_250_000,
            connection_receive_window_bytes: 16 * 1024 * 1024,
            datagram_receive_buffer_bytes: Some(1_250_000),
            datagram_send_buffer_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone)]
struct ServerIdentity {
    certificate_chain_der: Vec<Vec<u8>>,
    private_key_pkcs8_der: Vec<u8>,
}

/// Endpoint configuration.
///
/// The same configuration can describe a client-only endpoint (no server
/// identity) or an endpoint that also accepts incoming connections.
#[derive(Clone)]
pub struct EndpointConfig {
    alpn: Vec<Vec<u8>>,
    transport: TransportConfig,
    server_identity: Option<ServerIdentity>,
    client_roots_der: Vec<Vec<u8>>,
    rng_seed: Option<[u8; 32]>,
}

impl EndpointConfig {
    /// An endpoint with no ALPN, no server identity and no client trust
    /// roots.
    #[must_use]
    pub fn new() -> Self {
        Self {
            alpn: Vec::new(),
            transport: TransportConfig::default(),
            server_identity: None,
            client_roots_der: Vec::new(),
            rng_seed: None,
        }
    }

    /// Set the ALPN protocols advertised and accepted by this endpoint.
    ///
    /// Each protocol must be 1–255 bytes (RFC 7301).
    #[must_use]
    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn = protocols;
        self
    }

    /// Replace the transport parameters and buffer limits.
    #[must_use]
    pub fn with_transport(mut self, transport: TransportConfig) -> Self {
        self.transport = transport;
        self
    }

    /// Enable the server side with a DER certificate chain and a DER PKCS#8
    /// private key.
    #[must_use]
    pub fn with_server_identity(
        mut self,
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_pkcs8_der: Vec<u8>,
    ) -> Self {
        self.server_identity = Some(ServerIdentity {
            certificate_chain_der,
            private_key_pkcs8_der,
        });
        self
    }

    /// Trust the given DER-encoded root certificates when acting as a client.
    #[must_use]
    pub fn with_client_roots(mut self, roots_der: Vec<Vec<u8>>) -> Self {
        self.client_roots_der = roots_der;
        self
    }

    /// Seed the endpoint RNG. Intended for deterministic tests.
    #[must_use]
    pub fn with_rng_seed(mut self, seed: [u8; 32]) -> Self {
        self.rng_seed = Some(seed);
        self
    }

    fn validate(&self) -> Result<(), EndpointError> {
        if self
            .alpn
            .iter()
            .any(|protocol| protocol.is_empty() || protocol.len() > 255)
        {
            return Err(EndpointError::InvalidConfiguration(
                "ALPN protocol identifiers must be 1..=255 bytes",
            ));
        }
        if self
            .transport
            .max_idle_timeout_millis
            .is_some_and(|millis| millis > MAX_VARINT)
        {
            return Err(EndpointError::InvalidConfiguration(
                "idle timeout exceeds a QUIC varint",
            ));
        }
        if self.transport.stream_receive_window_bytes > MAX_VARINT {
            return Err(EndpointError::InvalidConfiguration(
                "stream receive window exceeds a QUIC varint",
            ));
        }
        if self.transport.connection_receive_window_bytes > MAX_VARINT {
            return Err(EndpointError::InvalidConfiguration(
                "connection receive window exceeds a QUIC varint",
            ));
        }
        Ok(())
    }

    pub(crate) fn build(self) -> Result<BuiltConfig, EndpointError> {
        self.validate()?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        for root in &self.client_roots_der {
            roots
                .add(CertificateDer::from(root.clone()))
                .map_err(|error| EndpointError::Tls(error.to_string()))?;
        }
        let client_builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| EndpointError::Tls(error.to_string()))?;
        let mut client = client_builder
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols.clone_from(&self.alpn);
        let client_crypto = QuicClientConfig::try_from(client)
            .map_err(|error| EndpointError::CipherSuite(error.to_string()))?;

        let server_crypto = match self.server_identity {
            Some(identity) => {
                let certificate_chain = identity
                    .certificate_chain_der
                    .into_iter()
                    .map(CertificateDer::from)
                    .collect::<Vec<_>>();
                let private_key =
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.private_key_pkcs8_der));
                let server_builder = rustls::ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .map_err(|error| EndpointError::Tls(error.to_string()))?;
                let mut server = server_builder
                    .with_no_client_auth()
                    .with_single_cert(certificate_chain, private_key)
                    .map_err(|error| EndpointError::Tls(error.to_string()))?;
                server.alpn_protocols.clone_from(&self.alpn);
                server.max_early_data_size = u32::MAX;
                Some(Arc::new(QuicServerConfig::try_from(server).map_err(
                    |error| EndpointError::CipherSuite(error.to_string()),
                )?))
            }
            None => None,
        };

        Ok(BuiltConfig {
            transport: self.transport,
            client_crypto: Arc::new(client_crypto),
            server_crypto,
            rng_seed: self.rng_seed,
        })
    }
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for EndpointConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointConfig")
            .field("alpn", &self.alpn)
            .field("transport", &self.transport)
            .field(
                "server_identity",
                &self.server_identity.as_ref().map(|_| "<redacted>"),
            )
            .field("client_roots", &self.client_roots_der.len())
            .field("rng_seed", &self.rng_seed.map(|_| "<redacted>"))
            .finish()
    }
}

pub(crate) struct BuiltConfig {
    pub(crate) transport: TransportConfig,
    pub(crate) client_crypto: Arc<QuicClientConfig>,
    pub(crate) server_crypto: Option<Arc<QuicServerConfig>>,
    pub(crate) rng_seed: Option<[u8; 32]>,
}

/// Translate the facade transport configuration into `quinn-proto`’s type.
///
/// Values are validated by [`EndpointConfig::validate`] first; the saturating
/// fallbacks here are unreachable in practice and avoid a panic on a
/// programmer error.
pub(crate) fn build_transport(
    config: &TransportConfig,
    telemetry: Arc<Telemetry>,
) -> QuinnTransportConfig {
    let mut transport = QuinnTransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(config.max_concurrent_bidi_streams))
        .max_concurrent_uni_streams(VarInt::from_u32(config.max_concurrent_uni_streams))
        .max_idle_timeout(
            config
                .max_idle_timeout_millis
                .map(|millis| IdleTimeout::from(VarInt::from_u64(millis).unwrap_or(VarInt::MAX))),
        )
        .stream_receive_window(
            VarInt::from_u64(config.stream_receive_window_bytes).unwrap_or(VarInt::MAX),
        )
        .receive_window(
            VarInt::from_u64(config.connection_receive_window_bytes).unwrap_or(VarInt::MAX),
        )
        .datagram_receive_buffer_size(config.datagram_receive_buffer_bytes)
        .datagram_send_buffer_size(config.datagram_send_buffer_bytes)
        .congestion_controller_factory(Arc::new(RecordingFactory::new(telemetry)));
    transport
}

#[cfg(test)]
mod tests {
    use super::{EndpointConfig, TransportConfig};
    use crate::error::EndpointError;

    #[test]
    fn empty_alpn_is_rejected() {
        let error = EndpointConfig::new()
            .with_alpn(vec![Vec::new()])
            .build()
            .err()
            .expect("invalid ALPN must fail");
        assert!(matches!(error, EndpointError::InvalidConfiguration(_)));
    }

    #[test]
    fn oversized_connection_window_is_rejected() {
        let transport = TransportConfig {
            connection_receive_window_bytes: 1 << 62,
            ..TransportConfig::default()
        };
        let error = EndpointConfig::new()
            .with_transport(transport)
            .build()
            .err()
            .expect("out-of-range window must fail");
        assert!(matches!(error, EndpointError::InvalidConfiguration(_)));
    }

    #[test]
    fn invalid_certificate_is_rejected() {
        let error = EndpointConfig::new()
            .with_server_identity(vec![vec![0, 1, 2]], vec![0; 8])
            .build()
            .err()
            .expect("a bogus certificate must fail");
        assert!(matches!(error, EndpointError::Tls(_)));
    }

    #[test]
    fn debug_redacts_private_material() {
        let config = EndpointConfig::new().with_server_identity(vec![vec![1]], vec![7; 8]);
        let rendered = format!("{config:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("7, 7, 7"));
    }
}

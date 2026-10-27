//! `RFC 5764` section 4.2 read/write direction mapping.
//!
//! `DTLS-SRTP` exports four *master* values, not session keys: a master key and
//! a master salt for each direction. `RFC 5764` section 4.2 assigns the
//! `client_write` material to "the SRTP keys used to encrypt and authenticate
//! packets sent by the client", and states that "the server MUST only use
//! these keys to decrypt and to check the authenticity of inbound packets".
//! The `server_write` material is the mirror image.
//!
//! Mapping therefore depends only on which side the local endpoint drives:
//!
//! | local role        | send material | receive material |
//! |-------------------|---------------|------------------|
//! | [`Role::Client`]  | `client_write`| `server_write`   |
//! | [`Role::Server`]  | `server_write`| `client_write`   |
//!
//! This module only selects the two master pairs. It performs no derivation:
//! the caller runs each pair through [`crate::SenderContext::from_master`] or
//! [`crate::ReceiverContext::from_master`], which applies `RFC 3711` section
//! 4.3.
//!
//! [`Role`] is deliberately independent of `rtx-dtls`: protocol crates at the
//! same dependency layer must not depend on each other (see `ARCHITECTURE.md`
//! section 6). The application maps the handshake role to this enum.

use zeroize::Zeroize;

use crate::{SESSION_KEY_LEN, SESSION_SALT_LEN};

/// Which side of the `DTLS-SRTP` association the local endpoint drives.
///
/// The meaning matches the handshake role: a client sent `ClientHello`, a
/// server answers it. The application translates the `rtx-dtls` role into this
/// type; `rtx-srtp` does not depend on `rtx-dtls` in production code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The local endpoint initiated the handshake.
    Client,
    /// The local endpoint accepted the handshake.
    Server,
}

/// Master key and master salt selected for one direction.
///
/// The values are secret keying material. `Debug` redacts them and `Drop`
/// zeroizes both arrays.
pub struct DirectionalMasterKeys {
    send_key: [u8; SESSION_KEY_LEN],
    send_salt: [u8; SESSION_SALT_LEN],
    receive_key: [u8; SESSION_KEY_LEN],
    receive_salt: [u8; SESSION_SALT_LEN],
}

impl DirectionalMasterKeys {
    const fn new(
        send_key: [u8; SESSION_KEY_LEN],
        send_salt: [u8; SESSION_SALT_LEN],
        receive_key: [u8; SESSION_KEY_LEN],
        receive_salt: [u8; SESSION_SALT_LEN],
    ) -> Self {
        Self {
            send_key,
            send_salt,
            receive_key,
            receive_salt,
        }
    }

    /// Master key protecting outbound `SRTP` packets.
    #[must_use]
    pub const fn send_key(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.send_key
    }

    /// Master salt protecting outbound `SRTP` packets.
    #[must_use]
    pub const fn send_salt(&self) -> &[u8; SESSION_SALT_LEN] {
        &self.send_salt
    }

    /// Master key authenticating inbound `SRTP` packets.
    #[must_use]
    pub const fn receive_key(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.receive_key
    }

    /// Master salt authenticating inbound `SRTP` packets.
    #[must_use]
    pub const fn receive_salt(&self) -> &[u8; SESSION_SALT_LEN] {
        &self.receive_salt
    }
}

impl Drop for DirectionalMasterKeys {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.send_salt.zeroize();
        self.receive_key.zeroize();
        self.receive_salt.zeroize();
    }
}

impl core::fmt::Debug for DirectionalMasterKeys {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DirectionalMasterKeys")
            .field("send", &"<redacted>")
            .field("receive", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Selects the send and receive master pairs for `role` (`RFC 5764` section
/// 4.2).
///
/// The four inputs are the exported `client_write` and `server_write` master
/// key/salt pairs. A client sends with `client_write` and receives with
/// `server_write`; a server sends with `server_write` and receives with
/// `client_write`. No derivation happens here: pass each selected pair to
/// [`crate::SenderContext::from_master`] or
/// [`crate::ReceiverContext::from_master`].
#[must_use]
pub fn map_directions(
    role: Role,
    client_write_key: [u8; SESSION_KEY_LEN],
    client_write_salt: [u8; SESSION_SALT_LEN],
    server_write_key: [u8; SESSION_KEY_LEN],
    server_write_salt: [u8; SESSION_SALT_LEN],
) -> DirectionalMasterKeys {
    match role {
        Role::Client => DirectionalMasterKeys::new(
            client_write_key,
            client_write_salt,
            server_write_key,
            server_write_salt,
        ),
        Role::Server => DirectionalMasterKeys::new(
            server_write_key,
            server_write_salt,
            client_write_key,
            client_write_salt,
        ),
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    const CLIENT_KEY: [u8; SESSION_KEY_LEN] = [0x11; SESSION_KEY_LEN];
    const CLIENT_SALT: [u8; SESSION_SALT_LEN] = [0x22; SESSION_SALT_LEN];
    const SERVER_KEY: [u8; SESSION_KEY_LEN] = [0x33; SESSION_KEY_LEN];
    const SERVER_SALT: [u8; SESSION_SALT_LEN] = [0x44; SESSION_SALT_LEN];

    fn map(role: Role) -> DirectionalMasterKeys {
        map_directions(role, CLIENT_KEY, CLIENT_SALT, SERVER_KEY, SERVER_SALT)
    }

    // SRTP-DIR-001 — RFC 5764 section 4.2: a client sends client_write and
    // receives server_write.
    #[test]
    fn client_sends_client_write_and_receives_server_write() {
        let keys = map(Role::Client);
        assert_eq!(keys.send_key(), &CLIENT_KEY);
        assert_eq!(keys.send_salt(), &CLIENT_SALT);
        assert_eq!(keys.receive_key(), &SERVER_KEY);
        assert_eq!(keys.receive_salt(), &SERVER_SALT);
    }

    // SRTP-DIR-002 — RFC 5764 section 4.2: a server sends server_write and
    // receives client_write.
    #[test]
    fn server_sends_server_write_and_receives_client_write() {
        let keys = map(Role::Server);
        assert_eq!(keys.send_key(), &SERVER_KEY);
        assert_eq!(keys.send_salt(), &SERVER_SALT);
        assert_eq!(keys.receive_key(), &CLIENT_KEY);
        assert_eq!(keys.receive_salt(), &CLIENT_SALT);
    }

    // SRTP-DIR-003 — the two roles are mirror images of each other.
    #[test]
    fn roles_are_mirror_images() {
        let client = map(Role::Client);
        let server = map(Role::Server);
        assert_eq!(client.send_key(), server.receive_key());
        assert_eq!(client.send_salt(), server.receive_salt());
        assert_eq!(client.receive_key(), server.send_key());
        assert_eq!(client.receive_salt(), server.send_salt());
    }

    // SRTP-DIR-004 — Debug never reveals either direction's material.
    #[test]
    fn directional_keys_debug_redacts_material() {
        let rendered = format!("{:?}", map(Role::Client));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("1111"));
        assert!(!rendered.contains("3333"));
    }
}

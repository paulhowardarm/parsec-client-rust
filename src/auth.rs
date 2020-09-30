// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Client app authentication data
use parsec_interface::requests::{request::RequestAuth, AuthType};
use parsec_interface::secrecy::{ExposeSecret, Secret};

use libc::geteuid;

/// Authentication data used in Parsec requests
#[derive(Clone, Debug)]
pub enum AuthenticationData {
    /// Used in cases where no authentication is desired or required
    None,
    /// Data used for direct, identity-based authentication
    ///
    /// The app name is wrapped in a [`Secret`](https://docs.rs/secrecy/*/secrecy/struct.Secret.html).
    /// The `Secret` struct can be imported from
    /// `parsec_client::core::secrecy::Secret`.
    AppIdentity(Secret<String>),
    /// Used when the authentication will be done using a Unix Peer Credential check.
    /// The caller does not supply any input data. When this authentication pattern is
    /// used, the client automatically populates the authentication field with the
    /// correct byte pattern for the effective user ID of the process in which the
    /// client is running.
    UnixPeerCredential,
}

impl AuthenticationData {
    /// Get the Parsec authentication type based on the data type
    pub fn auth_type(&self) -> AuthType {
        match self {
            AuthenticationData::None => AuthType::NoAuth,
            AuthenticationData::AppIdentity(_) => AuthType::Direct,
            AuthenticationData::UnixPeerCredential => AuthType::PeerCredentials,
        }
    }
}

impl From<&AuthenticationData> for RequestAuth {
    fn from(data: &AuthenticationData) -> Self {
        match data {
            AuthenticationData::None => RequestAuth::new(Vec::new()),
            AuthenticationData::AppIdentity(name) => {
                RequestAuth::new(name.expose_secret().bytes().collect())
            }
            AuthenticationData::UnixPeerCredential => {
                let this_process_uid: u32 = unsafe { geteuid() };
                RequestAuth::new(this_process_uid.to_le_bytes().to_vec())
            }
        }
    }
}

//! Known Ethereum 2.0 clients and their fingerprints.
//!
//! Currently using identify to fingerprint.

use libp2p::identify::IdentifyInfo;
use serde::Serialize;
use strum::{AsRefStr, AsStaticStr};

/// Various client and protocol information related to a node.
#[derive(Clone, Debug, Serialize)]
pub struct Client {
    /// The client's name (Ex: lighthouse, prism, nimbus, etc)
    pub kind: ClientKind,
    /// The client's version.
    pub version: String,
    /// The OS version of the client.
    pub os_version: String,
    /// The libp2p protocol version.
    pub protocol_version: String,
    /// Identify agent string
    pub agent_string: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, AsRefStr, AsStaticStr)]
pub enum ClientKind {
    /// A lighthouse node (the best kind).
    Lighthouse,
    /// A Nimbus node.
    Nimbus,
    /// A Teku node.
    Teku,
    /// A Prysm node.
    Prysm,
    /// A lodestar node.
    Lodestar,
    /// An unknown client.
    Unknown,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            kind: ClientKind::Unknown,
            version: "unknown".into(),
            os_version: "unknown".into(),
            protocol_version: "unknown".into(),
            agent_string: None,
        }
    }
}

impl Client {
    /// Builds a `Client` from `IdentifyInfo`.
    pub fn from_identify_info(info: &IdentifyInfo) -> Self {
        let (kind, version, os_version) = client_from_agent_version(&info.agent_version);

        Client {
            kind,
            version,
            os_version,
            protocol_version: info.protocol_version.clone(),
            agent_string: Some(info.agent_version.clone()),
        }
    }
}

impl std::fmt::Display for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ClientKind::Lighthouse => write!(
                f,
                "Lighthouse: version: {}, os_version: {}",
                self.version, self.os_version
            ),
            ClientKind::Teku => write!(
                f,
                "Teku: version: {}, os_version: {}",
                self.version, self.os_version
            ),
            ClientKind::Nimbus => write!(
                f,
                "Nimbus: version: {}, os_version: {}",
                self.version, self.os_version
            ),
            ClientKind::Prysm => write!(
                f,
                "Prysm: version: {}, os_version: {}",
                self.version, self.os_version
            ),
            ClientKind::Lodestar => write!(f, "Lodestar: version: {}", self.version),
            ClientKind::Unknown => {
                if let Some(agent_string) = &self.agent_string {
                    write!(f, "Unknown: {}", agent_string)
                } else {
                    write!(f, "Unknown")
                }
            }
        }
    }
}

impl std::fmt::Display for ClientKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}

// helper function to identify clients from their agent_version. Returns the client
// kind and it's associated version and the OS kind.
fn client_from_agent_version(agent_version: &str) -> (ClientKind, String, String) {
    let mut agent_split = agent_version.split('/');
    match agent_split.next() {
        Some("Lighthouse") => {
            let kind = ClientKind::Lighthouse;
            let mut version = String::from("unknown");
            let mut os_version = version.clone();
            if let Some(agent_version) = agent_split.next() {
                version = agent_version.into();
                if let Some(agent_os_version) = agent_split.next() {
                    os_version = agent_os_version.into();
                }
            }
            (kind, version, os_version)
        }
        Some("teku") => {
            let kind = ClientKind::Teku;
            let mut version = String::from("unknown");
            let mut os_version = version.clone();
            if agent_split.next().is_some() {
                if let Some(agent_version) = agent_split.next() {
                    version = agent_version.into();
                    if let Some(agent_os_version) = agent_split.next() {
                        os_version = agent_os_version.into();
                    }
                }
            }
            (kind, version, os_version)
        }
        Some("github.com") => {
            let kind = ClientKind::Prysm;
            let unknown = String::from("unknown");
            (kind, unknown.clone(), unknown)
        }
        Some("Prysm") => {
            let kind = ClientKind::Prysm;
            let mut version = String::from("unknown");
            let mut os_version = version.clone();
            if agent_split.next().is_some() {
                if let Some(agent_version) = agent_split.next() {
                    version = agent_version.into();
                    if let Some(agent_os_version) = agent_split.next() {
                        os_version = agent_os_version.into();
                    }
                }
            }
            (kind, version, os_version)
        }
        Some("nimbus") => {
            let kind = ClientKind::Nimbus;
            let mut version = String::from("unknown");
            let mut os_version = version.clone();
            if agent_split.next().is_some() {
                if let Some(agent_version) = agent_split.next() {
                    version = agent_version.into();
                    if let Some(agent_os_version) = agent_split.next() {
                        os_version = agent_os_version.into();
                    }
                }
            }
            (kind, version, os_version)
        }
        Some("nim-libp2p") => {
            let kind = ClientKind::Nimbus;
            let mut version = String::from("unknown");
            let mut os_version = version.clone();
            if let Some(agent_version) = agent_split.next() {
                version = agent_version.into();
                if let Some(agent_os_version) = agent_split.next() {
                    os_version = agent_os_version.into();
                }
            }
            (kind, version, os_version)
        }
        Some("js-libp2p") => {
            let kind = ClientKind::Lodestar;
            let mut version = String::from("unknown");
            let mut os_version = version.clone();
            if let Some(agent_version) = agent_split.next() {
                version = agent_version.into();
                if let Some(agent_os_version) = agent_split.next() {
                    os_version = agent_os_version.into();
                }
            }
            (kind, version, os_version)
        }
        _ => {
            let unknown = String::from("unknown");
            (ClientKind::Unknown, unknown.clone(), unknown)
        }
    }
}

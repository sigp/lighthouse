use std::sync::Arc;

use parking_lot::RwLock;
use libp2p::bytes::Bytes;
use discv5::enr::{Enr, EnrError};

use crate::discovery::enr::CombinedKey;

/// Represents a port advertised via an ENR
/// 
/// The ENR specification allows extension of the keys stored in any given ENR
/// as well as specific keys for TCP and UDP ports over both IPv4 and IPv6. This
/// type extends these to add the QUIC transport.
pub enum EnrPort {
    Tcp4(u16),
    Tcp6(u16),
    Udp4(u16),
    Udp6(u16),
    Quic4(u16),
    Quic6(u16),
}

/// Represents a mutable instance of an ENR
/// 
/// Any mutation of an ENR necessitates re-signing the new ENR, so this type
/// contains both the ENR itself as well as its corresponding signing key.
pub struct MutableEnr {
    /// Shared ENR
    enr: Arc<RwLock<Enr<CombinedKey>>>,
    /// Signing key for ENR modifications
    enr_key: Arc<CombinedKey>,
}

impl MutableEnr {
    pub fn new(enr: Enr<CombinedKey>, enr_key: CombinedKey) -> Self {
        Self {
            enr: Arc::new(RwLock::new(enr)),
            enr_key: Arc::new(enr_key),
        }
    }

    pub fn enr(&self) -> &Enr<CombinedKey> {
        &self.enr.read()
    }

    pub fn enr_key(&self) -> &CombinedKey {
        self.enr_key.as_ref()
    }

    /// Insert an arbitrary key-value pair into the ENR
    pub fn insert(&self, key: impl AsRef<[u8]>, value: &[u8]) -> Result<Option<Bytes>, EnrError> {
        self.enr.write().insert(key, &value, &self.enr_key)
    }

    /// Update the specified port being advertised via this ENR
    /// 
    /// If the port is already being advertised in this ENR, it is overwritten. Otherwise, it is added as a new key-value pair.
    pub fn update_port(&self, port: EnrPort) -> Result<Option<Bytes>, EnrError> {
        match port {
            EnrPort::Tcp4(p) => self.insert("tcp4", p.to_be_bytes().as_ref()),
            EnrPort::Tcp6(p) => self.insert("tcp6", p.to_be_bytes().as_ref()),
            EnrPort::Udp4(p) => self.insert("udp4", p.to_be_bytes().as_ref()),
            EnrPort::Udp6(p) => self.insert("udp6", p.to_be_bytes().as_ref()),
            EnrPort::Quic4(p) => self.insert("quic4", p.to_be_bytes().as_ref()),
            EnrPort::Quic6(p) => self.insert("quic6", p.to_be_bytes().as_ref()),
        }
    }
}
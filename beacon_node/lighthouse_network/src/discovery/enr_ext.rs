//! ENR extension trait to support libp2p integration.

use crate::{Enr, Multiaddr, PeerId};
use discv5::enr::{CombinedKey, CombinedPublicKey};
use libp2p::core::multiaddr::Protocol;
use libp2p::identity::{Keypair, PublicKey};
use tiny_keccak::{Hasher, Keccak};

/// Extend ENR for libp2p types.
pub trait EnrExt {
    /// The libp2p `PeerId` for the record.
    fn peer_id(&self) -> PeerId;

    /// Returns a list of multiaddrs if the ENR has an `ip` and either a `tcp` or `udp` key **or** an `ip6` and either a `tcp6` or `udp6`.
    /// The vector remains empty if these fields are not defined.
    fn multiaddr(&self) -> Vec<Multiaddr>;

    /// Returns a list of multiaddrs with the `PeerId` prepended.
    fn multiaddr_p2p(&self) -> Vec<Multiaddr>;

    /// Returns any multiaddrs that contain the TCP protocol with the `PeerId` prepended.
    fn multiaddr_p2p_tcp(&self) -> Vec<Multiaddr>;

    /// Returns any multiaddrs that contain the UDP protocol with the `PeerId` prepended.
    fn multiaddr_p2p_udp(&self) -> Vec<Multiaddr>;

    /// Returns any multiaddrs that contain the TCP protocol.
    fn multiaddr_tcp(&self) -> Vec<Multiaddr>;
}

/// Extend ENR CombinedPublicKey for libp2p types.
pub trait CombinedKeyPublicExt {
    /// Converts the publickey into a peer id, without consuming the key.
    fn as_peer_id(&self) -> PeerId;
}

/// Extend ENR CombinedKey for conversion to libp2p keys.
pub trait CombinedKeyExt {
    /// Converts a libp2p key into an ENR combined key.
    fn from_libp2p(key: Keypair) -> Result<CombinedKey, &'static str>;
}

impl EnrExt for Enr {
    /// The libp2p `PeerId` for the record.
    fn peer_id(&self) -> PeerId {
        self.public_key().as_peer_id()
    }

    /// Returns a list of multiaddrs if the ENR has an `ip` and either a `tcp` or `udp` key **or** an `ip6` and either a `tcp6` or `udp6`.
    /// The vector remains empty if these fields are not defined.
    fn multiaddr(&self) -> Vec<Multiaddr> {
        let mut multiaddrs: Vec<Multiaddr> = Vec::new();
        if let Some(ip) = self.ip4() {
            if let Some(udp) = self.udp4() {
                let mut multiaddr: Multiaddr = ip.into();
                multiaddr.push(Protocol::Udp(udp));
                multiaddrs.push(multiaddr);
            }

            if let Some(tcp) = self.tcp4() {
                let mut multiaddr: Multiaddr = ip.into();
                multiaddr.push(Protocol::Tcp(tcp));
                multiaddrs.push(multiaddr);
            }
        }
        if let Some(ip6) = self.ip6() {
            if let Some(udp6) = self.udp6() {
                let mut multiaddr: Multiaddr = ip6.into();
                multiaddr.push(Protocol::Udp(udp6));
                multiaddrs.push(multiaddr);
            }

            if let Some(tcp6) = self.tcp6() {
                let mut multiaddr: Multiaddr = ip6.into();
                multiaddr.push(Protocol::Tcp(tcp6));
                multiaddrs.push(multiaddr);
            }
        }
        multiaddrs
    }

    /// Returns a list of multiaddrs if the ENR has an `ip` and either a `tcp` or `udp` key **or** an `ip6` and either a `tcp6` or `udp6`.
    /// The vector remains empty if these fields are not defined.
    ///
    /// This also prepends the `PeerId` into each multiaddr with the `P2p` protocol.
    fn multiaddr_p2p(&self) -> Vec<Multiaddr> {
        let peer_id = self.peer_id();
        let mut multiaddrs: Vec<Multiaddr> = Vec::new();
        if let Some(ip) = self.ip4() {
            if let Some(udp) = self.udp4() {
                let mut multiaddr: Multiaddr = ip.into();
                multiaddr.push(Protocol::Udp(udp));
                multiaddr.push(Protocol::P2p(peer_id.into()));
                multiaddrs.push(multiaddr);
            }

            if let Some(tcp) = self.tcp4() {
                let mut multiaddr: Multiaddr = ip.into();
                multiaddr.push(Protocol::Tcp(tcp));
                multiaddr.push(Protocol::P2p(peer_id.into()));
                multiaddrs.push(multiaddr);
            }
        }
        if let Some(ip6) = self.ip6() {
            if let Some(udp6) = self.udp6() {
                let mut multiaddr: Multiaddr = ip6.into();
                multiaddr.push(Protocol::Udp(udp6));
                multiaddr.push(Protocol::P2p(peer_id.into()));
                multiaddrs.push(multiaddr);
            }

            if let Some(tcp6) = self.tcp6() {
                let mut multiaddr: Multiaddr = ip6.into();
                multiaddr.push(Protocol::Tcp(tcp6));
                multiaddr.push(Protocol::P2p(peer_id.into()));
                multiaddrs.push(multiaddr);
            }
        }
        multiaddrs
    }

    /// Returns a list of multiaddrs if the ENR has an `ip` and a `tcp` key **or** an `ip6` and a `tcp6`.
    /// The vector remains empty if these fields are not defined.
    ///
    /// This also prepends the `PeerId` into each multiaddr with the `P2p` protocol.
    fn multiaddr_p2p_tcp(&self) -> Vec<Multiaddr> {
        let peer_id = self.peer_id();
        let mut multiaddrs: Vec<Multiaddr> = Vec::new();
        if let Some(ip) = self.ip4() {
            if let Some(tcp) = self.tcp4() {
                let mut multiaddr: Multiaddr = ip.into();
                multiaddr.push(Protocol::Tcp(tcp));
                multiaddr.push(Protocol::P2p(peer_id.into()));
                multiaddrs.push(multiaddr);
            }
        }
        if let Some(ip6) = self.ip6() {
            if let Some(tcp6) = self.tcp6() {
                let mut multiaddr: Multiaddr = ip6.into();
                multiaddr.push(Protocol::Tcp(tcp6));
                multiaddr.push(Protocol::P2p(peer_id.into()));
                multiaddrs.push(multiaddr);
            }
        }
        multiaddrs
    }

    /// Returns a list of multiaddrs if the ENR has an `ip` and a `udp` key **or** an `ip6` and a `udp6`.
    /// The vector remains empty if these fields are not defined.
    ///
    /// This also prepends the `PeerId` into each multiaddr with the `P2p` protocol.
    fn multiaddr_p2p_udp(&self) -> Vec<Multiaddr> {
        let peer_id = self.peer_id();
        let mut multiaddrs: Vec<Multiaddr> = Vec::new();
        if let Some(ip) = self.ip4() {
            if let Some(udp) = self.udp4() {
                let mut multiaddr: Multiaddr = ip.into();
                multiaddr.push(Protocol::Udp(udp));
                multiaddr.push(Protocol::P2p(peer_id.into()));
                multiaddrs.push(multiaddr);
            }
        }
        if let Some(ip6) = self.ip6() {
            if let Some(udp6) = self.udp6() {
                let mut multiaddr: Multiaddr = ip6.into();
                multiaddr.push(Protocol::Udp(udp6));
                multiaddr.push(Protocol::P2p(peer_id.into()));
                multiaddrs.push(multiaddr);
            }
        }
        multiaddrs
    }

    /// Returns a list of multiaddrs if the ENR has an `ip` and either a `tcp` or `udp` key **or** an `ip6` and either a `tcp6` or `udp6`.
    /// The vector remains empty if these fields are not defined.
    fn multiaddr_tcp(&self) -> Vec<Multiaddr> {
        let mut multiaddrs: Vec<Multiaddr> = Vec::new();
        if let Some(ip) = self.ip4() {
            if let Some(tcp) = self.tcp4() {
                let mut multiaddr: Multiaddr = ip.into();
                multiaddr.push(Protocol::Tcp(tcp));
                multiaddrs.push(multiaddr);
            }
        }
        if let Some(ip6) = self.ip6() {
            if let Some(tcp6) = self.tcp6() {
                let mut multiaddr: Multiaddr = ip6.into();
                multiaddr.push(Protocol::Tcp(tcp6));
                multiaddrs.push(multiaddr);
            }
        }
        multiaddrs
    }
}

impl CombinedKeyPublicExt for CombinedPublicKey {
    /// Converts the publickey into a peer id, without consuming the key.
    ///
    /// This is only available with the `libp2p` feature flag.
    fn as_peer_id(&self) -> PeerId {
        use libp2p::identity::{ed25519, secp256k1};
        match self {
            Self::Secp256k1(pk) => {
                let pk_bytes = pk.to_sec1_bytes();
                let libp2p_pk: PublicKey = secp256k1::PublicKey::try_from_bytes(&pk_bytes)
                    .expect("valid public key")
                    .into();
                PeerId::from_public_key(&libp2p_pk)
            }
            Self::Ed25519(pk) => {
                let pk_bytes = pk.to_bytes();
                let libp2p_pk: PublicKey = ed25519::PublicKey::try_from_bytes(&pk_bytes)
                    .expect("valid public key")
                    .into();
                PeerId::from_public_key(&libp2p_pk)
            }
        }
    }
}

impl CombinedKeyExt for CombinedKey {
    fn from_libp2p(key: Keypair) -> Result<CombinedKey, &'static str> {
        match key.key_type() {
            libp2p::identity::KeyType::Secp256k1 => {
                let key = key.try_into_secp256k1().expect("right key type");
                let secret =
                    discv5::enr::k256::ecdsa::SigningKey::from_slice(&key.secret().to_bytes())
                        .expect("libp2p key must be valid");
                Ok(CombinedKey::Secp256k1(secret))
            }
            libp2p::identity::KeyType::Ed25519 => {
                let key = key.try_into_ed25519().expect("right key type");
                let ed_keypair = discv5::enr::ed25519_dalek::SigningKey::from_bytes(
                    &(key.to_bytes()[..32])
                        .try_into()
                        .expect("libp2p key must be valid"),
                );
                Ok(CombinedKey::from(ed_keypair))
            }
            _ => Err("Unsupported keypair kind"),
        }
    }
}

// helper function to convert a peer_id to a node_id. This is only possible for secp256k1/ed25519 libp2p
// peer_ids
pub fn peer_id_to_node_id(peer_id: &PeerId) -> Result<discv5::enr::NodeId, String> {
    // A libp2p peer id byte representation should be 2 length bytes + 4 protobuf bytes + compressed pk bytes
    // if generated from a PublicKey with Identity multihash.
    let pk_bytes = &peer_id.to_bytes()[2..];

    let public_key = PublicKey::try_decode_protobuf(pk_bytes).map_err(|e| {
        format!(
            " Cannot parse libp2p public key public key from peer id: {}",
            e
        )
    })?;

    match public_key.key_type() {
        libp2p::identity::KeyType::Secp256k1 => {
            let pk = public_key
                .clone()
                .try_into_secp256k1()
                .expect("right key type");
            let uncompressed_key_bytes = &pk.to_bytes_uncompressed()[1..];
            let mut output = [0_u8; 32];
            let mut hasher = Keccak::v256();
            hasher.update(uncompressed_key_bytes);
            hasher.finalize(&mut output);
            Ok(discv5::enr::NodeId::parse(&output).expect("Must be correct length"))
        }
        libp2p::identity::KeyType::Ed25519 => {
            let pk = public_key
                .clone()
                .try_into_secp256k1()
                .expect("right key type");
            let uncompressed_key_bytes = pk.to_bytes();
            let mut output = [0_u8; 32];
            let mut hasher = Keccak::v256();
            hasher.update(&uncompressed_key_bytes);
            hasher.finalize(&mut output);
            Ok(discv5::enr::NodeId::parse(&output).expect("Must be correct length"))
        }

        _ => Err(format!("Unsupported public key from peer {}", peer_id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256k1_peer_id_conversion() {
        let sk_hex = "df94a73d528434ce2309abb19c16aedb535322797dbd59c157b1e04095900f48";
        let sk_bytes = hex::decode(sk_hex).unwrap();
        let secret_key = discv5::enr::k256::ecdsa::SigningKey::from_slice(&sk_bytes).unwrap();

        let libp2p_sk = libp2p::identity::secp256k1::SecretKey::try_from_bytes(sk_bytes).unwrap();
        let secp256k1_kp: libp2p::identity::secp256k1::Keypair = libp2p_sk.into();
        let libp2p_kp: Keypair = secp256k1_kp.into();
        let peer_id = libp2p_kp.public().to_peer_id();

        let enr = discv5::enr::EnrBuilder::new("v4")
            .build(&secret_key)
            .unwrap();
        let node_id = peer_id_to_node_id(&peer_id).unwrap();

        assert_eq!(enr.node_id(), node_id);
    }

    #[test]
    fn test_ed25519_peer_conversion() {
        let sk_hex = "4dea8a5072119927e9d243a7d953f2f4bc95b70f110978e2f9bc7a9000e4b261";
        let sk_bytes = hex::decode(sk_hex).unwrap();
        let secret_key = discv5::enr::ed25519_dalek::SigningKey::from_bytes(
            &sk_bytes.clone().try_into().unwrap(),
        );

        let libp2p_sk = libp2p::identity::ed25519::SecretKey::try_from_bytes(sk_bytes).unwrap();
        let secp256k1_kp: libp2p::identity::ed25519::Keypair = libp2p_sk.into();
        let libp2p_kp: Keypair = secp256k1_kp.into();
        let peer_id = libp2p_kp.public().to_peer_id();

        let enr = discv5::enr::EnrBuilder::new("v4")
            .build(&secret_key)
            .unwrap();
        let node_id = peer_id_to_node_id(&peer_id).unwrap();

        assert_eq!(enr.node_id(), node_id);
    }
}

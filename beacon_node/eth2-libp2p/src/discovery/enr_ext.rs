//! ENR extension trait to support libp2p integration.
use crate::{Enr, Multiaddr, PeerId};
use discv5::enr::{CombinedKey, CombinedPublicKey};
use libp2p::core::{identity::Keypair, multiaddr::Protocol};
use tiny_keccak::{Hasher, Keccak};

/// Extend ENR for libp2p types.
pub trait EnrExt {
    /// The libp2p `PeerId` for the record.
    fn peer_id(&self) -> PeerId;

    /// Returns a list of multiaddrs if the ENR has an `ip` and either a `tcp` or `udp` key **or** an `ip6` and either a `tcp6` or `udp6`.
    /// The vector remains empty if these fields are not defined.
    fn multiaddr(&self) -> Vec<Multiaddr>;
}

/// Extend ENR CombinedPublicKey for libp2p types.
pub trait CombinedKeyPublicExt {
    /// Converts the publickey into a peer id, without consuming the key.
    fn into_peer_id(&self) -> PeerId;
}

/// Extend ENR CombinedKey for conversion to libp2p keys.
pub trait CombinedKeyExt {
    /// Converts a libp2p key into an ENR combined key.
    fn from_libp2p(key: &libp2p::core::identity::Keypair) -> Result<CombinedKey, &'static str>;
}

impl EnrExt for Enr {
    /// The libp2p `PeerId` for the record.
    fn peer_id(&self) -> PeerId {
        self.public_key().into_peer_id()
    }

    /// Returns a list of multiaddrs if the ENR has an `ip` and either a `tcp` or `udp` key **or** an `ip6` and either a `tcp6` or `udp6`.
    /// The vector remains empty if these fields are not defined.
    ///
    /// Note: Only available with the `libp2p` feature flag.
    fn multiaddr(&self) -> Vec<Multiaddr> {
        let mut multiaddrs: Vec<Multiaddr> = Vec::new();
        if let Some(ip) = self.ip() {
            if let Some(udp) = self.udp() {
                let mut multiaddr: Multiaddr = ip.into();
                multiaddr.push(Protocol::Udp(udp));
                multiaddrs.push(multiaddr);
            }

            if let Some(tcp) = self.tcp() {
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
}

impl CombinedKeyPublicExt for CombinedPublicKey {
    /// Converts the publickey into a peer id, without consuming the key.
    ///
    /// This is only available with the `libp2p` feature flag.
    fn into_peer_id(&self) -> PeerId {
        match self {
            Self::Secp256k1(pk) => {
                let pk_bytes = pk.serialize_compressed();
                let libp2p_pk = libp2p::core::PublicKey::Secp256k1(
                    libp2p::core::identity::secp256k1::PublicKey::decode(&pk_bytes)
                        .expect("valid public key"),
                );
                PeerId::from_public_key(libp2p_pk)
            }
            Self::Ed25519(pk) => {
                let pk_bytes = pk.to_bytes();
                let libp2p_pk = libp2p::core::PublicKey::Ed25519(
                    libp2p::core::identity::ed25519::PublicKey::decode(&pk_bytes)
                        .expect("valid public key"),
                );
                PeerId::from_public_key(libp2p_pk)
            }
        }
    }
}

impl CombinedKeyExt for CombinedKey {
    fn from_libp2p(key: &libp2p::core::identity::Keypair) -> Result<CombinedKey, &'static str> {
        match key {
            Keypair::Secp256k1(key) => {
                let secret = discv5::enr::secp256k1::SecretKey::parse(&key.secret().to_bytes())
                    .expect("libp2p key must be valid");
                Ok(CombinedKey::Secp256k1(secret))
            }
            Keypair::Ed25519(key) => {
                let ed_keypair =
                    discv5::enr::ed25519_dalek::SecretKey::from_bytes(&key.encode()[..32])
                        .expect("libp2p key must be valid");
                Ok(CombinedKey::from(ed_keypair))
            }
            _ => Err("ENR: Unsupported libp2p key type"),
        }
    }
}

// helper function to convert a peer_id to a node_id. This is only possible for secp256k1 libp2p
// peer_ids
fn peer_id_to_node_id(peer_id: &PeerId) -> Option<discv5::enr::NodeId> {
    let bytes = peer_id.as_bytes();
    // must be the identity hash
    if bytes.len() == 34 && bytes[0] == 0x00 {
        // left over is potentially secp256k1 key

        if let Ok(key) = discv5::enr::secp256k1::PublicKey::parse(&bytes[1..]) {
            let uncompressed_key_bytes = key.serialize();
            let mut output = [0_u8; 32];
            let mut hasher = Keccak::v256();
            hasher.update(&uncompressed_key_bytes);
            hasher.finalize(&mut output);
            return Some(discv5::enr::NodeId::parse(&output).expect("Must be correct length"));
        }
    }
    None
}

mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn test_peer_id_conversion() {
        let key = discv5::enr::secp256k1::SecretKey::parse_slice(
            &hex::decode("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
                .unwrap(),
        )
        .unwrap();

        let peer_id: PeerId =
            hex::decode("1220dd86cd1b9414f4b9b42a1b1258390ee9097298126df92a61789483ac90801ed6")
                .unwrap()
                .try_into()
                .unwrap();

        let node_id = peer_id_to_node_id(&peer_id).unwrap();

        let enr = {
            let mut builder = discv5::enr::EnrBuilder::new("v4");
            builder.build(&key).unwrap()
        };

        assert_eq!(enr.node_id(), node_id);
    }
}

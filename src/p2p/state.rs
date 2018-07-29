use std::io::Read;
use std::error::Error;
use std::path::Path;
use std::fs::File;
use std::sync::Arc;

use super::hex;
use super::secp256k1::Secp256k1;
use super::secp256k1::key::{ SecretKey, PublicKey };
use super::libp2p_core::Multiaddr;
use super::libp2p_peerstore::PeerId;
use super::libp2p_peerstore::json_peerstore::JsonPeerstore;
use super::config::NetworkConfig;


const PEERS_FILE: &str = "peerstore.json";
const LOCAL_SK_FILE: &str = "local.sk";

pub struct NetworkState {
    pub pubkey: PublicKey,
    pub seckey: SecretKey,
    pub peer_id: PeerId,
    pub listen_multiaddr: Multiaddr,
    pub peer_store: Arc<JsonPeerstore>,
}

impl NetworkState {
    pub fn new(config: &NetworkConfig) -> Result <Self, Box<Error>> {
        let curve = Secp256k1::new();
        let seckey = {
            let path = Path::new(&config.config_dir).join(LOCAL_SK_FILE);
            let mut contents = String::new();
            let mut file = File::open(path)?;
            file.read_to_string(&mut contents)?;
            let vec = hex::decode(contents)?;
            SecretKey::from_slice(&curve, &vec)?
        };
        let pubkey = PublicKey::from_secret_key(&curve, &seckey)?;
        let peer_id = PeerId::from_public_key(
            &pubkey.serialize_vec(&curve, false));
        let peer_store =  {
            let path = Path::new(&config.config_dir).join(PEERS_FILE);
            let base = JsonPeerstore::new(path)?;
            Arc::new(base)
        };
        let listen_multiaddr = "/ip4/0.0.0.0/tcp/0".parse::<Multiaddr>()?;
        Ok(Self {
            seckey,
            pubkey,
            peer_id,
            listen_multiaddr,
            peer_store,
        })
    }
}

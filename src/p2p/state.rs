extern crate rand;

use std::io::{ Read, Write };
use std::error::Error;
use std::fs::File;
use std::sync::Arc;
use std::time::Duration;

use super::config::NetworkConfig;
use super::libp2p_core::Multiaddr;
use super::libp2p_peerstore::{ Peerstore, PeerAccess, PeerId };
use super::libp2p_peerstore::json_peerstore::JsonPeerstore;
use super::pem;
use super::secp256k1::Secp256k1;
use super::secp256k1::key::{ SecretKey, PublicKey };
use super::slog::Logger;


const PEERS_FILE: &str = "peerstore.json";
const LOCAL_PEM_FILE: &str = "local_peer_id.pem";

pub struct NetworkState {
    pub config: NetworkConfig,
    pub pubkey: PublicKey,
    pub seckey: SecretKey,
    pub peer_id: PeerId,
    pub listen_multiaddr: Multiaddr,
    pub peer_store: Arc<JsonPeerstore>,
}

impl NetworkState {
    pub fn new(config: NetworkConfig, log: &Logger) -> Result <Self, Box<Error>> {
        let curve = Secp256k1::new();
        let seckey = match 
            NetworkState::load_secret_key_from_pem_file(&config, &curve)
        {
            Ok(k) => k,
            _ => NetworkState::generate_new_secret_key(&config, &curve)?
        };
        let pubkey = PublicKey::from_secret_key(&curve, &seckey)?;
        let peer_id = PeerId::from_public_key(
            &pubkey.serialize_vec(&curve, false));
        info!(log, "Loaded keys"; "peer_id" => &peer_id.to_base58());
        let peer_store =  {
            let path = config.data_dir.join(PEERS_FILE);
            let base = JsonPeerstore::new(path)?;
            Arc::new(base)
        };
        let listen_multiaddr = "/ip4/0.0.0.0/tcp/0".parse::<Multiaddr>()?;
        Ok(Self {
            config: config,
            seckey,
            pubkey,
            peer_id,
            listen_multiaddr,
            peer_store,
        })
    }

    pub fn add_peer(&mut self,
                    peer_id: PeerId,
                    multiaddr: Multiaddr,
                    duration_secs: u64) {
        self.peer_store.peer_or_create(&peer_id)
            .add_addr(multiaddr, Duration::from_secs(duration_secs));
    }

    // TODO: this shouldn't be hard-coded; distribute with peers json.
    pub fn add_sigp_peer(&mut self) {
        let peer_id = {
            let b58 = "Qmajfeei87f8V5N7SQwPw3wr57M1dNcGNwhTqf72v73E7U";
            b58.parse::<PeerId>().unwrap()
        };
        let multiaddr = {
            let string = "/dns/lh.sigp.io/tcp/10101";
            string.parse::<Multiaddr>().unwrap()
        };
        self.add_peer(peer_id, multiaddr, 3600 * 24 * 356);
    }

    /// Instantiate a SecretKey from a .pem file on disk. 
    pub fn load_secret_key_from_pem_file(config: &NetworkConfig, curve: &Secp256k1)
        -> Result<SecretKey, Box<Error>> 
    {
        let path = config.data_dir.join(LOCAL_PEM_FILE);
        let mut contents = String::new();
        let mut file = File::open(path)?;
        file.read_to_string(&mut contents)?;
        let pem_key = pem::parse(contents)?;
        let key = SecretKey::from_slice(curve, &pem_key.contents)?;
        Ok(key)
    }
    
    /// Generate a new SecretKey and store it on disk as a .pem file. 
    pub fn generate_new_secret_key(
        config: &NetworkConfig,
        curve: &Secp256k1)
        -> Result<SecretKey, Box<Error>> 
    {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::new(&curve, &mut rng);
        let pem_key = pem::Pem {
            tag: String::from("EC PRIVATE KEY"),
            contents: sk[..].to_vec()
        };
        let s_string = pem::encode(&pem_key);
        let path = config.data_dir.join(LOCAL_PEM_FILE);
        let mut s_file = File::create(path)?;
        s_file.write(s_string.as_bytes())?;
        Ok(sk)
    }
}

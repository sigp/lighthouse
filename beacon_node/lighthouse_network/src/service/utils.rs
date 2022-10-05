use crate::multiaddr::Protocol;
use crate::rpc::{MetaData, MetaDataV1, MetaDataV2};
use crate::types::{
    error, EnrAttestationBitfield, EnrSyncCommitteeBitfield, GossipEncoding, GossipKind,
};
use crate::{GossipTopic, NetworkConfig};
use libp2p::bandwidth::{BandwidthLogging, BandwidthSinks};
use libp2p::core::{
    identity::Keypair, multiaddr::Multiaddr, muxing::StreamMuxerBox, transport::Boxed,
};
use libp2p::gossipsub::subscription_filter::WhitelistSubscriptionFilter;
use libp2p::gossipsub::IdentTopic as Topic;
use libp2p::{core, noise, PeerId, Transport};
use prometheus_client::registry::Registry;
use slog::{debug, warn};
use ssz::Decode;
use ssz::Encode;
use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use types::{ChainSpec, EnrForkId, EthSpec, ForkContext, SubnetId, SyncSubnetId};

pub const NETWORK_KEY_FILENAME: &str = "key";
/// The maximum simultaneous libp2p connections per peer.
pub const MAX_CONNECTIONS_PER_PEER: u32 = 1;
/// The filename to store our local metadata.
pub const METADATA_FILENAME: &str = "metadata";

pub struct Context<'a> {
    pub config: &'a NetworkConfig,
    pub enr_fork_id: EnrForkId,
    pub fork_context: Arc<ForkContext>,
    pub chain_spec: &'a ChainSpec,
    pub gossipsub_registry: Option<&'a mut Registry>,
}

type BoxedTransport = Boxed<(PeerId, StreamMuxerBox)>;

/// The implementation supports TCP/IP, WebSockets over TCP/IP, noise as the encryption layer, and
/// mplex as the multiplexing layer.
pub fn build_transport(
    local_private_key: Keypair,
) -> std::io::Result<(BoxedTransport, Arc<BandwidthSinks>)> {
    let tcp =
        libp2p::tcp::TokioTcpTransport::new(libp2p::tcp::GenTcpConfig::default().nodelay(true));
    let transport = libp2p::dns::TokioDnsConfig::system(tcp)?;
    #[cfg(feature = "libp2p-websocket")]
    let transport = {
        let trans_clone = transport.clone();
        transport.or_transport(libp2p::websocket::WsConfig::new(trans_clone))
    };

    let (transport, bandwidth) = BandwidthLogging::new(transport);

    // mplex config
    let mut mplex_config = libp2p::mplex::MplexConfig::new();
    mplex_config.set_max_buffer_size(256);
    mplex_config.set_max_buffer_behaviour(libp2p::mplex::MaxBufferBehaviour::Block);

    // yamux config
    let mut yamux_config = libp2p::yamux::YamuxConfig::default();
    yamux_config.set_window_update_mode(libp2p::yamux::WindowUpdateMode::on_read());

    // Authentication
    Ok((
        transport
            .upgrade(core::upgrade::Version::V1)
            .authenticate(generate_noise_config(&local_private_key))
            .multiplex(core::upgrade::SelectUpgrade::new(
                yamux_config,
                mplex_config,
            ))
            .timeout(Duration::from_secs(10))
            .boxed(),
        bandwidth,
    ))
}

// Useful helper functions for debugging. Currently not used in the client.
#[allow(dead_code)]
fn keypair_from_hex(hex_bytes: &str) -> error::Result<Keypair> {
    let hex_bytes = if let Some(stripped) = hex_bytes.strip_prefix("0x") {
        stripped.to_string()
    } else {
        hex_bytes.to_string()
    };

    hex::decode(&hex_bytes)
        .map_err(|e| format!("Failed to parse p2p secret key bytes: {:?}", e).into())
        .and_then(keypair_from_bytes)
}

#[allow(dead_code)]
fn keypair_from_bytes(mut bytes: Vec<u8>) -> error::Result<Keypair> {
    libp2p::core::identity::secp256k1::SecretKey::from_bytes(&mut bytes)
        .map(|secret| {
            let keypair: libp2p::core::identity::secp256k1::Keypair = secret.into();
            Keypair::Secp256k1(keypair)
        })
        .map_err(|e| format!("Unable to parse p2p secret key: {:?}", e).into())
}

/// Loads a private key from disk. If this fails, a new key is
/// generated and is then saved to disk.
///
/// Currently only secp256k1 keys are allowed, as these are the only keys supported by discv5.
pub fn load_private_key(config: &NetworkConfig, log: &slog::Logger) -> Keypair {
    // check for key from disk
    let network_key_f = config.network_dir.join(NETWORK_KEY_FILENAME);
    if let Ok(mut network_key_file) = File::open(network_key_f.clone()) {
        let mut key_bytes: Vec<u8> = Vec::with_capacity(36);
        match network_key_file.read_to_end(&mut key_bytes) {
            Err(_) => debug!(log, "Could not read network key file"),
            Ok(_) => {
                // only accept secp256k1 keys for now
                if let Ok(secret_key) =
                    libp2p::core::identity::secp256k1::SecretKey::from_bytes(&mut key_bytes)
                {
                    let kp: libp2p::core::identity::secp256k1::Keypair = secret_key.into();
                    debug!(log, "Loaded network key from disk.");
                    return Keypair::Secp256k1(kp);
                } else {
                    debug!(log, "Network key file is not a valid secp256k1 key");
                }
            }
        }
    }

    // if a key could not be loaded from disk, generate a new one and save it
    let local_private_key = Keypair::generate_secp256k1();
    if let Keypair::Secp256k1(key) = local_private_key.clone() {
        let _ = std::fs::create_dir_all(&config.network_dir);
        match File::create(network_key_f.clone())
            .and_then(|mut f| f.write_all(&key.secret().to_bytes()))
        {
            Ok(_) => {
                debug!(log, "New network key generated and written to disk");
            }
            Err(e) => {
                warn!(
                    log,
                    "Could not write node key to file: {:?}. error: {}", network_key_f, e
                );
            }
        }
    }
    local_private_key
}

/// Generate authenticated XX Noise config from identity keys
fn generate_noise_config(
    identity_keypair: &Keypair,
) -> noise::NoiseAuthenticated<noise::XX, noise::X25519Spec, ()> {
    let static_dh_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(identity_keypair)
        .expect("signing can fail only once during starting a node");
    noise::NoiseConfig::xx(static_dh_keys).into_authenticated()
}

/// For a multiaddr that ends with a peer id, this strips this suffix. Rust-libp2p
/// only supports dialing to an address without providing the peer id.
pub fn strip_peer_id(addr: &mut Multiaddr) {
    let last = addr.pop();
    match last {
        Some(Protocol::P2p(_)) => {}
        Some(other) => addr.push(other),
        _ => {}
    }
}

/// Load metadata from persisted file. Return default metadata if loading fails.
pub fn load_or_build_metadata<E: EthSpec>(
    network_dir: &std::path::Path,
    log: &slog::Logger,
) -> MetaData<E> {
    // We load a V2 metadata version by default (regardless of current fork)
    // since a V2 metadata can be converted to V1. The RPC encoder is responsible
    // for sending the correct metadata version based on the negotiated protocol version.
    let mut meta_data = MetaDataV2 {
        seq_number: 0,
        attnets: EnrAttestationBitfield::<E>::default(),
        syncnets: EnrSyncCommitteeBitfield::<E>::default(),
    };
    // Read metadata from persisted file if available
    let metadata_path = network_dir.join(METADATA_FILENAME);
    if let Ok(mut metadata_file) = File::open(metadata_path) {
        let mut metadata_ssz = Vec::new();
        if metadata_file.read_to_end(&mut metadata_ssz).is_ok() {
            // Attempt to read a MetaDataV2 version from the persisted file,
            // if that fails, read MetaDataV1
            match MetaDataV2::<E>::from_ssz_bytes(&metadata_ssz) {
                Ok(persisted_metadata) => {
                    meta_data.seq_number = persisted_metadata.seq_number;
                    // Increment seq number if persisted attnet is not default
                    if persisted_metadata.attnets != meta_data.attnets
                        || persisted_metadata.syncnets != meta_data.syncnets
                    {
                        meta_data.seq_number += 1;
                    }
                    debug!(log, "Loaded metadata from disk");
                }
                Err(_) => {
                    match MetaDataV1::<E>::from_ssz_bytes(&metadata_ssz) {
                        Ok(persisted_metadata) => {
                            let persisted_metadata = MetaData::V1(persisted_metadata);
                            // Increment seq number as the persisted metadata version is updated
                            meta_data.seq_number = *persisted_metadata.seq_number() + 1;
                            debug!(log, "Loaded metadata from disk");
                        }
                        Err(e) => {
                            debug!(
                                log,
                                "Metadata from file could not be decoded";
                                "error" => ?e,
                            );
                        }
                    }
                }
            }
        }
    };

    // Wrap the MetaData
    let meta_data = MetaData::V2(meta_data);

    debug!(log, "Metadata sequence number"; "seq_num" => meta_data.seq_number());
    save_metadata_to_disk(network_dir, meta_data.clone(), log);
    meta_data
}

/// Creates a whitelist topic filter that covers all possible topics using the given set of
/// possible fork digests.
pub(crate) fn create_whitelist_filter(
    possible_fork_digests: Vec<[u8; 4]>,
    attestation_subnet_count: u64,
    sync_committee_subnet_count: u64,
) -> WhitelistSubscriptionFilter {
    let mut possible_hashes = HashSet::new();
    for fork_digest in possible_fork_digests {
        let mut add = |kind| {
            let topic: Topic =
                GossipTopic::new(kind, GossipEncoding::SSZSnappy, fork_digest).into();
            possible_hashes.insert(topic.hash());
        };

        use GossipKind::*;
        add(BeaconBlock);
        add(BeaconAggregateAndProof);
        add(VoluntaryExit);
        add(ProposerSlashing);
        add(AttesterSlashing);
        add(SignedContributionAndProof);
        for id in 0..attestation_subnet_count {
            add(Attestation(SubnetId::new(id)));
        }
        for id in 0..sync_committee_subnet_count {
            add(SyncCommitteeMessage(SyncSubnetId::new(id)));
        }
    }
    WhitelistSubscriptionFilter(possible_hashes)
}

/// Persist metadata to disk
pub(crate) fn save_metadata_to_disk<E: EthSpec>(
    dir: &Path,
    metadata: MetaData<E>,
    log: &slog::Logger,
) {
    let _ = std::fs::create_dir_all(&dir);
    match File::create(dir.join(METADATA_FILENAME))
        .and_then(|mut f| f.write_all(&metadata.as_ssz_bytes()))
    {
        Ok(_) => {
            debug!(log, "Metadata written to disk");
        }
        Err(e) => {
            warn!(
                log,
                "Could not write metadata to disk";
                "file" => format!("{:?}{:?}", dir, METADATA_FILENAME),
                "error" => %e
            );
        }
    }
}

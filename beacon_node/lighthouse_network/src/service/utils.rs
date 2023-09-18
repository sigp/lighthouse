use crate::multiaddr::Protocol;
use crate::rpc::{MetaData, MetaDataV1, MetaDataV2};
use crate::types::{
    error, EnrAttestationBitfield, EnrSyncCommitteeBitfield, GossipEncoding, GossipKind,
};
use crate::{GossipTopic, NetworkConfig};
use futures::future::Either;
use libp2p::bandwidth::BandwidthSinks;
use libp2p::core::{multiaddr::Multiaddr, muxing::StreamMuxerBox, transport::Boxed};
use libp2p::gossipsub;
use libp2p::identity::{secp256k1, Keypair};
use libp2p::{core, noise, yamux, PeerId, Transport, TransportExt};
use libp2p_quic;
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

/// The implementation supports TCP/IP, QUIC (experimental) over UDP, noise as the encryption layer, and
/// mplex/yamux as the multiplexing layer (when using TCP).
pub fn build_transport(
    local_private_key: Keypair,
    quic_support: bool,
) -> std::io::Result<(BoxedTransport, Arc<BandwidthSinks>)> {
    // mplex config
    let mut mplex_config = libp2p_mplex::MplexConfig::new();
    mplex_config.set_max_buffer_size(256);
    mplex_config.set_max_buffer_behaviour(libp2p_mplex::MaxBufferBehaviour::Block);

    // yamux config
    let mut yamux_config = yamux::Config::default();
    yamux_config.set_window_update_mode(yamux::WindowUpdateMode::on_read());

    // Creates the TCP transport layer
    let tcp = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true))
        .upgrade(core::upgrade::Version::V1)
        .authenticate(generate_noise_config(&local_private_key))
        .multiplex(core::upgrade::SelectUpgrade::new(
            yamux_config,
            mplex_config,
        ))
        .timeout(Duration::from_secs(10));

    let (transport, bandwidth) = if quic_support {
        // Enables Quic
        // The default quic configuration suits us for now.
        let quic_config = libp2p_quic::Config::new(&local_private_key);
        tcp.or_transport(libp2p_quic::tokio::Transport::new(quic_config))
            .map(|either_output, _| match either_output {
                Either::Left((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
                Either::Right((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
            })
            .with_bandwidth_logging()
    } else {
        tcp.with_bandwidth_logging()
    };

    // // Enables DNS over the transport.
    let transport = libp2p::dns::TokioDnsConfig::system(transport)?.boxed();

    Ok((transport, bandwidth))
}

// Useful helper functions for debugging. Currently not used in the client.
#[allow(dead_code)]
fn keypair_from_hex(hex_bytes: &str) -> error::Result<Keypair> {
    let hex_bytes = if let Some(stripped) = hex_bytes.strip_prefix("0x") {
        stripped.to_string()
    } else {
        hex_bytes.to_string()
    };

    hex::decode(hex_bytes)
        .map_err(|e| format!("Failed to parse p2p secret key bytes: {:?}", e).into())
        .and_then(keypair_from_bytes)
}

#[allow(dead_code)]
fn keypair_from_bytes(mut bytes: Vec<u8>) -> error::Result<Keypair> {
    secp256k1::SecretKey::try_from_bytes(&mut bytes)
        .map(|secret| {
            let keypair: secp256k1::Keypair = secret.into();
            keypair.into()
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
                if let Ok(secret_key) = secp256k1::SecretKey::try_from_bytes(&mut key_bytes) {
                    let kp: secp256k1::Keypair = secret_key.into();
                    debug!(log, "Loaded network key from disk.");
                    return kp.into();
                } else {
                    debug!(log, "Network key file is not a valid secp256k1 key");
                }
            }
        }
    }

    // if a key could not be loaded from disk, generate a new one and save it
    let local_private_key = secp256k1::Keypair::generate();
    let _ = std::fs::create_dir_all(&config.network_dir);
    match File::create(network_key_f.clone())
        .and_then(|mut f| f.write_all(&local_private_key.secret().to_bytes()))
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
    local_private_key.into()
}

/// Generate authenticated XX Noise config from identity keys
fn generate_noise_config(identity_keypair: &Keypair) -> noise::Config {
    noise::Config::new(identity_keypair).expect("signing can fail only once during starting a node")
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
) -> gossipsub::WhitelistSubscriptionFilter {
    let mut possible_hashes = HashSet::new();
    for fork_digest in possible_fork_digests {
        let mut add = |kind| {
            let topic: gossipsub::IdentTopic =
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
        add(BlsToExecutionChange);
        add(LightClientFinalityUpdate);
        add(LightClientOptimisticUpdate);
        for id in 0..attestation_subnet_count {
            add(Attestation(SubnetId::new(id)));
        }
        for id in 0..sync_committee_subnet_count {
            add(SyncCommitteeMessage(SyncSubnetId::new(id)));
        }
    }
    gossipsub::WhitelistSubscriptionFilter(possible_hashes)
}

/// Persist metadata to disk
pub(crate) fn save_metadata_to_disk<E: EthSpec>(
    dir: &Path,
    metadata: MetaData<E>,
    log: &slog::Logger,
) {
    let _ = std::fs::create_dir_all(dir);
    let metadata_bytes = match metadata {
        MetaData::V1(md) => md.as_ssz_bytes(),
        MetaData::V2(md) => md.as_ssz_bytes(),
    };
    match File::create(dir.join(METADATA_FILENAME)).and_then(|mut f| f.write_all(&metadata_bytes)) {
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

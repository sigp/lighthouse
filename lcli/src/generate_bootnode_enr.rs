use clap::ArgMatches;
use lighthouse_network::{
    discovery::{build_enr, CombinedKey, CombinedKeyExt, ENR_FILENAME},
    libp2p::identity::secp256k1,
    NetworkConfig, NETWORK_KEY_FILENAME,
};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::{fs, net::Ipv4Addr};
use types::{ChainSpec, EnrForkId, Epoch, EthSpec, Hash256};

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let ip: Ipv4Addr = clap_utils::parse_required(matches, "ip")?;
    let udp_port: u16 = clap_utils::parse_required(matches, "udp-port")?;
    let tcp_port: u16 = clap_utils::parse_required(matches, "tcp-port")?;
    let output_dir: PathBuf = clap_utils::parse_required(matches, "output-dir")?;
    let genesis_fork_version: [u8; 4] =
        clap_utils::parse_ssz_required(matches, "genesis-fork-version")?;

    if output_dir.exists() {
        return Err(format!(
            "{:?} already exists, will not override",
            output_dir
        ));
    }

    let mut config = NetworkConfig::default();
    config.enr_address = (Some(ip), None);
    config.enr_udp4_port = Some(udp_port);
    config.enr_tcp6_port = Some(tcp_port);

    let secp256k1_keypair = secp256k1::Keypair::generate();
    let enr_key = CombinedKey::from_secp256k1(&secp256k1_keypair);
    let enr_fork_id = EnrForkId {
        fork_digest: ChainSpec::compute_fork_digest(genesis_fork_version, Hash256::zero()),
        next_fork_version: genesis_fork_version,
        next_fork_epoch: Epoch::max_value(), // FAR_FUTURE_EPOCH
    };
    let enr = build_enr::<T>(&enr_key, &config, &enr_fork_id)
        .map_err(|e| format!("Unable to create ENR: {:?}", e))?;

    fs::create_dir_all(&output_dir).map_err(|e| format!("Unable to create output-dir: {:?}", e))?;

    let mut enr_file = File::create(output_dir.join(ENR_FILENAME))
        .map_err(|e| format!("Unable to create {}: {:?}", ENR_FILENAME, e))?;
    enr_file
        .write_all(enr.to_base64().as_bytes())
        .map_err(|e| format!("Unable to write ENR to {}: {:?}", ENR_FILENAME, e))?;

    let mut key_file = File::create(output_dir.join(NETWORK_KEY_FILENAME))
        .map_err(|e| format!("Unable to create {}: {:?}", NETWORK_KEY_FILENAME, e))?;

    let secret_bytes = secp256k1_keypair.secret().to_bytes();
    key_file
        .write_all(&secret_bytes)
        .map_err(|e| format!("Unable to write key to {}: {:?}", NETWORK_KEY_FILENAME, e))?;

    Ok(())
}

use clap::ArgMatches;
use eth2_libp2p::{
    discovery::{build_enr, CombinedKey, CombinedKeyExt, Keypair, ENR_FILENAME},
    NetworkConfig, NETWORK_KEY_FILENAME,
};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use types::{ChainSpec, EnrForkId, Epoch, EthSpec, Hash256};

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let ip: IpAddr = clap_utils::parse_required(matches, "ip")?;
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

    let config = NetworkConfig {
        enr_address: Some(ip),
        enr_udp_port: Some(udp_port),
        enr_tcp_port: Some(tcp_port),
        ..Default::default()
    };

    let local_keypair = Keypair::generate_secp256k1();
    let enr_key = CombinedKey::from_libp2p(&local_keypair)?;
    let enr_fork_id = EnrForkId {
        fork_digest: ChainSpec::compute_fork_digest(genesis_fork_version, Hash256::zero()),
        next_fork_version: genesis_fork_version,
        next_fork_epoch: Epoch::max_value(), // FAR_FUTURE_EPOCH
    };
    let enr = build_enr::<T>(&enr_key, &config, enr_fork_id)
        .map_err(|e| format!("Unable to create ENR: {:?}", e))?;

    fs::create_dir_all(&output_dir).map_err(|e| format!("Unable to create output-dir: {:?}", e))?;

    let mut enr_file = File::create(output_dir.join(ENR_FILENAME))
        .map_err(|e| format!("Unable to create {}: {:?}", ENR_FILENAME, e))?;
    enr_file
        .write_all(enr.to_base64().as_bytes())
        .map_err(|e| format!("Unable to write ENR to {}: {:?}", ENR_FILENAME, e))?;

    let secret_bytes = match local_keypair {
        Keypair::Secp256k1(key) => key.secret().to_bytes(),
        _ => return Err("Key is not a secp256k1 key".into()),
    };

    let mut key_file = File::create(output_dir.join(NETWORK_KEY_FILENAME))
        .map_err(|e| format!("Unable to create {}: {:?}", NETWORK_KEY_FILENAME, e))?;
    key_file
        .write_all(&secret_bytes)
        .map_err(|e| format!("Unable to write key to {}: {:?}", NETWORK_KEY_FILENAME, e))?;

    Ok(())
}

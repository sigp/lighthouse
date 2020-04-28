use clap::ArgMatches;
use eth2_libp2p::{
    discovery::{build_enr, CombinedKey, Keypair, ENR_FILENAME},
    NetworkConfig, NETWORK_KEY_FILENAME,
};
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use types::{EnrForkId, EthSpec};

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let ip: IpAddr = clap_utils::parse_required(matches, "ip")?;
    let udp_port: u16 = clap_utils::parse_required(matches, "udp-port")?;
    let tcp_port: u16 = clap_utils::parse_required(matches, "tcp-port")?;
    let output_dir: PathBuf = clap_utils::parse_required(matches, "output-dir")?;

    if output_dir.exists() {
        return Err(format!(
            "{:?} already exists, will not override",
            output_dir
        ));
    }

    let mut config = NetworkConfig::default();
    config.enr_address = Some(ip);
    config.enr_udp_port = Some(udp_port);
    config.enr_tcp_port = Some(tcp_port);

    let local_keypair = Keypair::generate_secp256k1();
    let enr_key: CombinedKey = local_keypair
        .clone()
        .try_into()
        .map_err(|e| format!("Unable to convert keypair: {:?}", e))?;
    let enr = build_enr::<T>(&enr_key, &config, EnrForkId::default())
        .map_err(|e| format!("Unable to create ENR: {:?}", e))?;

    fs::create_dir_all(&output_dir).map_err(|e| format!("Unable to create output-dir: {:?}", e))?;

    let mut enr_file = File::create(output_dir.join(ENR_FILENAME))
        .map_err(|e| format!("Unable to create {}: {:?}", ENR_FILENAME, e))?;
    enr_file
        .write_all(&enr.to_base64().as_bytes())
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

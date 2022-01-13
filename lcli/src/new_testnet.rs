use crate::generate_bootnode_enr::generate_enr;
use clap::ArgMatches;
use clap_utils::lcli_flags::*;
use clap_utils::{parse_optional, parse_required, parse_ssz_optional};
use eth2_network_config::Eth2NetworkConfig;
use genesis::interop_genesis_state;
use sensitive_url::SensitiveUrl;
use ssz::Decode;
use ssz::Encode;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{
    test_utils::generate_deterministic_keypairs, Address, Config, EthSpec, ExecutionPayloadHeader,
};

pub fn run<T: EthSpec>(testnet_dir_path: PathBuf, matches: &ArgMatches) -> Result<(), String> {
    let deposit_contract_address: Address = parse_required(matches, DEPOSIT_CONTRACT_ADDRESS_FLAG)?;
    let deposit_contract_deploy_block =
        parse_required(matches, DEPOSIT_CONTRACT_DEPLOY_BLOCK_FLAG)?;

    let overwrite_files = matches.is_present("force");

    if testnet_dir_path.exists() && !overwrite_files {
        return Err(format!(
            "{:?} already exists, will not overwrite. Use --force to overwrite",
            testnet_dir_path
        ));
    }

    let mut spec = T::default_spec();

    // Update the spec value if the flag was defined. Otherwise, leave it as the default.
    macro_rules! maybe_update {
        ($flag: tt, $var: ident) => {
            if let Some(val) = parse_optional(matches, $flag)? {
                spec.$var = val
            }
        };
    }

    spec.deposit_contract_address = deposit_contract_address;

    maybe_update!(MIN_GENESIS_TIME_FLAG, min_genesis_time);
    maybe_update!(MIN_DEPOSIT_AMOUNT_FLAG, min_deposit_amount);
    maybe_update!(
        MIN_GENESIS_ACTIVE_VALIDATOR_COUNT_FLAG,
        min_genesis_active_validator_count
    );
    maybe_update!(MAX_EFFECTIVE_BALANCE_FLAG, max_effective_balance);
    maybe_update!(
        EFFECTIVE_BALANCE_INCREMENT_FLAG,
        effective_balance_increment
    );
    maybe_update!(EJECTION_BALANCE_FLAG, ejection_balance);
    maybe_update!(ETH1_FOLLOW_DISTANCE_FLAG, eth1_follow_distance);
    maybe_update!(GENESIS_DELAY_FLAG, genesis_delay);
    maybe_update!(ETH1_ID_FLAG, deposit_chain_id);
    maybe_update!(ETH1_ID_FLAG, deposit_network_id);
    maybe_update!(SECONDS_PER_SLOT_FLAG, seconds_per_slot);
    maybe_update!(SECONDS_PER_ETH1_BLOCK_FLAG, seconds_per_eth1_block);

    if let Some(v) = parse_ssz_optional(matches, GENESIS_FORK_VERSION_FLAG)? {
        spec.genesis_fork_version = v;
    }

    if let Some(fork_epoch) = parse_optional(matches, ALTAIR_FORK_EPOCH_FLAG)? {
        spec.altair_fork_epoch = Some(fork_epoch);
    }

    if let Some(fork_epoch) = parse_optional(matches, MERGE_FORK_EPOCH_FLAG)? {
        spec.merge_fork_epoch = Some(fork_epoch);
    }

    let genesis_state_bytes = if matches.is_present("interop-genesis-state") {
        let execution_payload_header: Option<ExecutionPayloadHeader<T>> =
            parse_optional(matches, EXECUTION_PAYLOAD_HEADER_FLAG)?
                .map(|filename: String| {
                    let mut bytes = vec![];
                    let mut file = File::open(filename.as_str())
                        .map_err(|e| format!("Unable to open {}: {}", filename, e))?;
                    file.read_to_end(&mut bytes)
                        .map_err(|e| format!("Unable to read {}: {}", filename, e))?;
                    ExecutionPayloadHeader::<T>::from_ssz_bytes(bytes.as_slice())
                        .map_err(|e| format!("SSZ decode failed: {:?}", e))
                })
                .transpose()?;

        let (eth1_block_hash, genesis_time) = if let Some(payload) =
            execution_payload_header.as_ref()
        {
            let eth1_block_hash =
                parse_optional(matches, ETH1_BLOCK_HASH_FLAG)?.unwrap_or(payload.block_hash);
            let genesis_time =
                parse_optional(matches, GENESIS_TIME_FLAG)?.unwrap_or(payload.timestamp);
            (eth1_block_hash, genesis_time)
        } else {
            let eth1_block_hash = parse_required(matches, ETH1_BLOCK_HASH_FLAG).map_err(|_| {
                "One of `--execution-payload-header` or `--eth1-block-hash` must be set".to_string()
            })?;
            let genesis_time = parse_optional(matches, GENESIS_TIME_FLAG)?.unwrap_or(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| format!("Unable to get time: {:?}", e))?
                    .as_secs(),
            );
            (eth1_block_hash, genesis_time)
        };

        let validator_count = parse_required(matches, VALIDATOR_COUNT_FLAG)?;

        let keypairs = generate_deterministic_keypairs(validator_count);

        let genesis_state = interop_genesis_state::<T>(
            &keypairs,
            genesis_time,
            eth1_block_hash,
            execution_payload_header,
            &spec,
        )?;

        Some(genesis_state.as_ssz_bytes())
    } else {
        None
    };

    let mut boot_enrs = vec![];

    if let (Some(addr), Some(dir)) = (
        parse_optional::<String>(&matches, BOOT_ADDRESS_FLAG)?,
        parse_optional::<String>(&matches, BOOT_DIR_FLAG)?,
    ) {
        let url = SensitiveUrl::parse(addr.as_str()).unwrap();
        let host_addr = url
            .full
            .host()
            .unwrap()
            .to_string()
            .parse::<IpAddr>()
            .unwrap();
        let port = url.full.port().unwrap();
        let enr = generate_enr::<T>(
            host_addr,
            port,
            port,
            PathBuf::from(dir),
            spec.genesis_fork_version,
        )
        .unwrap();
        boot_enrs.push(enr);
    };

    let testnet = Eth2NetworkConfig {
        deposit_contract_deploy_block,
        boot_enr: Some(boot_enrs),
        genesis_state_bytes,
        config: Config::from_chain_spec::<T>(&spec),
    };

    testnet.write_to_file(testnet_dir_path, overwrite_files)
}

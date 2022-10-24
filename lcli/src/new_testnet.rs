use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required, parse_ssz_optional};
use eth2_network_config::Eth2NetworkConfig;
use genesis::interop_genesis_state;
use ssz::Decode;
use ssz::Encode;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{
    test_utils::generate_deterministic_keypairs, Address, Config, EthSpec, ExecutionPayloadHeader,
    ExecutionPayloadHeaderMerge,
};

pub fn run<T: EthSpec>(testnet_dir_path: PathBuf, matches: &ArgMatches) -> Result<(), String> {
    let deposit_contract_address: Address = parse_required(matches, "deposit-contract-address")?;
    let deposit_contract_deploy_block = parse_required(matches, "deposit-contract-deploy-block")?;

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

    maybe_update!("min-genesis-time", min_genesis_time);
    maybe_update!("min-deposit-amount", min_deposit_amount);
    maybe_update!(
        "min-genesis-active-validator-count",
        min_genesis_active_validator_count
    );
    maybe_update!("max-effective-balance", max_effective_balance);
    maybe_update!("effective-balance-increment", effective_balance_increment);
    maybe_update!("ejection-balance", ejection_balance);
    maybe_update!("eth1-follow-distance", eth1_follow_distance);
    maybe_update!("genesis-delay", genesis_delay);
    maybe_update!("eth1-id", deposit_chain_id);
    maybe_update!("eth1-id", deposit_network_id);
    maybe_update!("seconds-per-slot", seconds_per_slot);
    maybe_update!("seconds-per-eth1-block", seconds_per_eth1_block);

    if let Some(v) = parse_ssz_optional(matches, "genesis-fork-version")? {
        spec.genesis_fork_version = v;
    }

    if let Some(fork_epoch) = parse_optional(matches, "altair-fork-epoch")? {
        spec.altair_fork_epoch = Some(fork_epoch);
    }

    if let Some(fork_epoch) = parse_optional(matches, "merge-fork-epoch")? {
        spec.bellatrix_fork_epoch = Some(fork_epoch);
    }

    let genesis_state_bytes = if matches.is_present("interop-genesis-state") {
        let execution_payload_header: Option<ExecutionPayloadHeader<T>> =
            parse_optional(matches, "execution-payload-header")?
                .map(|filename: String| {
                    let mut bytes = vec![];
                    let mut file = File::open(filename.as_str())
                        .map_err(|e| format!("Unable to open {}: {}", filename, e))?;
                    file.read_to_end(&mut bytes)
                        .map_err(|e| format!("Unable to read {}: {}", filename, e))?;
                    //FIXME(sean)
                    ExecutionPayloadHeaderMerge::<T>::from_ssz_bytes(bytes.as_slice())
                        .map(ExecutionPayloadHeader::Merge)
                        .map_err(|e| format!("SSZ decode failed: {:?}", e))
                })
                .transpose()?;

        let (eth1_block_hash, genesis_time) = if let Some(payload) =
            execution_payload_header.as_ref()
        {
            let eth1_block_hash =
                parse_optional(matches, "eth1-block-hash")?.unwrap_or(payload.block_hash());
            let genesis_time =
                parse_optional(matches, "genesis-time")?.unwrap_or(payload.timestamp());
            (eth1_block_hash, genesis_time)
        } else {
            let eth1_block_hash = parse_required(matches, "eth1-block-hash").map_err(|_| {
                "One of `--execution-payload-header` or `--eth1-block-hash` must be set".to_string()
            })?;
            let genesis_time = parse_optional(matches, "genesis-time")?.unwrap_or(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| format!("Unable to get time: {:?}", e))?
                    .as_secs(),
            );
            (eth1_block_hash, genesis_time)
        };

        let validator_count = parse_required(matches, "validator-count")?;

        let keypairs = generate_deterministic_keypairs(validator_count);

        let genesis_state = interop_genesis_state::<T>(
            &keypairs,
            genesis_time,
            eth1_block_hash.into_root(),
            execution_payload_header,
            &spec,
        )?;

        Some(genesis_state.as_ssz_bytes())
    } else {
        None
    };

    let testnet = Eth2NetworkConfig {
        deposit_contract_deploy_block,
        boot_enr: Some(vec![]),
        genesis_state_bytes,
        config: Config::from_chain_spec::<T>(&spec),
    };

    testnet.write_to_file(testnet_dir_path, overwrite_files)
}

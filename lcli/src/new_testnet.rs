use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required, parse_ssz_optional};
use eth2_hashing::hash;
use eth2_network_config::Eth2NetworkConfig;
use genesis::interop_genesis_state;
use ssz::Decode;
use ssz::Encode;
use state_processing::process_activations;
use state_processing::upgrade::{
    upgrade_to_altair, upgrade_to_bellatrix, upgrade_to_capella, upgrade_to_eip4844,
};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{
    test_utils::generate_deterministic_keypairs, Address, BeaconState, ChainSpec, Config, Eth1Data,
    EthSpec, ExecutionPayloadHeader, ExecutionPayloadHeaderMerge, Hash256, Keypair, PublicKey,
    Validator,
};
use types::{BeaconStateMerge, ExecutionBlockHash};

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

    if let Some(proposer_score_boost) = parse_optional(matches, "proposer-score-boost")? {
        spec.proposer_score_boost = Some(proposer_score_boost);
    }

    if let Some(fork_epoch) = parse_optional(matches, "altair-fork-epoch")? {
        spec.altair_fork_epoch = Some(fork_epoch);
    }

    if let Some(fork_epoch) = parse_optional(matches, "bellatrix-fork-epoch")? {
        spec.bellatrix_fork_epoch = Some(fork_epoch);
    }

    if let Some(fork_epoch) = parse_optional(matches, "capella-fork-epoch")? {
        spec.capella_fork_epoch = Some(fork_epoch);
    }

    if let Some(fork_epoch) = parse_optional(matches, "eip4844-fork-epoch")? {
        spec.eip4844_fork_epoch = Some(fork_epoch);
    }

    if let Some(ttd) = parse_optional(matches, "ttd")? {
        spec.terminal_total_difficulty = ttd;
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
                parse_optional(matches, "eth1-block-hash")?.unwrap_or_else(|| payload.block_hash());
            let genesis_time =
                parse_optional(matches, "genesis-time")?.unwrap_or_else(|| payload.timestamp());
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

        let genesis_state = initialize_state_with_validators::<T>(
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

fn initialize_state_with_validators<T: EthSpec>(
    keypairs: &[Keypair],
    genesis_time: u64,
    eth1_block_hash: Hash256,
    execution_payload_header: Option<ExecutionPayloadHeader<T>>,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, String> {
    let default_header = ExecutionPayloadHeaderMerge {
        gas_limit: 10,
        base_fee_per_gas: 10.into(),
        timestamp: genesis_time,
        block_hash: ExecutionBlockHash(eth1_block_hash),
        prev_randao: Hash256::random(),
        parent_hash: ExecutionBlockHash::zero(),
        transactions_root: Hash256::random(),
        ..ExecutionPayloadHeaderMerge::default()
    };
    let execution_payload_header =
        execution_payload_header.or(Some(ExecutionPayloadHeader::Merge(default_header)));
    // Empty eth1 data
    let eth1_data = Eth1Data {
        block_hash: eth1_block_hash,
        deposit_count: 0,
        deposit_root: Hash256::from_str(
            "0xd70a234731285c6804c2a4f56711ddb8c82c99740f207854891028af34e27e5e",
        )
        .unwrap(), // empty deposit tree root
    };
    let mut state = BeaconState::new(genesis_time, eth1_data, spec);

    // Seed RANDAO with Eth1 entropy
    state.fill_randao_mixes_with(eth1_block_hash);

    for keypair in keypairs.into_iter() {
        let withdrawal_credentials = |pubkey: &PublicKey| {
            let mut credentials = hash(&pubkey.as_ssz_bytes());
            credentials[0] = spec.bls_withdrawal_prefix_byte;
            Hash256::from_slice(&credentials)
        };
        let amount = spec.max_effective_balance;
        // Create a new validator.
        let validator = Validator {
            pubkey: keypair.pk.clone().into(),
            withdrawal_credentials: withdrawal_credentials(&keypair.pk),
            activation_eligibility_epoch: spec.far_future_epoch,
            activation_epoch: spec.far_future_epoch,
            exit_epoch: spec.far_future_epoch,
            withdrawable_epoch: spec.far_future_epoch,
            effective_balance: std::cmp::min(
                amount - amount % (spec.effective_balance_increment),
                spec.max_effective_balance,
            ),
            slashed: false,
        };
        state.validators_mut().push(validator).unwrap();
        state.balances_mut().push(amount).unwrap();
    }

    process_activations(&mut state, spec).unwrap();

    if spec
        .altair_fork_epoch
        .map_or(false, |fork_epoch| fork_epoch == T::genesis_epoch())
    {
        upgrade_to_altair(&mut state, spec).unwrap();

        state.fork_mut().previous_version = spec.altair_fork_version;
    }

    // Similarly, perform an upgrade to the merge if configured from genesis.
    if spec
        .bellatrix_fork_epoch
        .map_or(false, |fork_epoch| fork_epoch == T::genesis_epoch())
    {
        upgrade_to_bellatrix(&mut state, spec).unwrap();

        // Remove intermediate Altair fork from `state.fork`.
        state.fork_mut().previous_version = spec.bellatrix_fork_version;

        // Override latest execution payload header.
        // See https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/merge/beacon-chain.md#testing

        if let Some(ExecutionPayloadHeader::Merge(ref header)) = execution_payload_header {
            *state
                .latest_execution_payload_header_merge_mut()
                .map_err(|_| {
                    "State must contain bellatrix execution payload header".to_string()
                })? = header.clone();
        }
    }

    // Now that we have our validators, initialize the caches (including the committees)
    state.build_all_caches(spec).unwrap();

    // Set genesis validators root for domain separation and chain versioning
    *state.genesis_validators_root_mut() = state.update_validators_tree_hash_cache().unwrap();

    Ok(state)
}

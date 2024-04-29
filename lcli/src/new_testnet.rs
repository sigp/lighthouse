use account_utils::eth2_keystore::keypair_from_secret;
use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required, parse_ssz_optional};
use eth2_network_config::{Eth2NetworkConfig, GenesisStateSource, TRUSTED_SETUP_BYTES};
use eth2_wallet::bip39::Seed;
use eth2_wallet::bip39::{Language, Mnemonic};
use eth2_wallet::{recover_validator_secret_from_mnemonic, KeyType};
use ethereum_hashing::hash;
use ssz::Decode;
use ssz::Encode;
use state_processing::process_activations;
use state_processing::upgrade::{
    upgrade_to_altair, upgrade_to_bellatrix, upgrade_to_capella, upgrade_to_deneb,
    upgrade_to_electra,
};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use types::ExecutionBlockHash;
use types::{
    test_utils::generate_deterministic_keypairs, Address, BeaconState, ChainSpec, Config, Epoch,
    Eth1Data, EthSpec, ExecutionPayloadHeader, ExecutionPayloadHeaderBellatrix,
    ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderDeneb, ExecutionPayloadHeaderElectra,
    ForkName, Hash256, Keypair, PublicKey, Validator,
};

pub fn run<E: EthSpec>(testnet_dir_path: PathBuf, matches: &ArgMatches) -> Result<(), String> {
    let deposit_contract_address: Address = parse_required(matches, "deposit-contract-address")?;
    let deposit_contract_deploy_block = parse_required(matches, "deposit-contract-deploy-block")?;

    let overwrite_files = matches.is_present("force");

    if testnet_dir_path.exists() && !overwrite_files {
        return Err(format!(
            "{:?} already exists, will not overwrite. Use --force to overwrite",
            testnet_dir_path
        ));
    }

    let mut spec = E::default_spec();

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

    if let Some(fork_epoch) = parse_optional(matches, "deneb-fork-epoch")? {
        spec.deneb_fork_epoch = Some(fork_epoch);
    }

    if let Some(fork_epoch) = parse_optional(matches, "electra-fork-epoch")? {
        spec.electra_fork_epoch = Some(fork_epoch);
    }

    if let Some(ttd) = parse_optional(matches, "ttd")? {
        spec.terminal_total_difficulty = ttd;
    }

    let validator_count = parse_required(matches, "validator-count")?;
    let execution_payload_header: Option<ExecutionPayloadHeader<E>> =
        parse_optional(matches, "execution-payload-header")?
            .map(|filename: String| {
                let mut bytes = vec![];
                let mut file = File::open(filename.as_str())
                    .map_err(|e| format!("Unable to open {}: {}", filename, e))?;
                file.read_to_end(&mut bytes)
                    .map_err(|e| format!("Unable to read {}: {}", filename, e))?;
                let fork_name = spec.fork_name_at_epoch(Epoch::new(0));
                match fork_name {
                    ForkName::Base | ForkName::Altair => Err(ssz::DecodeError::BytesInvalid(
                        "genesis fork must be post-merge".to_string(),
                    )),
                    ForkName::Bellatrix => {
                        ExecutionPayloadHeaderBellatrix::<E>::from_ssz_bytes(bytes.as_slice())
                            .map(ExecutionPayloadHeader::Bellatrix)
                    }
                    ForkName::Capella => {
                        ExecutionPayloadHeaderCapella::<E>::from_ssz_bytes(bytes.as_slice())
                            .map(ExecutionPayloadHeader::Capella)
                    }
                    ForkName::Deneb => {
                        ExecutionPayloadHeaderDeneb::<E>::from_ssz_bytes(bytes.as_slice())
                            .map(ExecutionPayloadHeader::Deneb)
                    }
                    ForkName::Electra => {
                        ExecutionPayloadHeaderElectra::<E>::from_ssz_bytes(bytes.as_slice())
                            .map(ExecutionPayloadHeader::Electra)
                    }
                }
                .map_err(|e| format!("SSZ decode failed: {:?}", e))
            })
            .transpose()?;

    let (eth1_block_hash, genesis_time) = if let Some(payload) = execution_payload_header.as_ref() {
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

    let genesis_state_bytes = if matches.is_present("interop-genesis-state") {
        let keypairs = generate_deterministic_keypairs(validator_count);
        let keypairs: Vec<_> = keypairs.into_iter().map(|kp| (kp.clone(), kp)).collect();

        let genesis_state = initialize_state_with_validators::<E>(
            &keypairs,
            genesis_time,
            eth1_block_hash.into_root(),
            execution_payload_header,
            &spec,
        )?;

        Some(genesis_state.as_ssz_bytes())
    } else if matches.is_present("derived-genesis-state") {
        let mnemonic_phrase: String = clap_utils::parse_required(matches, "mnemonic-phrase")?;
        let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase, Language::English).map_err(|e| {
            format!(
                "Unable to derive mnemonic from string {:?}: {:?}",
                mnemonic_phrase, e
            )
        })?;
        let seed = Seed::new(&mnemonic, "");
        let keypairs = (0..validator_count as u32)
            .map(|index| {
                let (secret, _) =
                    recover_validator_secret_from_mnemonic(seed.as_bytes(), index, KeyType::Voting)
                        .unwrap();

                let voting_keypair = keypair_from_secret(secret.as_bytes()).unwrap();

                let (secret, _) = recover_validator_secret_from_mnemonic(
                    seed.as_bytes(),
                    index,
                    KeyType::Withdrawal,
                )
                .unwrap();
                let withdrawal_keypair = keypair_from_secret(secret.as_bytes()).unwrap();
                (voting_keypair, withdrawal_keypair)
            })
            .collect::<Vec<_>>();
        let genesis_state = initialize_state_with_validators::<E>(
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

    let kzg_trusted_setup = if let Some(epoch) = spec.deneb_fork_epoch {
        // Only load the trusted setup if the deneb fork epoch is set
        if epoch != Epoch::max_value() {
            Some(TRUSTED_SETUP_BYTES.to_vec())
        } else {
            None
        }
    } else {
        None
    };
    let testnet = Eth2NetworkConfig {
        deposit_contract_deploy_block,
        boot_enr: Some(vec![]),
        genesis_state_bytes: genesis_state_bytes.map(Into::into),
        genesis_state_source: GenesisStateSource::IncludedBytes,
        config: Config::from_chain_spec::<E>(&spec),
        kzg_trusted_setup,
    };

    testnet.write_to_file(testnet_dir_path, overwrite_files)
}

/// Returns a `BeaconState` with the given validator keypairs embedded into the
/// genesis state. This allows us to start testnets without having to deposit validators
/// manually.
///
/// The optional `execution_payload_header` allows us to start a network from the bellatrix
/// fork without the need to transition to altair and bellatrix.
///
/// We need to ensure that `eth1_block_hash` is equal to the genesis block hash that is
/// generated from the execution side `genesis.json`.
fn initialize_state_with_validators<E: EthSpec>(
    keypairs: &[(Keypair, Keypair)], // Voting and Withdrawal keypairs
    genesis_time: u64,
    eth1_block_hash: Hash256,
    execution_payload_header: Option<ExecutionPayloadHeader<E>>,
    spec: &ChainSpec,
) -> Result<BeaconState<E>, String> {
    // If no header is provided, then start from a Bellatrix state by default
    let default_header: ExecutionPayloadHeader<E> =
        ExecutionPayloadHeader::Bellatrix(ExecutionPayloadHeaderBellatrix {
            block_hash: ExecutionBlockHash::from_root(eth1_block_hash),
            parent_hash: ExecutionBlockHash::zero(),
            ..ExecutionPayloadHeaderBellatrix::default()
        });
    let execution_payload_header = execution_payload_header.unwrap_or(default_header);
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
    state.fill_randao_mixes_with(eth1_block_hash).unwrap();

    for keypair in keypairs.iter() {
        let withdrawal_credentials = |pubkey: &PublicKey| {
            let mut credentials = hash(&pubkey.as_ssz_bytes());
            credentials[0] = spec.bls_withdrawal_prefix_byte;
            Hash256::from_slice(&credentials)
        };
        let amount = spec.max_effective_balance;
        // Create a new validator.
        let validator = Validator {
            pubkey: keypair.0.pk.clone().into(),
            withdrawal_credentials: withdrawal_credentials(&keypair.1.pk),
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
        .map_or(false, |fork_epoch| fork_epoch == E::genesis_epoch())
    {
        upgrade_to_altair(&mut state, spec).unwrap();

        state.fork_mut().previous_version = spec.altair_fork_version;
    }

    // Similarly, perform an upgrade to Bellatrix if configured from genesis.
    if spec
        .bellatrix_fork_epoch
        .map_or(false, |fork_epoch| fork_epoch == E::genesis_epoch())
    {
        upgrade_to_bellatrix(&mut state, spec).unwrap();

        // Remove intermediate Altair fork from `state.fork`.
        state.fork_mut().previous_version = spec.bellatrix_fork_version;

        // Override latest execution payload header.
        // See https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/bellatrix/beacon-chain.md#testing
        if let ExecutionPayloadHeader::Bellatrix(ref header) = execution_payload_header {
            *state
                .latest_execution_payload_header_bellatrix_mut()
                .or(Err("mismatched fork".to_string()))? = header.clone();
        }
    }

    // Similarly, perform an upgrade to Capella if configured from genesis.
    if spec
        .capella_fork_epoch
        .map_or(false, |fork_epoch| fork_epoch == E::genesis_epoch())
    {
        upgrade_to_capella(&mut state, spec).unwrap();

        // Remove intermediate Bellatrix fork from `state.fork`.
        state.fork_mut().previous_version = spec.capella_fork_version;

        // Override latest execution payload header.
        // See https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/bellatrix/beacon-chain.md#testing
        if let ExecutionPayloadHeader::Capella(ref header) = execution_payload_header {
            *state
                .latest_execution_payload_header_capella_mut()
                .or(Err("mismatched fork".to_string()))? = header.clone();
        }
    }

    // Similarly, perform an upgrade to Deneb if configured from genesis.
    if spec
        .deneb_fork_epoch
        .map_or(false, |fork_epoch| fork_epoch == E::genesis_epoch())
    {
        upgrade_to_deneb(&mut state, spec).unwrap();

        // Remove intermediate Capella fork from `state.fork`.
        state.fork_mut().previous_version = spec.deneb_fork_version;

        // Override latest execution payload header.
        // See https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/bellatrix/beacon-chain.md#testing
        if let ExecutionPayloadHeader::Deneb(ref header) = execution_payload_header {
            *state
                .latest_execution_payload_header_deneb_mut()
                .or(Err("mismatched fork".to_string()))? = header.clone();
        }
    }

    // Similarly, perform an upgrade to Electra if configured from genesis.
    if spec
        .electra_fork_epoch
        .map_or(false, |fork_epoch| fork_epoch == E::genesis_epoch())
    {
        upgrade_to_electra(&mut state, spec).unwrap();

        // Remove intermediate Deneb fork from `state.fork`.
        state.fork_mut().previous_version = spec.electra_fork_version;

        // Override latest execution payload header.
        // See https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/bellatrix/beacon-chain.md#testing
        if let ExecutionPayloadHeader::Electra(ref header) = execution_payload_header {
            *state
                .latest_execution_payload_header_electra_mut()
                .or(Err("mismatched fork".to_string()))? = header.clone();
        }
    }

    // Now that we have our validators, initialize the caches (including the committees)
    state.build_caches(spec).unwrap();

    // Set genesis validators root for domain separation and chain versioning
    *state.genesis_validators_root_mut() = state.update_validators_tree_hash_cache().unwrap();

    // Sanity check for state fork matching config fork.
    state
        .fork_name(spec)
        .map_err(|e| format!("state fork mismatch: {e:?}"))?;

    Ok(state)
}

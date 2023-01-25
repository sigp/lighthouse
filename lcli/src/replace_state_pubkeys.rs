use account_utils::{eth2_keystore::keypair_from_secret, mnemonic_from_phrase};
use clap::ArgMatches;
use eth2_network_config::Eth2NetworkConfig;
use eth2_wallet::bip39::Seed;
use eth2_wallet::{recover_validator_secret_from_mnemonic, KeyType};
use ssz::Encode;
use state_processing::common::DepositDataTree;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use tree_hash::TreeHash;
use types::{BeaconState, DepositData, EthSpec, Hash256, SignatureBytes, DEPOSIT_TREE_DEPTH};

pub fn run<T: EthSpec>(testnet_dir: PathBuf, matches: &ArgMatches) -> Result<(), String> {
    let path = matches
        .value_of("ssz-state")
        .ok_or("ssz-state not specified")?
        .parse::<PathBuf>()
        .map_err(|e| format!("Unable to parse ssz-state: {}", e))?;

    let mnemonic_phrase = matches
        .value_of("mnemonic")
        .ok_or("mnemonic not specified")?;

    let eth2_network_config = Eth2NetworkConfig::load(testnet_dir)?;
    let spec = &eth2_network_config.chain_spec::<T>()?;

    let mut state: BeaconState<T> = {
        let mut file = File::open(&path).map_err(|e| format!("Unable to open file: {}", e))?;

        let mut ssz = vec![];

        file.read_to_end(&mut ssz)
            .map_err(|e| format!("Unable to read file: {}", e))?;

        BeaconState::from_ssz_bytes(&ssz, spec)
            .map_err(|e| format!("Unable to decode SSZ: {:?}", e))?
    };

    let mnemonic = mnemonic_from_phrase(mnemonic_phrase)?;
    let seed = Seed::new(&mnemonic, "");

    let mut deposit_tree = DepositDataTree::create(&[], 0, DEPOSIT_TREE_DEPTH);
    let mut deposit_root = Hash256::zero();
    for (index, validator) in state.validators_mut().iter_mut().enumerate() {
        let (secret, _) =
            recover_validator_secret_from_mnemonic(seed.as_bytes(), index as u32, KeyType::Voting)
                .map_err(|e| format!("Unable to generate validator key: {:?}", e))?;

        let keypair = keypair_from_secret(secret.as_bytes())
            .map_err(|e| format!("Unable build keystore: {:?}", e))?;

        eprintln!("{}: {}", index, keypair.pk);

        validator.pubkey = keypair.pk.into();

        // Update the deposit tree.
        let mut deposit_data = DepositData {
            pubkey: validator.pubkey,
            // Set this to a junk value since it's very time consuming to generate the withdrawal
            // keys and it's not useful for the time being.
            withdrawal_credentials: Hash256::zero(),
            amount: spec.min_deposit_amount,
            signature: SignatureBytes::empty(),
        };
        deposit_data.signature = deposit_data.create_signature(&keypair.sk, spec);
        deposit_tree
            .push_leaf(deposit_data.tree_hash_root())
            .map_err(|e| format!("failed to create deposit tree: {:?}", e))?;
        deposit_root = deposit_tree.root();
    }

    // Update the genesis validators root since we changed the validators.
    *state.genesis_validators_root_mut() = state.validators().tree_hash_root();

    // Update the deposit root with our simulated deposits.
    state.eth1_data_mut().deposit_root = deposit_root;

    let mut file = File::create(path).map_err(|e| format!("Unable to create file: {}", e))?;

    file.write_all(&state.as_ssz_bytes())
        .map_err(|e| format!("Unable to write to file: {}", e))?;

    Ok(())
}

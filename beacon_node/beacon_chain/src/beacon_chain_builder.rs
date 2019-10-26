use crate::{BeaconChain, BeaconChainTypes};
use eth2_hashing::hash;
use lighthouse_bootstrap::Bootstrapper;
use merkle_proof::MerkleTree;
use rayon::prelude::*;
use slog::Logger;
use ssz::{Decode, Encode};
use state_processing::initialize_beacon_state_from_eth1;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tree_hash::{SignedRoot, TreeHash};
use types::{
    BeaconBlock, BeaconState, ChainSpec, Deposit, DepositData, Domain, EthSpec, Fork, Hash256,
    Keypair, PublicKey, Signature,
};

enum BuildStrategy<T: BeaconChainTypes> {
    FromGenesis {
        genesis_state: Box<BeaconState<T::EthSpec>>,
        genesis_block: Box<BeaconBlock<T::EthSpec>>,
    },
    LoadFromStore,
}

pub struct BeaconChainBuilder<T: BeaconChainTypes> {
    build_strategy: BuildStrategy<T>,
    spec: ChainSpec,
    log: Logger,
}

impl<T: BeaconChainTypes> BeaconChainBuilder<T> {
    pub fn recent_genesis(
        keypairs: &[Keypair],
        minutes: u64,
        spec: ChainSpec,
        log: Logger,
    ) -> Result<Self, String> {
        Self::quick_start(recent_genesis_time(minutes), keypairs, spec, log)
    }

    pub fn quick_start(
        genesis_time: u64,
        keypairs: &[Keypair],
        spec: ChainSpec,
        log: Logger,
    ) -> Result<Self, String> {
        let genesis_state = interop_genesis_state(keypairs, genesis_time, &spec)?;

        Ok(Self::from_genesis_state(genesis_state, spec, log))
    }

    pub fn yaml_state(file: &PathBuf, spec: ChainSpec, log: Logger) -> Result<Self, String> {
        let file = File::open(file.clone())
            .map_err(|e| format!("Unable to open YAML genesis state file {:?}: {:?}", file, e))?;

        let genesis_state = serde_yaml::from_reader(file)
            .map_err(|e| format!("Unable to parse YAML genesis state file: {:?}", e))?;

        Ok(Self::from_genesis_state(genesis_state, spec, log))
    }

    pub fn ssz_state(file: &PathBuf, spec: ChainSpec, log: Logger) -> Result<Self, String> {
        let mut file = File::open(file.clone())
            .map_err(|e| format!("Unable to open SSZ genesis state file {:?}: {:?}", file, e))?;

        let mut bytes = vec![];
        file.read_to_end(&mut bytes)
            .map_err(|e| format!("Failed to read SSZ file: {:?}", e))?;

        let genesis_state = BeaconState::from_ssz_bytes(&bytes)
            .map_err(|e| format!("Unable to parse SSZ genesis state file: {:?}", e))?;

        Ok(Self::from_genesis_state(genesis_state, spec, log))
    }

    pub fn json_state(file: &PathBuf, spec: ChainSpec, log: Logger) -> Result<Self, String> {
        let file = File::open(file.clone())
            .map_err(|e| format!("Unable to open JSON genesis state file {:?}: {:?}", file, e))?;

        let genesis_state = serde_json::from_reader(file)
            .map_err(|e| format!("Unable to parse JSON genesis state file: {:?}", e))?;

        Ok(Self::from_genesis_state(genesis_state, spec, log))
    }

    pub fn http_bootstrap(server: &str, spec: ChainSpec, log: Logger) -> Result<Self, String> {
        let bootstrapper = Bootstrapper::connect(server.to_string(), &log)
            .map_err(|e| format!("Failed to initialize bootstrap client: {}", e))?;

        let (genesis_state, genesis_block) = bootstrapper
            .genesis()
            .map_err(|e| format!("Failed to bootstrap genesis state: {}", e))?;

        Ok(Self {
            build_strategy: BuildStrategy::FromGenesis {
                genesis_block: Box::new(genesis_block),
                genesis_state: Box::new(genesis_state),
            },
            spec,
            log,
        })
    }

    fn from_genesis_state(
        genesis_state: BeaconState<T::EthSpec>,
        spec: ChainSpec,
        log: Logger,
    ) -> Self {
        Self {
            build_strategy: BuildStrategy::FromGenesis {
                genesis_block: Box::new(genesis_block(&genesis_state, &spec)),
                genesis_state: Box::new(genesis_state),
            },
            spec,
            log,
        }
    }

    pub fn from_store(spec: ChainSpec, log: Logger) -> Self {
        Self {
            build_strategy: BuildStrategy::LoadFromStore,
            spec,
            log,
        }
    }

    pub fn build(
        self,
        store: Arc<T::Store>,
        eth1_backend: T::Eth1Chain,
        event_handler: T::EventHandler,
    ) -> Result<BeaconChain<T>, String> {
        Ok(match self.build_strategy {
            BuildStrategy::LoadFromStore => {
                BeaconChain::from_store(store, eth1_backend, event_handler, self.spec, self.log)
                    .map_err(|e| format!("Error loading BeaconChain from database: {:?}", e))?
                    .ok_or_else(|| "Unable to find exising BeaconChain in database.".to_string())?
            }
            BuildStrategy::FromGenesis {
                genesis_block,
                genesis_state,
            } => BeaconChain::from_genesis(
                store,
                eth1_backend,
                event_handler,
                genesis_state.as_ref().clone(),
                genesis_block.as_ref().clone(),
                self.spec,
                self.log,
            )
            .map_err(|e| format!("Failed to initialize new beacon chain: {:?}", e))?,
        })
    }
}

fn genesis_block<T: EthSpec>(genesis_state: &BeaconState<T>, spec: &ChainSpec) -> BeaconBlock<T> {
    let mut genesis_block = BeaconBlock::empty(&spec);

    genesis_block.state_root = genesis_state.canonical_root();

    genesis_block
}

/// Builds a genesis state as defined by the Eth2 interop procedure (see below).
///
/// Reference:
/// https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start
fn interop_genesis_state<T: EthSpec>(
    keypairs: &[Keypair],
    genesis_time: u64,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, String> {
    let eth1_block_hash = Hash256::from_slice(&[0x42; 32]);
    let eth1_timestamp = 2_u64.pow(40);
    let amount = spec.max_effective_balance;

    let withdrawal_credentials = |pubkey: &PublicKey| {
        let mut credentials = hash(&pubkey.as_ssz_bytes());
        credentials[0] = spec.bls_withdrawal_prefix_byte;
        Hash256::from_slice(&credentials)
    };

    let datas = keypairs
        .into_par_iter()
        .map(|keypair| {
            let mut data = DepositData {
                withdrawal_credentials: withdrawal_credentials(&keypair.pk),
                pubkey: keypair.pk.clone().into(),
                amount,
                signature: Signature::empty_signature().into(),
            };

            let domain = spec.get_domain(
                spec.genesis_slot.epoch(T::slots_per_epoch()),
                Domain::Deposit,
                &Fork::default(),
            );
            data.signature = Signature::new(&data.signed_root()[..], domain, &keypair.sk).into();

            data
        })
        .collect::<Vec<_>>();

    let deposit_root_leaves = datas
        .par_iter()
        .map(|data| Hash256::from_slice(&data.tree_hash_root()))
        .collect::<Vec<_>>();

    let mut proofs = vec![];
    for i in 1..=deposit_root_leaves.len() {
        // Note: this implementation is not so efficient.
        //
        // If `MerkleTree` had a push method, we could just build one tree and sample it instead of
        // rebuilding the tree for each deposit.
        let tree = MerkleTree::create(
            &deposit_root_leaves[0..i],
            spec.deposit_contract_tree_depth as usize,
        );

        let (_, mut proof) = tree.generate_proof(i - 1, spec.deposit_contract_tree_depth as usize);
        proof.push(Hash256::from_slice(&int_to_bytes32(i)));

        assert_eq!(
            proof.len(),
            spec.deposit_contract_tree_depth as usize + 1,
            "Deposit proof should be correct len"
        );

        proofs.push(proof);
    }

    let deposits = datas
        .into_par_iter()
        .zip(proofs.into_par_iter())
        .map(|(data, proof)| (data, proof.into()))
        .map(|(data, proof)| Deposit { proof, data })
        .collect::<Vec<_>>();

    let mut state =
        initialize_beacon_state_from_eth1(eth1_block_hash, eth1_timestamp, deposits, spec)
            .map_err(|e| format!("Unable to initialize genesis state: {:?}", e))?;

    state.genesis_time = genesis_time;

    // Invalid all the caches after all the manual state surgery.
    state.drop_all_caches();

    Ok(state)
}

/// Returns `int` as little-endian bytes with a length of 32.
fn int_to_bytes32(int: usize) -> Vec<u8> {
    let mut vec = int.to_le_bytes().to_vec();
    vec.resize(32, 0);
    vec
}

/// Returns the system time, mod 30 minutes.
///
/// Used for easily creating testnets.
fn recent_genesis_time(minutes: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secs_after_last_period = now.checked_rem(minutes * 60).unwrap_or(0);
    now - secs_after_last_period
}

#[cfg(test)]
mod test {
    use super::*;
    use types::{test_utils::generate_deterministic_keypairs, EthSpec, MinimalEthSpec};

    type TestEthSpec = MinimalEthSpec;

    #[test]
    fn interop_state() {
        let validator_count = 16;
        let genesis_time = 42;
        let spec = &TestEthSpec::default_spec();

        let keypairs = generate_deterministic_keypairs(validator_count);

        let state = interop_genesis_state::<TestEthSpec>(&keypairs, genesis_time, spec)
            .expect("should build state");

        assert_eq!(
            state.eth1_data.block_hash,
            Hash256::from_slice(&[0x42; 32]),
            "eth1 block hash should be co-ordinated junk"
        );

        assert_eq!(
            state.genesis_time, genesis_time,
            "genesis time should be as specified"
        );

        for b in &state.balances {
            assert_eq!(
                *b, spec.max_effective_balance,
                "validator balances should be max effective balance"
            );
        }

        for v in &state.validators {
            let creds = v.withdrawal_credentials.as_bytes();
            assert_eq!(
                creds[0], spec.bls_withdrawal_prefix_byte,
                "first byte of withdrawal creds should be bls prefix"
            );
            assert_eq!(
                &creds[1..],
                &hash(&v.pubkey.as_ssz_bytes())[1..],
                "rest of withdrawal creds should be pubkey hash"
            )
        }

        assert_eq!(
            state.balances.len(),
            validator_count,
            "validator balances len should be correct"
        );

        assert_eq!(
            state.validators.len(),
            validator_count,
            "validator count should be correct"
        );
    }
}

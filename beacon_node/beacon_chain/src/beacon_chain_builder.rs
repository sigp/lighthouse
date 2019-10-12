use crate::persisted_beacon_chain::{PersistedBeaconChain, BEACON_CHAIN_DB_KEY};
use crate::{
    BeaconChain, BeaconChainTypes, CheckPoint, Eth1Chain, Eth1ChainBackend, EventHandler,
    ForkChoice,
};
use eth2_hashing::hash;
use lighthouse_bootstrap::Bootstrapper;
use lmd_ghost::{LmdGhost, ThreadSafeReducedTree};
use merkle_proof::MerkleTree;
use operation_pool::OperationPool;
use rayon::prelude::*;
use slog::Logger;
use ssz::{Decode, Encode};
use state_processing::initialize_beacon_state_from_eth1;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use store::Store;
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
    store: Option<Arc<T::Store>>,
    pub finalized_checkpoint: Option<CheckPoint<T::EthSpec>>,
    genesis_block_root: Option<Hash256>,
    op_pool: Option<OperationPool<T::EthSpec>>,
    fork_choice: Option<ForkChoice<T>>,
    eth1_chain: Option<Eth1Chain<T>>,
    event_handler: Option<T::EventHandler>,
    slot_clock: Option<T::SlotClock>,
    spec: ChainSpec,
    log: Option<Logger>,
}

impl<T: BeaconChainTypes> BeaconChainBuilder<T> {
    pub fn new(_spec_type: T::EthSpec) -> Self {
        Self {
            store: None,
            finalized_checkpoint: None,
            genesis_block_root: None,
            op_pool: None,
            fork_choice: None,
            eth1_chain: None,
            event_handler: None,
            slot_clock: None,
            spec: T::EthSpec::default_spec(),
            log: None,
        }
    }

    pub fn custom_spec(&mut self, spec: ChainSpec) -> &mut Self {
        self.spec = spec;
        self
    }

    pub fn store(&mut self, store: Arc<T::Store>) -> &mut Self {
        self.store = Some(store);
        self
    }

    pub fn logger(&mut self, logger: Logger) -> &mut Self {
        self.log = Some(logger);
        self
    }

    fn set_finalized_checkpoint(
        &mut self,
        beacon_state: BeaconState<T::EthSpec>,
        beacon_block: BeaconBlock<T::EthSpec>,
    ) {
        self.finalized_checkpoint = Some(CheckPoint {
            beacon_block_root: beacon_block.canonical_root(),
            beacon_block,
            beacon_state_root: beacon_state.canonical_root(),
            beacon_state,
        })
    }

    pub fn recent_genesis_state(
        &mut self,
        keypairs: &[Keypair],
        minutes: u64,
    ) -> Result<&mut Self, String> {
        self.quick_start_genesis_state(recent_genesis_time(minutes), keypairs)
    }

    pub fn quick_start_genesis_state(
        &mut self,
        genesis_time: u64,
        keypairs: &[Keypair],
    ) -> Result<&mut Self, String> {
        let genesis_state = interop_genesis_state(keypairs, genesis_time, &self.spec)?;
        let genesis_block = genesis_block(&genesis_state, &self.spec);

        self.set_finalized_checkpoint(genesis_state, genesis_block);
        self.genesis_block_root = Some(
            self.finalized_checkpoint
                .clone()
                .map(|c| c.beacon_block_root)
                .ok_or_else(|| "must have finalized checkpoint".to_string())?,
        );

        Ok(self)
    }

    pub fn yaml_state(&mut self, file: &PathBuf) -> Result<&mut Self, String> {
        let file = File::open(file.clone())
            .map_err(|e| format!("Unable to open YAML genesis state file {:?}: {:?}", file, e))?;

        let genesis_state = serde_yaml::from_reader(file)
            .map_err(|e| format!("Unable to parse YAML genesis state file: {:?}", e))?;
        let genesis_block = genesis_block(&genesis_state, &self.spec);

        self.set_finalized_checkpoint(genesis_state, genesis_block);
        self.genesis_block_root = Some(
            self.finalized_checkpoint
                .clone()
                .map(|c| c.beacon_block_root)
                .ok_or_else(|| "must have finalized checkpoint".to_string())?,
        );

        Ok(self)
    }

    pub fn ssz_state(&mut self, file: &PathBuf) -> Result<&mut Self, String> {
        let mut file = File::open(file.clone())
            .map_err(|e| format!("Unable to open SSZ genesis state file {:?}: {:?}", file, e))?;

        let mut bytes = vec![];
        file.read_to_end(&mut bytes)
            .map_err(|e| format!("Failed to read SSZ file: {:?}", e))?;

        let genesis_state = BeaconState::from_ssz_bytes(&bytes)
            .map_err(|e| format!("Unable to parse SSZ genesis state file: {:?}", e))?;
        let genesis_block = genesis_block(&genesis_state, &self.spec);

        self.set_finalized_checkpoint(genesis_state, genesis_block);
        self.genesis_block_root = Some(
            self.finalized_checkpoint
                .clone()
                .map(|c| c.beacon_block_root)
                .ok_or_else(|| "must have finalized checkpoint".to_string())?,
        );

        Ok(self)
    }

    pub fn json_state(&mut self, file: &PathBuf) -> Result<&mut Self, String> {
        let file = File::open(file.clone())
            .map_err(|e| format!("Unable to open JSON genesis state file {:?}: {:?}", file, e))?;

        let genesis_state = serde_json::from_reader(file)
            .map_err(|e| format!("Unable to parse JSON genesis state file: {:?}", e))?;
        let genesis_block = genesis_block(&genesis_state, &self.spec);

        self.set_finalized_checkpoint(genesis_state, genesis_block);
        self.genesis_block_root = Some(
            self.finalized_checkpoint
                .clone()
                .map(|c| c.beacon_block_root)
                .ok_or_else(|| "must have finalized checkpoint".to_string())?,
        );

        Ok(self)
    }

    pub fn http_bootstrap_state(&mut self, server: &str) -> Result<&mut Self, String> {
        let log = self
            .log
            .clone()
            .ok_or_else(|| "http_bootstrap requires a logger".to_string())?;

        let bootstrapper = Bootstrapper::connect(server.to_string(), &log)
            .map_err(|e| format!("Failed to initialize bootstrap client: {}", e))?;

        let (genesis_state, genesis_block) = bootstrapper
            .genesis()
            .map_err(|e| format!("Failed to bootstrap genesis state: {}", e))?;

        self.set_finalized_checkpoint(genesis_state, genesis_block);
        self.genesis_block_root = Some(
            self.finalized_checkpoint
                .clone()
                .map(|c| c.beacon_block_root)
                .ok_or_else(|| "must have finalized checkpoint".to_string())?,
        );

        Ok(self)
    }

    pub fn load_from_store(&mut self) -> Result<&mut Self, String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| "load_from_store requires a store.".to_string())?;

        let key = Hash256::from_slice(&BEACON_CHAIN_DB_KEY.as_bytes());
        let p: PersistedBeaconChain<T> = match store.get(&key) {
            Err(e) => {
                return Err(format!(
                    "DB error when reading persisted beacon chain: {:?}",
                    e
                ))
            }
            Ok(None) => return Err("No persisted beacon chain found in store".into()),
            Ok(Some(p)) => p,
        };

        self.op_pool = Some(
            p.op_pool
                .into_operation_pool(&p.canonical_head.beacon_state, &self.spec),
        );

        self.finalized_checkpoint = Some(p.canonical_head);
        self.genesis_block_root = Some(p.genesis_block_root);

        Ok(self)
    }

    pub fn fork_choice_backend(&mut self, backend: T::LmdGhost) -> Result<&mut Self, String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| "reduced_tree_fork_choice requires a store")?;
        let genesis_block_root = self
            .genesis_block_root
            .ok_or_else(|| "fork_choice_backend requires a genesis_block_root")?;

        self.fork_choice = Some(ForkChoice::new(store, backend, genesis_block_root));

        Ok(self)
    }

    pub fn eth1_backend(&mut self, backend: T::Eth1Chain) -> &mut Self {
        self.eth1_chain = Some(Eth1Chain::new(backend));
        self
    }

    pub fn event_handler(&mut self, handler: T::EventHandler) -> &mut Self {
        self.event_handler = Some(handler);
        self
    }

    pub fn slot_clock(&mut self, clock: T::SlotClock) -> &mut Self {
        self.slot_clock = Some(clock);
        self
    }

    pub fn build(self) -> Result<BeaconChain<T>, String> {
        panic!()
        /*
        Ok(match self.build_strategy {
            BuildStrategy::LoadFromStore => BeaconChain::from_store(
                store,
                eth1_backend,
                fork_choice_backend,
                event_handler,
                self.spec,
                self.log,
            )
            .map_err(|e| format!("Error loading BeaconChain from database: {:?}", e))?
            .ok_or_else(|| "Unable to find exising BeaconChain in database.".to_string())?,
            BuildStrategy::FromGenesis {
                genesis_block,
                genesis_state,
            } => BeaconChain::from_genesis(
                store,
                eth1_backend,
                fork_choice_backend,
                event_handler,
                genesis_state.as_ref().clone(),
                genesis_block.as_ref().clone(),
                self.spec,
                self.log,
            )
            .map_err(|e| format!("Failed to initialize new beacon chain: {:?}", e))?,
        })
        */
    }
}

/*
impl<T, S, E> BeaconChainBuilder<T>
where
    S: Store,
    E: EthSpec,
    T: BeaconChainTypes<LmdGhost = ThreadSafeReducedTree<S, E>, Store = S, EthSpec = E>,
{
    pub fn reduced_tree_fork_choice(&mut self) -> Result<&mut Self, String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| "reduced_tree_fork_choice requires a store")?;
        let finalized_checkpoint = &self
            .finalized_checkpoint
            .ok_or_else(|| "reduced_tree_fork_choice requires a finalized checkpoint")?;

        let backend = ThreadSafeReducedTree::new(
            store.clone(),
            &finalized_checkpoint.beacon_block,
            finalized_checkpoint.beacon_block_root,
        );

        let genesis_block_root = self
            .genesis_block_root
            .ok_or_else(|| "fork_choice_backend requires a genesis_block_root")?;

        self.fork_choice = Some(ForkChoice::new(store, backend, genesis_block_root));

        Ok(self)
    }
}
*/

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
    use crate::events::NullEventHandler;
    use crate::InteropEth1ChainBackend;
    use sloggers::{null::NullLoggerBuilder, Build};
    use slot_clock::{SlotClock, TestingSlotClock};
    use std::time::Duration;
    use store::MemoryStore;
    use types::{test_utils::generate_deterministic_keypairs, EthSpec, MinimalEthSpec, Slot};

    type TestEthSpec = MinimalEthSpec;

    fn get_logger() -> Logger {
        let builder = NullLoggerBuilder;
        builder.build().expect("should build logger")
    }

    #[test]
    fn recent_genesis() {
        let validator_count = 16;

        let log = get_logger();
        let store = Arc::new(MemoryStore::open());
        let keypairs = generate_deterministic_keypairs(validator_count);

        /*
            BeaconChainTypes<
                Store = MemoryStore,
                SlotClock = TestingSlotClock,
                LmdGhost = ThreadSafeReducedTree<MemoryStore, TestEthSpec>,
                EthSpec = TestEthSpec,
                EventHandler = NullEventHandler<MinimalEthSpec>,
                Eth1Chain = InteropEth1ChainBackend<MinimalEthSpec>,
            >,
        */

        let builder = BeaconChainBuilder::new(MinimalEthSpec)
            .logger(log.clone())
            .store(store.clone())
            .recent_genesis_state(&keypairs, 0)
            .expect("should build state using recent genesis")
            .eth1_backend(InteropEth1ChainBackend::default())
            .event_handler(NullEventHandler::default())
            .slot_clock(TestingSlotClock::new(
                Slot::new(0),
                Duration::from_secs(1),
                Duration::from_secs(1),
            ));

        let finalized_checkpoint = &builder
            .finalized_checkpoint
            .expect("should have finalized checkpoint");
        let reduced_tree = ThreadSafeReducedTree::new(
            store.clone(),
            &finalized_checkpoint.beacon_block,
            finalized_checkpoint.beacon_block_root,
        );

        builder.fork_choice_backend(reduced_tree);
    }

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

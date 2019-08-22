use crate::bootstrapper::Bootstrapper;
use crate::error::Result;
use crate::{config::GenesisState, ClientConfig};
use beacon_chain::{
    lmd_ghost::{LmdGhost, ThreadSafeReducedTree},
    slot_clock::SystemTimeSlotClock,
    store::Store,
    BeaconChain, BeaconChainTypes,
};
use slog::{crit, info, Logger};
use slot_clock::SlotClock;
use std::fs::File;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::SystemTime;
use tree_hash::TreeHash;
use types::{
    test_utils::TestingBeaconStateBuilder, BeaconBlock, BeaconState, ChainSpec, EthSpec, Hash256,
};

/// Provides a new, initialized `BeaconChain`
pub trait InitialiseBeaconChain<T: BeaconChainTypes> {
    fn initialise_beacon_chain(
        store: Arc<T::Store>,
        config: &ClientConfig,
        spec: ChainSpec,
        log: Logger,
    ) -> Result<BeaconChain<T>> {
        maybe_load_from_store_for_testnet::<_, T::Store, T::EthSpec>(store, config, spec, log)
    }
}

#[derive(Clone)]
pub struct ClientType<S: Store, E: EthSpec> {
    _phantom_t: PhantomData<S>,
    _phantom_u: PhantomData<E>,
}

impl<S, E> BeaconChainTypes for ClientType<S, E>
where
    S: Store + 'static,
    E: EthSpec + 'static + Clone,
{
    type Store = S;
    type SlotClock = SystemTimeSlotClock;
    type LmdGhost = ThreadSafeReducedTree<S, E>;
    type EthSpec = E;
}
impl<T: Store, E: EthSpec, X: BeaconChainTypes> InitialiseBeaconChain<X> for ClientType<T, E> {}

/// Loads a `BeaconChain` from `store`, if it exists. Otherwise, create a new chain from genesis.
fn maybe_load_from_store_for_testnet<T, U: Store, V: EthSpec>(
    store: Arc<U>,
    config: &ClientConfig,
    spec: ChainSpec,
    log: Logger,
) -> Result<BeaconChain<T>>
where
    T: BeaconChainTypes<Store = U, EthSpec = V>,
    T::LmdGhost: LmdGhost<U, V>,
{
    let genesis_state = match &config.genesis_state {
        GenesisState::Mainnet => {
            crit!(log, "This release does not support mainnet genesis state.");
            return Err("Mainnet is unsupported".into());
        }
        GenesisState::RecentGenesis { validator_count } => {
            generate_testnet_genesis_state(*validator_count, recent_genesis_time(), &spec)
        }
        GenesisState::Generated {
            validator_count,
            genesis_time,
        } => generate_testnet_genesis_state(*validator_count, *genesis_time, &spec),
        GenesisState::Yaml { file } => {
            let file = File::open(file).map_err(|e| {
                format!("Unable to open YAML genesis state file {:?}: {:?}", file, e)
            })?;

            serde_yaml::from_reader(file)
                .map_err(|e| format!("Unable to parse YAML genesis state file: {:?}", e))?
        }
        GenesisState::HttpBootstrap { server } => {
            let bootstrapper = Bootstrapper::from_server_string(server.to_string())
                .map_err(|e| format!("Failed to initialize bootstrap client: {}", e))?;

            let (state, _block) = bootstrapper
                .genesis()
                .map_err(|e| format!("Failed to bootstrap genesis state: {}", e))?;

            state
        }
    };

    let mut genesis_block = BeaconBlock::empty(&spec);
    genesis_block.state_root = Hash256::from_slice(&genesis_state.tree_hash_root());
    let genesis_block_root = genesis_block.canonical_root();

    // Slot clock
    let slot_clock = T::SlotClock::new(
        spec.genesis_slot,
        genesis_state.genesis_time,
        spec.seconds_per_slot,
    );

    // Try load an existing `BeaconChain` from the store. If unable, create a new one.
    if let Ok(Some(beacon_chain)) =
        BeaconChain::from_store(store.clone(), spec.clone(), log.clone())
    {
        // Here we check to ensure that the `BeaconChain` loaded from store has the expected
        // genesis block.
        //
        // Without this check, it's possible that there will be an existing DB with a `BeaconChain`
        // that has different parameters than provided to this executable.
        if beacon_chain.genesis_block_root == genesis_block_root {
            info!(
                log,
                "Loaded BeaconChain from store";
                "slot" => beacon_chain.head().beacon_state.slot,
                "best_slot" => beacon_chain.best_slot(),
            );

            Ok(beacon_chain)
        } else {
            crit!(
                log,
                "The BeaconChain loaded from disk has an incorrect genesis root. \
                 This may be caused by an old database in located in datadir."
            );
            Err("Incorrect genesis root".into())
        }
    } else {
        BeaconChain::from_genesis(
            store,
            slot_clock,
            genesis_state,
            genesis_block,
            spec,
            log.clone(),
        )
        .map_err(|e| format!("Failed to initialize new beacon chain: {:?}", e).into())
    }
}

fn generate_testnet_genesis_state<E: EthSpec>(
    validator_count: usize,
    genesis_time: u64,
    spec: &ChainSpec,
) -> BeaconState<E> {
    let (mut genesis_state, _keypairs) =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(validator_count, spec)
            .build();

    genesis_state.genesis_time = genesis_time;

    genesis_state
}

/// Returns the system time, mod 30 minutes.
///
/// Used for easily creating testnets.
fn recent_genesis_time() -> u64 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secs_after_last_period = now.checked_rem(30 * 60).unwrap_or(0);
    // genesis is now the last 30 minute block.
    now - secs_after_last_period
}

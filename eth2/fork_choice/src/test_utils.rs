use crate::ForkChoice;
use std::marker::PhantomData;
use std::sync::Arc;
use store::Store;
use types::{
    test_utils::{SeedableRng, TestRandom, TestingBeaconStateBuilder, XorShiftRng},
    BeaconBlock, BeaconState, EthSpec, FoundationEthSpec, Hash256, Keypair,
};

/// Creates a chain of blocks and produces `ForkChoice` instances with pre-filled stores.
pub struct TestingForkChoiceBuilder<S, E> {
    store: Arc<S>,
    pub chain: Vec<(Hash256, BeaconBlock)>,
    _phantom: PhantomData<E>,
}

impl<S: Store, E: EthSpec> TestingForkChoiceBuilder<S, E> {
    pub fn new(validator_count: usize, chain_length: usize, store: Arc<S>) -> Self {
        let chain = get_chain_of_blocks::<FoundationEthSpec, S>(
            chain_length,
            validator_count,
            store.clone(),
        );

        Self {
            store,
            chain,
            _phantom: PhantomData,
        }
    }

    pub fn genesis_root(&self) -> Hash256 {
        self.chain[0].0
    }

    /// Return a new `ForkChoice` instance with a chain stored in it's `Store`.
    pub fn build<F: ForkChoice<S>>(&self) -> F {
        F::new(self.store.clone())
    }
}

fn get_state<T: EthSpec>(validator_count: usize) -> BeaconState<T> {
    let spec = T::default_spec();

    let builder: TestingBeaconStateBuilder<T> =
        TestingBeaconStateBuilder::from_single_keypair(validator_count, &Keypair::random(), &spec);
    let (state, _keypairs) = builder.build();
    state
}

/// Generates a chain of blocks of length `len`.
///
/// Creates a `BeaconState` for the block and stores it in `Store`, along with the block.
///
/// Returns the chain of blocks.
fn get_chain_of_blocks<T: EthSpec, U: Store>(
    len: usize,
    validator_count: usize,
    store: Arc<U>,
) -> Vec<(Hash256, BeaconBlock)> {
    let spec = T::default_spec();
    let mut blocks_and_roots: Vec<(Hash256, BeaconBlock)> = vec![];
    let mut unique_hashes = (0..).into_iter().map(|i| Hash256::from(i));
    let mut random_block = BeaconBlock::random_for_test(&mut XorShiftRng::from_seed([42; 16]));
    random_block.previous_block_root = Hash256::zero();
    let beacon_state = get_state::<T>(validator_count);

    for i in 0..len {
        let slot = spec.genesis_slot + i as u64;

        // Generate and store the state.
        let mut state = beacon_state.clone();
        state.slot = slot;
        let state_root = unique_hashes.next().unwrap();
        store.put(&state_root, &state).unwrap();

        // Generate the block.
        let mut block = random_block.clone();
        block.slot = slot;
        block.state_root = state_root;

        // Chain all the blocks to their parents.
        if i > 0 {
            block.previous_block_root = blocks_and_roots[i - 1].0;
        }

        // Store the block.
        let block_root = unique_hashes.next().unwrap();
        store.put(&block_root, &block).unwrap();
        blocks_and_roots.push((block_root, block));
    }

    blocks_and_roots
}

// TODO: remove comments
// #![cfg(not(debug_assertions))]

use beacon_chain::{
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, HarnessType},
    ForkChoiceStore as BeaconForkChoiceStore,
};
use lmd_ghost::{ForkChoiceStore, SAFE_SLOTS_TO_UPDATE_JUSTIFIED};
use store::MemoryStore;
use types::{test_utils::generate_deterministic_keypairs, Epoch, EthSpec, MainnetEthSpec, Slot};
use types::{BeaconBlock, BeaconState, Hash256};

pub type E = MainnetEthSpec;

pub const VALIDATOR_COUNT: usize = 16;

struct ForkChoiceTest {
    harness: BeaconChainHarness<HarnessType<E>>,
}

impl ForkChoiceTest {
    pub fn new() -> Self {
        let harness = BeaconChainHarness::new_with_target_aggregators(
            MainnetEthSpec,
            generate_deterministic_keypairs(VALIDATOR_COUNT),
            // Ensure we always have an aggregator for each slot.
            u64::max_value(),
        );

        harness.advance_slot();

        Self { harness }
    }

    fn get<T, U>(&self, func: T) -> U
    where
        T: Fn(&BeaconForkChoiceStore<MemoryStore<E>, E>) -> U,
    {
        func(&self.harness.chain.fork_choice.backend().fc_store())
    }

    pub fn assert_justified_epoch(self, epoch: u64) -> Self {
        assert_eq!(
            self.get(|fc_store| fc_store.best_justified_checkpoint().epoch),
            Epoch::new(epoch)
        );
        self
    }

    pub fn apply_blocks_while<F>(self, mut predicate: F) -> Self
    where
        F: FnMut(&BeaconBlock<E>, &BeaconState<E>) -> bool,
    {
        self.harness.extend_chain_while(
            |block, state| predicate(&block.message, state),
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        );

        self
    }

    pub fn apply_blocks(self, count: usize) -> Self {
        self.harness.extend_chain(
            count,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        );

        self
    }

    pub fn move_outside_safe_to_update(self) -> Self {
        while is_safe_to_update(self.harness.chain.slot().unwrap()) {
            self.harness.advance_slot()
        }
        self
    }

    pub fn move_inside_safe_to_update(self) -> Self {
        while !is_safe_to_update(self.harness.chain.slot().unwrap()) {
            self.harness.advance_slot()
        }
        self
    }

    pub fn apply_block_directly_to_fork_choice<F>(self, mut func: F) -> Self
    where
        F: FnMut(&mut BeaconBlock<E>, &mut BeaconState<E>),
    {
        let (mut block, mut state) = self.harness.get_block();
        func(&mut block.message, &mut state);
        let current_slot = self.harness.chain.slot().unwrap();
        self.harness
            .chain
            .fork_choice
            .process_block(current_slot, &state, &block.message, block.canonical_root())
            .unwrap();
        self
    }
}

fn is_safe_to_update(slot: Slot) -> bool {
    slot % E::slots_per_epoch() < SAFE_SLOTS_TO_UPDATE_JUSTIFIED
}

/// - The new justified checkpoint descends from the current.
/// - Current slot is within `SAFE_SLOTS_TO_UPDATE_JUSTIFIED`
#[test]
fn justified_checkpoint_updates_with_descendent_inside_safe_slots() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.current_justified_checkpoint.epoch == 0)
        .move_inside_safe_to_update()
        .assert_justified_epoch(0)
        .apply_blocks(1)
        .assert_justified_epoch(2);
}

/// - The new justified checkpoint descends from the current.
/// - Current slot is **not** within `SAFE_SLOTS_TO_UPDATE_JUSTIFIED`
#[test]
fn justified_checkpoint_updates_with_descendent_outside_safe_slots() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.current_justified_checkpoint.epoch == 0)
        .move_outside_safe_to_update()
        .assert_justified_epoch(0)
        .apply_blocks(1)
        .assert_justified_epoch(2);
}

#[test]
fn justified_checkpoint_updates_with_non_descendent_outside_safe_slots() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.current_justified_checkpoint.epoch == 0)
        .move_outside_safe_to_update()
        .assert_justified_epoch(0)
        .apply_block_directly_to_fork_choice(|_, state| {
            state
                .set_block_root(Slot::new(0), Hash256::from_low_u64_be(42))
                .unwrap();
        })
        .assert_justified_epoch(0);
}

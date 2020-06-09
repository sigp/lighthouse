#![cfg(not(debug_assertions))]

use beacon_chain::{
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, HarnessType},
    ForkChoiceStore as BeaconForkChoiceStore,
};
use fork_choice::{ForkChoiceStore, SAFE_SLOTS_TO_UPDATE_JUSTIFIED};
use store::{MemoryStore, Store};
use types::{test_utils::generate_deterministic_keypairs, Epoch, EthSpec, MainnetEthSpec, Slot};
use types::{BeaconBlock, BeaconState, Hash256, SignedBeaconBlock};

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

    // TODO: unused.
    fn inspect<T>(&self, func: T)
    where
        T: Fn(&BeaconChainHarness<HarnessType<E>>, &BeaconForkChoiceStore<MemoryStore<E>, E>),
    {
        func(
            &self.harness,
            &self.harness.chain.fork_choice.read().fc_store(),
        )
    }

    fn get<T, U>(&self, func: T) -> U
    where
        T: Fn(&BeaconForkChoiceStore<MemoryStore<E>, E>) -> U,
    {
        func(&self.harness.chain.fork_choice.read().fc_store())
    }

    pub fn assert_justified_epoch(self, epoch: u64) -> Self {
        assert_eq!(
            self.get(|fc_store| fc_store.justified_checkpoint().epoch),
            Epoch::new(epoch)
        );
        self
    }

    pub fn assert_best_justified_epoch(self, epoch: u64) -> Self {
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
            .write()
            .on_block(current_slot, &block.message, block.canonical_root(), &state)
            .unwrap();
        self
    }

    fn check_justified_balances(&self) {
        let harness = &self.harness;
        let fc = self.harness.chain.fork_choice.read();

        let state_root = harness
            .chain
            .store
            .get_item::<SignedBeaconBlock<E>>(&fc.fc_store().justified_checkpoint().root)
            .unwrap()
            .unwrap()
            .message
            .state_root;
        let state = harness
            .chain
            .store
            .get_state(&state_root, None)
            .unwrap()
            .unwrap();
        let balances = state
            .validators
            .into_iter()
            .map(|v| {
                if v.is_active_at(state.current_epoch()) {
                    v.effective_balance
                } else {
                    0
                }
            })
            .collect::<Vec<_>>();

        assert_eq!(
            &balances[..],
            fc.fc_store().justified_balances(),
            "balances should match"
        )
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
/// - This is **not** the first justification since genesis
#[test]
fn justified_checkpoint_updates_with_descendent_outside_safe_slots() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.current_justified_checkpoint.epoch <= 2)
        .move_outside_safe_to_update()
        .assert_justified_epoch(2)
        .assert_best_justified_epoch(2)
        .apply_blocks(1)
        .assert_justified_epoch(3);
}

/// - The new justified checkpoint descends from the current.
/// - Current slot is **not** within `SAFE_SLOTS_TO_UPDATE_JUSTIFIED`
/// - This is the first justification since genesis
#[test]
fn justified_checkpoint_updates_first_justification_outside_safe_to_update() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.current_justified_checkpoint.epoch == 0)
        .move_outside_safe_to_update()
        .assert_justified_epoch(0)
        .assert_best_justified_epoch(0)
        .apply_blocks(1)
        .assert_justified_epoch(0)
        .assert_best_justified_epoch(2);
}

/// - The new justified checkpoint **does not** descend from the current.
/// - Current slot is within `SAFE_SLOTS_TO_UPDATE_JUSTIFIED`
/// - Finalized epoch has **not** increased.
#[test]
fn justified_checkpoint_updates_with_non_descendent_inside_safe_slots_without_finality() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.current_justified_checkpoint.epoch == 0)
        .move_inside_safe_to_update()
        .assert_justified_epoch(0)
        .apply_block_directly_to_fork_choice(|_, state| {
            state.finalized_checkpoint.epoch = Epoch::new(0);
            state
                .set_block_root(Slot::new(0), Hash256::from_low_u64_be(42))
                .unwrap();
        })
        .assert_justified_epoch(2)
        .assert_best_justified_epoch(2);
}

/// - The new justified checkpoint **does not** descend from the current.
/// - Current slot is **not** within `SAFE_SLOTS_TO_UPDATE_JUSTIFIED`.
/// - Finalized epoch has **not** increased.
#[test]
fn justified_checkpoint_updates_with_non_descendent_outside_safe_slots_without_finality() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.current_justified_checkpoint.epoch == 0)
        .move_outside_safe_to_update()
        .assert_justified_epoch(0)
        .apply_block_directly_to_fork_choice(|_, state| {
            state.finalized_checkpoint.epoch = Epoch::new(0);
            state
                .set_block_root(Slot::new(0), Hash256::from_low_u64_be(42))
                .unwrap();
        })
        .assert_justified_epoch(0)
        .assert_best_justified_epoch(2);
}

/// - The new justified checkpoint **does not** descend from the current.
/// - Current slot is **not** within `SAFE_SLOTS_TO_UPDATE_JUSTIFIED`
/// - Finalized epoch has increased.
#[test]
fn justified_checkpoint_updates_with_non_descendent_outside_safe_slots_with_finality() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.current_justified_checkpoint.epoch == 0)
        .move_outside_safe_to_update()
        .assert_justified_epoch(0)
        .apply_block_directly_to_fork_choice(|_, state| {
            state.finalized_checkpoint.epoch = Epoch::new(1);
            state
                .set_block_root(Slot::new(0), Hash256::from_low_u64_be(42))
                .unwrap();
        })
        .assert_justified_epoch(2)
        .assert_best_justified_epoch(2);
}

/// Check that the balances are obtained correctly.
#[test]
fn justified_balances() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.current_justified_checkpoint.epoch == 0)
        .apply_blocks(1)
        .assert_justified_epoch(2)
        .check_justified_balances()
}

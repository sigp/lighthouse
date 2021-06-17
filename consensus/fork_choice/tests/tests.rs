#![cfg(not(debug_assertions))]

use beacon_chain::{
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType},
    BeaconChain, BeaconChainError, BeaconForkChoiceStore, ChainConfig, ForkChoiceError,
    StateSkipConfig, WhenSlotSkipped,
};
use fork_choice::{
    ForkChoiceStore, InvalidAttestation, InvalidBlock, QueuedAttestation,
    SAFE_SLOTS_TO_UPDATE_JUSTIFIED,
};
use std::fmt;
use std::sync::Mutex;
use store::{MemoryStore, StoreConfig};
use types::{
    test_utils::{generate_deterministic_keypair, generate_deterministic_keypairs},
    Checkpoint, Epoch, EthSpec, IndexedAttestation, MainnetEthSpec, Slot, SubnetId,
};
use types::{BeaconBlock, BeaconState, Hash256, SignedBeaconBlock};

pub type E = MainnetEthSpec;

pub const VALIDATOR_COUNT: usize = 32;

/// Defines some delay between when an attestation is created and when it is mutated.
pub enum MutationDelay {
    /// No delay between creation and mutation.
    NoDelay,
    /// Create `n` blocks before mutating the attestation.
    Blocks(usize),
}

/// A helper struct to make testing fork choice more ergonomic and less repetitive.
struct ForkChoiceTest {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
}

/// Allows us to use `unwrap` in some cases.
impl fmt::Debug for ForkChoiceTest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForkChoiceTest").finish()
    }
}

impl ForkChoiceTest {
    /// Creates a new tester.
    pub fn new() -> Self {
        let harness = BeaconChainHarness::new_with_target_aggregators(
            MainnetEthSpec,
            generate_deterministic_keypairs(VALIDATOR_COUNT),
            // Ensure we always have an aggregator for each slot.
            u64::max_value(),
            StoreConfig::default(),
        );

        Self { harness }
    }

    /// Creates a new tester with a custom chain config.
    pub fn new_with_chain_config(chain_config: ChainConfig) -> Self {
        let harness = BeaconChainHarness::new_with_chain_config(
            MainnetEthSpec,
            generate_deterministic_keypairs(VALIDATOR_COUNT),
            // Ensure we always have an aggregator for each slot.
            u64::max_value(),
            StoreConfig::default(),
            chain_config,
        );

        Self { harness }
    }

    /// Get a value from the `ForkChoice` instantiation.
    fn get<T, U>(&self, func: T) -> U
    where
        T: Fn(&BeaconForkChoiceStore<E, MemoryStore<E>, MemoryStore<E>>) -> U,
    {
        func(&self.harness.chain.fork_choice.read().fc_store())
    }

    /// Assert the epochs match.
    pub fn assert_finalized_epoch(self, epoch: u64) -> Self {
        assert_eq!(
            self.get(|fc_store| fc_store.finalized_checkpoint().epoch),
            Epoch::new(epoch),
            "finalized_epoch"
        );
        self
    }

    /// Assert the epochs match.
    pub fn assert_justified_epoch(self, epoch: u64) -> Self {
        assert_eq!(
            self.get(|fc_store| fc_store.justified_checkpoint().epoch),
            Epoch::new(epoch),
            "justified_epoch"
        );
        self
    }

    /// Assert the epochs match.
    pub fn assert_best_justified_epoch(self, epoch: u64) -> Self {
        assert_eq!(
            self.get(|fc_store| fc_store.best_justified_checkpoint().epoch),
            Epoch::new(epoch),
            "best_justified_epoch"
        );
        self
    }

    /// Assert the given slot is greater than the head slot.
    pub fn assert_finalized_epoch_is_less_than(self, epoch: Epoch) -> Self {
        assert!(
            self.harness
                .chain
                .head_info()
                .unwrap()
                .finalized_checkpoint
                .epoch
                < epoch
        );
        self
    }

    /// Assert there was a shutdown signal sent by the beacon chain.
    pub fn assert_shutdown_signal_sent(mut self) -> Self {
        self.harness.shutdown_receiver.close();
        let msg = self.harness.shutdown_receiver.try_next().unwrap();
        assert!(msg.is_some());
        self
    }

    /// Assert no shutdown was signal sent by the beacon chain.
    pub fn assert_shutdown_signal_not_sent(mut self) -> Self {
        self.harness.shutdown_receiver.close();
        let msg = self.harness.shutdown_receiver.try_next().unwrap();
        assert!(msg.is_none());
        self
    }

    /// Inspect the queued attestations in fork choice.
    pub fn inspect_queued_attestations<F>(self, mut func: F) -> Self
    where
        F: FnMut(&[QueuedAttestation]),
    {
        self.harness
            .chain
            .fork_choice
            .write()
            .update_time(self.harness.chain.slot().unwrap())
            .unwrap();
        func(self.harness.chain.fork_choice.read().queued_attestations());
        self
    }

    /// Skip a slot, without producing a block.
    pub fn skip_slot(self) -> Self {
        self.harness.advance_slot();
        self
    }

    /// Skips `count` slots, without producing a block.
    pub fn skip_slots(self, count: usize) -> Self {
        for _ in 0..count {
            self.harness.advance_slot();
        }
        self
    }

    /// Build the chain whilst `predicate` returns `true` and `process_block_result` does not error.
    pub fn apply_blocks_while<F>(self, mut predicate: F) -> Result<Self, Self>
    where
        F: FnMut(&BeaconBlock<E>, &BeaconState<E>) -> bool,
    {
        self.harness.advance_slot();
        let mut state = self.harness.get_current_state();
        let validators = self.harness.get_all_validators();
        loop {
            let slot = self.harness.get_current_slot();
            let (block, state_) = self.harness.make_block(state, slot);
            state = state_;
            if !predicate(&block.message, &state) {
                break;
            }
            if let Ok(block_hash) = self.harness.process_block_result(block.clone()) {
                self.harness.attest_block(
                    &state,
                    block.state_root(),
                    block_hash,
                    &block,
                    &validators,
                );
                self.harness.advance_slot();
            } else {
                return Err(self);
            }
        }

        Ok(self)
    }

    /// Apply `count` blocks to the chain (with attestations).
    pub fn apply_blocks(self, count: usize) -> Self {
        self.harness.advance_slot();
        self.harness.extend_chain(
            count,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        );

        self
    }

    /// Apply `count` blocks to the chain (without attestations).
    pub fn apply_blocks_without_new_attestations(self, count: usize) -> Self {
        self.harness.advance_slot();
        self.harness.extend_chain(
            count,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(vec![]),
        );

        self
    }

    /// Moves to the next slot that is *outside* the `SAFE_SLOTS_TO_UPDATE_JUSTIFIED` range.
    ///
    /// If the chain is presently in an unsafe period, transition through it and the following safe
    /// period.
    pub fn move_to_next_unsafe_period(self) -> Self {
        self.move_inside_safe_to_update()
            .move_outside_safe_to_update()
    }

    /// Moves to the next slot that is *outside* the `SAFE_SLOTS_TO_UPDATE_JUSTIFIED` range.
    pub fn move_outside_safe_to_update(self) -> Self {
        while is_safe_to_update(self.harness.chain.slot().unwrap()) {
            self.harness.advance_slot()
        }
        self
    }

    /// Moves to the next slot that is *inside* the `SAFE_SLOTS_TO_UPDATE_JUSTIFIED` range.
    pub fn move_inside_safe_to_update(self) -> Self {
        while !is_safe_to_update(self.harness.chain.slot().unwrap()) {
            self.harness.advance_slot()
        }
        self
    }

    /// Applies a block directly to fork choice, bypassing the beacon chain.
    ///
    /// Asserts the block was applied successfully.
    pub fn apply_block_directly_to_fork_choice<F>(self, mut func: F) -> Self
    where
        F: FnMut(&mut BeaconBlock<E>, &mut BeaconState<E>),
    {
        let state = self
            .harness
            .chain
            .state_at_slot(
                self.harness.get_current_slot() - 1,
                StateSkipConfig::WithStateRoots,
            )
            .unwrap();
        let slot = self.harness.get_current_slot();
        let (mut block, mut state) = self.harness.make_block(state, slot);
        func(&mut block.message, &mut state);
        let current_slot = self.harness.get_current_slot();
        self.harness
            .chain
            .fork_choice
            .write()
            .on_block(current_slot, &block.message, block.canonical_root(), &state)
            .unwrap();
        self
    }

    /// Applies a block directly to fork choice, bypassing the beacon chain.
    ///
    /// Asserts that an error occurred and allows inspecting it via `comparison_func`.
    pub fn apply_invalid_block_directly_to_fork_choice<F, G>(
        self,
        mut mutation_func: F,
        mut comparison_func: G,
    ) -> Self
    where
        F: FnMut(&mut BeaconBlock<E>, &mut BeaconState<E>),
        G: FnMut(ForkChoiceError),
    {
        let state = self
            .harness
            .chain
            .state_at_slot(
                self.harness.get_current_slot() - 1,
                StateSkipConfig::WithStateRoots,
            )
            .unwrap();
        let slot = self.harness.get_current_slot();
        let (mut block, mut state) = self.harness.make_block(state, slot);
        mutation_func(&mut block.message, &mut state);
        let current_slot = self.harness.get_current_slot();
        let err = self
            .harness
            .chain
            .fork_choice
            .write()
            .on_block(current_slot, &block.message, block.canonical_root(), &state)
            .err()
            .expect("on_block did not return an error");
        comparison_func(err);
        self
    }

    /// Compares the justified balances in the `ForkChoiceStore` verses a direct lookup from the
    /// database.
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

    /// Returns an attestation that is valid for some slot in the given `chain`.
    ///
    /// Also returns some info about who created it.
    fn apply_attestation_to_chain<F, G>(
        self,
        delay: MutationDelay,
        mut mutation_func: F,
        mut comparison_func: G,
    ) -> Self
    where
        F: FnMut(&mut IndexedAttestation<E>, &BeaconChain<EphemeralHarnessType<E>>),
        G: FnMut(Result<(), BeaconChainError>),
    {
        let head = self.harness.chain.head().expect("should get head");
        let current_slot = self.harness.chain.slot().expect("should get slot");

        let mut attestation = self
            .harness
            .chain
            .produce_unaggregated_attestation(current_slot, 0)
            .expect("should not error while producing attestation");

        let validator_committee_index = 0;
        let validator_index = *head
            .beacon_state
            .get_beacon_committee(current_slot, attestation.data.index)
            .expect("should get committees")
            .committee
            .get(validator_committee_index)
            .expect("there should be an attesting validator");

        let committee_count = head
            .beacon_state
            .get_committee_count_at_slot(current_slot)
            .expect("should not error while getting committee count");

        let subnet_id = SubnetId::compute_subnet::<E>(
            current_slot,
            0,
            committee_count,
            &self.harness.chain.spec,
        )
        .expect("should compute subnet id");

        let validator_sk = generate_deterministic_keypair(validator_index).sk;

        attestation
            .sign(
                &validator_sk,
                validator_committee_index,
                &head.beacon_state.fork,
                self.harness.chain.genesis_validators_root,
                &self.harness.chain.spec,
            )
            .expect("should sign attestation");

        let mut verified_attestation = self
            .harness
            .chain
            .verify_unaggregated_attestation_for_gossip(attestation, Some(subnet_id))
            .expect("precondition: should gossip verify attestation");

        if let MutationDelay::Blocks(slots) = delay {
            self.harness.advance_slot();
            self.harness.extend_chain(
                slots,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::SomeValidators(vec![]),
            );
        }

        mutation_func(
            verified_attestation.__indexed_attestation_mut(),
            &self.harness.chain,
        );

        let result = self
            .harness
            .chain
            .apply_attestation_to_fork_choice(&verified_attestation);

        comparison_func(result);

        self
    }

    /// Check to ensure that we can read the finalized block. This is a regression test.
    pub fn check_finalized_block_is_accessible(self) -> Self {
        self.harness
            .chain
            .fork_choice
            .write()
            .get_block(
                &self
                    .harness
                    .chain
                    .head_info()
                    .unwrap()
                    .finalized_checkpoint
                    .root,
            )
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
        .unwrap()
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
        .unwrap()
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
        .unwrap()
        .move_to_next_unsafe_period()
        .assert_justified_epoch(0)
        .assert_best_justified_epoch(0)
        .apply_blocks(1)
        .assert_justified_epoch(2)
        .assert_best_justified_epoch(2);
}

/// - The new justified checkpoint **does not** descend from the current.
/// - Current slot is within `SAFE_SLOTS_TO_UPDATE_JUSTIFIED`
/// - Finalized epoch has **not** increased.
#[test]
fn justified_checkpoint_updates_with_non_descendent_inside_safe_slots_without_finality() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.current_justified_checkpoint.epoch == 0)
        .unwrap()
        .apply_blocks(1)
        .move_inside_safe_to_update()
        .assert_justified_epoch(2)
        .apply_block_directly_to_fork_choice(|_, state| {
            // The finalized checkpoint should not change.
            state.finalized_checkpoint.epoch = Epoch::new(0);

            // The justified checkpoint has changed.
            state.current_justified_checkpoint.epoch = Epoch::new(3);
            // The new block should **not** include the current justified block as an ancestor.
            state.current_justified_checkpoint.root = *state
                .get_block_root(Epoch::new(1).start_slot(E::slots_per_epoch()))
                .unwrap();
        })
        .assert_justified_epoch(3)
        .assert_best_justified_epoch(3);
}

/// - The new justified checkpoint **does not** descend from the current.
/// - Current slot is **not** within `SAFE_SLOTS_TO_UPDATE_JUSTIFIED`.
/// - Finalized epoch has **not** increased.
#[test]
fn justified_checkpoint_updates_with_non_descendent_outside_safe_slots_without_finality() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.current_justified_checkpoint.epoch == 0)
        .unwrap()
        .apply_blocks(1)
        .move_to_next_unsafe_period()
        .assert_justified_epoch(2)
        .apply_block_directly_to_fork_choice(|_, state| {
            // The finalized checkpoint should not change.
            state.finalized_checkpoint.epoch = Epoch::new(0);

            // The justified checkpoint has changed.
            state.current_justified_checkpoint.epoch = Epoch::new(3);
            // The new block should **not** include the current justified block as an ancestor.
            state.current_justified_checkpoint.root = *state
                .get_block_root(Epoch::new(1).start_slot(E::slots_per_epoch()))
                .unwrap();
        })
        .assert_justified_epoch(2)
        .assert_best_justified_epoch(3);
}

/// - The new justified checkpoint **does not** descend from the current.
/// - Current slot is **not** within `SAFE_SLOTS_TO_UPDATE_JUSTIFIED`
/// - Finalized epoch has increased.
#[test]
fn justified_checkpoint_updates_with_non_descendent_outside_safe_slots_with_finality() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.current_justified_checkpoint.epoch == 0)
        .unwrap()
        .apply_blocks(1)
        .move_to_next_unsafe_period()
        .assert_justified_epoch(2)
        .apply_block_directly_to_fork_choice(|_, state| {
            // The finalized checkpoint should change.
            state.finalized_checkpoint.epoch = Epoch::new(1);

            // The justified checkpoint has changed.
            state.current_justified_checkpoint.epoch = Epoch::new(3);
            // The new block should **not** include the current justified block as an ancestor.
            state.current_justified_checkpoint.root = *state
                .get_block_root(Epoch::new(1).start_slot(E::slots_per_epoch()))
                .unwrap();
        })
        .assert_justified_epoch(3)
        .assert_best_justified_epoch(3);
}

/// Check that the balances are obtained correctly.
#[test]
fn justified_balances() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.current_justified_checkpoint.epoch == 0)
        .unwrap()
        .apply_blocks(1)
        .assert_justified_epoch(2)
        .check_justified_balances()
}

macro_rules! assert_invalid_block {
    ($err: tt, $($error: pat) |+ $( if $guard: expr )?) => {
        assert!(
            matches!(
                $err,
                $( ForkChoiceError::InvalidBlock($error) ) |+ $( if $guard )?
            ),
        );
    };
}

/// Specification v0.12.1
///
/// assert block.parent_root in store.block_states
#[test]
fn invalid_block_unknown_parent() {
    let junk = Hash256::from_low_u64_be(42);

    ForkChoiceTest::new()
        .apply_blocks(2)
        .apply_invalid_block_directly_to_fork_choice(
            |block, _| {
                block.parent_root = junk;
            },
            |err| {
                assert_invalid_block!(
                    err,
                    InvalidBlock::UnknownParent(parent)
                    if parent == junk
                )
            },
        );
}

/// Specification v0.12.1
///
/// assert get_current_slot(store) >= block.slot
#[test]
fn invalid_block_future_slot() {
    ForkChoiceTest::new()
        .apply_blocks(2)
        .apply_invalid_block_directly_to_fork_choice(
            |block, _| {
                block.slot = block.slot + 1;
            },
            |err| assert_invalid_block!(err, InvalidBlock::FutureSlot { .. }),
        );
}

/// Specification v0.12.1
///
/// assert block.slot > finalized_slot
#[test]
fn invalid_block_finalized_slot() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch == 0)
        .unwrap()
        .apply_blocks(1)
        .apply_invalid_block_directly_to_fork_choice(
            |block, _| {
                block.slot = Epoch::new(2).start_slot(E::slots_per_epoch()) - 1;
            },
            |err| {
                assert_invalid_block!(
                    err,
                    InvalidBlock::FinalizedSlot { finalized_slot, .. }
                    if finalized_slot == Epoch::new(2).start_slot(E::slots_per_epoch())
                )
            },
        );
}

/// Specification v0.12.1
///
/// assert get_ancestor(store, hash_tree_root(block), finalized_slot) ==
/// store.finalized_checkpoint.root
///
/// Note: we technically don't do this exact check, but an equivalent check. Reference:
///
/// https://github.com/ethereum/eth2.0-specs/pull/1884
#[test]
fn invalid_block_finalized_descendant() {
    let invalid_ancestor = Mutex::new(Hash256::zero());

    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch == 0)
        .unwrap()
        .apply_blocks(1)
        .assert_finalized_epoch(2)
        .apply_invalid_block_directly_to_fork_choice(
            |block, state| {
                block.parent_root = *state
                    .get_block_root(Epoch::new(1).start_slot(E::slots_per_epoch()))
                    .unwrap();
                *invalid_ancestor.lock().unwrap() = block.parent_root;
            },
            |err| {
                assert_invalid_block!(
                    err,
                    InvalidBlock::NotFinalizedDescendant {  block_ancestor, .. }
                    if block_ancestor == Some(*invalid_ancestor.lock().unwrap())
                )
            },
        );
}

macro_rules! assert_invalid_attestation {
    ($err: tt, $($error: pat) |+ $( if $guard: expr )?) => {
        assert!(
            matches!(
                $err,
                $( Err(BeaconChainError::ForkChoiceError(ForkChoiceError::InvalidAttestation($error))) ) |+ $( if $guard )?
            ),
            "{:?}",
            $err
        );
    };
}

/// Ensure we can process a valid attestation.
#[test]
fn valid_attestation() {
    ForkChoiceTest::new()
        .apply_blocks_without_new_attestations(1)
        .apply_attestation_to_chain(
            MutationDelay::NoDelay,
            |_, _| {},
            |result| assert_eq!(result.unwrap(), ()),
        );
}

/// This test is not in the specification, however we reject an attestation with an empty
/// aggregation bitfield since it has no purpose beyond wasting our time.
#[test]
fn invalid_attestation_empty_bitfield() {
    ForkChoiceTest::new()
        .apply_blocks_without_new_attestations(1)
        .apply_attestation_to_chain(
            MutationDelay::NoDelay,
            |attestation, _| {
                attestation.attesting_indices = vec![].into();
            },
            |result| {
                assert_invalid_attestation!(result, InvalidAttestation::EmptyAggregationBitfield)
            },
        );
}

/// Specification v0.12.1:
///
/// assert target.epoch in [expected_current_epoch, previous_epoch]
///
/// (tests epoch after current epoch)
#[test]
fn invalid_attestation_future_epoch() {
    ForkChoiceTest::new()
        .apply_blocks_without_new_attestations(1)
        .apply_attestation_to_chain(
            MutationDelay::NoDelay,
            |attestation, _| {
                attestation.data.target.epoch = Epoch::new(2);
            },
            |result| {
                assert_invalid_attestation!(
                    result,
                    InvalidAttestation::FutureEpoch { attestation_epoch, current_epoch }
                    if attestation_epoch == Epoch::new(2) && current_epoch == Epoch::new(0)
                )
            },
        );
}

/// Specification v0.12.1:
///
/// assert target.epoch in [expected_current_epoch, previous_epoch]
///
/// (tests epoch prior to previous epoch)
#[test]
fn invalid_attestation_past_epoch() {
    ForkChoiceTest::new()
        .apply_blocks_without_new_attestations(E::slots_per_epoch() as usize * 3 + 1)
        .apply_attestation_to_chain(
            MutationDelay::NoDelay,
            |attestation, _| {
                attestation.data.target.epoch = Epoch::new(0);
            },
            |result| {
                assert_invalid_attestation!(
                    result,
                    InvalidAttestation::PastEpoch { attestation_epoch, current_epoch }
                    if attestation_epoch == Epoch::new(0) && current_epoch == Epoch::new(3)
                )
            },
        );
}

/// Specification v0.12.1:
///
/// assert target.epoch == compute_epoch_at_slot(attestation.data.slot)
#[test]
fn invalid_attestation_target_epoch() {
    ForkChoiceTest::new()
        .apply_blocks_without_new_attestations(E::slots_per_epoch() as usize + 1)
        .apply_attestation_to_chain(
            MutationDelay::NoDelay,
            |attestation, _| {
                attestation.data.slot = Slot::new(1);
            },
            |result| {
                assert_invalid_attestation!(
                    result,
                    InvalidAttestation::BadTargetEpoch { target, slot }
                    if target == Epoch::new(1) && slot == Slot::new(1)
                )
            },
        );
}

/// Specification v0.12.1:
///
/// assert target.root in store.blocks
#[test]
fn invalid_attestation_unknown_target_root() {
    let junk = Hash256::from_low_u64_be(42);

    ForkChoiceTest::new()
        .apply_blocks_without_new_attestations(1)
        .apply_attestation_to_chain(
            MutationDelay::NoDelay,
            |attestation, _| {
                attestation.data.target.root = junk;
            },
            |result| {
                assert_invalid_attestation!(
                    result,
                    InvalidAttestation::UnknownTargetRoot(root)
                    if root == junk
                )
            },
        );
}

/// Specification v0.12.1:
///
/// assert attestation.data.beacon_block_root in store.blocks
#[test]
fn invalid_attestation_unknown_beacon_block_root() {
    let junk = Hash256::from_low_u64_be(42);

    ForkChoiceTest::new()
        .apply_blocks_without_new_attestations(1)
        .apply_attestation_to_chain(
            MutationDelay::NoDelay,
            |attestation, _| {
                attestation.data.beacon_block_root = junk;
            },
            |result| {
                assert_invalid_attestation!(
                    result,
                    InvalidAttestation::UnknownHeadBlock { beacon_block_root }
                    if beacon_block_root == junk
                )
            },
        );
}

/// Specification v0.12.1:
///
/// assert store.blocks[attestation.data.beacon_block_root].slot <= attestation.data.slot
#[test]
fn invalid_attestation_future_block() {
    ForkChoiceTest::new()
        .apply_blocks_without_new_attestations(1)
        .apply_attestation_to_chain(
            MutationDelay::Blocks(1),
            |attestation, chain| {
                attestation.data.beacon_block_root = chain
                    .block_at_slot(chain.slot().unwrap(), WhenSlotSkipped::Prev)
                    .unwrap()
                    .unwrap()
                    .canonical_root();
            },
            |result| {
                assert_invalid_attestation!(
                    result,
                    InvalidAttestation::AttestsToFutureBlock { block, attestation }
                    if block == 2 && attestation == 1
                )
            },
        );
}

/// Specification v0.12.1:
///
/// assert target.root == get_ancestor(store, attestation.data.beacon_block_root, target_slot)
#[test]
fn invalid_attestation_inconsistent_ffg_vote() {
    let local_opt = Mutex::new(None);
    let attestation_opt = Mutex::new(None);

    ForkChoiceTest::new()
        .apply_blocks_without_new_attestations(1)
        .apply_attestation_to_chain(
            MutationDelay::NoDelay,
            |attestation, chain| {
                attestation.data.target.root = chain
                    .block_at_slot(Slot::new(1), WhenSlotSkipped::Prev)
                    .unwrap()
                    .unwrap()
                    .canonical_root();

                *attestation_opt.lock().unwrap() = Some(attestation.data.target.root);
                *local_opt.lock().unwrap() = Some(
                    chain
                        .block_at_slot(Slot::new(0), WhenSlotSkipped::Prev)
                        .unwrap()
                        .unwrap()
                        .canonical_root(),
                );
            },
            |result| {
                assert_invalid_attestation!(
                    result,
                    InvalidAttestation::InvalidTarget { attestation, local }
                    if attestation == attestation_opt.lock().unwrap().unwrap()
                        && local == local_opt.lock().unwrap().unwrap()
                )
            },
        );
}

/// Specification v0.12.1:
///
/// assert get_current_slot(store) >= attestation.data.slot + 1
#[test]
fn invalid_attestation_delayed_slot() {
    ForkChoiceTest::new()
        .apply_blocks_without_new_attestations(1)
        .inspect_queued_attestations(|queue| assert_eq!(queue.len(), 0))
        .apply_attestation_to_chain(
            MutationDelay::NoDelay,
            |_, _| {},
            |result| assert_eq!(result.unwrap(), ()),
        )
        .inspect_queued_attestations(|queue| assert_eq!(queue.len(), 1))
        .skip_slot()
        .inspect_queued_attestations(|queue| assert_eq!(queue.len(), 0));
}

/// Tests that the correct target root is used when the attested-to block is in a prior epoch to
/// the attestation.
#[test]
fn valid_attestation_skip_across_epoch() {
    ForkChoiceTest::new()
        .apply_blocks(E::slots_per_epoch() as usize - 1)
        .skip_slots(2)
        .apply_attestation_to_chain(
            MutationDelay::NoDelay,
            |attestation, _chain| {
                assert_eq!(
                    attestation.data.target.root,
                    attestation.data.beacon_block_root
                )
            },
            |result| result.unwrap(),
        );
}

#[test]
fn can_read_finalized_block() {
    ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch == 0)
        .unwrap()
        .apply_blocks(1)
        .check_finalized_block_is_accessible();
}

#[test]
#[should_panic]
fn weak_subjectivity_fail_on_startup() {
    let epoch = Epoch::new(0);
    let root = Hash256::from_low_u64_le(1);

    let chain_config = ChainConfig {
        weak_subjectivity_checkpoint: Some(Checkpoint { epoch, root }),
        import_max_skip_slots: None,
    };

    ForkChoiceTest::new_with_chain_config(chain_config);
}

#[test]
fn weak_subjectivity_pass_on_startup() {
    let epoch = Epoch::new(0);
    let root = Hash256::zero();

    let chain_config = ChainConfig {
        weak_subjectivity_checkpoint: Some(Checkpoint { epoch, root }),
        import_max_skip_slots: None,
    };

    ForkChoiceTest::new_with_chain_config(chain_config)
        .apply_blocks(E::slots_per_epoch() as usize)
        .assert_shutdown_signal_not_sent();
}

#[test]
fn weak_subjectivity_check_passes() {
    let setup_harness = ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch == 0)
        .unwrap()
        .apply_blocks(1)
        .assert_finalized_epoch(2);

    let checkpoint = setup_harness
        .harness
        .chain
        .head_info()
        .unwrap()
        .finalized_checkpoint;

    let chain_config = ChainConfig {
        weak_subjectivity_checkpoint: Some(checkpoint),
        import_max_skip_slots: None,
    };

    ForkChoiceTest::new_with_chain_config(chain_config.clone())
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch == 0)
        .unwrap()
        .apply_blocks(1)
        .assert_finalized_epoch(2)
        .assert_shutdown_signal_not_sent();
}

#[test]
fn weak_subjectivity_check_fails_early_epoch() {
    let setup_harness = ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch == 0)
        .unwrap()
        .apply_blocks(1)
        .assert_finalized_epoch(2);

    let mut checkpoint = setup_harness
        .harness
        .chain
        .head_info()
        .unwrap()
        .finalized_checkpoint;

    checkpoint.epoch = checkpoint.epoch - 1;

    let chain_config = ChainConfig {
        weak_subjectivity_checkpoint: Some(checkpoint),
        import_max_skip_slots: None,
    };

    ForkChoiceTest::new_with_chain_config(chain_config.clone())
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch < 3)
        .unwrap_err()
        .assert_finalized_epoch_is_less_than(checkpoint.epoch)
        .assert_shutdown_signal_sent();
}

#[test]
fn weak_subjectivity_check_fails_late_epoch() {
    let setup_harness = ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch == 0)
        .unwrap()
        .apply_blocks(1)
        .assert_finalized_epoch(2);

    let mut checkpoint = setup_harness
        .harness
        .chain
        .head_info()
        .unwrap()
        .finalized_checkpoint;

    checkpoint.epoch = checkpoint.epoch + 1;

    let chain_config = ChainConfig {
        weak_subjectivity_checkpoint: Some(checkpoint),
        import_max_skip_slots: None,
    };

    ForkChoiceTest::new_with_chain_config(chain_config.clone())
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch < 4)
        .unwrap_err()
        .assert_finalized_epoch_is_less_than(checkpoint.epoch)
        .assert_shutdown_signal_sent();
}

#[test]
fn weak_subjectivity_check_fails_incorrect_root() {
    let setup_harness = ForkChoiceTest::new()
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch == 0)
        .unwrap()
        .apply_blocks(1)
        .assert_finalized_epoch(2);

    let mut checkpoint = setup_harness
        .harness
        .chain
        .head_info()
        .unwrap()
        .finalized_checkpoint;

    checkpoint.root = Hash256::zero();

    let chain_config = ChainConfig {
        weak_subjectivity_checkpoint: Some(checkpoint),
        import_max_skip_slots: None,
    };

    ForkChoiceTest::new_with_chain_config(chain_config.clone())
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch < 3)
        .unwrap_err()
        .assert_finalized_epoch_is_less_than(checkpoint.epoch)
        .assert_shutdown_signal_sent();
}

#[test]
fn weak_subjectivity_check_epoch_boundary_is_skip_slot() {
    let setup_harness = ForkChoiceTest::new()
        // first two epochs
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch == 0)
        .unwrap();

    // get the head, it will become the finalized root of epoch 4
    let checkpoint_root = setup_harness.harness.chain.head_info().unwrap().block_root;

    setup_harness
        // epoch 3 will be entirely skip slots
        .skip_slots(E::slots_per_epoch() as usize)
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch < 5)
        .unwrap()
        .apply_blocks(1)
        .assert_finalized_epoch(5);

    // the checkpoint at epoch 4 should become the root of last block of epoch 2
    let checkpoint = Checkpoint {
        epoch: Epoch::new(4),
        root: checkpoint_root,
    };

    let chain_config = ChainConfig {
        weak_subjectivity_checkpoint: Some(checkpoint),
        import_max_skip_slots: None,
    };

    // recreate the chain exactly
    ForkChoiceTest::new_with_chain_config(chain_config.clone())
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch == 0)
        .unwrap()
        .skip_slots(E::slots_per_epoch() as usize)
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch < 5)
        .unwrap()
        .apply_blocks(1)
        .assert_finalized_epoch(5)
        .assert_shutdown_signal_not_sent();
}

#[test]
fn weak_subjectivity_check_epoch_boundary_is_skip_slot_failure() {
    let setup_harness = ForkChoiceTest::new()
        // first two epochs
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch == 0)
        .unwrap();

    // get the head, it will become the finalized root of epoch 4
    let checkpoint_root = setup_harness.harness.chain.head_info().unwrap().block_root;

    setup_harness
        // epoch 3 will be entirely skip slots
        .skip_slots(E::slots_per_epoch() as usize)
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch < 5)
        .unwrap()
        .apply_blocks(1)
        .assert_finalized_epoch(5);

    // Invalid checkpoint (epoch too early)
    let checkpoint = Checkpoint {
        epoch: Epoch::new(1),
        root: checkpoint_root,
    };

    let chain_config = ChainConfig {
        weak_subjectivity_checkpoint: Some(checkpoint),
        import_max_skip_slots: None,
    };

    // recreate the chain exactly
    ForkChoiceTest::new_with_chain_config(chain_config.clone())
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch == 0)
        .unwrap()
        .skip_slots(E::slots_per_epoch() as usize)
        .apply_blocks_while(|_, state| state.finalized_checkpoint.epoch < 6)
        .unwrap_err()
        .assert_finalized_epoch_is_less_than(checkpoint.epoch)
        .assert_shutdown_signal_sent();
}

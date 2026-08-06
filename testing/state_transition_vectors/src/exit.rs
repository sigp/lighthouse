use super::*;
use beacon_chain::test_utils::test_spec;
use state_processing::{
    BlockProcessingError, BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot,
    per_block_processing, per_block_processing::errors::ExitInvalid,
};
use std::sync::LazyLock;
use types::{BeaconBlock, Epoch};

// Default validator index to exit.
pub const VALIDATOR_INDEX: u64 = 0;
// Epoch that the state will be transitioned to by default, equal to SHARD_COMMITTEE_PERIOD.
// Derived from the spec so the value is correct for both mainnet (256) and minimal (64).
pub static STATE_EPOCH: LazyLock<Epoch> =
    LazyLock::new(|| Epoch::new(Spec::default_spec().shard_committee_period));

struct ExitTest {
    validator_index: u64,
    exit_epoch: Epoch,
    state_epoch: Epoch,
    #[allow(clippy::type_complexity)]
    state_modifier: Box<dyn FnOnce(&mut BeaconState)>,
    #[allow(clippy::type_complexity)]
    block_modifier: Box<dyn FnOnce(&BeaconChainHarness<EphemeralHarnessType>, &mut BeaconBlock)>,
    #[allow(dead_code)]
    expected: Result<(), BlockProcessingError>,
}

impl Default for ExitTest {
    fn default() -> Self {
        Self {
            validator_index: VALIDATOR_INDEX,
            exit_epoch: *STATE_EPOCH,
            state_epoch: *STATE_EPOCH,
            state_modifier: Box::new(|_| ()),
            block_modifier: Box::new(|_, _| ()),
            expected: Ok(()),
        }
    }
}

impl ExitTest {
    async fn block_and_pre_state(self) -> (SignedBeaconBlock, BeaconState) {
        let harness = get_harness(
            self.state_epoch.start_slot(Spec::slots_per_epoch()),
            VALIDATOR_COUNT,
        )
        .await;
        let mut state = harness.get_current_state();
        (self.state_modifier)(&mut state);

        let block_modifier = self.block_modifier;
        let validator_index = self.validator_index;
        let exit_epoch = self.exit_epoch;

        let (signed_block, state) = harness
            .make_block_with_modifier(state.clone(), state.slot() + 1, |block| {
                harness.add_voluntary_exit(block, validator_index, exit_epoch);
                block_modifier(&harness, block);
            })
            .await;
        ((*signed_block.0).clone(), state)
    }

    fn process(
        block: &SignedBeaconBlock,
        state: &mut BeaconState,
    ) -> Result<(), BlockProcessingError> {
        let mut ctxt = ConsensusContext::new(block.slot());
        per_block_processing(
            state,
            block,
            BlockSignatureStrategy::VerifyIndividual,
            VerifyBlockRoot::True,
            &mut ctxt,
            &test_spec(),
        )
    }

    #[cfg(all(test, not(debug_assertions)))]
    async fn run(self) -> BeaconState {
        let spec = &test_spec();
        let expected = self.expected.clone();
        assert_eq!(*STATE_EPOCH, spec.shard_committee_period);

        let (block, mut state) = self.block_and_pre_state().await;

        let result = Self::process(&block, &mut state);

        assert_eq!(result, expected);

        state
    }

    async fn test_vector(self, title: String) -> TestVector {
        let (block, pre_state) = self.block_and_pre_state().await;
        let mut post_state = pre_state.clone();
        let (post_state, error) = match Self::process(&block, &mut post_state) {
            Ok(_) => (Some(post_state), None),
            Err(e) => (None, Some(format!("{:?}", e))),
        };

        TestVector {
            title,
            pre_state,
            block,
            post_state,
            error,
        }
    }
}

vectors_and_tests!(
    // Ensures we can process a valid exit,
    valid_single_exit,
    ExitTest::default(),
    // Tests three exits in the same block.
    valid_three_exits,
    ExitTest {
        block_modifier: Box::new(|harness, block| {
            harness.add_voluntary_exit(block, 1, *STATE_EPOCH);
            harness.add_voluntary_exit(block, 2, *STATE_EPOCH);
        }),
        ..ExitTest::default()
    },
    // Ensures that a validator cannot be exited twice in the same block.
    invalid_duplicate,
    ExitTest {
        block_modifier: Box::new(|_, block| {
            // Duplicate the exit
            let exit = block.body().voluntary_exits().first().unwrap().clone();
            block.body_mut().voluntary_exits_push(exit).unwrap();
        }),
        expected: Err(BlockProcessingError::ExitInvalid {
            index: 1,
            reason: ExitInvalid::AlreadyExited(0),
        }),
        ..ExitTest::default()
    },
    // Tests the following line of the spec:
    //
    // Spec v0.12.1
    //
    // ```ignore
    // validator = state.validators[voluntary_exit.validator_index]
    // ```
    invalid_validator_unknown,
    ExitTest {
        block_modifier: Box::new(|_, block| {
            block
                .body_mut()
                .voluntary_exits_mut()
                .get_mut(0)
                .unwrap()
                .message
                .validator_index = VALIDATOR_COUNT as u64;
        }),
        expected: Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::ValidatorUnknown(VALIDATOR_COUNT as u64),
        }),
        ..ExitTest::default()
    },
    // Tests the following line of the spec:
    //
    // Spec v0.12.1
    //
    // ```ignore
    // # Verify exit has not been initiated
    // assert validator.exit_epoch == FAR_FUTURE_EPOCH
    // ```
    invalid_exit_already_initiated,
    ExitTest {
        state_modifier: Box::new(|state| {
            state.validators_mut().get_mut(0).unwrap().exit_epoch = *STATE_EPOCH + 1;
        }),
        expected: Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::AlreadyExited(0),
        }),
        ..ExitTest::default()
    },
    // Tests the following line of the spec:
    //
    // Spec v0.12.1
    //
    // ```ignore
    // # Verify the validator is active
    // assert is_active_validator(validator, get_current_epoch(state))
    // ```
    invalid_not_active_before_activation_epoch,
    ExitTest {
        state_modifier: Box::new(|state| {
            state.validators_mut().get_mut(0).unwrap().activation_epoch =
                Spec::default_spec().far_future_epoch;
        }),
        expected: Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::NotActive(0),
        }),
        ..ExitTest::default()
    },
    // Also tests the following line of the spec:
    //
    // Spec v0.12.1
    //
    // ```ignore
    // # Verify the validator is active
    // assert is_active_validator(validator, get_current_epoch(state))
    // ```
    invalid_not_active_after_exit_epoch,
    ExitTest {
        state_modifier: Box::new(|state| {
            state.validators_mut().get_mut(0).unwrap().exit_epoch = *STATE_EPOCH;
        }),
        expected: Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::NotActive(0),
        }),
        ..ExitTest::default()
    },
    // Ensures we can process an exit from genesis.
    valid_genesis_epoch,
    ExitTest {
        exit_epoch: Epoch::new(0),
        ..ExitTest::default()
    },
    // Ensures we can process an exit from the previous epoch.
    valid_previous_epoch,
    ExitTest {
        exit_epoch: *STATE_EPOCH - 1,
        ..ExitTest::default()
    },
    // Tests the following line of the spec:
    //
    // Spec v0.12.1
    //
    // ```ignore
    // # Exits must specify an epoch when they become valid; they are not
    // # valid before then
    // assert get_current_epoch(state) >= voluntary_exit.epoch
    // ```
    invalid_future_exit_epoch,
    ExitTest {
        exit_epoch: *STATE_EPOCH + 1,
        expected: Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::FutureEpoch {
                state: *STATE_EPOCH,
                exit: *STATE_EPOCH + 1,
            },
        }),
        ..ExitTest::default()
    },
    // Tests the following line of the spec:
    //
    // Spec v0.12.1
    //
    // ```ignore
    // # Verify the validator has been active long enough
    // assert get_current_epoch(state) >= validator.activation_epoch + PERSISTENT_COMMITTEE_PERIOD
    // ```
    invalid_too_young_by_one_epoch,
    ExitTest {
        state_epoch: *STATE_EPOCH - 1,
        exit_epoch: *STATE_EPOCH - 1,
        expected: Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::TooYoungToExit {
                current_epoch: *STATE_EPOCH - 1,
                earliest_exit_epoch: *STATE_EPOCH,
            },
        }),
        ..ExitTest::default()
    },
    // Also tests the following line of the spec:
    //
    // Spec v0.12.1
    //
    // ```ignore
    // # Verify the validator has been active long enough
    // assert get_current_epoch(state) >= validator.activation_epoch + PERSISTENT_COMMITTEE_PERIOD
    // ```
    invalid_too_young_by_a_lot,
    ExitTest {
        state_epoch: Epoch::new(0),
        exit_epoch: Epoch::new(0),
        expected: Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::TooYoungToExit {
                current_epoch: Epoch::new(0),
                earliest_exit_epoch: *STATE_EPOCH,
            },
        }),
        ..ExitTest::default()
    },
    // Tests the following line of the spec:
    //
    // Spec v0.12.1
    //
    // ```ignore
    // # Verify signature
    // domain = get_domain(state, DOMAIN_VOLUNTARY_EXIT,
    // voluntary_exit.epoch)
    // signing_root = compute_signing_root(voluntary_exit, domain)
    // assert bls.Verify(validator.pubkey, signing_root,
    // signed_voluntary_exit.signature)
    // ```
    invalid_bad_signature,
    ExitTest {
        block_modifier: Box::new(|_, block| {
            // Shift the validator index by 1 so that it's mismatched from the key that was
            // used to sign.
            block
                .body_mut()
                .voluntary_exits_mut()
                .get_mut(0)
                .unwrap()
                .message
                .validator_index = VALIDATOR_INDEX + 1;
        }),
        expected: Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::BadSignature,
        }),
        ..ExitTest::default()
    }
);

#[cfg(all(test, not(debug_assertions)))]
mod custom_tests {
    use super::*;

    fn assert_exited(state: &BeaconState, validator_index: usize) {
        let spec = Spec::default_spec();

        let validator = &state.validators().get(validator_index).unwrap();
        assert_eq!(
            validator.exit_epoch,
            // This is correct until we exceed the churn limit. If that happens, we
            // need to introduce more complex logic.
            state.current_epoch() + 1 + spec.max_seed_lookahead,
            "exit epoch"
        );
        assert_eq!(
            validator.withdrawable_epoch,
            validator.exit_epoch + Spec::default_spec().min_validator_withdrawability_delay,
            "withdrawable epoch"
        );
    }

    #[tokio::test]
    async fn valid() {
        let state = ExitTest::default().run().await;
        assert_exited(&state, VALIDATOR_INDEX as usize);
    }

    // The churn limit on minimal (2) is smaller than mainnet (4), so 3 exits
    // overflow into the next epoch, breaking the simple exit_epoch assertion.
    // TODO(spec-gates): This test should be made spec-agnostic.
    #[cfg(not(feature = "spec-non-mainnet"))]
    #[tokio::test]
    async fn valid_three() {
        let state = ExitTest {
            block_modifier: Box::new(|harness, block| {
                harness.add_voluntary_exit(block, 1, *STATE_EPOCH);
                harness.add_voluntary_exit(block, 2, *STATE_EPOCH);
            }),
            ..ExitTest::default()
        }
        .run()
        .await;

        for i in &[VALIDATOR_INDEX, 1, 2] {
            assert_exited(&state, *i as usize);
        }
    }
}

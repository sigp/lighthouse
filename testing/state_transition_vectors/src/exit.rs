use super::*;
use state_processing::{
    per_block_processing, per_block_processing::errors::ExitInvalid,
    test_utils::BlockProcessingBuilder, BlockProcessingError, BlockSignatureStrategy,
};
use types::{BeaconBlock, BeaconState, Epoch, EthSpec, SignedBeaconBlock};

// Default validator index to exit.
pub const VALIDATOR_INDEX: u64 = 0;
// Epoch that the state will be transitioned to by default, equal to SHARD_COMMITTEE_PERIOD.
pub const STATE_EPOCH: Epoch = Epoch::new(256);

struct ExitTest {
    validator_index: u64,
    exit_epoch: Epoch,
    state_epoch: Epoch,
    block_modifier: Box<dyn FnOnce(&mut BeaconBlock<E>)>,
    builder_modifier: Box<dyn FnOnce(BlockProcessingBuilder<E>) -> BlockProcessingBuilder<E>>,
    #[allow(dead_code)]
    expected: Result<(), BlockProcessingError>,
}

impl Default for ExitTest {
    fn default() -> Self {
        Self {
            validator_index: VALIDATOR_INDEX,
            exit_epoch: STATE_EPOCH,
            state_epoch: STATE_EPOCH,
            block_modifier: Box::new(|_| ()),
            builder_modifier: Box::new(|x| x),
            expected: Ok(()),
        }
    }
}

impl ExitTest {
    fn block_and_pre_state(self) -> (SignedBeaconBlock<E>, BeaconState<E>) {
        let spec = &E::default_spec();

        (self.builder_modifier)(
            get_builder(spec, self.state_epoch.as_u64(), VALIDATOR_COUNT)
                .insert_exit(self.validator_index, self.exit_epoch)
                .modify(self.block_modifier),
        )
        .build(None, None)
    }

    fn process(
        block: &SignedBeaconBlock<E>,
        state: &mut BeaconState<E>,
    ) -> Result<(), BlockProcessingError> {
        per_block_processing(
            state,
            block,
            None,
            BlockSignatureStrategy::VerifyIndividual,
            &E::default_spec(),
        )
    }

    #[cfg(test)]
    fn run(self) -> BeaconState<E> {
        let spec = &E::default_spec();
        let expected = self.expected.clone();
        assert_eq!(STATE_EPOCH, spec.shard_committee_period);

        let (block, mut state) = self.block_and_pre_state();

        let result = Self::process(&block, &mut state);

        assert_eq!(result, expected);

        state
    }

    fn test_vector(self, title: String) -> TestVector {
        let (block, pre_state) = self.block_and_pre_state();
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
    // Tests three exists in the same block.
    valid_three_exits,
    ExitTest {
        builder_modifier: Box::new(|builder| {
            builder
                .insert_exit(1, STATE_EPOCH)
                .insert_exit(2, STATE_EPOCH)
        }),
        ..ExitTest::default()
    },
    // Ensures that a validator cannot be exited twice in the same block.
    invalid_duplicate,
    ExitTest {
        block_modifier: Box::new(|block| {
            // Duplicate the exit
            let exit = block.body.voluntary_exits[0].clone();
            block.body.voluntary_exits.push(exit).unwrap();
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
        block_modifier: Box::new(|block| {
            block.body.voluntary_exits[0].message.validator_index = VALIDATOR_COUNT as u64;
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
        builder_modifier: Box::new(|mut builder| {
            builder.state.validators[0].exit_epoch = STATE_EPOCH + 1;
            builder
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
        builder_modifier: Box::new(|mut builder| {
            builder.state.validators[0].activation_epoch = builder.spec.far_future_epoch;
            builder
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
        builder_modifier: Box::new(|mut builder| {
            builder.state.validators[0].exit_epoch = STATE_EPOCH;
            builder
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
        exit_epoch: STATE_EPOCH - 1,
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
        exit_epoch: STATE_EPOCH + 1,
        expected: Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::FutureEpoch {
                state: STATE_EPOCH,
                exit: STATE_EPOCH + 1,
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
        state_epoch: STATE_EPOCH - 1,
        exit_epoch: STATE_EPOCH - 1,
        expected: Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::TooYoungToExit {
                current_epoch: STATE_EPOCH - 1,
                earliest_exit_epoch: STATE_EPOCH,
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
                earliest_exit_epoch: STATE_EPOCH,
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
        block_modifier: Box::new(|block| {
            // Shift the validator index by 1 so that it's mismatched from the key that was
            // used to sign.
            block.body.voluntary_exits[0].message.validator_index = VALIDATOR_INDEX + 1;
        }),
        expected: Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::BadSignature,
        }),
        ..ExitTest::default()
    }
);

#[cfg(test)]
mod custom_tests {
    use super::*;

    fn assert_exited(state: &BeaconState<E>, validator_index: usize) {
        let spec = E::default_spec();

        let validator = &state.validators[validator_index];
        assert_eq!(
            validator.exit_epoch,
            // This is correct until we exceed the churn limit. If that happens, we
            // need to introduce more complex logic.
            state.current_epoch() + 1 + spec.max_seed_lookahead,
            "exit epoch"
        );
        assert_eq!(
            validator.withdrawable_epoch,
            validator.exit_epoch + E::default_spec().min_validator_withdrawability_delay,
            "withdrawable epoch"
        );
    }

    #[test]
    fn valid() {
        let state = ExitTest::default().run();
        assert_exited(&state, VALIDATOR_INDEX as usize);
    }

    #[test]
    fn valid_three() {
        let state = ExitTest {
            builder_modifier: Box::new(|builder| {
                builder
                    .insert_exit(1, STATE_EPOCH)
                    .insert_exit(2, STATE_EPOCH)
            }),
            ..ExitTest::default()
        }
        .run();

        for i in &[VALIDATOR_INDEX, 1, 2] {
            assert_exited(&state, *i as usize);
        }
    }
}

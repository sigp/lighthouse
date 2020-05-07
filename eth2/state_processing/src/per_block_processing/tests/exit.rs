use super::*;

// Default validator index to exit.
pub const VALIDATOR_INDEX: u64 = 0;
// Epoch that the state will be transitioned to by default, equal to PERSISTENT_COMMITTEE_PERIOD.
pub const STATE_EPOCH: Epoch = Epoch::new(2048);

struct ExitTest {
    validator_index: u64,
    exit_epoch: Epoch,
    state_epoch: Epoch,
    block_modifier: Box<dyn FnOnce(&mut BeaconBlock<E>)>,
    builder_modifier: Box<dyn FnOnce(BlockProcessingBuilder<E>) -> BlockProcessingBuilder<E>>,
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
    fn run(self) -> BeaconState<E> {
        let spec = &E::default_spec();
        assert_eq!(STATE_EPOCH, spec.persistent_committee_period);
        let (block, mut state) = (self.builder_modifier)(
            get_builder(spec, self.state_epoch.as_u64(), VALIDATOR_COUNT)
                .insert_exit(self.validator_index, self.exit_epoch)
                .modify(self.block_modifier),
        )
        .build(None, None);

        let result = per_block_processing(
            &mut state,
            &block,
            None,
            BlockSignatureStrategy::VerifyIndividual,
            &spec,
        );

        assert_eq!(result, self.expected);

        state
    }
}

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

/// Ensures that a validator cannot be exited twice in the same block.
#[test]
fn invalid_duplicate() {
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
    }
    .run();
}

/// Tests the following line of the spec:
///
/// v0.11.2
///
/// ```ignore
/// validator = state.validators[voluntary_exit.validator_index]
/// ```
#[test]
fn invalid_validator_unknown() {
    ExitTest {
        block_modifier: Box::new(|block| {
            block.body.voluntary_exits[0].message.validator_index = VALIDATOR_COUNT as u64;
        }),
        expected: Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::ValidatorUnknown(VALIDATOR_COUNT as u64),
        }),
        ..ExitTest::default()
    }
    .run();
}

/// Tests the following line of the spec:
///
/// v0.11.2
///
/// ```ignore
/// # Verify exit has not been initiated
/// assert validator.exit_epoch == FAR_FUTURE_EPOCH
/// ```
#[test]
fn invalid_exit_already_initiated() {
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
    }
    .run();
}

#[test]
fn invalid_not_active_before_activation_epoch() {
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
    }
    .run();
}

/// Tests the following line of the spec:
///
/// v0.11.2
///
/// ```ignore
/// # Verify the validator is active
/// assert is_active_validator(validator, get_current_epoch(state))
/// ```
#[test]
fn invalid_not_active_after_exit_epoch() {
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
    }
    .run();
}

#[test]
fn valid_past_exit_epoch() {
    ExitTest {
        exit_epoch: Epoch::new(0),
        ..ExitTest::default()
    }
    .run();

    ExitTest {
        exit_epoch: STATE_EPOCH - 1,
        ..ExitTest::default()
    }
    .run();
}

/// Tests the following line of the spec:
///
/// v0.11.2
///
/// ```ignore
/// # Exits must specify an epoch when they become valid; they are not
/// # valid before then
/// assert get_current_epoch(state) >= voluntary_exit.epoch
/// ```
#[test]
fn invalid_future_exit_epoch() {
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
    }
    .run();
}

/// Tests the following line of the spec:
///
/// v0.11.2
///
/// ```ignore
/// # Verify the validator has been active long enough
/// assert get_current_epoch(state) >= validator.activation_epoch + PERSISTENT_COMMITTEE_PERIOD
/// ```
#[test]
fn invalid_too_young_by_one_epoch() {
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
    }
    .run();
}

/// Also tests the following line of the spec:
///
/// v0.11.2
///
/// ```ignore
/// # Verify the validator has been active long enough
/// assert get_current_epoch(state) >= validator.activation_epoch + PERSISTENT_COMMITTEE_PERIOD
/// ```
#[test]
fn invalid_too_young_by_a_lot() {
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
    }
    .run();
}

/// Tests the following line of the spec:
///
/// v0.11.2
///
/// ```ignore
/// # Verify signature
/// domain = get_domain(state, DOMAIN_VOLUNTARY_EXIT,
/// voluntary_exit.epoch)
/// signing_root = compute_signing_root(voluntary_exit, domain)
/// assert bls.Verify(validator.pubkey, signing_root,
/// signed_voluntary_exit.signature)
/// ```
#[test]
fn invalid_bad_signature() {
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
    .run();
}

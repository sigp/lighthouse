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
    fn run(self) {
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
    }
}

#[test]
fn valid() {
    ExitTest::default().run()
}

#[test]
fn valid_three() {
    ExitTest {
        builder_modifier: Box::new(|builder| {
            builder
                .insert_exit(1, STATE_EPOCH)
                .insert_exit(2, STATE_EPOCH)
        }),
        ..ExitTest::default()
    }
    .run()
}

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
    .run()
}

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
    .run()
}

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
    .run()
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
    .run()
}

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
    .run()
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
    .run()
}

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
    .run()
}

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
    .run()
}

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
    .run()
}

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
    .run()
}

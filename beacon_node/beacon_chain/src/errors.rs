use crate::beacon_chain::ForkChoiceError;
use crate::beacon_fork_choice_store::Error as ForkChoiceStoreError;
use crate::eth1_chain::Error as Eth1ChainError;
use crate::migrate::PruningError;
use crate::naive_aggregation_pool::Error as NaiveAggregationError;
use crate::observed_attestations::Error as ObservedAttestationsError;
use crate::observed_attesters::Error as ObservedAttestersError;
use crate::observed_block_producers::Error as ObservedBlockProducersError;
use futures::channel::mpsc::TrySendError;
use operation_pool::OpPoolError;
use safe_arith::ArithError;
use ssz_types::Error as SszTypesError;
use state_processing::{
    block_signature_verifier::Error as BlockSignatureVerifierError,
    per_block_processing::errors::{
        AttestationValidationError, AttesterSlashingValidationError, ExitValidationError,
        ProposerSlashingValidationError,
    },
    signature_sets::Error as SignatureSetError,
    state_advance::Error as StateAdvanceError,
    BlockProcessingError, SlotProcessingError,
};
use std::time::Duration;
use task_executor::ShutdownReason;
use types::*;

macro_rules! easy_from_to {
    ($from: ident, $to: ident) => {
        impl From<$from> for $to {
            fn from(e: $from) -> $to {
                $to::$from(e)
            }
        }
    };
}

#[derive(Debug)]
pub enum BeaconChainError {
    InsufficientValidators,
    UnableToReadSlot,
    RevertedFinalizedEpoch {
        previous_epoch: Epoch,
        new_epoch: Epoch,
    },
    SlotClockDidNotStart,
    NoStateForSlot(Slot),
    UnableToFindTargetRoot(Slot),
    BeaconStateError(BeaconStateError),
    DBInconsistent(String),
    DBError(store::Error),
    ForkChoiceError(ForkChoiceError),
    ForkChoiceStoreError(ForkChoiceStoreError),
    MissingBeaconBlock(Hash256),
    MissingBeaconState(Hash256),
    SlotProcessingError(SlotProcessingError),
    StateAdvanceError(StateAdvanceError),
    UnableToAdvanceState(String),
    NoStateForAttestation {
        beacon_block_root: Hash256,
    },
    CannotAttestToFutureState,
    AttestationValidationError(AttestationValidationError),
    ExitValidationError(ExitValidationError),
    ProposerSlashingValidationError(ProposerSlashingValidationError),
    AttesterSlashingValidationError(AttesterSlashingValidationError),
    StateSkipTooLarge {
        start_slot: Slot,
        requested_slot: Slot,
        max_task_runtime: Duration,
    },
    MissingFinalizedStateRoot(Slot),
    /// Returned when an internal check fails, indicating corrupt data.
    InvariantViolated(String),
    SszTypesError(SszTypesError),
    NoProposerForSlot(Slot),
    CanonicalHeadLockTimeout,
    AttestationCacheLockTimeout,
    ValidatorPubkeyCacheLockTimeout,
    SnapshotCacheLockTimeout,
    IncorrectStateForAttestation(RelativeEpochError),
    InvalidValidatorPubkeyBytes(bls::Error),
    ValidatorPubkeyCacheIncomplete(usize),
    SignatureSetError(SignatureSetError),
    BlockSignatureVerifierError(state_processing::block_signature_verifier::Error),
    DuplicateValidatorPublicKey,
    ValidatorPubkeyCacheFileError(String),
    ValidatorIndexUnknown(usize),
    OpPoolError(OpPoolError),
    NaiveAggregationError(NaiveAggregationError),
    ObservedAttestationsError(ObservedAttestationsError),
    ObservedAttestersError(ObservedAttestersError),
    ObservedBlockProducersError(ObservedBlockProducersError),
    PruningError(PruningError),
    ArithError(ArithError),
    InvalidShufflingId {
        shuffling_epoch: Epoch,
        head_block_epoch: Epoch,
    },
    WeakSubjectivtyVerificationFailure,
    WeakSubjectivtyShutdownError(TrySendError<ShutdownReason>),
    AttestingPriorToHead {
        head_slot: Slot,
        request_slot: Slot,
    },
    BadPreState {
        parent_root: Hash256,
        parent_slot: Slot,
        block_root: Hash256,
        block_slot: Slot,
        state_slot: Slot,
    },
    InvalidStateForShuffling {
        state_epoch: Epoch,
        shuffling_epoch: Epoch,
    },
    InconsistentForwardsIter {
        request_slot: Slot,
        slot: Slot,
    },
}

easy_from_to!(SlotProcessingError, BeaconChainError);
easy_from_to!(AttestationValidationError, BeaconChainError);
easy_from_to!(ExitValidationError, BeaconChainError);
easy_from_to!(ProposerSlashingValidationError, BeaconChainError);
easy_from_to!(AttesterSlashingValidationError, BeaconChainError);
easy_from_to!(SszTypesError, BeaconChainError);
easy_from_to!(OpPoolError, BeaconChainError);
easy_from_to!(NaiveAggregationError, BeaconChainError);
easy_from_to!(ObservedAttestationsError, BeaconChainError);
easy_from_to!(ObservedAttestersError, BeaconChainError);
easy_from_to!(ObservedBlockProducersError, BeaconChainError);
easy_from_to!(BlockSignatureVerifierError, BeaconChainError);
easy_from_to!(PruningError, BeaconChainError);
easy_from_to!(ArithError, BeaconChainError);
easy_from_to!(ForkChoiceStoreError, BeaconChainError);
easy_from_to!(StateAdvanceError, BeaconChainError);

#[derive(Debug)]
pub enum BlockProductionError {
    UnableToGetHeadInfo(BeaconChainError),
    UnableToGetBlockRootFromState,
    UnableToReadSlot,
    UnableToProduceAtSlot(Slot),
    SlotProcessingError(SlotProcessingError),
    BlockProcessingError(BlockProcessingError),
    Eth1ChainError(Eth1ChainError),
    BeaconStateError(BeaconStateError),
    StateAdvanceError(StateAdvanceError),
    OpPoolError(OpPoolError),
    /// The `BeaconChain` was explicitly configured _without_ a connection to eth1, therefore it
    /// cannot produce blocks.
    NoEth1ChainConnection,
    StateSlotTooHigh {
        produce_at_slot: Slot,
        state_slot: Slot,
    },
}

easy_from_to!(BlockProcessingError, BlockProductionError);
easy_from_to!(BeaconStateError, BlockProductionError);
easy_from_to!(SlotProcessingError, BlockProductionError);
easy_from_to!(Eth1ChainError, BlockProductionError);
easy_from_to!(StateAdvanceError, BlockProductionError);

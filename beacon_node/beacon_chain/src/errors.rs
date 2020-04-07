use crate::eth1_chain::Error as Eth1ChainError;
use crate::fork_choice::Error as ForkChoiceError;
use crate::naive_aggregation_pool::Error as NaiveAggregationError;
use crate::observed_attestations::Error as ObservedAttestationsError;
use crate::observed_attesters::Error as ObservedAttestersError;
use operation_pool::OpPoolError;
use ssz::DecodeError;
use ssz_types::Error as SszTypesError;
use state_processing::{
    block_signature_verifier::Error as BlockSignatureVerifierError,
    per_block_processing::errors::AttestationValidationError,
    signature_sets::Error as SignatureSetError, BlockProcessingError, SlotProcessingError,
};
use std::time::Duration;
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

#[derive(Debug, PartialEq)]
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
    MissingBeaconBlock(Hash256),
    MissingBeaconState(Hash256),
    SlotProcessingError(SlotProcessingError),
    UnableToAdvanceState(String),
    NoStateForAttestation {
        beacon_block_root: Hash256,
    },
    CannotAttestToFutureState,
    AttestationValidationError(AttestationValidationError),
    StateSkipTooLarge {
        start_slot: Slot,
        requested_slot: Slot,
        max_task_runtime: Duration,
    },
    /// Returned when an internal check fails, indicating corrupt data.
    InvariantViolated(String),
    SszTypesError(SszTypesError),
    CanonicalHeadLockTimeout,
    AttestationCacheLockTimeout,
    ValidatorPubkeyCacheLockTimeout,
    IncorrectStateForAttestation(RelativeEpochError),
    InvalidValidatorPubkeyBytes(DecodeError),
    ValidatorPubkeyCacheIncomplete(usize),
    SignatureSetError(SignatureSetError),
    BlockSignatureVerifierError(state_processing::block_signature_verifier::Error),
    DuplicateValidatorPublicKey,
    ValidatorPubkeyCacheFileError(String),
    OpPoolError(OpPoolError),
    NaiveAggregationError(NaiveAggregationError),
    ObservedAttestationsError(ObservedAttestationsError),
    ObservedAttestersError(ObservedAttestersError),
}

easy_from_to!(SlotProcessingError, BeaconChainError);
easy_from_to!(AttestationValidationError, BeaconChainError);
easy_from_to!(SszTypesError, BeaconChainError);
easy_from_to!(OpPoolError, BeaconChainError);
easy_from_to!(NaiveAggregationError, BeaconChainError);
easy_from_to!(ObservedAttestationsError, BeaconChainError);
easy_from_to!(ObservedAttestersError, BeaconChainError);
easy_from_to!(BlockSignatureVerifierError, BeaconChainError);

#[derive(Debug, PartialEq)]
pub enum BlockProductionError {
    UnableToGetBlockRootFromState,
    UnableToReadSlot,
    UnableToProduceAtSlot(Slot),
    SlotProcessingError(SlotProcessingError),
    BlockProcessingError(BlockProcessingError),
    Eth1ChainError(Eth1ChainError),
    BeaconStateError(BeaconStateError),
    OpPoolError(OpPoolError),
    /// The `BeaconChain` was explicitly configured _without_ a connection to eth1, therefore it
    /// cannot produce blocks.
    NoEth1ChainConnection,
}

easy_from_to!(BlockProcessingError, BlockProductionError);
easy_from_to!(BeaconStateError, BlockProductionError);
easy_from_to!(SlotProcessingError, BlockProductionError);
easy_from_to!(Eth1ChainError, BlockProductionError);

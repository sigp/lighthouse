use crate::attester_cache::Error as AttesterCacheError;
use crate::beacon_chain::ForkChoiceError;
use crate::beacon_fork_choice_store::Error as ForkChoiceStoreError;
use crate::eth1_chain::Error as Eth1ChainError;
use crate::historical_blocks::HistoricalBlockError;
use crate::migrate::PruningError;
use crate::naive_aggregation_pool::Error as NaiveAggregationError;
use crate::observed_aggregates::Error as ObservedAttestationsError;
use crate::observed_attesters::Error as ObservedAttestersError;
use crate::observed_block_producers::Error as ObservedBlockProducersError;
use execution_layer::PayloadStatus;
use fork_choice::ExecutionStatus;
use futures::channel::mpsc::TrySendError;
use operation_pool::OpPoolError;
use safe_arith::ArithError;
use ssz_types::Error as SszTypesError;
use state_processing::{
    block_signature_verifier::Error as BlockSignatureVerifierError,
    per_block_processing::errors::{
        AttestationValidationError, AttesterSlashingValidationError, ExitValidationError,
        ProposerSlashingValidationError, SyncCommitteeMessageValidationError,
    },
    signature_sets::Error as SignatureSetError,
    state_advance::Error as StateAdvanceError,
    BlockProcessingError, BlockReplayError, SlotProcessingError,
};
use std::time::Duration;
use task_executor::ShutdownReason;
use tokio::task::JoinError;
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
    UnableToComputeTimeAtSlot,
    RevertedFinalizedEpoch {
        old: Checkpoint,
        new: Checkpoint,
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
    SyncCommitteeMessageValidationError(SyncCommitteeMessageValidationError),
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
    BlockReplayError(BlockReplayError),
    DuplicateValidatorPublicKey,
    ValidatorPubkeyCacheError(String),
    ValidatorIndexUnknown(usize),
    ValidatorPubkeyUnknown(PublicKeyBytes),
    OpPoolError(OpPoolError),
    NaiveAggregationError(NaiveAggregationError),
    ObservedAttestationsError(ObservedAttestationsError),
    ObservedAttestersError(ObservedAttestersError),
    ObservedBlockProducersError(ObservedBlockProducersError),
    AttesterCacheError(AttesterCacheError),
    PruningError(PruningError),
    ArithError(ArithError),
    InvalidShufflingId {
        shuffling_epoch: Epoch,
        head_block_epoch: Epoch,
    },
    WeakSubjectivtyVerificationFailure,
    WeakSubjectivtyShutdownError(TrySendError<ShutdownReason>),
    AttestingToFinalizedSlot {
        finalized_slot: Slot,
        request_slot: Slot,
    },
    AttestingToAncientSlot {
        lowest_permissible_slot: Slot,
        request_slot: Slot,
    },
    BadPreState {
        parent_root: Hash256,
        parent_slot: Slot,
        block_root: Hash256,
        block_slot: Slot,
        state_slot: Slot,
    },
    HistoricalBlockError(HistoricalBlockError),
    InvalidStateForShuffling {
        state_epoch: Epoch,
        shuffling_epoch: Epoch,
    },
    SyncDutiesError(BeaconStateError),
    InconsistentForwardsIter {
        request_slot: Slot,
        slot: Slot,
    },
    InvalidReorgSlotIter {
        old_slot: Slot,
        new_slot: Slot,
    },
    AltairForkDisabled,
    BuilderMissing,
    ExecutionLayerMissing,
    BlockVariantLacksExecutionPayload(Hash256),
    ExecutionLayerErrorPayloadReconstruction(ExecutionBlockHash, execution_layer::Error),
    BlockHashMissingFromExecutionLayer(ExecutionBlockHash),
    InconsistentPayloadReconstructed {
        slot: Slot,
        exec_block_hash: ExecutionBlockHash,
        canonical_payload_root: Hash256,
        reconstructed_payload_root: Hash256,
        canonical_transactions_root: Hash256,
        reconstructed_transactions_root: Hash256,
    },
    AddPayloadLogicError,
    ExecutionForkChoiceUpdateFailed(execution_layer::Error),
    PrepareProposerBlockingFailed(execution_layer::Error),
    ExecutionForkChoiceUpdateInvalid {
        status: PayloadStatus,
    },
    BlockRewardSlotError,
    BlockRewardAttestationError,
    BlockRewardSyncError,
    HeadMissingFromForkChoice(Hash256),
    FinalizedBlockMissingFromForkChoice(Hash256),
    HeadBlockMissingFromForkChoice(Hash256),
    InvalidFinalizedPayload {
        finalized_root: Hash256,
        execution_block_hash: ExecutionBlockHash,
    },
    InvalidFinalizedPayloadShutdownError(TrySendError<ShutdownReason>),
    JustifiedPayloadInvalid {
        justified_root: Hash256,
        execution_block_hash: Option<ExecutionBlockHash>,
    },
    ForkchoiceUpdate(execution_layer::Error),
    FinalizedCheckpointMismatch {
        head_state: Checkpoint,
        fork_choice: Hash256,
    },
    InvalidSlot(Slot),
    HeadBlockNotFullyVerified {
        beacon_block_root: Hash256,
        execution_status: ExecutionStatus,
    },
    CannotAttestToFinalizedBlock {
        beacon_block_root: Hash256,
    },
    SyncContributionDataReferencesFinalizedBlock {
        beacon_block_root: Hash256,
    },
    RuntimeShutdown,
    TokioJoin(tokio::task::JoinError),
    ProcessInvalidExecutionPayload(JoinError),
    ForkChoiceSignalOutOfOrder {
        current: Slot,
        latest: Slot,
    },
    ForkchoiceUpdateParamsMissing,
    HeadHasInvalidPayload {
        block_root: Hash256,
        execution_status: ExecutionStatus,
    },
    AttestationHeadNotInForkChoice(Hash256),
    MissingPersistedForkChoice,
    CommitteePromiseFailed(oneshot_broadcast::Error),
    MaxCommitteePromises(usize),
}

easy_from_to!(SlotProcessingError, BeaconChainError);
easy_from_to!(AttestationValidationError, BeaconChainError);
easy_from_to!(SyncCommitteeMessageValidationError, BeaconChainError);
easy_from_to!(ExitValidationError, BeaconChainError);
easy_from_to!(ProposerSlashingValidationError, BeaconChainError);
easy_from_to!(AttesterSlashingValidationError, BeaconChainError);
easy_from_to!(SszTypesError, BeaconChainError);
easy_from_to!(OpPoolError, BeaconChainError);
easy_from_to!(NaiveAggregationError, BeaconChainError);
easy_from_to!(ObservedAttestationsError, BeaconChainError);
easy_from_to!(ObservedAttestersError, BeaconChainError);
easy_from_to!(ObservedBlockProducersError, BeaconChainError);
easy_from_to!(AttesterCacheError, BeaconChainError);
easy_from_to!(BlockSignatureVerifierError, BeaconChainError);
easy_from_to!(PruningError, BeaconChainError);
easy_from_to!(ArithError, BeaconChainError);
easy_from_to!(ForkChoiceStoreError, BeaconChainError);
easy_from_to!(HistoricalBlockError, BeaconChainError);
easy_from_to!(StateAdvanceError, BeaconChainError);
easy_from_to!(BlockReplayError, BeaconChainError);

#[derive(Debug)]
pub enum BlockProductionError {
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
    ExecutionLayerMissing,
    BlockingFailed(execution_layer::Error),
    TerminalPoWBlockLookupFailed(execution_layer::Error),
    GetPayloadFailed(execution_layer::Error),
    GetBlobsFailed(execution_layer::Error),
    BlobPayloadMismatch {
        blob_block_hash: ExecutionBlockHash,
        payload_block_hash: ExecutionBlockHash,
    },
    FailedToReadFinalizedBlock(store::Error),
    MissingFinalizedBlock(Hash256),
    BlockTooLarge(usize),
    ForkChoiceError(BeaconChainError),
    ShuttingDown,
    MissingSyncAggregate,
    MissingExecutionPayload,
    TokioJoin(tokio::task::JoinError),
    BeaconChain(BeaconChainError),
    InvalidPayloadFork,
}

easy_from_to!(BlockProcessingError, BlockProductionError);
easy_from_to!(BeaconStateError, BlockProductionError);
easy_from_to!(SlotProcessingError, BlockProductionError);
easy_from_to!(Eth1ChainError, BlockProductionError);
easy_from_to!(StateAdvanceError, BlockProductionError);

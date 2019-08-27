use super::signature_sets::Error as SignatureSetError;
use types::*;

/// The error returned from the `per_block_processing` function. Indicates that a block is either
/// invalid, or we were unable to determine it's validity (we encountered an unexpected error).
///
/// Any of the `...Error` variants indicate that at some point during block (and block operation)
/// verification, there was an error. There is no indication as to _where_ that error happened
/// (e.g., when processing attestations instead of when processing deposits).
#[derive(Debug, PartialEq)]
pub enum BlockProcessingError {
    RandaoSignatureInvalid,
    BulkSignatureVerificationFailed,
    StateRootMismatch,
    DepositCountInvalid {
        expected: usize,
        found: usize,
    },
    DuplicateTransfers {
        duplicates: usize,
    },
    HeaderInvalid {
        reason: HeaderInvalid,
    },
    ProposerSlashingInvalid {
        index: usize,
        reason: ProposerSlashingInvalid,
    },
    AttesterSlashingInvalid {
        index: usize,
        reason: AttesterSlashingInvalid,
    },
    IndexedAttestationInvalid {
        index: usize,
        reason: IndexedAttestationInvalid,
    },
    AttestationInvalid {
        index: usize,
        reason: AttestationInvalid,
    },
    DepositInvalid {
        index: usize,
        reason: DepositInvalid,
    },
    ExitInvalid {
        index: usize,
        reason: ExitInvalid,
    },
    TransferInvalid {
        index: usize,
        reason: TransferInvalid,
    },
    BeaconStateError(BeaconStateError),
    SignatureSetError(SignatureSetError),
    SszTypesError(ssz_types::Error),
}

impl From<BeaconStateError> for BlockProcessingError {
    fn from(e: BeaconStateError) -> Self {
        BlockProcessingError::BeaconStateError(e)
    }
}

impl From<SignatureSetError> for BlockProcessingError {
    fn from(e: SignatureSetError) -> Self {
        BlockProcessingError::SignatureSetError(e)
    }
}

impl From<ssz_types::Error> for BlockProcessingError {
    fn from(error: ssz_types::Error) -> Self {
        BlockProcessingError::SszTypesError(error)
    }
}

impl From<BlockOperationError<HeaderInvalid>> for BlockProcessingError {
    fn from(e: BlockOperationError<HeaderInvalid>) -> BlockProcessingError {
        match e {
            BlockOperationError::Invalid(reason) => BlockProcessingError::HeaderInvalid { reason },
            BlockOperationError::BeaconStateError(e) => BlockProcessingError::BeaconStateError(e),
            BlockOperationError::SignatureSetError(e) => BlockProcessingError::SignatureSetError(e),
            BlockOperationError::SszTypesError(e) => BlockProcessingError::SszTypesError(e),
        }
    }
}

/// A conversion that consumes `self` and adds an `index` variable to resulting struct.
///
/// Used here to allow converting an error into an upstream error that points to the object that
/// caused the error. For example, pointing to the index of an attestation that caused the
/// `AttestationInvalid` error.
pub trait IntoWithIndex<T>: Sized {
    fn into_with_index(self, index: usize) -> T;
}

macro_rules! impl_into_block_processing_error_with_index {
    ($($type: ident),*) => {
        $(
            impl IntoWithIndex<BlockProcessingError> for BlockOperationError<$type> {
                fn into_with_index(self, index: usize) -> BlockProcessingError {
                    match self {
                        BlockOperationError::Invalid(reason) => BlockProcessingError::$type {
                            index,
                            reason
                        },
                        BlockOperationError::BeaconStateError(e) => BlockProcessingError::BeaconStateError(e),
                        BlockOperationError::SignatureSetError(e) => BlockProcessingError::SignatureSetError(e),
                        BlockOperationError::SszTypesError(e) => BlockProcessingError::SszTypesError(e),
                    }
                }
            }
        )*
    };
}

impl_into_block_processing_error_with_index!(
    ProposerSlashingInvalid,
    AttesterSlashingInvalid,
    IndexedAttestationInvalid,
    AttestationInvalid,
    DepositInvalid,
    ExitInvalid,
    TransferInvalid
);

pub type HeaderValidationError = BlockOperationError<HeaderInvalid>;
pub type AttesterSlashingValidationError = BlockOperationError<AttesterSlashingInvalid>;
pub type ProposerSlashingValidationError = BlockOperationError<ProposerSlashingInvalid>;
pub type AttestationValidationError = BlockOperationError<AttestationInvalid>;
pub type DepositValidationError = BlockOperationError<DepositInvalid>;
pub type ExitValidationError = BlockOperationError<ExitInvalid>;
pub type TransferValidationError = BlockOperationError<TransferInvalid>;

#[derive(Debug, PartialEq)]
pub enum BlockOperationError<T> {
    Invalid(T),
    BeaconStateError(BeaconStateError),
    SignatureSetError(SignatureSetError),
    SszTypesError(ssz_types::Error),
}

impl<T> BlockOperationError<T> {
    pub fn invalid(reason: T) -> BlockOperationError<T> {
        BlockOperationError::Invalid(reason)
    }
}

impl<T> From<BeaconStateError> for BlockOperationError<T> {
    fn from(e: BeaconStateError) -> Self {
        BlockOperationError::BeaconStateError(e)
    }
}
impl<T> From<SignatureSetError> for BlockOperationError<T> {
    fn from(e: SignatureSetError) -> Self {
        BlockOperationError::SignatureSetError(e)
    }
}

impl<T> From<ssz_types::Error> for BlockOperationError<T> {
    fn from(error: ssz_types::Error) -> Self {
        BlockOperationError::SszTypesError(error)
    }
}

#[derive(Debug, PartialEq)]
pub enum HeaderInvalid {
    ProposalSignatureInvalid,
    StateSlotMismatch,
    ParentBlockRootMismatch { state: Hash256, block: Hash256 },
    ProposerSlashed(usize),
}

#[derive(Debug, PartialEq)]
pub enum ProposerSlashingInvalid {
    /// The proposer index is not a known validator.
    ProposerUnknown(u64),
    /// The two proposal have different epochs.
    ///
    /// (proposal_1_slot, proposal_2_slot)
    ProposalEpochMismatch(Slot, Slot),
    /// The proposals are identical and therefore not slashable.
    ProposalsIdentical,
    /// The specified proposer cannot be slashed because they are already slashed, or not active.
    ProposerNotSlashable(u64),
    /// The first proposal signature was invalid.
    BadProposal1Signature,
    /// The second proposal signature was invalid.
    BadProposal2Signature,
}

#[derive(Debug, PartialEq)]
pub enum AttesterSlashingInvalid {
    /// The attestation data is identical, an attestation cannot conflict with itself.
    AttestationDataIdentical,
    /// The attestations were not in conflict.
    NotSlashable,
    /// The first `IndexedAttestation` was invalid.
    IndexedAttestation1Invalid(BlockOperationError<IndexedAttestationInvalid>),
    /// The second `IndexedAttestation` was invalid.
    IndexedAttestation2Invalid(BlockOperationError<IndexedAttestationInvalid>),
    /// The validator index is unknown. One cannot slash one who does not exist.
    UnknownValidator(u64),
    /// The specified validator has already been withdrawn.
    ValidatorAlreadyWithdrawn(u64),
    /// There were no indices able to be slashed.
    NoSlashableIndices,
}

/// Describes why an object is invalid.
#[derive(Debug, PartialEq)]
pub enum AttestationInvalid {
    /// Shard exceeds SHARD_COUNT.
    BadShard,
    /// Attestation included before the inclusion delay.
    IncludedTooEarly {
        state: Slot,
        delay: u64,
        attestation: Slot,
    },
    /// Attestation slot is too far in the past to be included in a block.
    IncludedTooLate { state: Slot, attestation: Slot },
    /// Attestation target epoch does not match the current or previous epoch.
    BadTargetEpoch,
    /// Attestation justified checkpoint doesn't match the state's current or previous justified
    /// checkpoint.
    ///
    /// `is_current` is `true` if the attestation was compared to the
    /// `state.current_justified_checkpoint`, `false` if compared to `state.previous_justified_checkpoint`.
    WrongJustifiedCheckpoint {
        state: Checkpoint,
        attestation: Checkpoint,
        is_current: bool,
    },
    /// Attestation crosslink root does not match the state crosslink root for the attestations
    /// slot.
    BadParentCrosslinkHash,
    /// Attestation crosslink start epoch does not match the end epoch of the state crosslink.
    BadParentCrosslinkStartEpoch,
    /// Attestation crosslink end epoch does not match the expected value.
    BadParentCrosslinkEndEpoch,
    /// The custody bitfield has some bits set `true`. This is not allowed in phase 0.
    CustodyBitfieldHasSetBits,
    /// There are no set bits on the attestation -- an attestation must be signed by at least one
    /// validator.
    AggregationBitfieldIsEmpty,
    /// The custody bitfield length is not the smallest possible size to represent the committee.
    BadCustodyBitfieldLength {
        committee_len: usize,
        bitfield_len: usize,
    },
    /// The aggregation bitfield length is not the smallest possible size to represent the committee.
    BadAggregationBitfieldLength {
        committee_len: usize,
        bitfield_len: usize,
    },
    /// The bits set in the custody bitfield are not a subset of those set in the aggregation bits.
    CustodyBitfieldNotSubset,
    /// There was no known committee in this `epoch` for the given shard and slot.
    NoCommitteeForShard { shard: u64, slot: Slot },
    /// The validator index was unknown.
    UnknownValidator(u64),
    /// The attestation signature verification failed.
    BadSignature,
    /// The shard block root was not set to zero. This is a phase 0 requirement.
    ShardBlockRootNotZero,
    /// The indexed attestation created from this attestation was found to be invalid.
    BadIndexedAttestation(IndexedAttestationInvalid),
}

impl From<BlockOperationError<IndexedAttestationInvalid>>
    for BlockOperationError<AttestationInvalid>
{
    fn from(e: BlockOperationError<IndexedAttestationInvalid>) -> Self {
        match e {
            BlockOperationError::Invalid(e) => {
                BlockOperationError::invalid(AttestationInvalid::BadIndexedAttestation(e))
            }
            BlockOperationError::BeaconStateError(e) => BlockOperationError::BeaconStateError(e),
            BlockOperationError::SignatureSetError(e) => BlockOperationError::SignatureSetError(e),
            BlockOperationError::SszTypesError(e) => BlockOperationError::SszTypesError(e),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum IndexedAttestationInvalid {
    /// The custody bit 0 validators intersect with the bit 1 validators.
    CustodyBitValidatorsIntersect,
    /// The custody bitfield has some bits set `true`. This is not allowed in phase 0.
    CustodyBitfieldHasSetBits,
    /// The custody bitfield violated a type-level bound.
    CustodyBitfieldBoundsError(ssz_types::Error),
    /// No validator indices were specified.
    NoValidatorIndices,
    /// The number of indices exceeds the global maximum.
    ///
    /// (max_indices, indices_given)
    MaxIndicesExceed(usize, usize),
    /// The validator indices were not in increasing order.
    ///
    /// The error occurred between the given `index` and `index + 1`
    BadValidatorIndicesOrdering(usize),
    /// The validator index is unknown. One cannot slash one who does not exist.
    UnknownValidator(u64),
    /// The indexed attestation aggregate signature was not valid.
    BadSignature,
    /// There was an error whilst attempting to get a set of signatures. The signatures may have
    /// been invalid or an internal error occurred.
    SignatureSetError(SignatureSetError),
}

#[derive(Debug, PartialEq)]
pub enum DepositInvalid {
    /// The deposit index does not match the state index.
    BadIndex { state: u64, deposit: u64 },
    /// The signature (proof-of-possession) does not match the given pubkey.
    BadSignature,
    /// The signature or pubkey does not represent a valid BLS point.
    BadBlsBytes,
    /// The specified `branch` and `index` did not form a valid proof that the deposit is included
    /// in the eth1 deposit root.
    BadMerkleProof,
}

#[derive(Debug, PartialEq)]
pub enum ExitInvalid {
    /// The specified validator is not active.
    NotActive(u64),
    /// The specified validator is not in the state's validator registry.
    ValidatorUnknown(u64),
    /// The specified validator has a non-maximum exit epoch.
    AlreadyExited(u64),
    /// The specified validator has already initiated exit.
    AlreadyInitiatedExited(u64),
    /// The exit is for a future epoch.
    FutureEpoch { state: Epoch, exit: Epoch },
    /// The validator has not been active for long enough.
    TooYoungToExit {
        current_epoch: Epoch,
        earliest_exit_epoch: Epoch,
    },
    /// The exit signature was not signed by the validator.
    BadSignature,
    /// There was an error whilst attempting to get a set of signatures. The signatures may have
    /// been invalid or an internal error occurred.
    SignatureSetError(SignatureSetError),
}

#[derive(Debug, PartialEq)]
pub enum TransferInvalid {
    /// The validator indicated by `transfer.from` is unknown.
    FromValidatorUnknown(u64),
    /// The validator indicated by `transfer.to` is unknown.
    ToValidatorUnknown(u64),
    /// The balance of `transfer.from` is insufficient.
    ///
    /// (required, available)
    FromBalanceInsufficient(u64, u64),
    /// Adding `transfer.fee` to `transfer.amount` causes an overflow.
    ///
    /// (transfer_fee, transfer_amount)
    FeeOverflow(u64, u64),
    /// This transfer would result in the `transfer.from` account to have `0 < balance <
    /// min_deposit_amount`
    ///
    /// (resulting_amount, min_deposit_amount)
    SenderDust(u64, u64),
    /// This transfer would result in the `transfer.to` account to have `0 < balance <
    /// min_deposit_amount`
    ///
    /// (resulting_amount, min_deposit_amount)
    RecipientDust(u64, u64),
    /// The state slot does not match `transfer.slot`.
    ///
    /// (state_slot, transfer_slot)
    StateSlotMismatch(Slot, Slot),
    /// The `transfer.slot` is in the past relative to the state slot.
    ///
    ///
    /// (state_slot, transfer_slot)
    TransferSlotInPast(Slot, Slot),
    /// The `transfer.from` validator has been activated and is not withdrawable.
    ///
    /// (from_validator)
    FromValidatorIneligibleForTransfer(u64),
    /// The validators withdrawal credentials do not match `transfer.pubkey`.
    ///
    /// (state_credentials, transfer_pubkey_credentials)
    WithdrawalCredentialsMismatch(Hash256, Hash256),
    /// The deposit was not signed by `deposit.pubkey`.
    BadSignature,
    /// Overflow when adding to `transfer.to` balance.
    ///
    /// (to_balance, transfer_amount)
    ToBalanceOverflow(u64, u64),
    /// Overflow when adding to beacon proposer balance.
    ///
    /// (proposer_balance, transfer_fee)
    ProposerBalanceOverflow(u64, u64),
}

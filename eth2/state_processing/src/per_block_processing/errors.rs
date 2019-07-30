use types::*;

macro_rules! impl_from_beacon_state_error {
    ($type: ident) => {
        impl From<BeaconStateError> for $type {
            fn from(e: BeaconStateError) -> $type {
                $type::BeaconStateError(e)
            }
        }
    };
}

macro_rules! impl_into_with_index_with_beacon_error {
    ($error_type: ident, $invalid_type: ident) => {
        impl IntoWithIndex<BlockProcessingError> for $error_type {
            fn into_with_index(self, i: usize) -> BlockProcessingError {
                match self {
                    $error_type::Invalid(e) => {
                        BlockProcessingError::Invalid(BlockInvalid::$invalid_type(i, e))
                    }
                    $error_type::BeaconStateError(e) => BlockProcessingError::BeaconStateError(e),
                }
            }
        }
    };
}

macro_rules! impl_into_with_index_without_beacon_error {
    ($error_type: ident, $invalid_type: ident) => {
        impl IntoWithIndex<BlockProcessingError> for $error_type {
            fn into_with_index(self, i: usize) -> BlockProcessingError {
                match self {
                    $error_type::Invalid(e) => {
                        BlockProcessingError::Invalid(BlockInvalid::$invalid_type(i, e))
                    }
                }
            }
        }
    };
}

/// A conversion that consumes `self` and adds an `index` variable to resulting struct.
///
/// Used here to allow converting an error into an upstream error that points to the object that
/// caused the error. For example, pointing to the index of an attestation that caused the
/// `AttestationInvalid` error.
pub trait IntoWithIndex<T>: Sized {
    fn into_with_index(self, index: usize) -> T;
}

/*
 * Block Validation
 */

/// The object is invalid or validation failed.
#[derive(Debug, PartialEq)]
pub enum BlockProcessingError {
    /// Validation completed successfully and the object is invalid.
    Invalid(BlockInvalid),
    /// Encountered a `BeaconStateError` whilst attempting to determine validity.
    BeaconStateError(BeaconStateError),
    /// Encountered an `ssz_types::Error` whilst attempting to determine validity.
    SszTypesError(ssz_types::Error),
}

impl_from_beacon_state_error!(BlockProcessingError);

/// Describes why an object is invalid.
#[derive(Debug, PartialEq)]
pub enum BlockInvalid {
    StateSlotMismatch,
    ParentBlockRootMismatch {
        state: Hash256,
        block: Hash256,
    },
    ProposerSlashed(usize),
    BadSignature,
    BadRandaoSignature,
    MaxAttestationsExceeded,
    MaxAttesterSlashingsExceed,
    MaxProposerSlashingsExceeded,
    DepositCountInvalid,
    DuplicateTransfers,
    MaxExitsExceeded,
    MaxTransfersExceed,
    AttestationInvalid(usize, AttestationInvalid),
    /// A `IndexedAttestation` inside an `AttesterSlashing` was invalid.
    ///
    /// To determine the offending `AttesterSlashing` index, divide the error message `usize` by two.
    IndexedAttestationInvalid(usize, IndexedAttestationInvalid),
    AttesterSlashingInvalid(usize, AttesterSlashingInvalid),
    ProposerSlashingInvalid(usize, ProposerSlashingInvalid),
    DepositInvalid(usize, DepositInvalid),
    // TODO: merge this into the `DepositInvalid` error.
    DepositProcessingFailed(usize),
    ExitInvalid(usize, ExitInvalid),
    TransferInvalid(usize, TransferInvalid),
    // NOTE: this is only used in tests, normally a state root mismatch is handled
    // in the beacon_chain rather than in state_processing
    StateRootMismatch,
}

impl From<ssz_types::Error> for BlockProcessingError {
    fn from(error: ssz_types::Error) -> Self {
        BlockProcessingError::SszTypesError(error)
    }
}

impl Into<BlockProcessingError> for BlockInvalid {
    fn into(self) -> BlockProcessingError {
        BlockProcessingError::Invalid(self)
    }
}

/*
 * Attestation Validation
 */

/// The object is invalid or validation failed.
#[derive(Debug, PartialEq)]
pub enum AttestationValidationError {
    /// Validation completed successfully and the object is invalid.
    Invalid(AttestationInvalid),
    /// Encountered a `BeaconStateError` whilst attempting to determine validity.
    BeaconStateError(BeaconStateError),
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

impl_from_beacon_state_error!(AttestationValidationError);
impl_into_with_index_with_beacon_error!(AttestationValidationError, AttestationInvalid);

impl From<IndexedAttestationValidationError> for AttestationValidationError {
    fn from(err: IndexedAttestationValidationError) -> Self {
        let IndexedAttestationValidationError::Invalid(e) = err;
        AttestationValidationError::Invalid(AttestationInvalid::BadIndexedAttestation(e))
    }
}

impl From<ssz_types::Error> for AttestationValidationError {
    fn from(error: ssz_types::Error) -> Self {
        Self::from(IndexedAttestationValidationError::from(error))
    }
}

/*
 * `AttesterSlashing` Validation
 */

/// The object is invalid or validation failed.
#[derive(Debug, PartialEq)]
pub enum AttesterSlashingValidationError {
    /// Validation completed successfully and the object is invalid.
    Invalid(AttesterSlashingInvalid),
    /// Encountered a `BeaconStateError` whilst attempting to determine validity.
    BeaconStateError(BeaconStateError),
}

/// Describes why an object is invalid.
#[derive(Debug, PartialEq)]
pub enum AttesterSlashingInvalid {
    /// The attestation data is identical, an attestation cannot conflict with itself.
    AttestationDataIdentical,
    /// The attestations were not in conflict.
    NotSlashable,
    /// The first `IndexedAttestation` was invalid.
    IndexedAttestation1Invalid(IndexedAttestationInvalid),
    /// The second `IndexedAttestation` was invalid.
    IndexedAttestation2Invalid(IndexedAttestationInvalid),
    /// The validator index is unknown. One cannot slash one who does not exist.
    UnknownValidator(u64),
    /// The specified validator has already been withdrawn.
    ValidatorAlreadyWithdrawn(u64),
    /// There were no indices able to be slashed.
    NoSlashableIndices,
}

impl_from_beacon_state_error!(AttesterSlashingValidationError);
impl_into_with_index_with_beacon_error!(AttesterSlashingValidationError, AttesterSlashingInvalid);

/*
 * `IndexedAttestation` Validation
 */

/// The object is invalid or validation failed.
#[derive(Debug, PartialEq)]
pub enum IndexedAttestationValidationError {
    /// Validation completed successfully and the object is invalid.
    Invalid(IndexedAttestationInvalid),
}

/// Describes why an object is invalid.
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
}

impl Into<IndexedAttestationInvalid> for IndexedAttestationValidationError {
    fn into(self) -> IndexedAttestationInvalid {
        match self {
            IndexedAttestationValidationError::Invalid(e) => e,
        }
    }
}

impl From<ssz_types::Error> for IndexedAttestationValidationError {
    fn from(error: ssz_types::Error) -> Self {
        IndexedAttestationValidationError::Invalid(
            IndexedAttestationInvalid::CustodyBitfieldBoundsError(error),
        )
    }
}

impl_into_with_index_without_beacon_error!(
    IndexedAttestationValidationError,
    IndexedAttestationInvalid
);

/*
 * `ProposerSlashing` Validation
 */

/// The object is invalid or validation failed.
#[derive(Debug, PartialEq)]
pub enum ProposerSlashingValidationError {
    /// Validation completed successfully and the object is invalid.
    Invalid(ProposerSlashingInvalid),
}

/// Describes why an object is invalid.
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

impl_into_with_index_without_beacon_error!(
    ProposerSlashingValidationError,
    ProposerSlashingInvalid
);

/*
 * `Deposit` Validation
 */

/// The object is invalid or validation failed.
#[derive(Debug, PartialEq)]
pub enum DepositValidationError {
    /// Validation completed successfully and the object is invalid.
    Invalid(DepositInvalid),
    /// Encountered a `BeaconStateError` whilst attempting to determine validity.
    BeaconStateError(BeaconStateError),
}

/// Describes why an object is invalid.
#[derive(Debug, PartialEq)]
pub enum DepositInvalid {
    /// The deposit index does not match the state index.
    BadIndex { state: u64, deposit: u64 },
    /// The signature (proof-of-possession) does not match the given pubkey.
    BadSignature,
    /// The specified `branch` and `index` did not form a valid proof that the deposit is included
    /// in the eth1 deposit root.
    BadMerkleProof,
}

impl_from_beacon_state_error!(DepositValidationError);
impl_into_with_index_with_beacon_error!(DepositValidationError, DepositInvalid);

/*
 * `Exit` Validation
 */

/// The object is invalid or validation failed.
#[derive(Debug, PartialEq)]
pub enum ExitValidationError {
    /// Validation completed successfully and the object is invalid.
    Invalid(ExitInvalid),
}

/// Describes why an object is invalid.
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
}

impl_into_with_index_without_beacon_error!(ExitValidationError, ExitInvalid);

/*
 * `Transfer` Validation
 */

/// The object is invalid or validation failed.
#[derive(Debug, PartialEq)]
pub enum TransferValidationError {
    /// Validation completed successfully and the object is invalid.
    Invalid(TransferInvalid),
    /// Encountered a `BeaconStateError` whilst attempting to determine validity.
    BeaconStateError(BeaconStateError),
}

/// Describes why an object is invalid.
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

impl_from_beacon_state_error!(TransferValidationError);
impl_into_with_index_with_beacon_error!(TransferValidationError, TransferInvalid);

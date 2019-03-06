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
}

impl_from_beacon_state_error!(BlockProcessingError);

/// Describes why an object is invalid.
#[derive(Debug, PartialEq)]
pub enum BlockInvalid {
    StateSlotMismatch,
    BadSignature,
    BadRandaoSignature,
    MaxAttestationsExceeded,
    MaxAttesterSlashingsExceed,
    MaxProposerSlashingsExceeded,
    MaxDepositsExceeded,
    MaxExitsExceeded,
    MaxTransfersExceed,
    AttestationInvalid(usize, AttestationInvalid),
    AttesterSlashingInvalid(usize, AttesterSlashingInvalid),
    ProposerSlashingInvalid(usize, ProposerSlashingInvalid),
    DepositInvalid(usize, DepositInvalid),
    // TODO: merge this into the `DepositInvalid` error.
    DepositProcessingFailed(usize),
    ExitInvalid(usize, ExitInvalid),
    TransferInvalid(usize, TransferInvalid),
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
    /// Attestation references a pre-genesis slot.
    ///
    /// (genesis_slot, attestation_slot)
    PreGenesis(Slot, Slot),
    /// Attestation included before the inclusion delay.
    ///
    /// (state_slot, inclusion_delay, attestation_slot)
    IncludedTooEarly(Slot, u64, Slot),
    /// Attestation slot is too far in the past to be included in a block.
    ///
    /// (state_slot, attestation_slot)
    IncludedTooLate(Slot, Slot),
    /// Attestation justified epoch does not match the states current or previous justified epoch.
    ///
    /// (attestation_justified_epoch, state_epoch, used_previous_epoch)
    WrongJustifiedEpoch(Epoch, Epoch, bool),
    /// Attestation justified epoch root does not match root known to the state.
    ///
    /// (state_justified_root, attestation_justified_root)
    WrongJustifiedRoot(Hash256, Hash256),
    /// Attestation crosslink root does not match the state crosslink root for the attestations
    /// slot.
    BadLatestCrosslinkRoot,
    /// The custody bitfield has some bits set `true`. This is not allowed in phase 0.
    CustodyBitfieldHasSetBits,
    /// There are no set bits on the attestation -- an attestation must be signed by at least one
    /// validator.
    AggregationBitfieldIsEmpty,
    /// The custody bitfield length is not the smallest possible size to represent the committee.
    ///
    /// (committee_len, bitfield_len)
    BadCustodyBitfieldLength(usize, usize),
    /// The aggregation bitfield length is not the smallest possible size to represent the committee.
    ///
    /// (committee_len, bitfield_len)
    BadAggregationBitfieldLength(usize, usize),
    /// There was no known committee for the given shard in the given slot.
    ///
    /// (attestation_data_shard, attestation_data_slot)
    NoCommitteeForShard(u64, Slot),
    /// The attestation signature verification failed.
    BadSignature,
    /// The shard block root was not set to zero. This is a phase 0 requirement.
    ShardBlockRootNotZero,
}

impl_from_beacon_state_error!(AttestationValidationError);
impl_into_with_index_with_beacon_error!(AttestationValidationError, AttestationInvalid);

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
    /// The first `SlashableAttestation` was invalid.
    SlashableAttestation1Invalid(SlashableAttestationInvalid),
    /// The second `SlashableAttestation` was invalid.
    SlashableAttestation2Invalid(SlashableAttestationInvalid),
    /// The validator index is unknown. One cannot slash one who does not exist.
    UnknownValidator(u64),
    /// There were no indices able to be slashed.
    NoSlashableIndices,
}

impl_from_beacon_state_error!(AttesterSlashingValidationError);
impl_into_with_index_with_beacon_error!(AttesterSlashingValidationError, AttesterSlashingInvalid);

/*
 * `SlashableAttestation` Validation
 */

/// The object is invalid or validation failed.
#[derive(Debug, PartialEq)]
pub enum SlashableAttestationValidationError {
    /// Validation completed successfully and the object is invalid.
    Invalid(SlashableAttestationInvalid),
}

/// Describes why an object is invalid.
#[derive(Debug, PartialEq)]
pub enum SlashableAttestationInvalid {
    /// The custody bitfield has some bits set `true`. This is not allowed in phase 0.
    CustodyBitfieldHasSetBits,
    /// No validator indices were specified.
    NoValidatorIndices,
    /// The validator indices were not in increasing order.
    ///
    /// The error occured between the given `index` and `index + 1`
    BadValidatorIndicesOrdering(usize),
    /// The custody bitfield length is not the smallest possible size to represent the validators.
    ///
    /// (validators_len, bitfield_len)
    BadCustodyBitfieldLength(usize, usize),
    /// The number of slashable indices exceed the global maximum.
    ///
    /// (max_indices, indices_given)
    MaxIndicesExceed(usize, usize),
    /// The validator index is unknown. One cannot slash one who does not exist.
    UnknownValidator(u64),
    /// The slashable attestation aggregate signature was not valid.
    BadSignature,
}

impl Into<SlashableAttestationInvalid> for SlashableAttestationValidationError {
    fn into(self) -> SlashableAttestationInvalid {
        match self {
            SlashableAttestationValidationError::Invalid(e) => e,
        }
    }
}

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
    /// The two proposal have different slots.
    ///
    /// (proposal_1_slot, proposal_2_slot)
    ProposalSlotMismatch(Slot, Slot),
    /// The two proposal have different shards.
    ///
    /// (proposal_1_shard, proposal_2_shard)
    ProposalShardMismatch(u64, u64),
    /// The two proposal have different block roots.
    ///
    /// (proposal_1_root, proposal_2_root)
    ProposalBlockRootMismatch(Hash256, Hash256),
    /// The specified proposer has already been slashed.
    ProposerAlreadySlashed,
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
}

/// Describes why an object is invalid.
#[derive(Debug, PartialEq)]
pub enum DepositInvalid {
    /// The deposit index does not match the state index.
    ///
    /// (state_index, deposit_index)
    BadIndex(u64, u64),
}

impl_into_with_index_without_beacon_error!(DepositValidationError, DepositInvalid);

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
    /// The specified validator is not in the state's validator registry.
    ValidatorUnknown(u64),
    AlreadyExited,
    /// The exit is for a future epoch.
    ///
    /// (state_epoch, exit_epoch)
    FutureEpoch(Epoch, Epoch),
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
}

/// Describes why an object is invalid.
#[derive(Debug, PartialEq)]
pub enum TransferInvalid {}

impl_into_with_index_without_beacon_error!(TransferValidationError, TransferInvalid);

use types::BeaconStateError;

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

pub trait IntoWithIndex<T>: Sized {
    fn into_with_index(self, i: usize) -> T;
}

/*
 * Block Validation
 */

#[derive(Debug, PartialEq)]
pub enum BlockProcessingError {
    /// The `BeaconBlock` is invalid.
    Invalid(BlockInvalid),
    BeaconStateError(BeaconStateError),
}

impl_from_beacon_state_error!(BlockProcessingError);

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

#[derive(Debug, PartialEq)]
pub enum AttestationValidationError {
    /// The `Attestation` is invalid.
    Invalid(AttestationInvalid),
    /// Encountered a `BeaconStateError` whilst attempting to determine validity.
    BeaconStateError(BeaconStateError),
}

#[derive(Debug, PartialEq)]
pub enum AttestationInvalid {
    PreGenesis,
    IncludedTooEarly,
    IncludedTooLate,
    WrongJustifiedSlot,
    WrongJustifiedRoot,
    BadLatestCrosslinkRoot,
    CustodyBitfieldHasSetBits,
    AggregationBitfieldIsEmpty,
    BadAggregationBitfieldLength,
    BadCustodyBitfieldLength,
    NoCommitteeForShard,
    BadSignature,
    ShardBlockRootNotZero,
}

impl_from_beacon_state_error!(AttestationValidationError);
impl_into_with_index_with_beacon_error!(AttestationValidationError, AttestationInvalid);

/*
 * `AttesterSlashing` Validation
 */

#[derive(Debug, PartialEq)]
pub enum AttesterSlashingValidationError {
    /// The `SlashableAttestation` is invalid.
    Invalid(AttesterSlashingInvalid),
    /// Encountered a `BeaconStateError` whilst attempting to determine validity.
    BeaconStateError(BeaconStateError),
}

#[derive(Debug, PartialEq)]
pub enum AttesterSlashingInvalid {
    AttestationDataIdentical,
    NotSlashable,
    SlashableAttestation1Invalid(SlashableAttestationInvalid),
    SlashableAttestation2Invalid(SlashableAttestationInvalid),
    UnknownValidator,
    NoSlashableIndices,
}

impl_from_beacon_state_error!(AttesterSlashingValidationError);
impl_into_with_index_with_beacon_error!(AttesterSlashingValidationError, AttesterSlashingInvalid);

/*
 * `SlashableAttestation` Validation
 */

#[derive(Debug, PartialEq)]
pub enum SlashableAttestationValidationError {
    Invalid(SlashableAttestationInvalid),
}

#[derive(Debug, PartialEq)]
pub enum SlashableAttestationInvalid {
    CustodyBitfieldHasSetBits,
    NoValidatorIndices,
    BadValidatorIndicesOrdering,
    BadCustodyBitfieldLength,
    MaxIndicesExceed,
    UnknownValidator,
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

#[derive(Debug, PartialEq)]
pub enum ProposerSlashingValidationError {
    Invalid(ProposerSlashingInvalid),
}

#[derive(Debug, PartialEq)]
pub enum ProposerSlashingInvalid {
    ProposerUnknown,
    ProposalSlotMismatch,
    ProposalShardMismatch,
    ProposalBlockRootMismatch,
    ProposerAlreadySlashed,
    BadProposal1Signature,
    BadProposal2Signature,
}

impl_into_with_index_without_beacon_error!(
    ProposerSlashingValidationError,
    ProposerSlashingInvalid
);

/*
 * `Deposit` Validation
 */

#[derive(Debug, PartialEq)]
pub enum DepositValidationError {
    Invalid(DepositInvalid),
}

#[derive(Debug, PartialEq)]
pub enum DepositInvalid {
    BadIndex,
}

impl_into_with_index_without_beacon_error!(DepositValidationError, DepositInvalid);

/*
 * `Exit` Validation
 */

#[derive(Debug, PartialEq)]
pub enum ExitValidationError {
    Invalid(ExitInvalid),
}

#[derive(Debug, PartialEq)]
pub enum ExitInvalid {
    ValidatorUnknown,
    AlreadyExited,
    FutureEpoch,
    BadSignature,
}

impl_into_with_index_without_beacon_error!(ExitValidationError, ExitInvalid);

/*
 * `Transfer` Validation
 */

#[derive(Debug, PartialEq)]
pub enum TransferValidationError {
    Invalid(TransferInvalid),
}

#[derive(Debug, PartialEq)]
pub enum TransferInvalid {}

impl_into_with_index_without_beacon_error!(TransferValidationError, TransferInvalid);

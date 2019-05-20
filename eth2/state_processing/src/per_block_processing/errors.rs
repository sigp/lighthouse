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
    MaxDepositsExceeded,
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
    PreGenesis { genesis: Slot, attestation: Slot },
    /// Attestation included before the inclusion delay.
    IncludedTooEarly {
        state: Slot,
        delay: u64,
        attestation: Slot,
    },
    /// Attestation slot is too far in the past to be included in a block.
    IncludedTooLate { state: Slot, attestation: Slot },
    /// Attestation justified epoch does not match the states current or previous justified epoch.
    ///
    /// `is_current` is `true` if the attestation was compared to the
    /// `state.current_justified_epoch`, `false` if compared to `state.previous_justified_epoch`.
    WrongJustifiedEpoch {
        state: Epoch,
        attestation: Epoch,
        is_current: bool,
    },
    /// Attestation justified epoch root does not match root known to the state.
    ///
    /// `is_current` is `true` if the attestation was compared to the
    /// `state.current_justified_epoch`, `false` if compared to `state.previous_justified_epoch`.
    WrongJustifiedRoot {
        state: Hash256,
        attestation: Hash256,
        is_current: bool,
    },
    /// Attestation crosslink root does not match the state crosslink root for the attestations
    /// slot.
    BadPreviousCrosslink,
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
    /// There was no known committee in this `epoch` for the given shard and slot.
    NoCommitteeForShard { shard: u64, slot: Slot },
    /// The validator index was unknown.
    UnknownValidator(u64),
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

impl Into<IndexedAttestationInvalid> for IndexedAttestationValidationError {
    fn into(self) -> IndexedAttestationInvalid {
        match self {
            IndexedAttestationValidationError::Invalid(e) => e,
        }
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
    /// The specified proposer has already been slashed.
    ProposerAlreadySlashed,
    /// The specified proposer has already been withdrawn.
    ProposerAlreadyWithdrawn(u64),
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
    /// The proof-of-possession does not match the given pubkey.
    BadProofOfPossession,
    /// The withdrawal credentials for the depositing validator did not match the withdrawal
    /// credentials of an existing validator with the same public key.
    BadWithdrawalCredentials,
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
    /// The specified validator is not in the state's validator registry.
    ValidatorUnknown(u64),
    /// The specified validator has a non-maximum exit epoch.
    AlreadyExited(u64),
    /// The specified validator has already initiated exit.
    AlreadyInitiatedExited(u64),
    /// The exit is for a future epoch.
    FutureEpoch { state: Epoch, exit: Epoch },
    /// The validator has not been active for long enough.
    TooYoungToLeave { lifespan: Epoch, expected: u64 },
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
    InvalidResultingFromBalance(u64, u64),
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
    FromValidatorIneligableForTransfer(u64),
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

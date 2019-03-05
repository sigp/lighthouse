use types::BeaconStateError;

#[derive(Debug, PartialEq)]
pub enum AttestationValidationError {
    Invalid(AttestationInvalid),
    ProcessingError(BeaconStateError),
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

impl From<BeaconStateError> for AttestationValidationError {
    fn from(e: BeaconStateError) -> AttestationValidationError {
        AttestationValidationError::ProcessingError(e)
    }
}

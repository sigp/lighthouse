/// Reasons why an `AttestationRecord` can be invalid.
pub enum Invalid {
    AttestationTooRecent,
    AttestationTooOld,
    JustifiedSlotImpermissable,
    JustifiedBlockNotInChain,
    JustifiedBlockHashMismatch,
    UnknownShard,
    ShardBlockHashMismatch,
    SignatureInvalid,
}

/// The outcome of validating the `AttestationRecord`.
///
/// Distinct from the `Error` enum as an `Outcome` indicates that validation executed sucessfully
/// and determined the validity `AttestationRecord`.
pub enum Outcome {
    Valid,
    Invalid(Invalid),
}

/// Errors that prevent this function from correctly validating the `AttestationRecord`.
///
/// Distinct from the `Outcome` enum as `Errors` indicate that validation encountered an unexpected
/// condition and was unable to perform its duty.
pub enum Error {
    BlockHasNoParent,
    BadValidatorIndex,
    UnableToLookupBlockAtSlot,
    OutOfBoundsBitfieldIndex,
    PublicKeyCorrupt,
    NoPublicKeyForValidator,
    DBError(String),
}

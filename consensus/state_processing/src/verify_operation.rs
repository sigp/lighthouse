use crate::per_block_processing::{
    errors::{
        AttesterSlashingValidationError, ExitValidationError, ProposerSlashingValidationError,
    },
    verify_attester_slashing, verify_exit, verify_proposer_slashing,
};
use crate::VerifySignatures;
use types::{
    AttesterSlashing, BeaconState, ChainSpec, EthSpec, ProposerSlashing, SignedVoluntaryExit,
};

/// Wrapper around an operation type that acts as proof that its signature has been checked.
///
/// The inner field is private, meaning instances of this type can only be constructed
/// by calling `validate`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SigVerifiedOp<T>(T);

impl<T> SigVerifiedOp<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Trait for operations that can be verified and transformed into a `SigVerifiedOp`.
pub trait VerifyOperation<E: EthSpec>: Sized {
    type Error;

    fn validate(
        self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<SigVerifiedOp<Self>, Self::Error>;
}

impl<E: EthSpec> VerifyOperation<E> for SignedVoluntaryExit {
    type Error = ExitValidationError;

    fn validate(
        self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<SigVerifiedOp<Self>, Self::Error> {
        verify_exit(state, &self, VerifySignatures::True, spec)?;
        Ok(SigVerifiedOp(self))
    }
}

impl<E: EthSpec> VerifyOperation<E> for AttesterSlashing<E> {
    type Error = AttesterSlashingValidationError;

    fn validate(
        self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<SigVerifiedOp<Self>, Self::Error> {
        verify_attester_slashing(state, &self, VerifySignatures::True, spec)?;
        Ok(SigVerifiedOp(self))
    }
}

impl<E: EthSpec> VerifyOperation<E> for ProposerSlashing {
    type Error = ProposerSlashingValidationError;

    fn validate(
        self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<SigVerifiedOp<Self>, Self::Error> {
        verify_proposer_slashing(&self, state, VerifySignatures::True, spec)?;
        Ok(SigVerifiedOp(self))
    }
}

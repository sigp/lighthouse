use crate::per_block_processing::{
    errors::{
        AttesterSlashingValidationError, BlsExecutionChangeValidationError, ExitValidationError,
        ProposerSlashingValidationError,
    },
    verify_attester_slashing, verify_bls_to_execution_change, verify_exit,
    verify_proposer_slashing,
};
use crate::VerifySignatures;
use derivative::Derivative;
use smallvec::{smallvec, SmallVec};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use types::{
    AttesterSlashing, BeaconState, ChainSpec, Epoch, EthSpec, Fork, ForkVersion, ProposerSlashing,
    SignedBlsToExecutionChange, SignedVoluntaryExit,
};

const MAX_FORKS_VERIFIED_AGAINST: usize = 2;

/// Wrapper around an operation type that acts as proof that its signature has been checked.
///
/// The inner `op` field is private, meaning instances of this type can only be constructed
/// by calling `validate`.
#[derive(Derivative, Debug, Clone, Encode, Decode)]
#[derivative(
    PartialEq,
    Eq,
    Hash(bound = "T: Encode + Decode + std::hash::Hash, E: EthSpec")
)]
pub struct SigVerifiedOp<T: Encode + Decode, E: EthSpec> {
    op: T,
    verified_against: VerifiedAgainst,
    #[ssz(skip_serializing, skip_deserializing)]
    _phantom: PhantomData<E>,
}

/// Information about the fork versions that this message was verified against.
///
/// In general it is not safe to assume that a `SigVerifiedOp` constructed at some point in the past
/// will continue to be valid in the presence of a changing `state.fork()`. The reason for this
/// is that the fork versions that the message's epochs map to might change.
///
/// For example a proposer slashing at a phase0 slot verified against an Altair state will use
/// the phase0 fork version, but will become invalid once the Bellatrix fork occurs because that
/// slot will start to map to the Altair fork version. This is because `Fork::get_fork_version` only
/// remembers the most recent two forks.
///
/// In the other direction, a proposer slashing at a Bellatrix slot verified against an Altair state
/// will use the Altair fork version, but will become invalid once the Bellatrix fork occurs because
/// that slot will start to map to the Bellatrix fork version.
///
/// We need to store multiple `ForkVersion`s because attester slashings contain two indexed
/// attestations which may be signed using different versions.
#[derive(Debug, PartialEq, Eq, Clone, Hash, Encode, Decode)]
pub struct VerifiedAgainst {
    fork_versions: SmallVec<[ForkVersion; MAX_FORKS_VERIFIED_AGAINST]>,
}

impl<T, E> SigVerifiedOp<T, E>
where
    T: VerifyOperation<E>,
    E: EthSpec,
{
    /// This function must be private because it assumes that `op` has already been verified.
    fn new(op: T, state: &BeaconState<E>) -> Self {
        let verified_against = VerifiedAgainst {
            fork_versions: op
                .verification_epochs()
                .into_iter()
                .map(|epoch| state.fork().get_fork_version(epoch))
                .collect(),
        };

        SigVerifiedOp {
            op,
            verified_against,
            _phantom: PhantomData,
        }
    }

    pub fn into_inner(self) -> T {
        self.op
    }

    pub fn as_inner(&self) -> &T {
        &self.op
    }

    pub fn signature_is_still_valid(&self, current_fork: &Fork) -> bool {
        // The .all() will return true if the iterator is empty.
        self.as_inner()
            .verification_epochs()
            .into_iter()
            .zip(self.verified_against.fork_versions.iter())
            .all(|(epoch, verified_fork_version)| {
                current_fork.get_fork_version(epoch) == *verified_fork_version
            })
    }

    /// Return one of the fork versions this message was verified against.
    ///
    /// This is only required for the v12 schema downgrade and can be deleted once all nodes
    /// are upgraded to v12.
    pub fn first_fork_verified_against(&self) -> Option<ForkVersion> {
        self.verified_against.fork_versions.first().copied()
    }
}

/// Trait for operations that can be verified and transformed into a `SigVerifiedOp`.
pub trait VerifyOperation<E: EthSpec>: Encode + Decode + Sized {
    type Error;

    fn validate(
        self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<SigVerifiedOp<Self, E>, Self::Error>;

    /// Return the epochs at which parts of this message were verified.
    ///
    /// These need to map 1-to-1 to the `SigVerifiedOp::verified_against` for this type.
    ///
    /// If the message is valid across all forks it should return an empty smallvec.
    fn verification_epochs(&self) -> SmallVec<[Epoch; MAX_FORKS_VERIFIED_AGAINST]>;
}

impl<E: EthSpec> VerifyOperation<E> for SignedVoluntaryExit {
    type Error = ExitValidationError;

    fn validate(
        self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<SigVerifiedOp<Self, E>, Self::Error> {
        verify_exit(state, &self, VerifySignatures::True, spec)?;
        Ok(SigVerifiedOp::new(self, state))
    }

    #[allow(clippy::integer_arithmetic)]
    fn verification_epochs(&self) -> SmallVec<[Epoch; MAX_FORKS_VERIFIED_AGAINST]> {
        smallvec![self.message.epoch]
    }
}

impl<E: EthSpec> VerifyOperation<E> for AttesterSlashing<E> {
    type Error = AttesterSlashingValidationError;

    fn validate(
        self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<SigVerifiedOp<Self, E>, Self::Error> {
        verify_attester_slashing(state, &self, VerifySignatures::True, spec)?;
        Ok(SigVerifiedOp::new(self, state))
    }

    #[allow(clippy::integer_arithmetic)]
    fn verification_epochs(&self) -> SmallVec<[Epoch; MAX_FORKS_VERIFIED_AGAINST]> {
        smallvec![
            self.attestation_1.data.target.epoch,
            self.attestation_2.data.target.epoch
        ]
    }
}

impl<E: EthSpec> VerifyOperation<E> for ProposerSlashing {
    type Error = ProposerSlashingValidationError;

    fn validate(
        self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<SigVerifiedOp<Self, E>, Self::Error> {
        verify_proposer_slashing(&self, state, VerifySignatures::True, spec)?;
        Ok(SigVerifiedOp::new(self, state))
    }

    #[allow(clippy::integer_arithmetic)]
    fn verification_epochs(&self) -> SmallVec<[Epoch; MAX_FORKS_VERIFIED_AGAINST]> {
        // Only need a single epoch because the slots of the two headers must be equal.
        smallvec![self
            .signed_header_1
            .message
            .slot
            .epoch(E::slots_per_epoch())]
    }
}

impl<E: EthSpec> VerifyOperation<E> for SignedBlsToExecutionChange {
    type Error = BlsExecutionChangeValidationError;

    fn validate(
        self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<SigVerifiedOp<Self, E>, Self::Error> {
        verify_bls_to_execution_change(state, &self, VerifySignatures::True, spec)?;
        Ok(SigVerifiedOp::new(self, state))
    }

    #[allow(clippy::integer_arithmetic)]
    fn verification_epochs(&self) -> SmallVec<[Epoch; MAX_FORKS_VERIFIED_AGAINST]> {
        smallvec![]
    }
}

use crate::per_block_processing::{
    errors::{
        AttesterSlashingValidationError, BlsExecutionChangeValidationError, ExitValidationError,
        ProposerSlashingValidationError,
    },
    verify_attester_slashing, verify_bls_to_execution_change, verify_exit,
    verify_proposer_slashing,
};
use crate::VerifySignatures;
use arbitrary::Arbitrary;
use derivative::Derivative;
use smallvec::{smallvec, SmallVec};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use test_random_derive::TestRandom;
use types::{
    test_utils::TestRandom, AttesterSlashing, AttesterSlashingBase, AttesterSlashingOnDisk,
    AttesterSlashingRefOnDisk, BeaconState, ChainSpec, Epoch, EthSpec, Fork, ForkVersion,
    ProposerSlashing, SignedBlsToExecutionChange, SignedVoluntaryExit,
};

const MAX_FORKS_VERIFIED_AGAINST: usize = 2;

pub trait TransformPersist {
    type Persistable: Encode + Decode;
    type PersistableRef<'a>: Encode
    where
        Self: 'a;

    /// Returns a reference to the object in a form that implements `Encode`
    fn as_persistable_ref(&self) -> Self::PersistableRef<'_>;

    /// Converts the object back into its original form.
    fn from_persistable(persistable: Self::Persistable) -> Self;
}

/// Wrapper around an operation type that acts as proof that its signature has been checked.
///
/// The inner `op` field is private, meaning instances of this type can only be constructed
/// by calling `validate`.
#[derive(Derivative, Debug, Clone, Arbitrary)]
#[derivative(
    PartialEq,
    Eq,
    Hash(bound = "T: TransformPersist + std::hash::Hash, E: EthSpec")
)]
#[arbitrary(bound = "T: TransformPersist + Arbitrary<'arbitrary>, E: EthSpec")]
pub struct SigVerifiedOp<T: TransformPersist, E: EthSpec> {
    op: T,
    verified_against: VerifiedAgainst,
    _phantom: PhantomData<E>,
}

impl<T: TransformPersist, E: EthSpec> Encode for SigVerifiedOp<T, E> {
    fn is_ssz_fixed_len() -> bool {
        <SigVerifiedOpEncode<T::Persistable> as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <SigVerifiedOpEncode<T::Persistable> as Encode>::ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let persistable_ref = self.op.as_persistable_ref();
        SigVerifiedOpEncode {
            op: persistable_ref,
            verified_against: &self.verified_against,
        }
        .ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        let persistable_ref = self.op.as_persistable_ref();
        SigVerifiedOpEncode {
            op: persistable_ref,
            verified_against: &self.verified_against,
        }
        .ssz_bytes_len()
    }
}

impl<T: TransformPersist, E: EthSpec> Decode for SigVerifiedOp<T, E> {
    fn is_ssz_fixed_len() -> bool {
        <SigVerifiedOpDecode<T::Persistable> as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <SigVerifiedOpDecode<T::Persistable> as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let on_disk = SigVerifiedOpDecode::<T::Persistable>::from_ssz_bytes(bytes)?;
        Ok(SigVerifiedOp {
            op: T::from_persistable(on_disk.op),
            verified_against: on_disk.verified_against,
            _phantom: PhantomData,
        })
    }
}

/// On-disk variant of `SigVerifiedOp` that implements `Encode`.
///
/// We use separate types for Encode and Decode so we can efficiently handle references: the Encode
/// type contains references, while the Decode type does not.
#[derive(Debug, Encode)]
struct SigVerifiedOpEncode<'a, P: Encode> {
    op: P,
    verified_against: &'a VerifiedAgainst,
}

/// On-disk variant of `SigVerifiedOp` that implements `Encode`.
#[derive(Debug, Decode)]
struct SigVerifiedOpDecode<P: Decode> {
    op: P,
    verified_against: VerifiedAgainst,
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
#[derive(Debug, PartialEq, Eq, Clone, Hash, Encode, Decode, TestRandom, Arbitrary)]
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
pub trait VerifyOperation<E: EthSpec>: TransformPersist + Sized {
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
        verify_exit(state, None, &self, VerifySignatures::True, spec)?;
        Ok(SigVerifiedOp::new(self, state))
    }

    #[allow(clippy::arithmetic_side_effects)]
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
        verify_attester_slashing(state, self.to_ref(), VerifySignatures::True, spec)?;
        Ok(SigVerifiedOp::new(self, state))
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn verification_epochs(&self) -> SmallVec<[Epoch; MAX_FORKS_VERIFIED_AGAINST]> {
        smallvec![
            self.attestation_1().data().target.epoch,
            self.attestation_2().data().target.epoch
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

    #[allow(clippy::arithmetic_side_effects)]
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

    #[allow(clippy::arithmetic_side_effects)]
    fn verification_epochs(&self) -> SmallVec<[Epoch; MAX_FORKS_VERIFIED_AGAINST]> {
        smallvec![]
    }
}

/// Trait for operations that can be verified and transformed into a
/// `SigVerifiedOp`.
///
/// The `At` suffix indicates that we can specify a particular epoch at which to
/// verify the operation.
pub trait VerifyOperationAt<E: EthSpec>: VerifyOperation<E> + Sized {
    fn validate_at(
        self,
        state: &BeaconState<E>,
        validate_at_epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<SigVerifiedOp<Self, E>, Self::Error>;
}

impl<E: EthSpec> VerifyOperationAt<E> for SignedVoluntaryExit {
    fn validate_at(
        self,
        state: &BeaconState<E>,
        validate_at_epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<SigVerifiedOp<Self, E>, Self::Error> {
        verify_exit(
            state,
            Some(validate_at_epoch),
            &self,
            VerifySignatures::True,
            spec,
        )?;
        Ok(SigVerifiedOp::new(self, state))
    }
}

impl TransformPersist for SignedVoluntaryExit {
    type Persistable = Self;
    type PersistableRef<'a> = &'a Self;

    fn as_persistable_ref(&self) -> Self::PersistableRef<'_> {
        self
    }

    fn from_persistable(persistable: Self::Persistable) -> Self {
        persistable
    }
}

impl<E: EthSpec> TransformPersist for AttesterSlashing<E> {
    type Persistable = AttesterSlashingOnDisk<E>;
    type PersistableRef<'a> = AttesterSlashingRefOnDisk<'a, E>;

    fn as_persistable_ref(&self) -> Self::PersistableRef<'_> {
        self.to_ref().into()
    }

    fn from_persistable(persistable: Self::Persistable) -> Self {
        persistable.into()
    }
}

// TODO: Remove this once we no longer support DB schema version 17
impl<E: EthSpec> TransformPersist for types::AttesterSlashingBase<E> {
    type Persistable = Self;
    type PersistableRef<'a> = &'a Self;

    fn as_persistable_ref(&self) -> Self::PersistableRef<'_> {
        self
    }

    fn from_persistable(persistable: Self::Persistable) -> Self {
        persistable
    }
}
// TODO: Remove this once we no longer support DB schema version 17
impl<E: EthSpec> From<SigVerifiedOp<AttesterSlashingBase<E>, E>>
    for SigVerifiedOp<AttesterSlashing<E>, E>
{
    fn from(base: SigVerifiedOp<AttesterSlashingBase<E>, E>) -> Self {
        SigVerifiedOp {
            op: AttesterSlashing::Base(base.op),
            verified_against: base.verified_against,
            _phantom: PhantomData,
        }
    }
}
// TODO: Remove this once we no longer support DB schema version 17
impl<E: EthSpec> TryFrom<SigVerifiedOp<AttesterSlashing<E>, E>>
    for SigVerifiedOp<AttesterSlashingBase<E>, E>
{
    type Error = String;

    fn try_from(slashing: SigVerifiedOp<AttesterSlashing<E>, E>) -> Result<Self, Self::Error> {
        match slashing.op {
            AttesterSlashing::Base(base) => Ok(SigVerifiedOp {
                op: base,
                verified_against: slashing.verified_against,
                _phantom: PhantomData,
            }),
            AttesterSlashing::Electra(_) => Err("non-base attester slashing".to_string()),
        }
    }
}

impl TransformPersist for ProposerSlashing {
    type Persistable = Self;
    type PersistableRef<'a> = &'a Self;

    fn as_persistable_ref(&self) -> Self::PersistableRef<'_> {
        self
    }

    fn from_persistable(persistable: Self::Persistable) -> Self {
        persistable
    }
}

impl TransformPersist for SignedBlsToExecutionChange {
    type Persistable = Self;
    type PersistableRef<'a> = &'a Self;

    fn as_persistable_ref(&self) -> Self::PersistableRef<'_> {
        self
    }

    fn from_persistable(persistable: Self::Persistable) -> Self {
        persistable
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod test {
    use super::*;
    use types::{
        test_utils::{SeedableRng, TestRandom, XorShiftRng},
        MainnetEthSpec,
    };

    type E = MainnetEthSpec;

    fn roundtrip_test<T: TestRandom + TransformPersist + PartialEq + std::fmt::Debug>() {
        let runs = 10;
        let mut rng = XorShiftRng::seed_from_u64(0xff0af5a356af1123);

        for _ in 0..runs {
            let op = T::random_for_test(&mut rng);
            let verified_against = VerifiedAgainst::random_for_test(&mut rng);

            let verified_op = SigVerifiedOp {
                op,
                verified_against,
                _phantom: PhantomData::<E>,
            };

            let serialized = verified_op.as_ssz_bytes();
            let deserialized = SigVerifiedOp::from_ssz_bytes(&serialized).unwrap();
            let reserialized = deserialized.as_ssz_bytes();
            assert_eq!(verified_op, deserialized);
            assert_eq!(serialized, reserialized);
        }
    }

    #[test]
    fn sig_verified_op_exit_roundtrip() {
        roundtrip_test::<SignedVoluntaryExit>();
    }

    #[test]
    fn proposer_slashing_roundtrip() {
        roundtrip_test::<ProposerSlashing>();
    }

    #[test]
    fn attester_slashing_roundtrip() {
        roundtrip_test::<AttesterSlashing<E>>();
    }

    #[test]
    fn bls_to_execution_roundtrip() {
        roundtrip_test::<SignedBlsToExecutionChange>();
    }
}

use crate::{
    test_utils::TestRandom, BeaconState, ChainSpec, Epoch, EthSpec, Hash256, PublicKeyBytes,
};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

const NUM_FIELDS: usize = 8;

/// Information about a `BeaconChain` validator.
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TestRandom, Default)]
#[serde(deny_unknown_fields)]
pub struct Validator {
    #[serde(flatten)]
    pub immutable: Arc<ValidatorImmutable>,
    #[serde(flatten)]
    pub mutable: ValidatorMutable,
}

/// The mutable fields of a validator.
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct ValidatorMutable {
    #[serde(with = "serde_utils::quoted_u64")]
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

/// The immutable fields of a validator, behind an `Arc` to enable sharing.
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TestRandom)]
pub struct ValidatorImmutable {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
}

pub trait ValidatorTrait:
    std::fmt::Debug
    + PartialEq
    + Clone
    + serde::Serialize
    + Send
    + Sync
    + serde::de::DeserializeOwned
    + ssz::Encode
    + ssz::Decode
    + TreeHash
    + TestRandom
{
}

impl ValidatorTrait for Validator {}
impl ValidatorTrait for ValidatorMutable {}

impl Validator {
    pub fn pubkey(&self) -> &PublicKeyBytes {
        &self.immutable.pubkey
    }

    /// Replace the validator's pubkey (should only be used during testing).
    pub fn replace_pubkey(&mut self, pubkey: PublicKeyBytes) {
        self.immutable = Arc::new(ValidatorImmutable {
            pubkey,
            withdrawal_credentials: self.immutable.withdrawal_credentials,
        });
    }

    #[inline]
    pub fn withdrawal_credentials(&self) -> Hash256 {
        self.immutable.withdrawal_credentials
    }

    #[inline]
    pub fn effective_balance(&self) -> u64 {
        self.mutable.effective_balance
    }

    #[inline]
    pub fn slashed(&self) -> bool {
        self.mutable.slashed
    }

    #[inline]
    pub fn activation_eligibility_epoch(&self) -> Epoch {
        self.mutable.activation_eligibility_epoch
    }

    #[inline]
    pub fn activation_epoch(&self) -> Epoch {
        self.mutable.activation_epoch
    }

    #[inline]
    pub fn activation_epoch_mut(&mut self) -> &mut Epoch {
        &mut self.mutable.activation_epoch
    }

    #[inline]
    pub fn exit_epoch(&self) -> Epoch {
        self.mutable.exit_epoch
    }

    pub fn exit_epoch_mut(&mut self) -> &mut Epoch {
        &mut self.mutable.exit_epoch
    }

    #[inline]
    pub fn withdrawable_epoch(&self) -> Epoch {
        self.mutable.withdrawable_epoch
    }

    /// Returns `true` if the validator is considered active at some epoch.
    #[inline]
    pub fn is_active_at(&self, epoch: Epoch) -> bool {
        self.activation_epoch() <= epoch && epoch < self.exit_epoch()
    }

    /// Returns `true` if the validator is slashable at some epoch.
    #[inline]
    pub fn is_slashable_at(&self, epoch: Epoch) -> bool {
        !self.slashed() && self.activation_epoch() <= epoch && epoch < self.withdrawable_epoch()
    }

    /// Returns `true` if the validator is considered exited at some epoch.
    #[inline]
    pub fn is_exited_at(&self, epoch: Epoch) -> bool {
        self.exit_epoch() <= epoch
    }

    /// Returns `true` if the validator is able to withdraw at some epoch.
    #[inline]
    pub fn is_withdrawable_at(&self, epoch: Epoch) -> bool {
        epoch >= self.withdrawable_epoch()
    }

    /// Returns `true` if the validator is eligible to join the activation queue.
    ///
    /// Spec v0.12.1
    #[inline]
    pub fn is_eligible_for_activation_queue(&self, spec: &ChainSpec) -> bool {
        self.activation_eligibility_epoch() == spec.far_future_epoch
            && self.effective_balance() == spec.max_effective_balance
    }

    /// Returns `true` if the validator is eligible to be activated.
    ///
    /// Spec v0.12.1
    #[inline]
    pub fn is_eligible_for_activation<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> bool {
        // Placement in queue is finalized
        self.activation_eligibility_epoch() <= state.finalized_checkpoint().epoch
        // Has not yet been activated
        && self.activation_epoch() == spec.far_future_epoch
    }

    fn tree_hash_root_internal(&self) -> Result<Hash256, tree_hash::Error> {
        let mut hasher = tree_hash::MerkleHasher::with_leaves(NUM_FIELDS);

        hasher.write(self.pubkey().tree_hash_root().as_bytes())?;
        hasher.write(self.withdrawal_credentials().tree_hash_root().as_bytes())?;
        hasher.write(self.effective_balance().tree_hash_root().as_bytes())?;
        hasher.write(self.slashed().tree_hash_root().as_bytes())?;
        hasher.write(
            self.activation_eligibility_epoch()
                .tree_hash_root()
                .as_bytes(),
        )?;
        hasher.write(self.activation_epoch().tree_hash_root().as_bytes())?;
        hasher.write(self.exit_epoch().tree_hash_root().as_bytes())?;
        hasher.write(self.withdrawable_epoch().tree_hash_root().as_bytes())?;

        hasher.finish()
    }
}

/// Yields a "default" `Validator`. Primarily used for testing.
impl Default for ValidatorImmutable {
    fn default() -> Self {
        ValidatorImmutable {
            pubkey: PublicKeyBytes::empty(),
            withdrawal_credentials: Hash256::default(),
        }
    }
}

impl Default for ValidatorMutable {
    fn default() -> Self {
        ValidatorMutable {
            activation_eligibility_epoch: Epoch::from(std::u64::MAX),
            activation_epoch: Epoch::from(std::u64::MAX),
            exit_epoch: Epoch::from(std::u64::MAX),
            withdrawable_epoch: Epoch::from(std::u64::MAX),
            slashed: false,
            effective_balance: std::u64::MAX,
        }
    }
}

impl TreeHash for Validator {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_root(&self) -> Hash256 {
        self.tree_hash_root_internal()
            .expect("Validator tree_hash_root should not fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default() {
        let v = Validator::default();

        let epoch = Epoch::new(0);

        assert!(!v.is_active_at(epoch));
        assert!(!v.is_exited_at(epoch));
        assert!(!v.is_withdrawable_at(epoch));
        assert!(!v.slashed());
    }

    #[test]
    fn is_active_at() {
        let epoch = Epoch::new(10);

        let v = Validator {
            mutable: ValidatorMutable {
                activation_epoch: epoch,
                ..Default::default()
            },
            ..Validator::default()
        };

        assert!(!v.is_active_at(epoch - 1));
        assert!(v.is_active_at(epoch));
        assert!(v.is_active_at(epoch + 1));
    }

    #[test]
    fn is_exited_at() {
        let epoch = Epoch::new(10);

        let v = Validator {
            mutable: ValidatorMutable {
                exit_epoch: epoch,
                ..ValidatorMutable::default()
            },
            ..Validator::default()
        };

        assert!(!v.is_exited_at(epoch - 1));
        assert!(v.is_exited_at(epoch));
        assert!(v.is_exited_at(epoch + 1));
    }

    #[test]
    fn is_withdrawable_at() {
        let epoch = Epoch::new(10);

        let v = Validator {
            mutable: ValidatorMutable {
                withdrawable_epoch: epoch,
                ..ValidatorMutable::default()
            },
            ..Validator::default()
        };

        assert!(!v.is_withdrawable_at(epoch - 1));
        assert!(v.is_withdrawable_at(epoch));
        assert!(v.is_withdrawable_at(epoch + 1));
    }

    ssz_and_tree_hash_tests!(Validator);
}

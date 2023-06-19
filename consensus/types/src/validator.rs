use crate::{
    test_utils::TestRandom, Address, BeaconState, ChainSpec, Epoch, EthSpec, Hash256,
    PublicKeyBytes,
};
use arbitrary::Arbitrary;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

const NUM_FIELDS: usize = 8;

/// Information about a `BeaconChain` validator.
///
/// Spec v0.12.1
#[derive(
    Arbitrary, Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TestRandom,
)]
#[serde(deny_unknown_fields)]
pub struct Validator {
    pub pubkey: Arc<PublicKeyBytes>,
    #[serde(flatten)]
    pub mutable: ValidatorMutable,
}

/// The mutable fields of a validator.
#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom, Arbitrary,
)]
pub struct ValidatorMutable {
    pub withdrawal_credentials: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
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
    + for<'a> arbitrary::Arbitrary<'a>
{
}

impl ValidatorTrait for Validator {}
impl ValidatorTrait for ValidatorMutable {}

impl Validator {
    pub fn pubkey(&self) -> &PublicKeyBytes {
        &self.pubkey
    }

    pub fn pubkey_clone(&self) -> Arc<PublicKeyBytes> {
        self.pubkey.clone()
    }

    /// Replace the validator's pubkey (should only be used during testing).
    pub fn replace_pubkey(&mut self, pubkey: PublicKeyBytes) {
        self.pubkey = Arc::new(pubkey);
    }

    #[inline]
    pub fn withdrawal_credentials(&self) -> Hash256 {
        self.mutable.withdrawal_credentials
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

    /// Returns `true` if the validator has eth1 withdrawal credential.
    pub fn has_eth1_withdrawal_credential(&self, spec: &ChainSpec) -> bool {
        self.withdrawal_credentials()
            .as_bytes()
            .first()
            .map(|byte| *byte == spec.eth1_address_withdrawal_prefix_byte)
            .unwrap_or(false)
    }

    /// Get the eth1 withdrawal address if this validator has one initialized.
    pub fn get_eth1_withdrawal_address(&self, spec: &ChainSpec) -> Option<Address> {
        self.has_eth1_withdrawal_credential(spec)
            .then(|| {
                self.withdrawal_credentials()
                    .as_bytes()
                    .get(12..)
                    .map(Address::from_slice)
            })
            .flatten()
    }

    /// Changes withdrawal credentials to  the provided eth1 execution address.
    ///
    /// WARNING: this function does NO VALIDATION - it just does it!
    pub fn change_withdrawal_credentials(&mut self, execution_address: &Address, spec: &ChainSpec) {
        let mut bytes = [0u8; 32];
        bytes[0] = spec.eth1_address_withdrawal_prefix_byte;
        bytes[12..].copy_from_slice(execution_address.as_bytes());
        self.mutable.withdrawal_credentials = Hash256::from(bytes);
    }

    /// Returns `true` if the validator is fully withdrawable at some epoch.
    pub fn is_fully_withdrawable_at(&self, balance: u64, epoch: Epoch, spec: &ChainSpec) -> bool {
        self.has_eth1_withdrawal_credential(spec)
            && self.withdrawable_epoch() <= epoch
            && balance > 0
    }

    /// Returns `true` if the validator is partially withdrawable.
    pub fn is_partially_withdrawable_validator(&self, balance: u64, spec: &ChainSpec) -> bool {
        self.has_eth1_withdrawal_credential(spec)
            && self.effective_balance() == spec.max_effective_balance
            && balance > spec.max_effective_balance
    }
}

impl Default for Validator {
    fn default() -> Self {
        Validator {
            pubkey: Arc::new(PublicKeyBytes::empty()),
            mutable: <_>::default(),
        }
    }
}

impl Default for ValidatorMutable {
    fn default() -> Self {
        ValidatorMutable {
            withdrawal_credentials: Hash256::zero(),
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

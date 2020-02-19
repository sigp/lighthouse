use crate::{
    test_utils::TestRandom, BeaconState, ChainSpec, Epoch, EthSpec, Hash256, PublicKeyBytes,
};
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, DecodeError};
use ssz_derive::Encode;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Information about a `BeaconChain` validator.
///
/// Spec v0.10.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, TestRandom, TreeHash)]
pub struct Validator {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

impl Validator {
    /// Returns `true` if the validator is considered active at some epoch.
    pub fn is_active_at(&self, epoch: Epoch) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

    /// Returns `true` if the validator is slashable at some epoch.
    pub fn is_slashable_at(&self, epoch: Epoch) -> bool {
        !self.slashed && self.activation_epoch <= epoch && epoch < self.withdrawable_epoch
    }

    /// Returns `true` if the validator is considered exited at some epoch.
    pub fn is_exited_at(&self, epoch: Epoch) -> bool {
        self.exit_epoch <= epoch
    }

    /// Returns `true` if the validator is able to withdraw at some epoch.
    pub fn is_withdrawable_at(&self, epoch: Epoch) -> bool {
        epoch >= self.withdrawable_epoch
    }

    /// Returns `true` if the validator is eligible to join the activation queue.
    ///
    /// Spec v0.10.1
    pub fn is_eligible_for_activation_queue(&self, spec: &ChainSpec) -> bool {
        self.activation_eligibility_epoch == spec.far_future_epoch
            && self.effective_balance == spec.max_effective_balance
    }

    /// Returns `true` if the validator is eligible to be activated.
    ///
    /// Spec v0.10.1
    pub fn is_eligible_for_activation<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> bool {
        // Placement in queue is finalized
        self.activation_eligibility_epoch <= state.finalized_checkpoint.epoch
        // Has not yet been activated
        && self.activation_epoch == spec.far_future_epoch
    }
}

impl Default for Validator {
    /// Yields a "default" `Validator`. Primarily used for testing.
    fn default() -> Self {
        Self {
            pubkey: PublicKeyBytes::empty(),
            withdrawal_credentials: Hash256::default(),
            activation_eligibility_epoch: Epoch::from(std::u64::MAX),
            activation_epoch: Epoch::from(std::u64::MAX),
            exit_epoch: Epoch::from(std::u64::MAX),
            withdrawable_epoch: Epoch::from(std::u64::MAX),
            slashed: false,
            effective_balance: std::u64::MAX,
        }
    }
}

impl Decode for Validator {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        <PublicKeyBytes as Decode>::ssz_fixed_len()
            + <Hash256 as Decode>::ssz_fixed_len()
            + <u64 as Decode>::ssz_fixed_len()
            + <bool as Decode>::ssz_fixed_len()
            + <Epoch as Decode>::ssz_fixed_len()
            + <Epoch as Decode>::ssz_fixed_len()
            + <Epoch as Decode>::ssz_fixed_len()
            + <Epoch as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != <Self as Decode>::ssz_fixed_len() {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: <Self as Decode>::ssz_fixed_len(),
            });
        }

        let mut start = 0;
        let mut end = 0;

        macro_rules! decode_field {
            ($type: ty) => {{
                start = end;
                end += <$type as Decode>::ssz_fixed_len();
                <$type as Decode>::from_ssz_bytes(&bytes[start..end])?
            }};
        }

        Ok(Self {
            pubkey: decode_field!(PublicKeyBytes),
            withdrawal_credentials: decode_field!(Hash256),
            effective_balance: decode_field!(u64),
            slashed: decode_field!(bool),
            activation_eligibility_epoch: decode_field!(Epoch),
            activation_epoch: decode_field!(Epoch),
            exit_epoch: decode_field!(Epoch),
            withdrawable_epoch: decode_field!(Epoch),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default() {
        let v = Validator::default();

        let epoch = Epoch::new(0);

        assert_eq!(v.is_active_at(epoch), false);
        assert_eq!(v.is_exited_at(epoch), false);
        assert_eq!(v.is_withdrawable_at(epoch), false);
        assert_eq!(v.slashed, false);
    }

    #[test]
    fn is_active_at() {
        let epoch = Epoch::new(10);

        let v = Validator {
            activation_epoch: epoch,
            ..Validator::default()
        };

        assert_eq!(v.is_active_at(epoch - 1), false);
        assert_eq!(v.is_active_at(epoch), true);
        assert_eq!(v.is_active_at(epoch + 1), true);
    }

    #[test]
    fn is_exited_at() {
        let epoch = Epoch::new(10);

        let v = Validator {
            exit_epoch: epoch,
            ..Validator::default()
        };

        assert_eq!(v.is_exited_at(epoch - 1), false);
        assert_eq!(v.is_exited_at(epoch), true);
        assert_eq!(v.is_exited_at(epoch + 1), true);
    }

    #[test]
    fn is_withdrawable_at() {
        let epoch = Epoch::new(10);

        let v = Validator {
            withdrawable_epoch: epoch,
            ..Validator::default()
        };

        assert_eq!(v.is_withdrawable_at(epoch - 1), false);
        assert_eq!(v.is_withdrawable_at(epoch), true);
        assert_eq!(v.is_withdrawable_at(epoch + 1), true);
    }

    ssz_and_tree_hash_tests!(Validator);
}

use crate::{test_utils::TestRandom, Epoch, Hash256, PublicKey};
use rand::RngCore;
use serde_derive::Serialize;
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};

const STATUS_FLAG_INITIATED_EXIT: u8 = 1;
const STATUS_FLAG_WITHDRAWABLE: u8 = 2;

#[derive(Debug, PartialEq, Clone, Copy, Serialize)]
pub enum StatusFlags {
    InitiatedExit,
    Withdrawable,
}

struct StatusFlagsDecodeError;

impl From<StatusFlagsDecodeError> for DecodeError {
    fn from(_: StatusFlagsDecodeError) -> DecodeError {
        DecodeError::Invalid
    }
}

/// Handles the serialization logic for the `status_flags` field of the `Validator`.
fn status_flag_to_byte(flag: Option<StatusFlags>) -> u8 {
    if let Some(flag) = flag {
        match flag {
            StatusFlags::InitiatedExit => STATUS_FLAG_INITIATED_EXIT,
            StatusFlags::Withdrawable => STATUS_FLAG_WITHDRAWABLE,
        }
    } else {
        0
    }
}

/// Handles the deserialization logic for the `status_flags` field of the `Validator`.
fn status_flag_from_byte(flag: u8) -> Result<Option<StatusFlags>, StatusFlagsDecodeError> {
    match flag {
        0 => Ok(None),
        1 => Ok(Some(StatusFlags::InitiatedExit)),
        2 => Ok(Some(StatusFlags::Withdrawable)),
        _ => Err(StatusFlagsDecodeError),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Validator {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: Hash256,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawal_epoch: Epoch,
    pub penalized_epoch: Epoch,
    pub status_flags: Option<StatusFlags>,
}

impl Validator {
    /// Returns `true` if the validator is considered active at some epoch.
    pub fn is_active_at(&self, epoch: Epoch) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

    /// Returns `true` if the validator is considered exited at some epoch.
    pub fn is_exited_at(&self, epoch: Epoch) -> bool {
        self.exit_epoch <= epoch
    }

    /// Returns `true` if the validator is considered penalized at some epoch.
    pub fn is_penalized_at(&self, epoch: Epoch) -> bool {
        self.penalized_epoch <= epoch
    }

    /// Returns `true` if the validator is considered penalized at some epoch.
    pub fn has_initiated_exit(&self) -> bool {
        self.status_flags == Some(StatusFlags::InitiatedExit)
    }
}

impl Default for Validator {
    /// Yields a "default" `Validator`. Primarily used for testing.
    fn default() -> Self {
        Self {
            pubkey: PublicKey::default(),
            withdrawal_credentials: Hash256::default(),
            activation_epoch: Epoch::from(std::u64::MAX),
            exit_epoch: Epoch::from(std::u64::MAX),
            withdrawal_epoch: Epoch::from(std::u64::MAX),
            penalized_epoch: Epoch::from(std::u64::MAX),
            status_flags: None,
        }
    }
}

impl<T: RngCore> TestRandom<T> for StatusFlags {
    fn random_for_test(rng: &mut T) -> Self {
        let options = vec![StatusFlags::InitiatedExit, StatusFlags::Withdrawable];
        options[(rng.next_u32() as usize) % options.len()]
    }
}

impl Encodable for Validator {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.pubkey);
        s.append(&self.withdrawal_credentials);
        s.append(&self.activation_epoch);
        s.append(&self.exit_epoch);
        s.append(&self.withdrawal_epoch);
        s.append(&self.penalized_epoch);
        s.append(&status_flag_to_byte(self.status_flags));
    }
}

impl Decodable for Validator {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (pubkey, i) = <_>::ssz_decode(bytes, i)?;
        let (withdrawal_credentials, i) = <_>::ssz_decode(bytes, i)?;
        let (activation_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (exit_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (withdrawal_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (penalized_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (status_flags_byte, i): (u8, usize) = <_>::ssz_decode(bytes, i)?;

        let status_flags = status_flag_from_byte(status_flags_byte)?;

        Ok((
            Self {
                pubkey,
                withdrawal_credentials,
                activation_epoch,
                exit_epoch,
                withdrawal_epoch,
                penalized_epoch,
                status_flags,
            },
            i,
        ))
    }
}

impl TreeHash for Validator {
    fn hash_tree_root_internal(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.pubkey.hash_tree_root_internal());
        result.append(&mut self.withdrawal_credentials.hash_tree_root_internal());
        result.append(&mut self.activation_epoch.hash_tree_root_internal());
        result.append(&mut self.exit_epoch.hash_tree_root_internal());
        result.append(&mut self.withdrawal_epoch.hash_tree_root_internal());
        result.append(&mut self.penalized_epoch.hash_tree_root_internal());
        result.append(
            &mut u64::from(status_flag_to_byte(self.status_flags)).hash_tree_root_internal(),
        );
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for Validator {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            pubkey: <_>::random_for_test(rng),
            withdrawal_credentials: <_>::random_for_test(rng),
            activation_epoch: <_>::random_for_test(rng),
            exit_epoch: <_>::random_for_test(rng),
            withdrawal_epoch: <_>::random_for_test(rng),
            penalized_epoch: <_>::random_for_test(rng),
            status_flags: Some(<_>::random_for_test(rng)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    #[test]
    fn test_validator_can_be_active() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut validator = Validator::random_for_test(&mut rng);

        let activation_epoch = u64::random_for_test(&mut rng);
        let exit_epoch = activation_epoch + 234;

        validator.activation_epoch = Epoch::from(activation_epoch);
        validator.exit_epoch = Epoch::from(exit_epoch);

        for slot in (activation_epoch - 100)..(exit_epoch + 100) {
            let slot = Epoch::from(slot);
            if slot < activation_epoch {
                assert!(!validator.is_active_at(slot));
            } else if slot >= exit_epoch {
                assert!(!validator.is_active_at(slot));
            } else {
                assert!(validator.is_active_at(slot));
            }
        }
    }

    ssz_tests!(Validator);
}

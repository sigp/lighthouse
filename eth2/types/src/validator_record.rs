use super::bls::PublicKey;
use super::Hash256;
use crate::test_utils::TestRandom;
use rand::RngCore;
use ssz::{Decodable, DecodeError, Encodable, SszStream};

const STATUS_FLAG_INITIATED_EXIT: u8 = 1;
const STATUS_FLAG_WITHDRAWABLE: u8 = 2;

#[derive(Debug, PartialEq, Clone, Copy)]
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

/// Handles the serialization logic for the `status_flags` field of the `ValidatorRecord`.
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

/// Handles the deserialization logic for the `status_flags` field of the `ValidatorRecord`.
fn status_flag_from_byte(flag: u8) -> Result<Option<StatusFlags>, StatusFlagsDecodeError> {
    match flag {
        0 => Ok(None),
        1 => Ok(Some(StatusFlags::InitiatedExit)),
        2 => Ok(Some(StatusFlags::Withdrawable)),
        _ => Err(StatusFlagsDecodeError),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatorRecord {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: Hash256,
    pub proposer_slots: u64,
    pub activation_slot: u64,
    pub exit_slot: u64,
    pub withdrawal_slot: u64,
    pub penalized_slot: u64,
    pub exit_count: u64,
    pub status_flags: Option<StatusFlags>,
    pub custody_commitment: Hash256,
    pub latest_custody_reseed_slot: u64,
    pub penultimate_custody_reseed_slot: u64,
}

impl ValidatorRecord {
    /// This predicate indicates if the validator represented by this record is considered "active" at `slot`.
    pub fn is_active_at(&self, slot: u64) -> bool {
        self.activation_slot <= slot && slot < self.exit_slot
    }
}

impl Default for ValidatorRecord {
    /// Yields a "default" `ValidatorRecord`. Primarily used for testing.
    fn default() -> Self {
        Self {
            pubkey: PublicKey::default(),
            withdrawal_credentials: Hash256::default(),
            proposer_slots: 0,
            activation_slot: std::u64::MAX,
            exit_slot: std::u64::MAX,
            withdrawal_slot: std::u64::MAX,
            penalized_slot: std::u64::MAX,
            exit_count: 0,
            status_flags: None,
            custody_commitment: Hash256::default(),
            latest_custody_reseed_slot: 0, // NOTE: is `GENESIS_SLOT`
            penultimate_custody_reseed_slot: 0, // NOTE: is `GENESIS_SLOT`
        }
    }
}

impl<T: RngCore> TestRandom<T> for StatusFlags {
    fn random_for_test(rng: &mut T) -> Self {
        let options = vec![StatusFlags::InitiatedExit, StatusFlags::Withdrawable];
        options[(rng.next_u32() as usize) % options.len()].clone()
    }
}

impl Encodable for ValidatorRecord {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.pubkey);
        s.append(&self.withdrawal_credentials);
        s.append(&self.proposer_slots);
        s.append(&self.activation_slot);
        s.append(&self.exit_slot);
        s.append(&self.withdrawal_slot);
        s.append(&self.penalized_slot);
        s.append(&self.exit_count);
        s.append(&status_flag_to_byte(self.status_flags));
        s.append(&self.custody_commitment);
        s.append(&self.latest_custody_reseed_slot);
        s.append(&self.penultimate_custody_reseed_slot);
    }
}

impl Decodable for ValidatorRecord {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (pubkey, i) = <_>::ssz_decode(bytes, i)?;
        let (withdrawal_credentials, i) = <_>::ssz_decode(bytes, i)?;
        let (proposer_slots, i) = <_>::ssz_decode(bytes, i)?;
        let (activation_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (exit_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (withdrawal_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (penalized_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (exit_count, i) = <_>::ssz_decode(bytes, i)?;
        let (status_flags_byte, i): (u8, usize) = <_>::ssz_decode(bytes, i)?;
        let (custody_commitment, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_custody_reseed_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (penultimate_custody_reseed_slot, i) = <_>::ssz_decode(bytes, i)?;

        let status_flags = status_flag_from_byte(status_flags_byte)?;

        Ok((
            Self {
                pubkey,
                withdrawal_credentials,
                proposer_slots,
                activation_slot,
                exit_slot,
                withdrawal_slot,
                penalized_slot,
                exit_count,
                status_flags,
                custody_commitment,
                latest_custody_reseed_slot,
                penultimate_custody_reseed_slot,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for ValidatorRecord {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            pubkey: <_>::random_for_test(rng),
            withdrawal_credentials: <_>::random_for_test(rng),
            proposer_slots: <_>::random_for_test(rng),
            activation_slot: <_>::random_for_test(rng),
            exit_slot: <_>::random_for_test(rng),
            withdrawal_slot: <_>::random_for_test(rng),
            penalized_slot: <_>::random_for_test(rng),
            exit_count: <_>::random_for_test(rng),
            status_flags: Some(<_>::random_for_test(rng)),
            custody_commitment: <_>::random_for_test(rng),
            latest_custody_reseed_slot: <_>::random_for_test(rng),
            penultimate_custody_reseed_slot: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = ValidatorRecord::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_validator_can_be_active() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut validator = ValidatorRecord::random_for_test(&mut rng);

        let activation_slot = u64::random_for_test(&mut rng);
        let exit_slot = activation_slot + 234;

        validator.activation_slot = activation_slot;
        validator.exit_slot = exit_slot;

        for slot in (activation_slot - 100)..(exit_slot + 100) {
            if slot < activation_slot {
                assert!(!validator.is_active_at(slot));
            } else if slot >= exit_slot {
                assert!(!validator.is_active_at(slot));
            } else {
                assert!(validator.is_active_at(slot));
            }
        }
    }
}

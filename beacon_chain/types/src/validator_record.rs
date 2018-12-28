use super::bls::PublicKey;
use super::{Address, Hash256};
use crate::test_utils::TestRandom;
use rand::RngCore;
use ssz::{Decodable, DecodeError, Encodable, SszStream};
use std::convert;

#[derive(Debug, PartialEq, Clone)]
pub enum ValidatorStatus {
    PendingActivation,
    Active,
    PendingExit,
    PendingWithdraw,
    Withdrawn,
    Penalized,
}

impl convert::From<u8> for ValidatorStatus {
    fn from(status: u8) -> Self {
        match status {
            0 => ValidatorStatus::PendingActivation,
            1 => ValidatorStatus::Active,
            2 => ValidatorStatus::PendingExit,
            3 => ValidatorStatus::PendingWithdraw,
            5 => ValidatorStatus::Withdrawn,
            127 => ValidatorStatus::Penalized,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatorRecord {
    pub pubkey: PublicKey,
    pub withdrawal_shard: u64,
    pub withdrawal_address: Address,
    pub randao_commitment: Hash256,
    pub randao_last_change: u64,
    pub balance: u64,
    pub status: ValidatorStatus,
    pub exit_slot: u64,
}

impl Encodable for ValidatorStatus {
    fn ssz_append(&self, s: &mut SszStream) {
        let byte: u8 = match self {
            ValidatorStatus::PendingActivation => 0,
            ValidatorStatus::Active => 1,
            ValidatorStatus::PendingExit => 2,
            ValidatorStatus::PendingWithdraw => 3,
            ValidatorStatus::Withdrawn => 5,
            ValidatorStatus::Penalized => 127,
        };
        s.append(&byte);
    }
}

impl Decodable for ValidatorStatus {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (byte, i) = u8::ssz_decode(bytes, i)?;
        let status = match byte {
            0 => ValidatorStatus::PendingActivation,
            1 => ValidatorStatus::Active,
            2 => ValidatorStatus::PendingExit,
            3 => ValidatorStatus::PendingWithdraw,
            5 => ValidatorStatus::Withdrawn,
            127 => ValidatorStatus::Penalized,
            _ => return Err(DecodeError::Invalid),
        };
        Ok((status, i))
    }
}

impl<T: RngCore> TestRandom<T> for ValidatorStatus {
    fn random_for_test(rng: &mut T) -> Self {
        let options = vec![
            ValidatorStatus::PendingActivation,
            ValidatorStatus::Active,
            ValidatorStatus::PendingExit,
            ValidatorStatus::PendingWithdraw,
            ValidatorStatus::Withdrawn,
            ValidatorStatus::Penalized,
        ];
        options[(rng.next_u32() as usize) % options.len()].clone()
    }
}

impl Encodable for ValidatorRecord {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.pubkey);
        s.append(&self.withdrawal_shard);
        s.append(&self.withdrawal_address);
        s.append(&self.randao_commitment);
        s.append(&self.randao_last_change);
        s.append(&self.balance);
        s.append(&self.status);
        s.append(&self.exit_slot);
    }
}

impl Decodable for ValidatorRecord {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (pubkey, i) = <_>::ssz_decode(bytes, i)?;
        let (withdrawal_shard, i) = <_>::ssz_decode(bytes, i)?;
        let (withdrawal_address, i) = <_>::ssz_decode(bytes, i)?;
        let (randao_commitment, i) = <_>::ssz_decode(bytes, i)?;
        let (randao_last_change, i) = <_>::ssz_decode(bytes, i)?;
        let (balance, i) = <_>::ssz_decode(bytes, i)?;
        let (status, i) = <_>::ssz_decode(bytes, i)?;
        let (exit_slot, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                pubkey,
                withdrawal_shard,
                withdrawal_address,
                randao_commitment,
                randao_last_change,
                balance,
                status,
                exit_slot,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for ValidatorRecord {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            pubkey: <_>::random_for_test(rng),
            withdrawal_shard: <_>::random_for_test(rng),
            withdrawal_address: <_>::random_for_test(rng),
            randao_commitment: <_>::random_for_test(rng),
            randao_last_change: <_>::random_for_test(rng),
            balance: <_>::random_for_test(rng),
            status: <_>::random_for_test(rng),
            exit_slot: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::*;
    use crate::test_utils::TestRandom;
    use rand::{prng::XorShiftRng, SeedableRng};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = ValidatorRecord::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_validator_status_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = ValidatorStatus::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}

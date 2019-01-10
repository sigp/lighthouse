use super::bls::PublicKey;
use super::Hash256;
use crate::test_utils::TestRandom;
use rand::RngCore;
use ssz::{Decodable, DecodeError, Encodable, SszStream};
use std::convert;

#[derive(Debug, PartialEq, Clone, Copy)]
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
    pub withdrawal_credentials: Hash256,
    pub randao_commitment: Hash256,
    pub randao_layers: u64,
    pub status: ValidatorStatus,
    pub latest_status_change_slot: u64,
    pub exit_count: u64,
    pub custody_commitment: Hash256,
    pub latest_custody_reseed_slot: u64,
    pub penultimate_custody_reseed_slot: u64,
}

impl ValidatorRecord {
    pub fn status_is(&self, status: ValidatorStatus) -> bool {
        self.status == status
    }
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
        options[(rng.next_u32() as usize) % options.len()]
    }
}

impl Encodable for ValidatorRecord {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.pubkey);
        s.append(&self.withdrawal_credentials);
        s.append(&self.randao_commitment);
        s.append(&self.randao_layers);
        s.append(&self.status);
        s.append(&self.latest_status_change_slot);
        s.append(&self.exit_count);
        s.append(&self.custody_commitment);
        s.append(&self.latest_custody_reseed_slot);
        s.append(&self.penultimate_custody_reseed_slot);
    }
}

impl Decodable for ValidatorRecord {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (pubkey, i) = <_>::ssz_decode(bytes, i)?;
        let (withdrawal_credentials, i) = <_>::ssz_decode(bytes, i)?;
        let (randao_commitment, i) = <_>::ssz_decode(bytes, i)?;
        let (randao_layers, i) = <_>::ssz_decode(bytes, i)?;
        let (status, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_status_change_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (exit_count, i) = <_>::ssz_decode(bytes, i)?;
        let (custody_commitment, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_custody_reseed_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (penultimate_custody_reseed_slot, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                pubkey,
                withdrawal_credentials,
                randao_commitment,
                randao_layers,
                status,
                latest_status_change_slot,
                exit_count,
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
            randao_commitment: <_>::random_for_test(rng),
            randao_layers: <_>::random_for_test(rng),
            status: <_>::random_for_test(rng),
            latest_status_change_slot: <_>::random_for_test(rng),
            exit_count: <_>::random_for_test(rng),
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
    pub fn test_validator_status_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = ValidatorStatus::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}

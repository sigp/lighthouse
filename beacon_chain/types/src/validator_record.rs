use super::bls::PublicKey;
use super::Hash256;
use crate::test_utils::TestRandom;
use rand::RngCore;
use ssz::{Decodable, DecodeError, Encodable, SszStream};
use std::convert;
use std::default;

const STATUS_FLAG_INITIATED_EXIT: u8 = 1;
const STATUS_FLAG_WITHDRAWABLE: u8 = 2;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum StatusFlags {
    InitiatedExit,
    Withdrawable,
}

impl convert::From<u8> for StatusFlags {
    fn from(status_flag: u8) -> Self {
        match status_flag {
            STATUS_FLAG_INITIATED_EXIT => StatusFlags::InitiatedExit,
            STATUS_FLAG_WITHDRAWABLE => StatusFlags::Withdrawable,
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

impl default::Default for ValidatorRecord {
    fn default() -> Self {
        Self {
            pubkey: PublicKey::default(),
            withdrawal_credentials: Hash256::default(),
            randao_commitment: Hash256::default(),
            randao_layers: 0,
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

impl Encodable for StatusFlags {
    fn ssz_append(&self, s: &mut SszStream) {
        let byte: u8 = match self {
            StatusFlags::InitiatedExit => STATUS_FLAG_INITIATED_EXIT,
            StatusFlags::Withdrawable => STATUS_FLAG_WITHDRAWABLE,
        };
        s.append(&byte);
    }
}

impl Decodable for StatusFlags {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (byte, i) = u8::ssz_decode(bytes, i)?;
        let status = match byte {
            1 => StatusFlags::InitiatedExit,
            2 => StatusFlags::Withdrawable,
            _ => return Err(DecodeError::Invalid),
        };
        Ok((status, i))
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
        s.append(&self.randao_commitment);
        s.append(&self.randao_layers);
        s.append(&self.activation_slot);
        s.append(&self.exit_slot);
        s.append(&self.withdrawal_slot);
        s.append(&self.penalized_slot);
        s.append(&self.exit_count);
        if let Some(status_flags) = self.status_flags {
            s.append(&status_flags);
        } else {
            s.append(&(0 as u8));
        }
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
        let (activation_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (exit_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (withdrawal_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (penalized_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (exit_count, i) = <_>::ssz_decode(bytes, i)?;
        let (status_flags_byte, i): (u8, usize) = <_>::ssz_decode(bytes, i)?;
        let (custody_commitment, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_custody_reseed_slot, i) = <_>::ssz_decode(bytes, i)?;
        let (penultimate_custody_reseed_slot, i) = <_>::ssz_decode(bytes, i)?;

        let status_flags = if status_flags_byte == 0u8 {
            None
        } else {
            Some(StatusFlags::from(status_flags_byte))
        };

        Ok((
            Self {
                pubkey,
                withdrawal_credentials,
                randao_commitment,
                randao_layers,
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
            randao_commitment: <_>::random_for_test(rng),
            randao_layers: <_>::random_for_test(rng),
            exit_count: <_>::random_for_test(rng),
            status_flags: Some(<_>::random_for_test(rng)),
            custody_commitment: <_>::random_for_test(rng),
            latest_custody_reseed_slot: <_>::random_for_test(rng),
            penultimate_custody_reseed_slot: <_>::random_for_test(rng),
            ..Self::default()
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
        let original = StatusFlags::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}

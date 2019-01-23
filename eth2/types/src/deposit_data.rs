use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::DepositInput;
use crate::test_utils::TestRandom;
use rand::RngCore;

#[derive(Debug, PartialEq, Clone)]
pub struct DepositData {
    pub amount: u64,
    pub timestamp: u64,
    pub deposit_input: DepositInput,
}

impl Encodable for DepositData {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.amount);
        s.append(&self.timestamp);
        s.append(&self.deposit_input);
    }
}

impl Decodable for DepositData {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (amount, i) = <_>::ssz_decode(bytes, i)?;
        let (timestamp, i) = <_>::ssz_decode(bytes, i)?;
        let (deposit_input, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                amount,
                timestamp,
                deposit_input,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for DepositData {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            amount: <_>::random_for_test(rng),
            timestamp: <_>::random_for_test(rng),
            deposit_input: <_>::random_for_test(rng),
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
        let original = DepositData::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}

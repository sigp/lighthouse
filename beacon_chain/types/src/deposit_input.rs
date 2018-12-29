use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::Hash256;
use crate::test_utils::TestRandom;
use bls::{PublicKey, Signature};
use rand::RngCore;

#[derive(Debug, PartialEq, Clone)]
pub struct DepositInput {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: Hash256,
    pub randao_commitment: Hash256,
    pub poc_commitment: Hash256,
    pub proof_of_possession: Signature,
}

impl Encodable for DepositInput {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.pubkey);
        s.append(&self.withdrawal_credentials);
        s.append(&self.randao_commitment);
        s.append(&self.poc_commitment);
        s.append(&self.proof_of_possession);
    }
}

impl Decodable for DepositInput {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (pubkey, i) = <_>::ssz_decode(bytes, i)?;
        let (withdrawal_credentials, i) = <_>::ssz_decode(bytes, i)?;
        let (randao_commitment, i) = <_>::ssz_decode(bytes, i)?;
        let (poc_commitment, i) = <_>::ssz_decode(bytes, i)?;
        let (proof_of_possession, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                pubkey,
                withdrawal_credentials,
                randao_commitment,
                poc_commitment,
                proof_of_possession,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for DepositInput {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            pubkey: <_>::random_for_test(rng),
            withdrawal_credentials: <_>::random_for_test(rng),
            randao_commitment: <_>::random_for_test(rng),
            poc_commitment: <_>::random_for_test(rng),
            proof_of_possession: <_>::random_for_test(rng),
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
        let original = DepositInput::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}

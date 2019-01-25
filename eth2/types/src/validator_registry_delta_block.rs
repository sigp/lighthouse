use super::Hash256;
use crate::test_utils::TestRandom;
use bls::PublicKey;
use rand::RngCore;
use ssz::{Decodable, DecodeError, Encodable, SszStream};

// The information gathered from the PoW chain validator registration function.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatorRegistryDeltaBlock {
    pub latest_registry_delta_root: Hash256,
    pub validator_index: u32,
    pub pubkey: PublicKey,
    pub slot: u64,
    pub flag: u64,
}

impl Default for ValidatorRegistryDeltaBlock {
    /// Yields a "default" `Validator`. Primarily used for testing.
    fn default() -> Self {
        Self {
            latest_registry_delta_root: Hash256::zero(),
            validator_index: std::u32::MAX,
            pubkey: PublicKey::default(),
            slot: std::u64::MAX,
            flag: std::u64::MAX,
        }
    }
}

impl Encodable for ValidatorRegistryDeltaBlock {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.latest_registry_delta_root);
        s.append(&self.validator_index);
        s.append(&self.pubkey);
        s.append(&self.slot);
        s.append(&self.flag);
    }
}

impl Decodable for ValidatorRegistryDeltaBlock {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (latest_registry_delta_root, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_index, i) = <_>::ssz_decode(bytes, i)?;
        let (pubkey, i) = <_>::ssz_decode(bytes, i)?;
        let (slot, i) = <_>::ssz_decode(bytes, i)?;
        let (flag, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                latest_registry_delta_root,
                validator_index,
                pubkey,
                slot,
                flag,
            },
            i,
        ))
    }
}

impl<T: RngCore> TestRandom<T> for ValidatorRegistryDeltaBlock {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            latest_registry_delta_root: <_>::random_for_test(rng),
            validator_index: <_>::random_for_test(rng),
            pubkey: <_>::random_for_test(rng),
            slot: <_>::random_for_test(rng),
            flag: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ssz::ssz_encode;
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = ValidatorRegistryDeltaBlock::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}

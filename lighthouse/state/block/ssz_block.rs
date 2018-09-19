use super::ssz::decode::{
    decode_length,
    Decodable,
};
use super::utils::hash::canonical_hash;

pub enum BlockValidatorError {
    SszInvalid,
    BadPowHash,
    SlotTooLow,
    SlotTooHigh,
}

const LENGTH_BYTES: usize = 4;
const MIN_SSZ_BLOCK_LENGTH: usize = {
    32 +    // parent_hash
    8 +     // slot_number
    32 +    // randao_reveal
    LENGTH_BYTES +     // attestations (assuming zero)
    32 +    // pow_chain_ref
    32 +    // active_state_root
    32      // crystallized_state_root
};
const MAX_SSZ_BLOCK_LENGTH: usize = MIN_SSZ_BLOCK_LENGTH + 2^24;


pub struct SszBlock<'a> {
    ssz: &'a [u8],
    attestation_len: usize,
}

impl<'a> SszBlock<'a> {
    pub fn from_vec(vec: &'a Vec<u8>)
        -> Result<Self, BlockValidatorError>
    {
        let ssz = &vec[..];
        if vec.len() < MIN_SSZ_BLOCK_LENGTH {
            return Err(BlockValidatorError::SszInvalid);
        }
        if vec.len() > MAX_SSZ_BLOCK_LENGTH {
            return Err(BlockValidatorError::SszInvalid);
        }
        let attestation_len = decode_length(ssz, 72, LENGTH_BYTES)
            .map_err(|_| BlockValidatorError::SszInvalid)?;
        // Is the length adequate now we know now many attestation
        // records exist?
        if vec.len() < (76 + attestation_len + 96) {
            return Err(BlockValidatorError::SszInvalid);
        }
        Ok(Self{
            ssz,
            attestation_len
        })
    }

    pub fn block_hash(&self) -> Vec<u8> {
        canonical_hash(self.ssz)
    }

    pub fn parent_hash(&self) -> &[u8] {
        &self.ssz[0..32]
    }

    pub fn slot_number(&self) -> u64 {
        u64::ssz_decode(&self.ssz, 32).unwrap().0
    }

    pub fn randao_reveal(&self) -> &[u8] {
        &self.ssz[40..72]
    }

    pub fn attestations(&self) -> &[u8] {
        let start = 72 + LENGTH_BYTES;
        &self.ssz[start..(start + self.attestation_len)]
    }

    pub fn pow_chain_ref(&self) -> &[u8] {
        let len = self.ssz.len();
        &self.ssz[(len - 96)..(len - 64)]
    }

    pub fn act_state_root(&self) -> &[u8] {
        let len = self.ssz.len();
        &self.ssz[(len - 64)..(len - 32)]
    }

    pub fn cry_state_root(&self) -> &[u8] {
        let len = self.ssz.len();
        &self.ssz[(len - 32)..(len)]
    }
}

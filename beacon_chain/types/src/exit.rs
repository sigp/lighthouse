use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use bls::AggregateSignature;

#[derive(Debug, PartialEq, Clone)]
pub struct Exit {
    pub slot: u64,
    pub validator_index: u32,
    pub signature: AggregateSignature,
}

impl Encodable for Exit {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.validator_index);
        s.append(&self.signature);
    }
}

impl Decodable for Exit {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slot, i) = u64::ssz_decode(bytes, i)?;
        let (validator_index, i) = u32::ssz_decode(bytes, i)?;
        let (signature, i) = AggregateSignature::ssz_decode(bytes, i)?;

        Ok((
            Self {
                slot,
                validator_index,
                signature,
            },
            i,
        ))
    }
}

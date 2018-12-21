use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::{BeaconBlockBody, Hash256};
use bls::AggregateSignature;

#[derive(Debug, PartialEq, Clone, Default)]
pub struct BeaconBlock {
    pub slot: u64,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub randao_reveal: Hash256,
    pub candidate_pow_receipt_root: Hash256,
    pub signature: AggregateSignature,
    pub body: BeaconBlockBody,
}

impl Encodable for BeaconBlock {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.parent_root);
        s.append(&self.state_root);
        s.append(&self.randao_reveal);
        s.append(&self.candidate_pow_receipt_root);
        s.append(&self.signature);
        s.append(&self.body);
    }
}

impl Decodable for BeaconBlock {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slot, i) = <_>::ssz_decode(bytes, i)?;
        let (parent_root, i) = <_>::ssz_decode(bytes, i)?;
        let (state_root, i) = <_>::ssz_decode(bytes, i)?;
        let (randao_reveal, i) = <_>::ssz_decode(bytes, i)?;
        let (candidate_pow_receipt_root, i) = <_>::ssz_decode(bytes, i)?;
        let (signature, i) = <_>::ssz_decode(bytes, i)?;
        let (body, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                slot,
                parent_root,
                state_root,
                randao_reveal,
                candidate_pow_receipt_root,
                signature,
                body,
            },
            i,
        ))
    }
}

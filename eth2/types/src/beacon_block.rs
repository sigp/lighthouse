use crate::test_utils::TestRandom;
use crate::{BeaconBlockBody, ChainSpec, Eth1Data, Hash256, ProposalSignedData, Slot};
use bls::Signature;
use rand::RngCore;
use serde_derive::Serialize;
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct BeaconBlock {
    pub slot: Slot,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    pub signature: Signature,
    pub body: BeaconBlockBody,
}

impl BeaconBlock {
    /// Produce the first block of the Beacon Chain.
    pub fn genesis(state_root: Hash256, spec: &ChainSpec) -> BeaconBlock {
        BeaconBlock {
            slot: spec.genesis_slot,
            parent_root: spec.zero_hash,
            state_root,
            randao_reveal: spec.empty_signature.clone(),
            eth1_data: Eth1Data {
                deposit_root: spec.zero_hash,
                block_hash: spec.zero_hash,
            },
            signature: spec.empty_signature.clone(),
            body: BeaconBlockBody {
                proposer_slashings: vec![],
                attester_slashings: vec![],
                attestations: vec![],
                deposits: vec![],
                exits: vec![],
            },
        }
    }

    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from(&self.hash_tree_root()[..])
    }

    pub fn proposal_root(&self, spec: &ChainSpec) -> Hash256 {
        let block_without_signature_root = {
            let mut block_without_signature = self.clone();
            block_without_signature.signature = spec.empty_signature.clone();
            block_without_signature.canonical_root()
        };

        let proposal = ProposalSignedData {
            slot: self.slot,
            shard: spec.beacon_chain_shard_number,
            block_root: block_without_signature_root,
        };
        Hash256::from(&proposal.hash_tree_root()[..])
    }
}

impl Encodable for BeaconBlock {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.parent_root);
        s.append(&self.state_root);
        s.append(&self.randao_reveal);
        s.append(&self.eth1_data);
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
        let (eth1_data, i) = <_>::ssz_decode(bytes, i)?;
        let (signature, i) = <_>::ssz_decode(bytes, i)?;
        let (body, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                slot,
                parent_root,
                state_root,
                randao_reveal,
                eth1_data,
                signature,
                body,
            },
            i,
        ))
    }
}

impl TreeHash for BeaconBlock {
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.slot.hash_tree_root());
        result.append(&mut self.parent_root.hash_tree_root());
        result.append(&mut self.state_root.hash_tree_root());
        result.append(&mut self.randao_reveal.hash_tree_root());
        result.append(&mut self.eth1_data.hash_tree_root());
        result.append(&mut self.signature.hash_tree_root());
        result.append(&mut self.body.hash_tree_root());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for BeaconBlock {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            slot: <_>::random_for_test(rng),
            parent_root: <_>::random_for_test(rng),
            state_root: <_>::random_for_test(rng),
            randao_reveal: <_>::random_for_test(rng),
            eth1_data: <_>::random_for_test(rng),
            signature: <_>::random_for_test(rng),
            body: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::ssz_encode;

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = BeaconBlock::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = BeaconBlock::random_for_test(&mut rng);

        let result = original.hash_tree_root();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}

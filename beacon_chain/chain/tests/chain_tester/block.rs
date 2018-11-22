use super::ChainTester;
use db::ClientDB;
use ssz::decode::Decodable;
use types::{BeaconBlock, Hash256};
use validator_shuffling::{block_proposer_for_slot, shard_and_committee_for_slot};

impl<T: ClientDB> ChainTester<T> {
    pub fn produce_perfect_block(&self, slot: u64, parent_hash: &Hash256) -> BeaconBlock {
        let parent_block = {
            let ssz = self
                .chain
                .store
                .block
                .get_serialized_block(&parent_hash[..])
                .unwrap()
                .unwrap();
            let (block, _) = BeaconBlock::ssz_decode(&ssz, 0).unwrap();
            block
        };

        // TODO: the following five variables are not implemented yet; implement them.
        let randao_reveal = Hash256::zero();
        let pow_chain_reference = Hash256::zero();
        let attestations = vec![];
        let specials = vec![];

        self.chain
            .produce_block(
                slot,
                &parent_block,
                randao_reveal,
                pow_chain_reference,
                attestations,
                specials,
            ).unwrap()
    }
}

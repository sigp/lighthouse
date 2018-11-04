use super::ChainTester;
use db::ClientDB;
use ssz::decode::Decodable;
use types::{BeaconBlock, Hash256};
use validator_shuffling::{block_proposer_for_slot, shard_and_committee_for_slot};

impl<T: ClientDB> ChainTester<T> {
    pub fn valid_block_at_slot(&self, slot: u64, parent_hash: &Hash256) -> BeaconBlock {
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
        let parent_cry_state = self
            .chain
            .crystallized_states
            .get(&parent_block.crystallized_state_root)
            .unwrap();
    }
}

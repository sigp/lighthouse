/*
 * Note: this is a copy of the ./tests.rs file that is rigged to give some fast and easy
 * benchmarking.
 *
 * This file should be moved into a bench/ dir in the root and structured correctly.
 */

extern crate ssz;
extern crate test;

use self::test::Bencher;
use self::ssz::{
    SszStream,
};
use std::sync::Arc;
use super::{
    validate_ssz_block,
    BlockStatus,
    ProposerMap,
};
use super::utils::types::{
    Hash256,
};
use super::SszBlock;
use super::super::Block;

use super::tests::{
    TestStore,
    generate_attestations_for_slot,
};

#[derive(Debug)]
struct BenchmarkParams {
    total_validators: usize,
    cycle_length: u8,
    shard_count: u16,
    shards_per_slot: u16,
    validators_per_shard: usize,
}

impl BenchmarkParams {
    pub fn danny_wants() -> Self {
        /*
         * 10M Eth where each validator is 32 ETH
         */
        let total_validators: usize = 10_000_000 / 32;
        /*
         * 64 slots per cycle
         */
        let cycle_length: u8 = 64;
        /*
         * 1024 shards
         */
        let shard_count: u16 = 1024;
        /*
         * Number of shards per slot
         */
        let shards_per_slot: u16 = 1024 / u16::from(cycle_length);
        /*
         * Number of validators in each shard
         */
        let validators_per_shard: usize = total_validators / usize::from(shard_count);

        Self {
            total_validators,
            cycle_length,
            shard_count,
            shards_per_slot,
            validators_per_shard,
        }
    }
}

#[bench]
fn bench_block_validation(b: &mut Bencher) {
    let stores = TestStore::new();

    let params = BenchmarkParams::danny_wants();

    println!("{:?}", params);

    let cycle_length = params.cycle_length;
    let shards_per_slot = params.shards_per_slot;
    let validators_per_shard = params.validators_per_shard;

    let present_slot = u64::from(cycle_length) * 10000;
    let justified_slot = present_slot - u64::from(cycle_length);
    let justified_block_hash = Hash256::from("justified_hash".as_bytes());
    let shard_block_hash = Hash256::from("shard_hash".as_bytes());
    let parent_hashes: Vec<Hash256> = (0..(cycle_length * 2))
        .map(|i| Hash256::from(i as u64))
        .collect();
    let pow_chain_ref = Hash256::from("pow_chain".as_bytes());
    let active_state_root = Hash256::from("active_state".as_bytes());
    let crystallized_state_root = Hash256::from("cry_state".as_bytes());

    stores.pow_chain.put_block_hash(pow_chain_ref.as_ref()).unwrap();
    stores.block.put_block(justified_block_hash.as_ref(), &vec![42]).unwrap();


    let block_slot = present_slot;
    let validator_index: usize = 0;
    let proposer_map = {
        let mut proposer_map = ProposerMap::new();
        proposer_map.insert(present_slot, validator_index);
        proposer_map
    };
    let attestation_slot = block_slot - 1;
    let (attester_map, attestations, _keypairs) =
        generate_attestations_for_slot(
            attestation_slot,
            block_slot,
            shards_per_slot,
            validators_per_shard,
            cycle_length,
            &parent_hashes,
            &shard_block_hash,
            &justified_block_hash,
            justified_slot,
            &stores);

    let block = Block {
        parent_hash: Hash256::from("parent".as_bytes()),
        slot_number: block_slot,
        randao_reveal: Hash256::from("randao".as_bytes()),
        attestations,
        pow_chain_ref,
        active_state_root,
        crystallized_state_root,
    };

    let mut stream = SszStream::new();
    stream.append(&block);
    let serialized_block = stream.drain();
    let ssz_block = SszBlock::from_slice(&serialized_block[..]).unwrap();

    let parent_hashes = Arc::new(parent_hashes);
    let proposer_map = Arc::new(proposer_map);
    let attester_map = Arc::new(attester_map);
    b.iter(|| {
        let status = validate_ssz_block(
            &ssz_block,
            present_slot,
            cycle_length,
            justified_slot,
            &parent_hashes,
            &proposer_map,
            &attester_map,
            &stores.block.clone(),
            &stores.validator.clone(),
            &stores.pow_chain.clone()).unwrap();
        assert_eq!(status, BlockStatus::NewBlock);
    });
}

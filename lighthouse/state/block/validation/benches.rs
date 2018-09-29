extern crate test;

use self::test::Bencher;

use std::sync::Arc;

use super::{
    validate_ssz_block,
    AttesterMap,
    ProposerMap,
};

use super::tests::{
    TestStore,
    TestParams,
    setup_block_validation_scenario,
    serialize_block,
};

use super::super::{
    Block,
    SszBlock,
};

fn bench_block_validation_scenario<F>(
    b: &mut Bencher,
    validation_slot: u64,
    validation_last_justified_slot: u64,
    params: &TestParams,
    mutator_func: F)
    where F: FnOnce(Block, AttesterMap, ProposerMap, TestStore)
                -> (Block, AttesterMap, ProposerMap, TestStore)
{
    let (block,
     parent_hashes,
     attester_map,
     proposer_map,
     stores) = setup_block_validation_scenario(&params);

    let (block,
         attester_map,
         proposer_map,
         stores) = mutator_func(block, attester_map, proposer_map, stores);

    let ssz_bytes = serialize_block(&block);
    let ssz_block = SszBlock::from_slice(&ssz_bytes[..])
        .unwrap();

    let parent_hashes = Arc::new(parent_hashes);
    let proposer_map = Arc::new(proposer_map);
    let attester_map = Arc::new(attester_map);
    b.iter(|| {
        validate_ssz_block(
            &ssz_block,
            validation_slot,
            params.cycle_length,
            validation_last_justified_slot,
            &parent_hashes.clone(),
            &proposer_map.clone(),
            &attester_map.clone(),
            &stores.block.clone(),
            &stores.validator.clone(),
            &stores.pow_chain.clone())
    });
}

#[bench]
fn bench_block_validation_10m_eth(b: &mut Bencher) {
    let total_validators: usize = 10_000_000 / 32;
    let cycle_length: u8 = 64;
    let shard_count: u16 = 1024;
    let shards_per_slot: u16 = 1024 / u16::from(cycle_length);
    let validators_per_shard: usize = total_validators / usize::from(shard_count);
    let block_slot = u64::from(cycle_length) * 10000;
    let attestations_justified_slot = block_slot - u64::from(cycle_length);

    let params = TestParams {
        total_validators,
        cycle_length,
        shard_count,
        shards_per_slot,
        validators_per_shard,
        block_slot,
        attestations_justified_slot,
    };
    let validation_slot = params.block_slot;
    let validation_last_justified_slot = params.attestations_justified_slot;

    let no_mutate = |block, attester_map, proposer_map, stores| {
        (block, attester_map, proposer_map, stores)
    };

    bench_block_validation_scenario(
        b,
        validation_slot,
        validation_last_justified_slot,
        &params,
        no_mutate);
}

#[bench]
fn bench_block_validation_100m_eth(b: &mut Bencher) {
    let total_validators: usize = 100_000_000 / 32;
    let cycle_length: u8 = 64;
    let shard_count: u16 = 1024;
    let shards_per_slot: u16 = 1024 / u16::from(cycle_length);
    let validators_per_shard: usize = total_validators / usize::from(shard_count);
    let block_slot = u64::from(cycle_length) * 10000;
    let attestations_justified_slot = block_slot - u64::from(cycle_length);

    let params = TestParams {
        total_validators,
        cycle_length,
        shard_count,
        shards_per_slot,
        validators_per_shard,
        block_slot,
        attestations_justified_slot,
    };

    let validation_slot = params.block_slot;
    let validation_last_justified_slot = params.attestations_justified_slot;

    let no_mutate = |block, attester_map, proposer_map, stores| {
        (block, attester_map, proposer_map, stores)
    };

    bench_block_validation_scenario(
        b,
        validation_slot,
        validation_last_justified_slot,
        &params,
        no_mutate);
}

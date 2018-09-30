extern crate test;

use self::test::Bencher;

use std::sync::Arc;

use super::{
    BlockValidationContext,
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
        let context = BlockValidationContext {
            present_slot: params.validation_context_slot,
            cycle_length: params.cycle_length,
            last_justified_slot: params.validation_context_justified_slot,
            last_finalized_slot: params.validation_context_finalized_slot,
            parent_hashes: parent_hashes.clone(),
            proposer_map: proposer_map.clone(),
            attester_map: attester_map.clone(),
            block_store: stores.block.clone(),
            validator_store: stores.validator.clone(),
            pow_store: stores.pow_chain.clone()
        };
        let result = context.validate_ssz_block(&ssz_block);
        assert!(result.is_ok());
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
    let parent_proposer_index = 0;

    let validation_context_slot = block_slot;
    let validation_context_justified_slot = attestations_justified_slot;
    let validation_context_finalized_slot = 0;

    let params = TestParams {
        total_validators,
        cycle_length,
        shard_count,
        shards_per_slot,
        validators_per_shard,
        parent_proposer_index,
        block_slot,
        attestations_justified_slot,
        validation_context_slot,
        validation_context_justified_slot,
        validation_context_finalized_slot,
    };

    let no_mutate = |block, attester_map, proposer_map, stores| {
        (block, attester_map, proposer_map, stores)
    };

    bench_block_validation_scenario(
        b,
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
    let parent_proposer_index = 0;

    let validation_context_slot = block_slot;
    let validation_context_justified_slot = attestations_justified_slot;
    let validation_context_finalized_slot = 0;

    let params = TestParams {
        total_validators,
        cycle_length,
        shard_count,
        shards_per_slot,
        validators_per_shard,
        parent_proposer_index,
        block_slot,
        attestations_justified_slot,
        validation_context_slot,
        validation_context_justified_slot,
        validation_context_finalized_slot,
    };

    let no_mutate = |block, attester_map, proposer_map, stores| {
        (block, attester_map, proposer_map, stores)
    };

    bench_block_validation_scenario(
        b,
        &params,
        no_mutate);
}

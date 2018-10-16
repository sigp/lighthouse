use super::bls::{
    AggregateSignature,
};
use super::helpers::{
    BeaconBlockTestParams,
    TestStore,
    run_block_validation_scenario,
    serialize_block,
};
use super::types::{
    BeaconBlock,
    Hash256,
    ProposerMap,
};
use super::ssz_helpers::ssz_beacon_block::SszBeaconBlock;
use super::validation::block_validation::{
    SszBeaconBlockValidationError,
    BeaconBlockStatus,
};
use super::validation::attestation_validation::{
    AttestationValidationError,
};
use super::hashing::canonical_hash;

fn get_simple_params() -> BeaconBlockTestParams {
    let validators_per_shard: usize = 5;
    let cycle_length: u8 = 2;
    let shard_count: u16 = 4;
    let shards_per_slot: u16 = shard_count / u16::from(cycle_length);
    let total_validators: usize = validators_per_shard * shard_count as usize;
    let block_slot = u64::from(cycle_length) * 10000;
    let attestations_justified_slot = block_slot - u64::from(cycle_length);
    let parent_proposer_index = 0;

    let validation_context_slot = block_slot;
    let validation_context_justified_slot = attestations_justified_slot;
    let validation_context_justified_block_hash = Hash256::from("justified_hash".as_bytes());
    let validation_context_finalized_slot = 0;

    BeaconBlockTestParams {
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
        validation_context_justified_block_hash,
        validation_context_finalized_slot,
    }
}

// TODO: test bad ssz serialization

#[test]
fn test_block_validation_valid() {
    let params = get_simple_params();

    let mutator = |block: BeaconBlock, attester_map, proposer_map, stores| {
        /*
         * Do not mutate
         */
        (block, attester_map, proposer_map, stores)
    };

    let status = run_block_validation_scenario(
        &params,
        mutator);

    assert_eq!(status.unwrap().0, BeaconBlockStatus::NewBlock);
}

#[test]
fn test_block_validation_valid_known_block() {
    let params = get_simple_params();

    let mutator = |block: BeaconBlock, attester_map, proposer_map, stores: TestStore| {
        /*
         * Pre-store the block in the database
         */
        let block_ssz = serialize_block(&block);
        let block_hash = canonical_hash(&block_ssz);
        stores.block.put_serialized_block(&block_hash, &block_ssz).unwrap();
        (block, attester_map, proposer_map, stores)
    };

    let status = run_block_validation_scenario(
        &params,
        mutator);

    assert_eq!(status.unwrap(), (BeaconBlockStatus::KnownBlock, None));
}

#[test]
fn test_block_validation_parent_slot_too_high() {
    let params = get_simple_params();

    let mutator = |mut block: BeaconBlock, attester_map, proposer_map, stores| {
        block.slot = params.validation_context_justified_slot + 1;
        (block, attester_map, proposer_map, stores)
    };

    let status = run_block_validation_scenario(
        &params,
        mutator);

    assert_eq!(status, Err(SszBeaconBlockValidationError::ParentSlotHigherThanBlockSlot));
}

#[test]
fn test_block_validation_invalid_future_slot() {
    let params = get_simple_params();

    let mutator = |mut block: BeaconBlock, attester_map, proposer_map, stores| {
        block.slot = block.slot + 1;
        (block, attester_map, proposer_map, stores)
    };

    let status = run_block_validation_scenario(
        &params,
        mutator);

    assert_eq!(status, Err(SszBeaconBlockValidationError::FutureSlot));
}

#[test]
fn test_block_validation_invalid_slot_already_finalized() {
    let mut params = get_simple_params();

    params.validation_context_finalized_slot = params.block_slot;
    params.validation_context_justified_slot = params.validation_context_finalized_slot +
        u64::from(params.cycle_length);

    let mutator = |block, attester_map, proposer_map, stores| {
        /*
         * Do not mutate
         */
        (block, attester_map, proposer_map, stores)
    };

    let status = run_block_validation_scenario(
        &params,
        mutator);

    assert_eq!(status, Err(SszBeaconBlockValidationError::SlotAlreadyFinalized));
}

#[test]
fn test_block_validation_invalid_unknown_pow_hash() {
    let params = get_simple_params();

    let mutator = |mut block: BeaconBlock, attester_map, proposer_map, stores| {
        block.pow_chain_reference = Hash256::from("unknown pow hash".as_bytes());
        (block, attester_map, proposer_map, stores)
    };

    let status = run_block_validation_scenario(
        &params,
        mutator);

    assert_eq!(status, Err(SszBeaconBlockValidationError::UnknownPoWChainRef));
}

#[test]
fn test_block_validation_invalid_unknown_parent_hash() {
    let params = get_simple_params();

    let mutator = |mut block: BeaconBlock, attester_map, proposer_map, stores| {
        block.ancestor_hashes[0] = Hash256::from("unknown parent block".as_bytes());
        (block, attester_map, proposer_map, stores)
    };

    let status = run_block_validation_scenario(
        &params,
        mutator);

    assert_eq!(status, Err(SszBeaconBlockValidationError::UnknownParentHash));
}

#[test]
fn test_block_validation_invalid_1st_attestation_signature() {
    let params = get_simple_params();

    let mutator = |mut block: BeaconBlock, attester_map, proposer_map, stores| {
        /*
         * Set the second attestaion record to have an invalid signature.
         */
        block.attestations[0].aggregate_sig = AggregateSignature::new();
        (block, attester_map, proposer_map, stores)
    };

    let status = run_block_validation_scenario(
        &params,
        mutator);

    assert_eq!(status, Err(SszBeaconBlockValidationError::AttestationValidationError(
                AttestationValidationError::BadAggregateSignature)));
}

#[test]
fn test_block_validation_invalid_no_parent_proposer_signature() {
    let params = get_simple_params();

    let mutator = |block: BeaconBlock, attester_map, mut proposer_map: ProposerMap, stores: TestStore| {
        /*
         * Set the proposer for this slot to be a validator that does not exist.
         */
        let ssz = {
            let parent_hash = block.parent_hash().unwrap().as_ref();
            stores.block.get_serialized_block(parent_hash).unwrap().unwrap()
        };
        let parent_block_slot = SszBeaconBlock::from_slice(&ssz[..]).unwrap().slot();
        proposer_map.insert(parent_block_slot, params.total_validators + 1);
        (block, attester_map, proposer_map, stores)
    };

    let status = run_block_validation_scenario(
        &params,
        mutator);

    assert_eq!(status, Err(SszBeaconBlockValidationError::NoProposerSignature));
}

#[test]
fn test_block_validation_invalid_bad_proposer_map() {
    let params = get_simple_params();

    let mutator = |block, attester_map, _, stores| {
        /*
         * Initialize a new, empty proposer map
         */
        let proposer_map = ProposerMap::new();
        (block, attester_map, proposer_map, stores)
    };

    let status = run_block_validation_scenario(
        &params,
        mutator);

    assert_eq!(status, Err(SszBeaconBlockValidationError::BadProposerMap));
}

#[test]
fn test_block_validation_invalid_2nd_attestation_signature() {
    let params = get_simple_params();

    let mutator = |mut block: BeaconBlock, attester_map, proposer_map, stores| {
        /*
         * Set the second attestaion record to have an invalid signature.
         */
        block.attestations[1].aggregate_sig = AggregateSignature::new();
        (block, attester_map, proposer_map, stores)
    };

    let status = run_block_validation_scenario(
        &params,
        mutator);

    assert_eq!(status, Err(SszBeaconBlockValidationError::AttestationValidationError(
                AttestationValidationError::BadAggregateSignature)));
}

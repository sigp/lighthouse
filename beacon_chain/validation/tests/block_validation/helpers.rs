use std::sync::Arc;

use super::attestation_validation::helpers::{generate_attestation, insert_justified_block_hash};
use super::bls::Keypair;
use super::db::stores::{BeaconBlockStore, PoWChainStore, ValidatorStore};
use super::db::MemoryDB;
use super::ssz::SszStream;
use super::ssz_helpers::ssz_beacon_block::SszBeaconBlock;
use super::types::{AttestationRecord, AttesterMap, BeaconBlock, Hash256, ProposerMap};
use super::validation::block_validation::{
    BeaconBlockValidationContext, SszBeaconBlockValidationError,
};

#[derive(Debug)]
pub struct BeaconBlockTestParams {
    pub total_validators: usize,
    pub cycle_length: u8,
    pub shard_count: u16,
    pub shards_per_slot: u16,
    pub validators_per_shard: usize,
    pub block_slot: u64,
    pub attestations_justified_slot: u64,
    pub parent_proposer_index: usize,
    pub validation_context_slot: u64,
    pub validation_context_justified_slot: u64,
    pub validation_context_justified_block_hash: Hash256,
    pub validation_context_finalized_slot: u64,
}

pub struct TestStore {
    pub db: Arc<MemoryDB>,
    pub block: Arc<BeaconBlockStore<MemoryDB>>,
    pub pow_chain: Arc<PoWChainStore<MemoryDB>>,
    pub validator: Arc<ValidatorStore<MemoryDB>>,
}

impl TestStore {
    pub fn new() -> Self {
        let db = Arc::new(MemoryDB::open());
        let block = Arc::new(BeaconBlockStore::new(db.clone()));
        let pow_chain = Arc::new(PoWChainStore::new(db.clone()));
        let validator = Arc::new(ValidatorStore::new(db.clone()));
        Self {
            db,
            block,
            pow_chain,
            validator,
        }
    }
}

type ParentHashes = Vec<Hash256>;

/// Setup for a block validation function, without actually executing the
/// block validation function.
pub fn setup_block_validation_scenario(
    params: &BeaconBlockTestParams,
) -> (
    BeaconBlock,
    ParentHashes,
    AttesterMap,
    ProposerMap,
    TestStore,
) {
    let stores = TestStore::new();

    let cycle_length = params.cycle_length;
    let shards_per_slot = params.shards_per_slot;
    let validators_per_shard = params.validators_per_shard;
    let block_slot = params.block_slot;
    let attestations_justified_slot = params.attestations_justified_slot;

    let mut parent_hashes: Vec<Hash256> = (0..(cycle_length * 2))
        .map(|i| Hash256::from(i as u64))
        .collect();
    let parent_hash = Hash256::from("parent_hash".as_bytes());
    let ancestor_hashes = vec![parent_hash.clone(); 32];
    let randao_reveal = Hash256::from("randao_reveal".as_bytes());
    let justified_block_hash = Hash256::from("justified_hash".as_bytes());
    let pow_chain_ref = Hash256::from("pow_chain".as_bytes());
    let active_state_root = Hash256::from("active_state".as_bytes());
    let crystallized_state_root = Hash256::from("cry_state".as_bytes());
    let shard_block_hash = Hash256::from("shard_block_hash".as_bytes());

    /*
     * Store a valid PoW chain ref
     */
    stores
        .pow_chain
        .put_block_hash(pow_chain_ref.as_ref())
        .unwrap();

    /*
     * Generate a minimum viable parent block and store it in the database.
     */
    let mut parent_block = BeaconBlock::zero();
    let parent_attestation = AttestationRecord::zero();
    parent_block.slot = block_slot - 1;
    parent_block.attestations.push(parent_attestation);
    let parent_block_ssz = serialize_block(&parent_block);
    stores
        .block
        .put_serialized_block(parent_hash.as_ref(), &parent_block_ssz)
        .unwrap();

    let proposer_map = {
        let mut proposer_map = ProposerMap::new();
        proposer_map.insert(parent_block.slot, params.parent_proposer_index);
        proposer_map
    };

    let (attester_map, attestations, _keypairs) = {
        let mut i = 0;
        let attestation_slot = block_slot - 1;
        let mut attester_map = AttesterMap::new();
        let mut attestations = vec![];
        let mut keypairs = vec![];

        /*
         * Insert the required justified_block_hash into parent_hashes
         */
        insert_justified_block_hash(
            &mut parent_hashes,
            &justified_block_hash,
            block_slot,
            attestation_slot,
        );
        /*
         * For each shard in this slot, generate an attestation.
         */
        for shard in 0..shards_per_slot {
            let mut signing_keys = vec![];
            let mut attesters = vec![];
            /*
             * Generate a random keypair for each validator and clone it into the
             * list of keypairs. Store it in the database.
             */
            for _ in 0..validators_per_shard {
                let keypair = Keypair::random();
                keypairs.push(keypair.clone());
                stores
                    .validator
                    .put_public_key_by_index(i, &keypair.pk)
                    .unwrap();
                signing_keys.push(Some(keypair.sk.clone()));
                attesters.push(i);
                i += 1;
            }
            attester_map.insert((attestation_slot, shard), attesters);

            let attestation = generate_attestation(
                shard,
                &shard_block_hash,
                block_slot,
                attestation_slot,
                attestations_justified_slot,
                &justified_block_hash,
                cycle_length,
                &parent_hashes,
                &signing_keys[..],
                &stores.block,
            );
            attestations.push(attestation);
        }
        (attester_map, attestations, keypairs)
    };

    let block = BeaconBlock {
        slot: block_slot,
        randao_reveal,
        pow_chain_reference: pow_chain_ref,
        ancestor_hashes,
        active_state_root,
        crystallized_state_root,
        attestations,
        specials: vec![],
    };

    (block, parent_hashes, attester_map, proposer_map, stores)
}

/// Helper function to take some BeaconBlock and SSZ serialize it.
pub fn serialize_block(b: &BeaconBlock) -> Vec<u8> {
    let mut stream = SszStream::new();
    stream.append(b);
    stream.drain()
}

/// Setup and run a block validation scenario, given some parameters.
///
/// Returns the Result returned from the block validation function.
pub fn run_block_validation_scenario<F>(
    params: &BeaconBlockTestParams,
    mutator_func: F,
) -> Result<BeaconBlock, SszBeaconBlockValidationError>
where
    F: FnOnce(BeaconBlock, AttesterMap, ProposerMap, TestStore)
        -> (BeaconBlock, AttesterMap, ProposerMap, TestStore),
{
    let (block, parent_hashes, attester_map, proposer_map, stores) =
        setup_block_validation_scenario(&params);

    let (block, attester_map, proposer_map, stores) =
        mutator_func(block, attester_map, proposer_map, stores);

    let ssz_bytes = serialize_block(&block);
    let ssz_block = SszBeaconBlock::from_slice(&ssz_bytes[..]).unwrap();

    let context = BeaconBlockValidationContext {
        present_slot: params.validation_context_slot,
        cycle_length: params.cycle_length,
        last_justified_slot: params.validation_context_justified_slot,
        last_justified_block_hash: params.validation_context_justified_block_hash,
        last_finalized_slot: params.validation_context_finalized_slot,
        recent_block_hashes: Arc::new(parent_hashes),
        proposer_map: Arc::new(proposer_map),
        attester_map: Arc::new(attester_map),
        block_store: stores.block.clone(),
        validator_store: stores.validator.clone(),
        pow_store: stores.pow_chain.clone(),
    };
    let block_hash = Hash256::from(&ssz_block.block_hash()[..]);
    let validation_result = context.validate_ssz_block(&ssz_block);
    /*
     * If validation returned a block, make sure it's the same block we supplied to it.
     *
     * I.e., there were no errors during the serialization -> deserialization process.
     */
    if let Ok(returned_block) = &validation_result {
        assert_eq!(*returned_block, block);
    };
    validation_result
}

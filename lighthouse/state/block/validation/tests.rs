extern crate ssz;

use self::ssz::{
    SszStream,
};
use std::sync::Arc;
use super::{
    validate_ssz_block,
    BlockStatus,
    AttesterMap,
    ProposerMap,
};
use super::db::stores::{
    BlockStore,
    PoWChainStore,
    ValidatorStore,
};
use super::db::{
    MemoryDB,
};
use super::utils::hash::canonical_hash;
use super::utils::types::{
    Hash256,
    Bitfield,
};
use super::SszBlock;
use super::super::Block;
use super::super::attestation_record::AttestationRecord;
use super::super::super::bls::{
    Keypair,
    Signature,
    AggregateSignature,
};

struct TestStore {
    db: Arc<MemoryDB>,
    block: Arc<BlockStore<MemoryDB>>,
    pow_chain: Arc<PoWChainStore<MemoryDB>>,
    validator: Arc<ValidatorStore<MemoryDB>>,
}

impl TestStore {
    pub fn new() -> Self {
        let db = Arc::new(MemoryDB::open());
        let block = Arc::new(BlockStore::new(db.clone()));
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

#[test]
fn test_block_validation() {
    let stores = TestStore::new();

    let cycle_length: u8 = 2;
    let shard_count: u16 = 2;
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

    let validators_per_shard = 10;

    let block_slot = present_slot;
    let validator_index: usize = 0;
    let proposer_map = {
        let mut proposer_map = ProposerMap::new();
        proposer_map.insert(present_slot, validator_index);
        proposer_map
    };
    let (attester_map, attestations, _keypairs) = {
        let mut i = 0;
        let mut attester_map = AttesterMap::new();
        let mut attestations = vec![];
        let mut keypairs = vec![];
        for shard in 0..shard_count {
            let mut attesters = vec![];
            let mut attester_bitfield = Bitfield::new();
            let mut aggregate_sig = AggregateSignature::new();
            let attestation_slot = block_slot - 1;

            let parent_hashes_slice = {
                let distance: usize = (block_slot - attestation_slot) as usize;
                let last: usize = parent_hashes.len() - distance;
                let first: usize = last - usize::from(cycle_length);
                &parent_hashes[first..last]
            };

            let attestation_message = {
                let mut stream = SszStream::new();
                stream.append(&attestation_slot);
                stream.append_vec(&parent_hashes_slice.to_vec());
                stream.append(&shard);
                stream.append(&shard_block_hash);
                stream.append(&justified_slot);
                let bytes = stream.drain();
                canonical_hash(&bytes)
            };



            for attestation_index in 0..validators_per_shard {
               /*
                * Add the attester to the attestation indices for this shard.
                */
               attesters.push(i);
               /*
                * Set the voters bit on the bitfield to true.
                */
               attester_bitfield.set_bit(attestation_index, true);
               /*
                * Generate a random keypair for this validatior and clone it into the
                * list of keypairs.
                */
               let keypair = Keypair::random();
               keypairs.push(keypair.clone());
               /*
                * Store the validators public key in the database.
                */
               stores.validator.put_public_key_by_index(i, &keypair.pk).unwrap();
               /*
                * Generate a new signature and aggregate it on the rolling signature.
                */
               let sig = Signature::new(&attestation_message, &keypair.sk);
               aggregate_sig.add(&sig);
               /*
                * Increment the validator counter to monotonically assign validators.
                */
               i += 1;
            }

            attester_map.insert((attestation_slot, shard), attesters);
            let attestation = AttestationRecord {
                slot: attestation_slot,
                shard_id: shard,
                oblique_parent_hashes: vec![],
                shard_block_hash,
                attester_bitfield,
                justified_slot,
                justified_block_hash,
                aggregate_sig,
            };
            attestations.push(attestation);
        }
        (attester_map, attestations, keypairs)
    };

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

    let status = validate_ssz_block(
        &ssz_block,
        present_slot,
        cycle_length,
        justified_slot,
        &Arc::new(parent_hashes),
        &Arc::new(proposer_map),
        &Arc::new(attester_map),
        &stores.block.clone(),
        &stores.validator.clone(),
        &stores.pow_chain.clone()).unwrap();

    assert_eq!(status, BlockStatus::NewBlock);
}

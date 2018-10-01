use std::sync::Arc;

use super::db::{
    MemoryDB,
};
use super::db::stores::{
    BlockStore,
    ValidatorStore,
};
use super::state::attestation_record::{
    AttestationRecord,
    AttestationValidationContext,
    AttestationValidationError,
};
use super::state::block::validation::AttesterMap;
use super::bls::{
    AggregateSignature,
    Keypair,
    SecretKey,
    Signature,
};
use super::ssz::SszStream;
use super::utils::types::{
    Hash256,
    Bitfield,
};
use super::utils::hash::{
    canonical_hash,
};


pub struct TestStore {
    pub db: Arc<MemoryDB>,
    pub block: Arc<BlockStore<MemoryDB>>,
    pub validator: Arc<ValidatorStore<MemoryDB>>,
}

impl TestStore {
    pub fn new() -> Self {
        let db = Arc::new(MemoryDB::open());
        let block = Arc::new(BlockStore::new(db.clone()));
        let validator = Arc::new(ValidatorStore::new(db.clone()));
        Self {
            db,
            block,
            validator,
        }
    }
}

fn generate_message_hash(slot: u64,
                         parent_hashes: &[Hash256],
                         shard_id: u16,
                         shard_block_hash: &Hash256,
                         justified_slot: u64)
    -> Vec<u8>
{
    let mut stream = SszStream::new();
    stream.append(&slot);
    stream.append_vec(&parent_hashes.to_vec());
    stream.append(&shard_id);
    stream.append(shard_block_hash);
    stream.append(&justified_slot);
    let bytes = stream.drain();
    canonical_hash(&bytes)
}

pub fn generate_attestation(shard_id: u16,
                            shard_block_hash: &Hash256,
                            block_slot: u64,
                            attestation_slot: u64,
                            justified_slot: u64,
                            justified_block_hash: &Hash256,
                            cycle_length: u8,
                            parent_hashes: &[Hash256],
                            signing_keys: &[Option<SecretKey>])
    -> AttestationRecord
{
    let mut attester_bitfield = Bitfield::new();
    let mut aggregate_sig = AggregateSignature::new();

    let parent_hashes_slice = {
        let distance: usize = (block_slot - attestation_slot) as usize;
        let last: usize = parent_hashes.len() - distance;
        let first: usize = last - usize::from(cycle_length);
        &parent_hashes[first..last]
    };

    /*
     * Generate the message that will be signed across for this attr record.
     */
    let attestation_message = generate_message_hash(
        attestation_slot,
        parent_hashes_slice,
        shard_id,
        shard_block_hash,
        justified_slot);

    for (i, secret_key) in signing_keys.iter().enumerate() {
        /*
         * If the signing key is Some, set the bitfield bit to true
         * and sign the aggregate sig.
         */
        if let Some(sk) = secret_key {
            attester_bitfield.set_bit(i, true);
            let sig = Signature::new(&attestation_message, sk);
            aggregate_sig.add(&sig);
        }
    }

    AttestationRecord {
        slot: attestation_slot,
        shard_id,
        oblique_parent_hashes: vec![],
        shard_block_hash: shard_block_hash.clone(),
        attester_bitfield,
        justified_slot,
        justified_block_hash: justified_block_hash.clone(),
        aggregate_sig,
    }
}

/*
fn get_valid_attestation_and_context(shard_id: u16,
                                     shard_block_hash: Hash256,
                                     attester_count: usize,
                                     signing_attesters: &[usize])
    -> (AttestationRecord, AttestationValidationContext<MemoryDB>)
{
    let stores = TestStore::new();

    let block_slot = 10000;
    let cycle_length: u8 = 64;
    let last_justified_slot = block_slot - u64::from(cycle_length);
    let parent_hashes: Vec<Hash256> = (0..(cycle_length * 2))
        .map(|i| Hash256::from(i as u64))
        .collect();
    let parent_hashes = Arc::new(parent_hashes);
    let attester_map = Arc::new(AttesterMap::new());
    let justified_block_hash = Hash256::from("justified_block".as_bytes());

    stores.block.put_serialized_block(&justified_block_hash.as_ref(), &[42]).unwrap();

    let aggregate_sig = AggregateSignature::new();
    let attester_bitfield = Bitfield::new();

    let mut attestation_indices = vec![];
    for attester_index in 0..attester_count {
        let kp = Keypair::random();
        let validator_index = attester_count - attester_index;
        attestation_indices.push(validator_index);
        stores.validator.put_public_key_by_index(validator_index, &kp.pk);
    }

    let context: AttestationValidationContext<MemoryDB> = AttestationValidationContext {
        block_slot,
        cycle_length,
        last_justified_slot,
        parent_hashes,
        block_store: stores.block.clone(),
        validator_store: stores.validator.clone(),
        attester_map,
    };

    let attestation = AttestationRecord {
        slot: block_slot - 1,
        shard_id,
        oblique_parent_hashes: vec![],
        shard_block_hash,
        attester_bitfield,
        justified_slot: last_justified_slot,
        justified_block_hash,
        aggregate_sig,
    };
    (attestation, context)
}
*/

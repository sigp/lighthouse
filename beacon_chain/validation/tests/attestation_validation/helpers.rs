use std::sync::Arc;

use super::db::{
    MemoryDB,
};
use super::db::stores::{
    ValidatorStore,
    BeaconBlockStore,
};
use super::types::{
    AttestationRecord,
    AttesterMap,
    Bitfield,
    BeaconBlock,
    Hash256,
};
use super::validation::attestation_validation::{
    AttestationValidationContext,
};
use super::bls::{
    AggregateSignature,
    Keypair,
    SecretKey,
    Signature,
};
use super::ssz::SszStream;
use super::hashing::{
    canonical_hash,
};


pub struct TestStore {
    pub db: Arc<MemoryDB>,
    pub validator: Arc<ValidatorStore<MemoryDB>>,
    pub block: Arc<BeaconBlockStore<MemoryDB>>,
}

impl TestStore {
    pub fn new() -> Self {
        let db = Arc::new(MemoryDB::open());
        let validator = Arc::new(ValidatorStore::new(db.clone()));
        let block = Arc::new(BeaconBlockStore::new(db.clone()));
        Self {
            db,
            validator,
            block,
        }
    }
}

pub struct TestRig {
    pub attestation: AttestationRecord,
    pub context: AttestationValidationContext<MemoryDB>,
    pub stores: TestStore,
    pub attester_count: usize,
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
                            signing_keys: &[Option<SecretKey>],
                            block_store: &BeaconBlockStore<MemoryDB>)
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
     * Create a justified block at the correct slot and store it in the db.
     */
    create_block_at_slot(&block_store, &justified_block_hash, justified_slot);

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

/// Create a minimum viable block at some slot.
///
/// Allows the validation function to read the block and verify its slot.
pub fn create_block_at_slot(block_store: &BeaconBlockStore<MemoryDB>, hash: &Hash256, slot: u64) {
    let mut justified_block = BeaconBlock::zero();
    justified_block.attestations.push(AttestationRecord::zero());
    justified_block.slot = slot;
    let mut s = SszStream::new();
    s.append(&justified_block);
    let justified_block_ssz = s.drain();
    block_store.put_serialized_block(&hash.to_vec(), &justified_block_ssz).unwrap();
}

/// Inserts a justified_block_hash in a position that will be referenced by an attestation record.
pub fn insert_justified_block_hash(
    parent_hashes: &mut Vec<Hash256>,
    justified_block_hash: &Hash256,
    block_slot: u64,
    attestation_slot: u64)
{
    let attestation_parent_hash_index = parent_hashes.len() - 1 -
        (block_slot as usize - attestation_slot as usize);
    parent_hashes[attestation_parent_hash_index] = justified_block_hash.clone();
}

pub fn setup_attestation_validation_test(shard_id: u16, attester_count: usize)
    -> TestRig
{
    let stores = TestStore::new();

    let block_slot = 10000;
    let cycle_length: u8 = 64;
    let mut parent_hashes: Vec<Hash256> = (0..(cycle_length * 2))
        .map(|i| Hash256::from(i as u64))
        .collect();
    let attestation_slot = block_slot - 1;
    let parent_block_slot = attestation_slot;
    let last_justified_slot = attestation_slot - 1;
    let justified_block_hash = Hash256::from("justified_block".as_bytes());
    let shard_block_hash = Hash256::from("shard_block".as_bytes());

    /*
     * Insert the required justified_block_hash into parent_hashes
     */
    insert_justified_block_hash(
        &mut parent_hashes,
        &justified_block_hash,
        block_slot,
        attestation_slot);

    let parent_hashes = Arc::new(parent_hashes);

    let mut keypairs = vec![];
    let mut signing_keys = vec![];
    let mut attester_map = AttesterMap::new();
    let mut attesters = vec![];

    /*
     * Generate a random keypair for each validator and clone it into the
     * list of keypairs. Store it in the database.
     */
    for i in 0..attester_count {
       let keypair = Keypair::random();
       keypairs.push(keypair.clone());
       stores.validator.put_public_key_by_index(i, &keypair.pk).unwrap();
       signing_keys.push(Some(keypair.sk.clone()));
       attesters.push(i);
    }
    attester_map.insert((attestation_slot, shard_id), attesters);

    let context: AttestationValidationContext<MemoryDB> = AttestationValidationContext {
        block_slot,
        parent_block_slot,
        cycle_length,
        last_justified_slot,
        recent_block_hashes: parent_hashes.clone(),
        block_store: stores.block.clone(),
        validator_store: stores.validator.clone(),
        attester_map: Arc::new(attester_map),
    };
    let attestation = generate_attestation(
        shard_id,
        &shard_block_hash,
        block_slot,
        attestation_slot,
        last_justified_slot,
        &justified_block_hash,
        cycle_length,
        &parent_hashes.clone(),
        &signing_keys,
        &stores.block);

    TestRig {
        attestation,
        context,
        stores,
        attester_count,
    }
}

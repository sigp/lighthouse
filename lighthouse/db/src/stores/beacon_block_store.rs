use super::BLOCKS_DB_COLUMN as DB_COLUMN;
use super::{ClientDB, DBError};
use ssz::{Decodable, DecodeError};
use std::sync::Arc;
use types::Hash256;

type BeaconBlockHash = Vec<u8>;
type BeaconBlockSsz = Vec<u8>;

#[derive(Clone, Debug, PartialEq)]
pub enum BeaconBlockAtSlotError {
    UnknownBeaconBlock,
    InvalidBeaconBlock,
    DBError(String),
}

pub struct BeaconBlockStore<T>
where
    T: ClientDB,
{
    db: Arc<T>,
}

impl<T: ClientDB> BeaconBlockStore<T> {
    pub fn new(db: Arc<T>) -> Self {
        Self { db }
    }

    pub fn put_serialized_block(&self, hash: &[u8], ssz: &[u8]) -> Result<(), DBError> {
        self.db.put(DB_COLUMN, hash, ssz)
    }

    pub fn get_serialized_block(&self, hash: &[u8]) -> Result<Option<Vec<u8>>, DBError> {
        self.db.get(DB_COLUMN, hash)
    }

    pub fn block_exists(&self, hash: &[u8]) -> Result<bool, DBError> {
        self.db.exists(DB_COLUMN, hash)
    }

    pub fn delete_block(&self, hash: &[u8]) -> Result<(), DBError> {
        self.db.delete(DB_COLUMN, hash)
    }

    /// Retrieve the block at a slot given a "head_hash" and a slot.
    ///
    /// A "head_hash" must be a block hash with a slot number greater than or equal to the desired
    /// slot.
    ///
    /// This function will read each block down the chain until it finds a block with the given
    /// slot number. If the slot is skipped, the function will return None.
    ///
    /// If a block is found, a tuple of (block_hash, serialized_block) is returned.
    pub fn block_at_slot(
        &self,
        head_hash: &[u8],
        slot: u64,
    ) -> Result<Option<(BeaconBlockHash, BeaconBlockSsz)>, BeaconBlockAtSlotError> {
        match self.get_serialized_block(head_hash)? {
            None => Err(BeaconBlockAtSlotError::UnknownBeaconBlock),
            Some(ssz) => {
                let (retrieved_slot, parent_hash) = slot_and_parent_from_block_ssz(&ssz, 0)
                    .map_err(|_| BeaconBlockAtSlotError::InvalidBeaconBlock)?;
                match retrieved_slot {
                    s if s == slot => Ok(Some((head_hash.to_vec(), ssz.to_vec()))),
                    s if s < slot => Ok(None),
                    _ => self.block_at_slot(&parent_hash, slot),
                }
            }
        }
    }
}

/// Read `block.slot` and `block.parent_root` from a SSZ-encoded block bytes.
///
/// Assumes the block starts at byte `i`.
fn slot_and_parent_from_block_ssz(ssz: &[u8], i: usize) -> Result<(u64, Hash256), DecodeError> {
    // Assuming the slot is the first field on a block.
    let (slot, i) = u64::ssz_decode(&ssz, i)?;
    // Assuming the parent has is the second field on a block.
    let (parent_root, _) = Hash256::ssz_decode(&ssz, i)?;
    Ok((slot, parent_root))
}

impl From<DBError> for BeaconBlockAtSlotError {
    fn from(e: DBError) -> Self {
        BeaconBlockAtSlotError::DBError(e.message)
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::MemoryDB;
    use super::*;

    use std::sync::Arc;
    use std::thread;

    use ssz::ssz_encode;
    use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use types::BeaconBlock;
    use types::Hash256;

    #[test]
    fn test_put_serialized_block() {
        let db = Arc::new(MemoryDB::open());
        let store = BeaconBlockStore::new(db.clone());

        let ssz = "some bytes".as_bytes();
        let hash = &Hash256::from("some hash".as_bytes()).to_vec();

        store.put_serialized_block(hash, ssz).unwrap();
        assert_eq!(db.get(DB_COLUMN, hash).unwrap().unwrap(), ssz);
    }

    #[test]
    fn test_get_serialized_block() {
        let db = Arc::new(MemoryDB::open());
        let store = BeaconBlockStore::new(db.clone());

        let ssz = "some bytes".as_bytes();
        let hash = &Hash256::from("some hash".as_bytes()).to_vec();

        db.put(DB_COLUMN, hash, ssz).unwrap();
        assert_eq!(store.get_serialized_block(hash).unwrap().unwrap(), ssz);
    }

    #[test]
    fn test_get_unknown_serialized_block() {
        let db = Arc::new(MemoryDB::open());
        let store = BeaconBlockStore::new(db.clone());

        let ssz = "some bytes".as_bytes();
        let hash = &Hash256::from("some hash".as_bytes()).to_vec();
        let other_hash = &Hash256::from("another hash".as_bytes()).to_vec();

        db.put(DB_COLUMN, other_hash, ssz).unwrap();
        assert_eq!(store.get_serialized_block(hash).unwrap(), None);
    }

    #[test]
    fn test_block_exists() {
        let db = Arc::new(MemoryDB::open());
        let store = BeaconBlockStore::new(db.clone());

        let ssz = "some bytes".as_bytes();
        let hash = &Hash256::from("some hash".as_bytes()).to_vec();

        db.put(DB_COLUMN, hash, ssz).unwrap();
        assert!(store.block_exists(hash).unwrap());
    }

    #[test]
    fn test_block_does_not_exist() {
        let db = Arc::new(MemoryDB::open());
        let store = BeaconBlockStore::new(db.clone());

        let ssz = "some bytes".as_bytes();
        let hash = &Hash256::from("some hash".as_bytes()).to_vec();
        let other_hash = &Hash256::from("another hash".as_bytes()).to_vec();

        db.put(DB_COLUMN, hash, ssz).unwrap();
        assert!(!store.block_exists(other_hash).unwrap());
    }

    #[test]
    fn test_delete_block() {
        let db = Arc::new(MemoryDB::open());
        let store = BeaconBlockStore::new(db.clone());

        let ssz = "some bytes".as_bytes();
        let hash = &Hash256::from("some hash".as_bytes()).to_vec();

        db.put(DB_COLUMN, hash, ssz).unwrap();
        assert!(db.exists(DB_COLUMN, hash).unwrap());

        store.delete_block(hash).unwrap();
        assert!(!db.exists(DB_COLUMN, hash).unwrap());
    }

    #[test]
    fn test_invalid_block_at_slot() {
        let db = Arc::new(MemoryDB::open());
        let store = BeaconBlockStore::new(db.clone());

        let ssz = "definitly not a valid block".as_bytes();
        let hash = &Hash256::from("some hash".as_bytes()).to_vec();

        db.put(DB_COLUMN, hash, ssz).unwrap();
        assert_eq!(
            store.block_at_slot(hash, 42),
            Err(BeaconBlockAtSlotError::InvalidBeaconBlock)
        );
    }

    #[test]
    fn test_unknown_block_at_slot() {
        let db = Arc::new(MemoryDB::open());
        let store = BeaconBlockStore::new(db.clone());

        let ssz = "some bytes".as_bytes();
        let hash = &Hash256::from("some hash".as_bytes()).to_vec();
        let other_hash = &Hash256::from("another hash".as_bytes()).to_vec();

        db.put(DB_COLUMN, hash, ssz).unwrap();
        assert_eq!(
            store.block_at_slot(other_hash, 42),
            Err(BeaconBlockAtSlotError::UnknownBeaconBlock)
        );
    }

    #[test]
    fn test_block_store_on_memory_db() {
        let db = Arc::new(MemoryDB::open());
        let bs = Arc::new(BeaconBlockStore::new(db.clone()));

        let thread_count = 10;
        let write_count = 10;

        // We're expecting the product of these numbers to fit in one byte.
        assert!(thread_count * write_count <= 255);

        let mut handles = vec![];
        for t in 0..thread_count {
            let wc = write_count;
            let bs = bs.clone();
            let handle = thread::spawn(move || {
                for w in 0..wc {
                    let key = (t * w) as u8;
                    let val = 42;
                    bs.put_serialized_block(&vec![key], &vec![val]).unwrap();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        for t in 0..thread_count {
            for w in 0..write_count {
                let key = (t * w) as u8;
                assert!(bs.block_exists(&vec![key]).unwrap());
                let val = bs.get_serialized_block(&vec![key]).unwrap().unwrap();
                assert_eq!(vec![42], val);
            }
        }
    }

    #[test]
    fn test_block_at_slot() {
        let db = Arc::new(MemoryDB::open());
        let bs = Arc::new(BeaconBlockStore::new(db.clone()));
        let mut rng = XorShiftRng::from_seed([42; 16]);

        // Specify test block parameters.
        let hashes = [
            Hash256::from(&[0; 32][..]),
            Hash256::from(&[1; 32][..]),
            Hash256::from(&[2; 32][..]),
            Hash256::from(&[3; 32][..]),
            Hash256::from(&[4; 32][..]),
        ];
        let parent_hashes = [
            Hash256::from(&[255; 32][..]), // Genesis block.
            Hash256::from(&[0; 32][..]),
            Hash256::from(&[1; 32][..]),
            Hash256::from(&[2; 32][..]),
            Hash256::from(&[3; 32][..]),
        ];
        let slots = [0, 1, 3, 4, 5];

        // Generate a vec of random blocks and store them in the DB.
        let block_count = 5;
        let mut blocks: Vec<BeaconBlock> = Vec::with_capacity(5);
        for i in 0..block_count {
            let mut block = BeaconBlock::random_for_test(&mut rng);

            block.parent_root = parent_hashes[i];
            block.slot = slots[i];

            let ssz = ssz_encode(&block);
            db.put(DB_COLUMN, &hashes[i].to_vec(), &ssz).unwrap();

            // Ensure the slot and parent_root decoding fn works correctly.
            let (decoded_slot, decoded_parent_root) =
                slot_and_parent_from_block_ssz(&ssz, 0).unwrap();
            assert_eq!(decoded_slot, block.slot);
            assert_eq!(decoded_parent_root, block.parent_root);

            blocks.push(block);
        }

        // Test that certain slots can be reached from certain hashes.
        let test_cases = vec![(4, 4), (4, 3), (4, 2), (4, 1), (4, 0)];
        for (hashes_index, slot_index) in test_cases {
            let (matched_block_hash, matched_block_ssz) = bs
                .block_at_slot(&hashes[hashes_index], slots[slot_index])
                .unwrap()
                .unwrap();
            let (retrieved_slot, _) =
                slot_and_parent_from_block_ssz(&matched_block_ssz, 0).unwrap();
            assert_eq!(retrieved_slot, slots[slot_index]);
            assert_eq!(matched_block_hash, hashes[slot_index].to_vec());
        }

        let ssz = bs.block_at_slot(&hashes[4], 2).unwrap();
        assert_eq!(ssz, None);

        let ssz = bs.block_at_slot(&hashes[4], 6).unwrap();
        assert_eq!(ssz, None);

        let ssz = bs.block_at_slot(&Hash256::from("unknown".as_bytes()), 2);
        assert_eq!(ssz, Err(BeaconBlockAtSlotError::UnknownBeaconBlock));
    }
}

use super::BLOCKS_DB_COLUMN as DB_COLUMN;
use super::{ClientDB, DBError};
use ssz::Decodable;
use std::sync::Arc;
use types::{readers::BeaconBlockReader, BeaconBlock, Hash256, Slot};

#[derive(Clone, Debug, PartialEq)]
pub enum BeaconBlockAtSlotError {
    UnknownBeaconBlock(Hash256),
    InvalidBeaconBlock(Hash256),
    DBError(String),
}

pub struct BeaconBlockStore<T>
where
    T: ClientDB,
{
    db: Arc<T>,
}

// Implements `put`, `get`, `exists` and `delete` for the store.
impl_crud_for_store!(BeaconBlockStore, DB_COLUMN);

impl<T: ClientDB> BeaconBlockStore<T> {
    pub fn new(db: Arc<T>) -> Self {
        Self { db }
    }

    pub fn get_deserialized(&self, hash: &Hash256) -> Result<Option<BeaconBlock>, DBError> {
        match self.get(&hash)? {
            None => Ok(None),
            Some(ssz) => {
                let (block, _) = BeaconBlock::ssz_decode(&ssz, 0).map_err(|_| DBError {
                    message: "Bad BeaconBlock SSZ.".to_string(),
                })?;
                Ok(Some(block))
            }
        }
    }

    /// Retuns an object implementing `BeaconBlockReader`, or `None` (if hash not known).
    ///
    /// Note: Presently, this function fully deserializes a `BeaconBlock` and returns that. In the
    /// future, it would be ideal to return an object capable of reading directly from serialized
    /// SSZ bytes.
    pub fn get_reader(&self, hash: &Hash256) -> Result<Option<impl BeaconBlockReader>, DBError> {
        match self.get(&hash)? {
            None => Ok(None),
            Some(ssz) => {
                let (block, _) = BeaconBlock::ssz_decode(&ssz, 0).map_err(|_| DBError {
                    message: "Bad BeaconBlock SSZ.".to_string(),
                })?;
                Ok(Some(block))
            }
        }
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
    ///
    /// Note: this function uses a loop instead of recursion as the compiler is over-strict when it
    /// comes to recursion and the `impl Trait` pattern. See:
    /// https://stackoverflow.com/questions/54032940/using-impl-trait-in-a-recursive-function
    pub fn block_at_slot(
        &self,
        head_hash: &Hash256,
        slot: Slot,
    ) -> Result<Option<(Hash256, impl BeaconBlockReader)>, BeaconBlockAtSlotError> {
        let mut current_hash = *head_hash;

        loop {
            if let Some(block_reader) = self.get_reader(&current_hash)? {
                if block_reader.slot() == slot {
                    break Ok(Some((current_hash, block_reader)));
                } else if block_reader.slot() < slot {
                    break Ok(None);
                } else {
                    current_hash = block_reader.parent_root();
                }
            } else {
                break Err(BeaconBlockAtSlotError::UnknownBeaconBlock(current_hash));
            }
        }
    }
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

    test_crud_for_store!(BeaconBlockStore, DB_COLUMN);

    #[test]
    fn head_hash_slot_too_low() {
        let db = Arc::new(MemoryDB::open());
        let bs = Arc::new(BeaconBlockStore::new(db.clone()));
        let mut rng = XorShiftRng::from_seed([42; 16]);

        let mut block = BeaconBlock::random_for_test(&mut rng);
        block.slot = Slot::from(10_u64);

        let block_root = block.canonical_root();
        bs.put(&block_root, &ssz_encode(&block)).unwrap();

        let result = bs.block_at_slot(&block_root, Slot::from(11_u64)).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_invalid_block_at_slot() {
        let db = Arc::new(MemoryDB::open());
        let store = BeaconBlockStore::new(db.clone());

        let ssz = "definitly not a valid block".as_bytes();
        let hash = &Hash256::from([0xAA; 32]);

        db.put(DB_COLUMN, hash.as_bytes(), ssz).unwrap();
        assert_eq!(
            store.block_at_slot(hash, Slot::from(42_u64)),
            Err(BeaconBlockAtSlotError::DBError(
                "Bad BeaconBlock SSZ.".into()
            ))
        );
    }

    #[test]
    fn test_unknown_block_at_slot() {
        let db = Arc::new(MemoryDB::open());
        let store = BeaconBlockStore::new(db.clone());

        let ssz = "some bytes".as_bytes();
        let hash = &Hash256::from([0xAA; 32]);
        let other_hash = &Hash256::from([0xBB; 32]);

        db.put(DB_COLUMN, hash.as_bytes(), ssz).unwrap();
        assert_eq!(
            store.block_at_slot(other_hash, Slot::from(42_u64)),
            Err(BeaconBlockAtSlotError::UnknownBeaconBlock(*other_hash))
        );
    }

    #[test]
    fn test_block_store_on_memory_db() {
        let db = Arc::new(MemoryDB::open());
        let bs = Arc::new(BeaconBlockStore::new(db.clone()));

        let thread_count = 10;
        let write_count = 10;

        let mut handles = vec![];
        for t in 0..thread_count {
            let wc = write_count;
            let bs = bs.clone();
            let handle = thread::spawn(move || {
                for w in 0..wc {
                    let key = t * w;
                    let val = 42;
                    bs.put(&Hash256::from_low_u64_le(key), &vec![val]).unwrap();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        for t in 0..thread_count {
            for w in 0..write_count {
                let key = t * w;
                assert!(bs.exists(&Hash256::from_low_u64_le(key)).unwrap());
                let val = bs.get(&Hash256::from_low_u64_le(key)).unwrap().unwrap();
                assert_eq!(vec![42], val);
            }
        }
    }

    #[test]
    #[ignore]
    fn test_block_at_slot() {
        let db = Arc::new(MemoryDB::open());
        let bs = Arc::new(BeaconBlockStore::new(db.clone()));
        let mut rng = XorShiftRng::from_seed([42; 16]);

        // Specify test block parameters.
        let hashes = [
            Hash256::from([0; 32]),
            Hash256::from([1; 32]),
            Hash256::from([2; 32]),
            Hash256::from([3; 32]),
            Hash256::from([4; 32]),
        ];
        let parent_hashes = [
            Hash256::from([255; 32]), // Genesis block.
            Hash256::from([0; 32]),
            Hash256::from([1; 32]),
            Hash256::from([2; 32]),
            Hash256::from([3; 32]),
        ];
        let unknown_hash = Hash256::from([101; 32]); // different from all above
        let slots: Vec<Slot> = vec![0, 1, 3, 4, 5].iter().map(|x| Slot::new(*x)).collect();

        // Generate a vec of random blocks and store them in the DB.
        let block_count = 5;
        let mut blocks: Vec<BeaconBlock> = Vec::with_capacity(5);
        for i in 0..block_count {
            let mut block = BeaconBlock::random_for_test(&mut rng);

            block.parent_root = parent_hashes[i];
            block.slot = slots[i];

            let ssz = ssz_encode(&block);
            db.put(DB_COLUMN, hashes[i].as_bytes(), &ssz).unwrap();

            blocks.push(block);
        }

        // Test that certain slots can be reached from certain hashes.
        let test_cases = vec![(4, 4), (4, 3), (4, 2), (4, 1), (4, 0)];
        for (hashes_index, slot_index) in test_cases {
            let (matched_block_hash, reader) = bs
                .block_at_slot(&hashes[hashes_index], slots[slot_index])
                .unwrap()
                .unwrap();
            assert_eq!(matched_block_hash, hashes[slot_index]);
            assert_eq!(reader.slot(), slots[slot_index]);
        }

        let ssz = bs.block_at_slot(&hashes[4], Slot::new(2)).unwrap();
        assert_eq!(ssz, None);

        let ssz = bs.block_at_slot(&hashes[4], Slot::new(6)).unwrap();
        assert_eq!(ssz, None);

        let ssz = bs.block_at_slot(&unknown_hash, Slot::new(2));
        assert_eq!(
            ssz,
            Err(BeaconBlockAtSlotError::UnknownBeaconBlock(unknown_hash))
        );
    }
}

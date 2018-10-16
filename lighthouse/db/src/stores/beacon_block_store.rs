extern crate ssz_helpers;

use self::ssz_helpers::ssz_beacon_block::{
    SszBeaconBlock,
};
use std::sync::Arc;
use super::{
    ClientDB,
    DBError,
};
use super::BLOCKS_DB_COLUMN as DB_COLUMN;

#[derive(Clone, Debug, PartialEq)]
pub enum BeaconBlockAtSlotError {
    UnknownBeaconBlock,
    InvalidBeaconBlock,
    DBError(String),
}

pub struct BeaconBlockStore<T>
    where T: ClientDB
{
    db: Arc<T>,
}

impl<T: ClientDB> BeaconBlockStore<T> {
    pub fn new(db: Arc<T>) -> Self {
        Self {
            db,
        }
    }

    pub fn put_serialized_block(&self, hash: &[u8], ssz: &[u8])
        -> Result<(), DBError>
    {
        self.db.put(DB_COLUMN, hash, ssz)
    }

    pub fn get_serialized_block(&self, hash: &[u8])
        -> Result<Option<Vec<u8>>, DBError>
    {
        self.db.get(DB_COLUMN, hash)
    }

    pub fn block_exists(&self, hash: &[u8])
        -> Result<bool, DBError>
    {
        self.db.exists(DB_COLUMN, hash)
    }

    pub fn block_exists_in_canonical_chain(&self, hash: &[u8])
        -> Result<bool, DBError>
    {
        // TODO: implement logic for canonical chain
        self.db.exists(DB_COLUMN, hash)
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
    pub fn block_at_slot(&self, head_hash: &[u8], slot: u64)
        -> Result<Option<(Vec<u8>, Vec<u8>)>, BeaconBlockAtSlotError>
    {
        match self.get_serialized_block(head_hash)? {
            None => Err(BeaconBlockAtSlotError::UnknownBeaconBlock),
            Some(ssz) => {
                let block = SszBeaconBlock::from_slice(&ssz)
                    .map_err(|_| BeaconBlockAtSlotError::InvalidBeaconBlock)?;
                match block.slot() {
                    s if s == slot => Ok(Some((head_hash.to_vec(), ssz.to_vec()))),
                    s if s < slot => Ok(None),
                    _ => {
                        match block.parent_hash() {
                            Some(parent_hash) => self.block_at_slot(parent_hash, slot),
                            None => Err(BeaconBlockAtSlotError::UnknownBeaconBlock)
                        }
                    }
                }
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
    extern crate ssz;
    extern crate types;

    use self::types::beacon_block::BeaconBlock;
    use self::types::attestation_record::AttestationRecord;
    use self::types::Hash256;
    use self::ssz::SszStream;

    use super::*;
    use super::super::super::MemoryDB;
    use std::thread;
    use std::sync::Arc;

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

        let blocks = (0..5).into_iter()
            .map(|_| {
                let mut block = BeaconBlock::zero();
                let ar = AttestationRecord::zero();
                block.attestations.push(ar);
                block
            });

        let hashes = [
            Hash256::from("zero".as_bytes()),
            Hash256::from("one".as_bytes()),
            Hash256::from("two".as_bytes()),
            Hash256::from("three".as_bytes()),
            Hash256::from("four".as_bytes()),
        ];

        let parent_hashes = [
            Hash256::from("genesis".as_bytes()),
            Hash256::from("zero".as_bytes()),
            Hash256::from("one".as_bytes()),
            Hash256::from("two".as_bytes()),
            Hash256::from("three".as_bytes()),
        ];

        let slots = [0, 1, 3, 4, 5];

        for (i, mut block) in blocks.enumerate() {
            block.ancestor_hashes.push(parent_hashes[i]);
            block.slot = slots[i];
            let mut s = SszStream::new();
            s.append(&block);
            let ssz = s.drain();
            bs.put_serialized_block(&hashes[i].to_vec(), &ssz).unwrap();
        }

        let tuple = bs.block_at_slot(&hashes[4], 5).unwrap().unwrap();
        let block = SszBeaconBlock::from_slice(&tuple.1).unwrap();
        assert_eq!(block.slot(), 5);
        assert_eq!(tuple.0, hashes[4].to_vec());

        let tuple = bs.block_at_slot(&hashes[4], 4).unwrap().unwrap();
        let block = SszBeaconBlock::from_slice(&tuple.1).unwrap();
        assert_eq!(block.slot(), 4);
        assert_eq!(tuple.0, hashes[3].to_vec());

        let tuple = bs.block_at_slot(&hashes[4], 3).unwrap().unwrap();
        let block = SszBeaconBlock::from_slice(&tuple.1).unwrap();
        assert_eq!(block.slot(), 3);
        assert_eq!(tuple.0, hashes[2].to_vec());

        let tuple = bs.block_at_slot(&hashes[4], 0).unwrap().unwrap();
        let block = SszBeaconBlock::from_slice(&tuple.1).unwrap();
        assert_eq!(block.slot(), 0);
        assert_eq!(tuple.0, hashes[0].to_vec());

        let ssz = bs.block_at_slot(&hashes[4], 2).unwrap();
        assert_eq!(ssz, None);

        let ssz = bs.block_at_slot(&hashes[4], 6).unwrap();
        assert_eq!(ssz, None);

        let ssz = bs.block_at_slot(&Hash256::from("unknown".as_bytes()), 2);
        assert_eq!(ssz, Err(BeaconBlockAtSlotError::UnknownBeaconBlock));
    }
}

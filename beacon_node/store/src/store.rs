use super::*;

pub type Vec<u8> = Vec<u8>;

pub trait Store: Sync + Send + Sized {
    fn put(&self, key: &Hash256, item: &impl StoreItem) -> Result<(), Error> {
        item.db_put(self, key)
    }

    fn get<I: StoreItem>(&self, key: &Hash256) -> Result<Option<I>, Error> {
        I::db_get(self, key)
    }

    fn exists<I: StoreItem>(&self, key: &Hash256) -> Result<bool, Error> {
        I::db_exists(self, key)
    }

    fn delete<I: StoreItem>(&self, key: &Hash256) -> Result<(), Error> {
        I::db_delete(self, key)
    }

    fn get_block_at_preceding_slot(
        &self,
        start_block_root: Hash256,
        slot: Slot,
    ) -> Result<Option<(Hash256, BeaconBlock)>, Error> {
        block_at_slot::get_block_at_preceeding_slot(self, slot, start_block_root)
    }

    fn get_bytes(&self, col: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    fn put_bytes(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), Error>;

    fn key_exists(&self, col: &str, key: &[u8]) -> Result<bool, Error>;

    fn key_delete(&self, col: &str, key: &[u8]) -> Result<(), Error>;
}

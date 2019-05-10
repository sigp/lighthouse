use super::STATES_DB_COLUMN as DB_COLUMN;
use super::{ClientDB, DBError};
use ssz::Decodable;
use std::sync::Arc;
use types::{BeaconState, EthSpec, Hash256};

pub struct BeaconStateStore<T>
where
    T: ClientDB,
{
    db: Arc<T>,
}

// Implements `put`, `get`, `exists` and `delete` for the store.
impl_crud_for_store!(BeaconStateStore, DB_COLUMN);

impl<T: ClientDB> BeaconStateStore<T> {
    pub fn new(db: Arc<T>) -> Self {
        Self { db }
    }

    pub fn get_deserialized<B: EthSpec>(
        &self,
        hash: &Hash256,
    ) -> Result<Option<BeaconState<B>>, DBError> {
        match self.get(&hash)? {
            None => Ok(None),
            Some(ssz) => {
                let state = BeaconState::from_ssz_bytes(&ssz).map_err(|_| DBError {
                    message: "Bad State SSZ.".to_string(),
                })?;
                Ok(Some(state))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::MemoryDB;
    use super::*;

    use ssz::ssz_encode;
    use std::sync::Arc;
    use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use types::{FoundationBeaconState, Hash256};

    test_crud_for_store!(BeaconStateStore, DB_COLUMN);

    #[test]
    fn test_reader() {
        let db = Arc::new(MemoryDB::open());
        let store = BeaconStateStore::new(db.clone());

        let mut rng = XorShiftRng::from_seed([42; 16]);
        let state: FoundationBeaconState = BeaconState::random_for_test(&mut rng);
        let state_root = state.canonical_root();

        store.put(&state_root, &ssz_encode(&state)).unwrap();

        let decoded = store.get_deserialized(&state_root).unwrap().unwrap();

        assert_eq!(state, decoded);
    }
}

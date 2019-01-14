use super::STATES_DB_COLUMN as DB_COLUMN;
use super::{ClientDB, DBError};
use ssz::Decodable;
use std::sync::Arc;
use types::{readers::BeaconStateReader, BeaconState, Hash256};

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

    /// Retuns an object implementing `BeaconStateReader`, or `None` (if hash not known).
    ///
    /// Note: Presently, this function fully deserializes a `BeaconState` and returns that. In the
    /// future, it would be ideal to return an object capable of reading directly from serialized
    /// SSZ bytes.
    pub fn get_reader(&self, hash: &Hash256) -> Result<Option<impl BeaconStateReader>, DBError> {
        match self.get(&hash)? {
            None => Ok(None),
            Some(ssz) => {
                let (state, _) = BeaconState::ssz_decode(&ssz, 0).map_err(|_| DBError {
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

    use std::sync::Arc;
    use ssz::ssz_encode;
    use types::Hash256;
    use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    test_crud_for_store!(BeaconStateStore, DB_COLUMN);

    #[test]
    fn test_reader() {
        let db = Arc::new(MemoryDB::open());
        let store = BeaconStateStore::new(db.clone());

        let mut rng = XorShiftRng::from_seed([42; 16]);
        let state = BeaconState::random_for_test(&mut rng);
        let state_root = state.canonical_root();

        store.put(&state_root, &ssz_encode(&state)).unwrap();

        let reader = store.get_reader(&state_root).unwrap().unwrap();
        let decoded = reader.into_beacon_state().unwrap();

        assert_eq!(state, decoded);
    }
}

use crate::errors::BeaconChainError;
use crate::{BeaconChainTypes, BeaconStore};
use bls::PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN;
use smallvec::SmallVec;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;
use store::{DBColumn, Error as StoreError, StoreItem, StoreOp};
use types::{BeaconState, FixedBytesExtended, Hash256, PublicKey, PublicKeyBytes};

/// Provides a mapping of `validator_index -> validator_publickey`.
///
/// This cache exists for two reasons:
///
/// 1. To avoid reading a `BeaconState` from disk each time we need a public key.
/// 2. To reduce the amount of public key _decompression_ required. A `BeaconState` stores public
///    keys in compressed form and they are needed in decompressed form for signature verification.
///    Decompression is expensive when many keys are involved.
pub struct ValidatorPubkeyCache<T: BeaconChainTypes> {
    pubkeys: Vec<PublicKey>,
    indices: HashMap<PublicKeyBytes, usize>,
    pubkey_bytes: Vec<PublicKeyBytes>,
    // Indices in this set should be flushed to disk
    staged_indices: BTreeMap<usize, PublicKey>,
    _phantom: PhantomData<T>,
}

impl<T: BeaconChainTypes> ValidatorPubkeyCache<T> {
    /// Create a new public key cache using the keys in `state.validators`.
    ///
    /// The new cache will be updated with the keys from `state` and immediately written to disk.
    pub fn new(
        state: &BeaconState<T::EthSpec>,
        store: BeaconStore<T>,
    ) -> Result<Self, BeaconChainError> {
        let mut cache = Self {
            pubkeys: vec![],
            indices: HashMap::new(),
            pubkey_bytes: vec![],
            staged_indices: BTreeMap::new(),
            _phantom: PhantomData,
        };

        cache.import_new_pubkeys(state)?;
        let (_, db_ops) = cache.get_db_ops();
        store.do_atomically_with_block_and_blobs_cache(db_ops)?;

        Ok(cache)
    }

    /// Load the pubkey cache from the given on-disk database.
    pub fn load_from_store(store: BeaconStore<T>) -> Result<Self, BeaconChainError> {
        let mut pubkeys = vec![];
        let mut indices = HashMap::new();
        let mut pubkey_bytes = vec![];

        for validator_index in 0.. {
            if let Some(db_pubkey) =
                store.get_item(&DatabasePubkey::key_for_index(validator_index))?
            {
                let (pk, pk_bytes) = DatabasePubkey::as_pubkey(&db_pubkey)?;
                pubkeys.push(pk);
                indices.insert(pk_bytes, validator_index);
                pubkey_bytes.push(pk_bytes);
            } else {
                break;
            }
        }

        Ok(ValidatorPubkeyCache {
            pubkeys,
            indices,
            pubkey_bytes,
            staged_indices: BTreeMap::new(),
            _phantom: PhantomData,
        })
    }

    /// Scan the given `state` and add any new validator public keys.
    ///
    /// Does not delete any keys from `self` if they don't appear in `state`.
    ///
    /// NOTE: The caller *must* commit the returned I/O batch as part of the block import process.
    pub fn import_new_pubkeys(
        &mut self,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<(), BeaconChainError> {
        if state.validators().len() > self.pubkeys.len() {
            self.import(
                state
                    .validators()
                    .iter_from(self.pubkeys.len())?
                    .map(|v| v.pubkey),
            )
        } else {
            Ok(())
        }
    }

    /// Adds zero or more validators to `self`.
    fn import<I>(&mut self, validator_keys: I) -> Result<(), BeaconChainError>
    where
        I: Iterator<Item = PublicKeyBytes> + ExactSizeIterator,
    {
        self.pubkey_bytes.reserve(validator_keys.len());
        self.pubkeys.reserve(validator_keys.len());
        self.indices.reserve(validator_keys.len());

        for pubkey_bytes in validator_keys {
            let i = self.pubkeys.len();

            if self.indices.contains_key(&pubkey_bytes) {
                return Err(BeaconChainError::DuplicateValidatorPublicKey);
            }

            let pubkey: PublicKey = (&pubkey_bytes)
                .try_into()
                .map_err(BeaconChainError::InvalidValidatorPubkeyBytes)?;

            // Stage the new validator key for writing to disk.
            // It will be committed atomically when the block that introduced it is written to disk.
            // Notably it is NOT written while the write lock on the cache is held.
            // See: https://github.com/sigp/lighthouse/issues/2327
            self.staged_indices.insert(i, pubkey.clone());

            self.pubkeys.push(pubkey);
            self.pubkey_bytes.push(pubkey_bytes);
            self.indices.insert(pubkey_bytes, i);
        }

        Ok(())
    }

    /// Get the public key for a validator with index `i`.
    pub fn get(&self, i: usize) -> Option<&PublicKey> {
        self.pubkeys.get(i)
    }

    /// Get the `PublicKey` for a validator with `PublicKeyBytes`.
    pub fn get_pubkey_from_pubkey_bytes(&self, pubkey: &PublicKeyBytes) -> Option<&PublicKey> {
        self.get_index(pubkey).and_then(|index| self.get(index))
    }

    /// Get the public key (in bytes form) for a validator with index `i`.
    pub fn get_pubkey_bytes(&self, i: usize) -> Option<&PublicKeyBytes> {
        self.pubkey_bytes.get(i)
    }

    /// Get the index of a validator with `pubkey`.
    pub fn get_index(&self, pubkey: &PublicKeyBytes) -> Option<usize> {
        self.indices.get(pubkey).copied()
    }

    /// Returns the number of validators in the cache.
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// Returns `true` if there are no validators in the cache.
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    /// Returns a list of validator indices and their associated database operations
    /// from the mapping of `staged_indices` that are currently being persisted in the cache.
    pub fn get_db_ops(&self) -> (Vec<usize>, Vec<StoreOp<'static, T::EthSpec>>) {
        let mut store_ops = vec![];
        let mut indices = vec![];

        for (i, pubkey) in self.staged_indices.iter() {
            store_ops.push(StoreOp::KeyValueOp(
                DatabasePubkey::from_pubkey(pubkey)
                    .as_kv_store_op(DatabasePubkey::key_for_index(*i)),
            ));
            indices.push(*i);
        }
        (indices, store_ops)
    }

    /// Flush `indices` from the `staged_indices` cache. This action should only
    /// be made after writing validators to disk.
    pub fn flush_staged_indices(&mut self, indices: Vec<usize>) {
        for index in indices {
            self.staged_indices.remove(&index);
        }
    }
}

/// Wrapper for a public key stored in the database.
///
/// Keyed by the validator index as `Hash256::from_low_u64_be(index)`.
#[derive(Encode, Decode)]
pub struct DatabasePubkey {
    pubkey: SmallVec<[u8; PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN]>,
}

impl StoreItem for DatabasePubkey {
    fn db_column() -> DBColumn {
        DBColumn::PubkeyCache
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

impl DatabasePubkey {
    fn key_for_index(index: usize) -> Hash256 {
        Hash256::from_low_u64_be(index as u64)
    }

    pub fn from_pubkey(pubkey: &PublicKey) -> Self {
        Self {
            pubkey: pubkey.serialize_uncompressed().into(),
        }
    }

    pub fn as_pubkey(&self) -> Result<(PublicKey, PublicKeyBytes), BeaconChainError> {
        let pubkey = PublicKey::deserialize_uncompressed(&self.pubkey)
            .map_err(BeaconChainError::InvalidValidatorPubkeyBytes)?;
        let pubkey_bytes = pubkey.compress();
        Ok((pubkey, pubkey_bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{BeaconChainHarness, EphemeralHarnessType};
    use logging::create_test_tracing_subscriber;
    use std::sync::Arc;
    use store::HotColdDB;
    use types::{EthSpec, Keypair, MainnetEthSpec};

    type E = MainnetEthSpec;
    type T = EphemeralHarnessType<E>;

    fn get_state(validator_count: usize) -> (BeaconState<E>, Vec<Keypair>) {
        let harness = BeaconChainHarness::builder(MainnetEthSpec)
            .default_spec()
            .deterministic_keypairs(validator_count)
            .fresh_ephemeral_store()
            .build();

        harness.advance_slot();

        (harness.get_current_state(), harness.validator_keypairs)
    }

    fn get_store() -> BeaconStore<T> {
        create_test_tracing_subscriber();
        Arc::new(HotColdDB::open_ephemeral(<_>::default(), Arc::new(E::default_spec())).unwrap())
    }

    #[allow(clippy::needless_range_loop)]
    fn check_cache_get(cache: &ValidatorPubkeyCache<T>, keypairs: &[Keypair]) {
        let validator_count = keypairs.len();

        for i in 0..validator_count + 1 {
            if i < validator_count {
                let pubkey = cache.get(i).expect("pubkey should be present");
                assert_eq!(pubkey, &keypairs[i].pk, "pubkey should match cache");

                let pubkey_bytes: PublicKeyBytes = pubkey.clone().into();

                assert_eq!(
                    i,
                    cache
                        .get_index(&pubkey_bytes)
                        .expect("should resolve index"),
                    "index should match cache"
                );
            } else {
                assert_eq!(
                    cache.get(i),
                    None,
                    "should not get pubkey for out of bounds index",
                );
            }
        }
    }

    #[test]
    fn basic_operation() {
        let (state, keypairs) = get_state(8);

        let store = get_store();

        let mut cache = ValidatorPubkeyCache::new(&state, store).expect("should create cache");

        check_cache_get(&cache, &keypairs[..]);

        // Try adding a state with the same number of keypairs.
        let (state, keypairs) = get_state(8);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        check_cache_get(&cache, &keypairs[..]);

        // Try adding a state with less keypairs.
        let (state, _) = get_state(1);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        check_cache_get(&cache, &keypairs[..]);

        // Try adding a state with more keypairs.
        let (state, keypairs) = get_state(12);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        check_cache_get(&cache, &keypairs[..]);
    }

    #[test]
    fn persistence() {
        let (state, keypairs) = get_state(8);

        let store = get_store();

        // Create a new cache.
        let cache = ValidatorPubkeyCache::new(&state, store.clone()).expect("should create cache");
        check_cache_get(&cache, &keypairs[..]);
        drop(cache);

        // Re-init the cache from the store.
        let mut cache =
            ValidatorPubkeyCache::load_from_store(store.clone()).expect("should open cache");
        check_cache_get(&cache, &keypairs[..]);

        // Add some more keypairs.
        let (state, keypairs) = get_state(12);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        store
            .do_atomically_with_block_and_blobs_cache(cache.get_db_ops().1)
            .unwrap();
        check_cache_get(&cache, &keypairs[..]);
        drop(cache);

        // Re-init the cache from the store.
        let cache = ValidatorPubkeyCache::load_from_store(store).expect("should open cache");
        check_cache_get(&cache, &keypairs[..]);
    }


    /// Test for crash safety: ensures that the staged_indices mechanism prevents
    /// gaps in the on-disk pubkey cache when crashes occur during block import.
    ///
    /// This test validates the fix for issue #7216:
    /// https://github.com/sigp/lighthouse/issues/7216
    ///
    /// The bug scenario:
    /// 1. Import new validators into in-memory cache
    /// 2. Get DB operations to persist them
    /// 3. Crash before flushing staged_indices
    /// 4. On restart, in-memory cache loads from disk (missing the new validators)
    /// 5. Subsequent blocks don't re-add those validators (already in memory)
    /// 6. Result: gap in on-disk cache that never gets filled
    ///
    /// The fix ensures that:
    /// - New validators are staged until confirmed written to disk
    /// - If we crash before flushing, they remain staged for retry
    /// - Multiple get_db_ops() calls return the same operations until flushed
    #[test]
    fn crash_safety_with_staged_indices() {
        let (state_8, keypairs_8) = get_state(8);
        let store = get_store();

        // Create initial cache with 8 validators and persist to disk.
        let cache = ValidatorPubkeyCache::new(&state_8, store.clone())
            .expect("should create cache");
        check_cache_get(&cache, &keypairs_8[..]);
        assert_eq!(cache.len(), 8, "cache should have 8 validators");
        assert_eq!(cache.staged_indices.len(), 0, "no staged indices after creation");
        drop(cache);

        // Reload cache from disk.
        let mut cache = ValidatorPubkeyCache::load_from_store(store.clone())
            .expect("should load cache from store");
        check_cache_get(&cache, &keypairs_8[..]);
        assert_eq!(cache.len(), 8, "reloaded cache should have 8 validators");

        // Import 4 more validators (total 12).
        let (state_12, keypairs_12) = get_state(12);
        cache
            .import_new_pubkeys(&state_12)
            .expect("should import new pubkeys");

        // Verify in-memory cache now has all 12 validators.
        assert_eq!(cache.len(), 12, "cache should have 12 validators in memory");
        check_cache_get(&cache, &keypairs_12[..]);

        // Verify new validators are staged (indices 8, 9, 10, 11).
        assert_eq!(
            cache.staged_indices.len(),
            4,
            "should have 4 staged validators"
        );
        for i in 8..12 {
            assert!(
                cache.staged_indices.contains_key(&i),
                "validator {} should be staged",
                i
            );
        }

        // Get DB operations for persisting the new validators.
        let (indices_to_write_1, db_ops_1) = cache.get_db_ops();
        assert_eq!(indices_to_write_1.len(), 4, "should have 4 indices to write");
        assert_eq!(db_ops_1.len(), 4, "should have 4 db operations");
        assert_eq!(indices_to_write_1, vec![8, 9, 10, 11], "indices should be 8-11");

        // SIMULATE CRASH: Get DB ops but DON'T write to disk and DON'T flush staged indices.
        // In the real scenario, the program would crash here before:
        // 1. Writing db_ops to disk
        // 2. Calling flush_staged_indices()
        // The staged_indices remain populated, allowing retry on next startup.

        // Verify staged indices are still present (not flushed).
        assert_eq!(
            cache.staged_indices.len(),
            4,
            "staged indices should still be present after get_db_ops"
        );

        // Verify that calling get_db_ops() again returns the same operations.
        // This is critical for crash safety: we can retry the write.
        let (indices_to_write_2, db_ops_2) = cache.get_db_ops();
        assert_eq!(
            indices_to_write_2, indices_to_write_1,
            "should return same indices on retry"
        );
        assert_eq!(db_ops_2.len(), 4, "should return same db_ops count on retry");

        // SIMULATE RESTART: Drop cache and reload from disk.
        drop(cache);
        let cache_after_crash = ValidatorPubkeyCache::load_from_store(store.clone())
            .expect("should load cache after simulated crash");

        // Verify only the first 8 validators are on disk (validators 8-11 were never persisted).
        assert_eq!(
            cache_after_crash.len(),
            8,
            "reloaded cache should only have 8 validators (crash prevented write)"
        );
        check_cache_get(&cache_after_crash, &keypairs_8[..]);

        // Verify validators 8-11 are NOT in the reloaded cache.
        for i in 8..12 {
            assert!(
                cache_after_crash.get(i).is_none(),
                "validator {} should not exist after crash",
                i
            );
        }

        // NOW TEST THE FIX: Properly persist with flush.
        drop(cache_after_crash);
        let mut cache = ValidatorPubkeyCache::load_from_store(store.clone())
            .expect("should load cache");

        // Re-import the validators (simulating the next block import).
        cache
            .import_new_pubkeys(&state_12)
            .expect("should re-import pubkeys");
        assert_eq!(cache.len(), 12, "cache should have 12 validators again");

        // Get DB operations and this time properly persist them.
        let (indices_to_write, db_ops) = cache.get_db_ops();
        assert_eq!(indices_to_write.len(), 4, "should have 4 indices to write");

        // Write to disk.
        store
            .do_atomically_with_block_and_blobs_cache(db_ops)
            .expect("should write to disk");

        // CRITICAL: Flush the staged indices after successful write.
        cache.flush_staged_indices(indices_to_write);

        // Verify staged indices are now cleared.
        assert_eq!(
            cache.staged_indices.len(),
            0,
            "staged indices should be cleared after flush"
        );

        // Drop and reload to verify persistence.
        drop(cache);
        let final_cache = ValidatorPubkeyCache::load_from_store(store)
            .expect("should load final cache");

        // Verify all 12 validators are now persisted on disk.
        assert_eq!(
            final_cache.len(),
            12,
            "final cache should have all 12 validators persisted"
        );
        check_cache_get(&final_cache, &keypairs_12[..]);

        // Verify no staged indices remain.
        assert_eq!(
            final_cache.staged_indices.len(),
            0,
            "no staged indices in reloaded cache"
        );
    }

    /// Test that demonstrates the specific gap scenario from issue #7216.
    ///
    /// Without the staged_indices fix, this scenario could lead to:
    /// In-memory: [0,1,2,3,4,5,6,7,8,9,10,11]
    /// On-disk:   [0,1,2,3,4,5,6,7] (missing 8,9,10,11)
    ///
    /// And the gap would never be filled because subsequent imports see
    /// validators 8-11 already in memory and skip them.
    #[test]
    fn prevents_on_disk_gaps() {
        let store = get_store();

        // Start with 5 validators.
        let (state_5, keypairs_5) = get_state(5);
        let mut cache = ValidatorPubkeyCache::new(&state_5, store.clone())
            .expect("should create cache");
        assert_eq!(cache.len(), 5);

        // Add 3 more validators (total 8).
        let (state_8, _keypairs_8) = get_state(8);
        cache
            .import_new_pubkeys(&state_8)
            .expect("should import 3 new validators");
        assert_eq!(cache.len(), 8);
        assert_eq!(cache.staged_indices.len(), 3, "validators 5,6,7 staged");

        // Write validators 5,6,7 to disk and properly flush.
        let (indices, db_ops) = cache.get_db_ops();
        store
            .do_atomically_with_block_and_blobs_cache(db_ops)
            .expect("should write validators 5,6,7");
        cache.flush_staged_indices(indices);
        assert_eq!(cache.staged_indices.len(), 0);

        // Add 4 more validators (total 12).
        let (state_12, keypairs_12) = get_state(12);
        cache
            .import_new_pubkeys(&state_12)
            .expect("should import 4 new validators");
        assert_eq!(cache.len(), 12);
        assert_eq!(cache.staged_indices.len(), 4, "validators 8,9,10,11 staged");

        // Simulate partial write: only write validators 8 and 9.
        let (mut indices, db_ops) = cache.get_db_ops();
        assert_eq!(indices, vec![8, 9, 10, 11]);

        // Only write first 2 operations (validators 8 and 9).
        store
            .do_atomically_with_block_and_blobs_cache(db_ops.into_iter().take(2).collect())
            .expect("should write validators 8,9");

        // Only flush the first 2 indices.
        indices.truncate(2);
        cache.flush_staged_indices(indices);

        // Validators 10,11 should still be staged.
        assert_eq!(
            cache.staged_indices.len(),
            2,
            "validators 10,11 should remain staged"
        );
        assert!(cache.staged_indices.contains_key(&10));
        assert!(cache.staged_indices.contains_key(&11));

        // On next get_db_ops(), only validators 10,11 should be returned.
        let (indices_remaining, db_ops_remaining) = cache.get_db_ops();
        assert_eq!(
            indices_remaining,
            vec![10, 11],
            "only unwritten validators returned"
        );
        assert_eq!(db_ops_remaining.len(), 2);

        // Complete the write.
        store
            .do_atomically_with_block_and_blobs_cache(db_ops_remaining)
            .expect("should write validators 10,11");
        cache.flush_staged_indices(indices_remaining);

        // All staged indices should now be cleared.
        assert_eq!(cache.staged_indices.len(), 0);

        // Verify complete persistence by reloading.
        drop(cache);
        let reloaded = ValidatorPubkeyCache::load_from_store(store)
            .expect("should reload cache");
        assert_eq!(
            reloaded.len(),
            12,
            "all 12 validators should be persisted without gaps"
        );
        check_cache_get(&reloaded, &keypairs_12[..]);
    }
}

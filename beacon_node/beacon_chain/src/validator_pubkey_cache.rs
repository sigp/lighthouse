use crate::errors::BeaconChainError;
use crate::{BeaconChainTypes, BeaconStore};
use bls::PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN;
use bls::{PublicKey, PublicKeyBytes};
use fixed_bytes::FixedBytesExtended;
use rayon::prelude::*;
use smallvec::SmallVec;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::per_block_processing::signature_sets::get_pubkey_from_state;
use std::borrow::Cow;
use std::collections::HashMap;
use std::marker::PhantomData;
use store::{DBColumn, Error as StoreError, StoreItem, StoreOp};
use tracing::instrument;
use types::{BeaconState, Hash256};

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
    _phantom: PhantomData<T>,
}

impl<T: BeaconChainTypes> ValidatorPubkeyCache<T> {
    /// Create a new public key cache using the keys in `state.validators`.
    ///
    /// The new cache will be updated with the keys from `state` and immediately written to disk.
    #[instrument(name = "validator_pubkey_cache_new", skip_all)]
    pub fn new(
        state: &BeaconState<T::EthSpec>,
        store: BeaconStore<T>,
    ) -> Result<Self, BeaconChainError> {
        let mut cache = Self {
            pubkeys: vec![],
            indices: HashMap::new(),
            pubkey_bytes: vec![],
            _phantom: PhantomData,
        };

        let store_ops = cache.import_new_pubkeys(state)?;
        store.do_atomically_with_block_and_blobs_cache(store_ops)?;

        Ok(cache)
    }

    /// Load the pubkey cache from the given on-disk database.
    #[instrument(name = "validator_pubkey_cache_load_from_store", skip_all)]
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
            _phantom: PhantomData,
        })
    }

    /// Scan the given `state` and add the public keys of any new validators that are finalized.
    ///
    /// A validator is finalized if its activation eligibility epoch is finalized, or if it comes
    /// before such a validator in the registry.
    ///
    /// Does not delete any keys from `self` if they don't appear in `state`.
    ///
    /// NOTE: This method used to import all new pubkeys from that state that were not present in
    /// the cache, under the assumption that once a deposit is finalized, its processing always
    /// leads to the same validator set. This turns out not to be true at the Gloas epoch boundary
    /// where a deposit for a 0xB0 credential can either create a validator (if processed before
    /// the fork) or a builder (if processed at the boundary).
    ///
    /// See: FIXME(sproul) add issue/PR number once PR is opened
    ///
    /// NOTE: The caller *must* commit the returned I/O batch as part of the block import process.
    #[instrument(skip_all)]
    pub fn import_new_pubkeys(
        &mut self,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<Vec<StoreOp<'static, T::EthSpec>>, BeaconChainError> {
        // If any key from the state is not present, there could be new eligible keys, so perform the
        // scan.
        if self.pubkeys.len() < state.validators().len() {
            let finalized_epoch = state.finalized_checkpoint().epoch;

            // Import every new validator up to and including the last one with a finalized
            // activation eligibility epoch. The validators before it are in the finalized registry
            // too, even if they are not eligible themselves (e.g. a deposit of less than 32 ETH).
            // They can't be skipped because the cache is indexed by position.
            let mut new_pubkeys = vec![];
            let mut num_finalized = 0;
            for validator in state.validators().iter_from(self.pubkeys.len())? {
                new_pubkeys.push(validator.pubkey);
                if validator.activation_eligibility_epoch <= finalized_epoch {
                    num_finalized = new_pubkeys.len();
                }
            }
            new_pubkeys.truncate(num_finalized);

            self.import(new_pubkeys)
        } else {
            // Fast path for the case where there are no new deposits: all keys from state are
            // already known (which implies they are all finalized).
            Ok(vec![])
        }
    }

    /// Adds zero or more validators to `self`.
    fn import(
        &mut self,
        validator_keys: Vec<PublicKeyBytes>,
    ) -> Result<Vec<StoreOp<'static, T::EthSpec>>, BeaconChainError> {
        self.pubkey_bytes.reserve(validator_keys.len());
        self.pubkeys.reserve(validator_keys.len());
        self.indices.reserve(validator_keys.len());

        let mut store_ops = Vec::with_capacity(validator_keys.len());

        let is_initial_import = self.pubkeys.is_empty();

        // Helper to insert a decompressed key
        let mut insert_key =
            |pubkey_bytes: PublicKeyBytes, pubkey: PublicKey| -> Result<(), BeaconChainError> {
                let i = self.pubkeys.len();

                if self.indices.contains_key(&pubkey_bytes) {
                    return Err(BeaconChainError::DuplicateValidatorPublicKey);
                }

                // Stage the new validator key for writing to disk.
                // It will be committed atomically when the block that introduced it is written to disk.
                // Notably it is NOT written while the write lock on the cache is held.
                // See: https://github.com/sigp/lighthouse/issues/2327
                store_ops.push(StoreOp::KeyValueOp(
                    DatabasePubkey::from_pubkey(&pubkey)
                        .as_kv_store_op(DatabasePubkey::key_for_index(i)),
                ));

                self.pubkeys.push(pubkey);
                self.pubkey_bytes.push(pubkey_bytes);
                self.indices.insert(pubkey_bytes, i);
                Ok(())
            };

        if is_initial_import {
            // On first startup, decompress keys in parallel for better performance
            let decompressed: Vec<(PublicKeyBytes, PublicKey)> = validator_keys
                .into_par_iter()
                .map(|pubkey_bytes| {
                    let pubkey = (&pubkey_bytes)
                        .try_into()
                        .map_err(BeaconChainError::InvalidValidatorPubkeyBytes)?;
                    Ok((pubkey_bytes, pubkey))
                })
                .collect::<Result<Vec<_>, BeaconChainError>>()?;

            for (pubkey_bytes, pubkey) in decompressed {
                insert_key(pubkey_bytes, pubkey)?;
            }
        } else {
            // Sequential path for incremental updates
            for pubkey_bytes in validator_keys {
                let pubkey = (&pubkey_bytes)
                    .try_into()
                    .map_err(BeaconChainError::InvalidValidatorPubkeyBytes)?;
                insert_key(pubkey_bytes, pubkey)?;
            }
        }

        Ok(store_ops)
    }

    /// Get the public key for a validator with index `i`.
    pub fn get(&self, i: usize) -> Option<&PublicKey> {
        self.pubkeys.get(i)
    }

    /// Get the public key for the validator with index `i` in `state`.
    ///
    /// Keys for validators in the cache are borrowed from the cache, whilst keys for validators
    /// beyond the end of the cache are decompressed from `state`.
    ///
    /// Returns `None` if `state` does not contain a validator with index `i`.
    pub fn get_for_state<'a>(
        &'a self,
        state: &'a BeaconState<T::EthSpec>,
        i: usize,
    ) -> Option<Cow<'a, PublicKey>> {
        if i >= state.validators().len() {
            return None;
        }
        self.get(i)
            .map(Cow::Borrowed)
            .or_else(|| get_pubkey_from_state(state, i))
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

    /// Get the index of the validator with `pubkey` in `state`.
    ///
    /// Validators in the cache are looked up in the cache, whilst validators beyond the end of the
    /// cache are searched for in `state`.
    ///
    /// Returns `None` if `state` does not contain a validator with `pubkey`.
    pub fn get_index_for_state(
        &self,
        state: &BeaconState<T::EthSpec>,
        pubkey: &PublicKeyBytes,
    ) -> Option<usize> {
        if let Some(index) = self.get_index(pubkey) {
            return (index < state.validators().len()).then_some(index);
        }
        // A validator missing from the cache can only be beyond the end of it.
        state
            .validators()
            .iter_from(self.len())
            .ok()?
            .position(|validator| validator.pubkey == *pubkey)
            .map(|i| self.len() + i)
    }

    /// Returns the number of validators in the cache.
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// Returns `true` if there are no validators in the cache.
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
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
    use bls::Keypair;
    use logging::create_test_tracing_subscriber;
    use std::sync::Arc;
    use store::HotColdDB;
    use types::{Epoch, EthSpec, Spec};

    type E = Spec;
    type T = EphemeralHarnessType<E>;

    fn get_state(validator_count: usize) -> (BeaconState<E>, Vec<Keypair>) {
        let harness = BeaconChainHarness::builder(Spec::default())
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
        // >= 32 validators required for Gloas genesis under the mainnet preset (32 slots/epoch).
        let (state, keypairs) = get_state(32);

        let store = get_store();

        let mut cache = ValidatorPubkeyCache::new(&state, store).expect("should create cache");

        check_cache_get(&cache, &keypairs[..]);

        // Try adding a state with the same number of keypairs.
        let (state, keypairs) = get_state(32);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        check_cache_get(&cache, &keypairs[..]);

        // Try adding a state with more keypairs.
        let (state, keypairs) = get_state(48);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        check_cache_get(&cache, &keypairs[..]);
    }

    #[test]
    fn persistence() {
        let (state, keypairs) = get_state(32);

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
        let (state, keypairs) = get_state(48);
        let ops = cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        store.do_atomically_with_block_and_blobs_cache(ops).unwrap();
        check_cache_get(&cache, &keypairs[..]);
        drop(cache);

        // Re-init the cache from the store.
        let cache = ValidatorPubkeyCache::load_from_store(store).expect("should open cache");
        check_cache_get(&cache, &keypairs[..]);
    }

    #[test]
    fn parallel_import_maintains_order() {
        // Test that parallel decompression on first startup maintains correct order and indices
        let (state, keypairs) = get_state(100);
        let store = get_store();

        // Create cache from empty state (triggers parallel path)
        let cache: ValidatorPubkeyCache<T> =
            ValidatorPubkeyCache::new(&state, store).expect("should create cache");

        check_cache_get(&cache, &keypairs[..]);
    }

    #[test]
    fn incremental_import_maintains_order() {
        // Test that incremental imports maintain correct order (triggers sequential path)
        let store = get_store();

        // Start with 50 validators
        let (state1, keypairs1) = get_state(50);
        let mut cache =
            ValidatorPubkeyCache::new(&state1, store.clone()).expect("should create cache");
        check_cache_get(&cache, &keypairs1[..]);

        // Add 50 more validators
        let (state2, keypairs2) = get_state(100);
        let ops = cache
            .import_new_pubkeys(&state2)
            .expect("should import pubkeys");
        store.do_atomically_with_block_and_blobs_cache(ops).unwrap();

        // Verify all 100 validators are correctly indexed
        check_cache_get(&cache, &keypairs2[..]);
    }

    #[test]
    fn unfinalized_validators_not_imported() {
        let (mut state, keypairs) = get_state(48);

        // Give the last 8 validators an activation eligibility epoch that is not finalized yet.
        for i in 40..48 {
            let validator = state.get_validator_mut(i).unwrap();
            validator.activation_eligibility_epoch = Epoch::new(1);
        }
        assert_eq!(state.finalized_checkpoint().epoch, Epoch::new(0));

        let mut cache = ValidatorPubkeyCache::<T>::new(&state, get_store()).unwrap();
        check_cache_get(&cache, &keypairs[..40]);

        // Importing again without finality advancing does nothing.
        assert!(cache.import_new_pubkeys(&state).unwrap().is_empty());
        check_cache_get(&cache, &keypairs[..40]);

        // Once the eligibility epoch is finalized the remaining validators are imported.
        state.finalized_checkpoint_mut().epoch = Epoch::new(1);
        assert_eq!(cache.import_new_pubkeys(&state).unwrap().len(), 8);
        check_cache_get(&cache, &keypairs[..]);
    }

    #[test]
    fn ineligible_validator_does_not_block_initial_import() {
        let (mut state, keypairs) = get_state(48);

        // A validator that never becomes eligible for activation (e.g. a deposit of less than
        // 32 ETH) is still imported when a later validator is finalized.
        let validator = state.get_validator_mut(10).unwrap();
        validator.activation_eligibility_epoch = E::default_spec().far_future_epoch;

        let cache = ValidatorPubkeyCache::<T>::new(&state, get_store()).unwrap();
        check_cache_get(&cache, &keypairs[..]);
    }

    #[test]
    fn ineligible_validator_does_not_block_incremental_import() {
        let (state, keypairs) = get_state(32);
        let mut cache = ValidatorPubkeyCache::<T>::new(&state, get_store()).unwrap();
        check_cache_get(&cache, &keypairs[..]);

        // Add 16 more validators, one of which never becomes eligible for activation.
        let (mut state, keypairs) = get_state(48);
        let validator = state.get_validator_mut(40).unwrap();
        validator.activation_eligibility_epoch = E::default_spec().far_future_epoch;

        assert_eq!(cache.import_new_pubkeys(&state).unwrap().len(), 16);
        check_cache_get(&cache, &keypairs[..]);
    }

    #[test]
    fn trailing_ineligible_validators_not_imported() {
        let (mut state, keypairs) = get_state(48);

        // With no finalized validator after them, ineligible validators are left out.
        for i in 46..48 {
            let validator = state.get_validator_mut(i).unwrap();
            validator.activation_eligibility_epoch = E::default_spec().far_future_epoch;
        }

        let cache = ValidatorPubkeyCache::<T>::new(&state, get_store()).unwrap();
        check_cache_get(&cache, &keypairs[..46]);
    }

    #[test]
    fn get_index_for_state_finds_uncached_validators() {
        let (mut state, keypairs) = get_state(48);

        // Leave the last 8 validators out of the cache.
        for i in 40..48 {
            let validator = state.get_validator_mut(i).unwrap();
            validator.activation_eligibility_epoch = Epoch::new(1);
        }
        let cache = ValidatorPubkeyCache::<T>::new(&state, get_store()).unwrap();
        assert_eq!(cache.len(), 40);

        // Cached and uncached validators are both found.
        for (i, keypair) in keypairs.iter().enumerate() {
            let pubkey = keypair.pk.compress();
            assert_eq!(cache.get_index_for_state(&state, &pubkey), Some(i));
        }

        // A pubkey that is not in the state is not found.
        let (_, more_keypairs) = get_state(64);
        let unknown_pubkey = more_keypairs[60].pk.compress();
        assert_eq!(cache.get_index_for_state(&state, &unknown_pubkey), None);
    }

    #[test]
    fn get_index_for_state_ignores_validators_not_in_state() {
        let (mut state, keypairs) = get_state(48);
        for i in 40..48 {
            let validator = state.get_validator_mut(i).unwrap();
            validator.activation_eligibility_epoch = Epoch::new(1);
        }
        let cache = ValidatorPubkeyCache::<T>::new(&state, get_store()).unwrap();
        assert_eq!(cache.len(), 40);

        // A state with fewer validators than the cache only resolves its own validators.
        let (small_state, _) = get_state(32);
        let in_small_state = keypairs[10].pk.compress();
        let cached_only = keypairs[35].pk.compress();
        let uncached = keypairs[44].pk.compress();
        assert_eq!(
            cache.get_index_for_state(&small_state, &in_small_state),
            Some(10)
        );
        assert_eq!(cache.get_index_for_state(&small_state, &cached_only), None);
        assert_eq!(cache.get_index_for_state(&small_state, &uncached), None);
    }
}

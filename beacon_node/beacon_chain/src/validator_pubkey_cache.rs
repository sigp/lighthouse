use crate::errors::BeaconChainError;
use crate::{BeaconChainTypes, BeaconStore};
use ssz::{Decode, Encode};
use std::collections::HashMap;
use std::convert::TryInto;
use store::{DBColumn, Error as StoreError, StoreItem};
use types::{BeaconState, Hash256, PublicKey, PublicKeyBytes};

/// Provides a mapping of `validator_index -> validator_publickey`.
///
/// This cache exists for two reasons:
///
/// 1. To avoid reading a `BeaconState` from disk each time we need a public key.
/// 2. To reduce the amount of public key _decompression_ required. A `BeaconState` stores public
///    keys in compressed form and they are needed in decompressed form for signature verification.
///    Decompression is expensive when many keys are involved.
///
/// The cache has a `backing` that it uses to maintain a persistent, on-disk
/// copy of itself. This allows it to be restored between process invocations.
pub struct ValidatorPubkeyCache<T: BeaconChainTypes> {
    pubkeys: Vec<PublicKey>,
    indices: HashMap<PublicKeyBytes, usize>,
    pubkey_bytes: Vec<PublicKeyBytes>,
    store: BeaconStore<T>,
}

impl<T: BeaconChainTypes> ValidatorPubkeyCache<T> {
    /// Create a new public key cache using the keys in `state.validators`.
    ///
    /// Also creates a new persistence file, returning an error if there is already a file at
    /// `persistence_path`.
    pub fn new(
        state: &BeaconState<T::EthSpec>,
        store: BeaconStore<T>,
    ) -> Result<Self, BeaconChainError> {
        let mut cache = Self {
            pubkeys: vec![],
            indices: HashMap::new(),
            pubkey_bytes: vec![],
            store,
        };

        cache.import_new_pubkeys(state)?;

        Ok(cache)
    }

    /// Load the pubkey cache from the given on-disk database.
    pub fn load_from_store(store: BeaconStore<T>) -> Result<Self, BeaconChainError> {
        let mut pubkeys = vec![];
        let mut indices = HashMap::new();
        let mut pubkey_bytes = vec![];

        for validator_index in 0.. {
            if let Some(DatabasePubkey(pubkey)) =
                store.get_item(&DatabasePubkey::key_for_index(validator_index))?
            {
                pubkeys.push((&pubkey).try_into().map_err(|e| {
                    BeaconChainError::ValidatorPubkeyCacheError(format!("{:?}", e))
                })?);
                pubkey_bytes.push(pubkey);
                indices.insert(pubkey, validator_index);
            } else {
                break;
            }
        }

        Ok(ValidatorPubkeyCache {
            pubkeys,
            indices,
            pubkey_bytes,
            store,
        })
    }

    /// Scan the given `state` and add any new validator public keys.
    ///
    /// Does not delete any keys from `self` if they don't appear in `state`.
    pub fn import_new_pubkeys(
        &mut self,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<(), BeaconChainError> {
        if state.validators().len() > self.pubkeys.len() {
            self.import(
                state.validators()[self.pubkeys.len()..]
                    .iter()
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

        for pubkey in validator_keys {
            let i = self.pubkeys.len();

            if self.indices.contains_key(&pubkey) {
                return Err(BeaconChainError::DuplicateValidatorPublicKey);
            }

            // The item is written to disk _before_ it is written into
            // the local struct.
            //
            // This means that a pubkey cache read from disk will always be equivalent to or
            // _later than_ the cache that was running in the previous instance of Lighthouse.
            //
            // The motivation behind this ordering is that we do not want to have states that
            // reference a pubkey that is not in our cache. However, it's fine to have pubkeys
            // that are never referenced in a state.
            self.store
                .put_item(&DatabasePubkey::key_for_index(i), &DatabasePubkey(pubkey))?;

            self.pubkeys.push(
                (&pubkey)
                    .try_into()
                    .map_err(BeaconChainError::InvalidValidatorPubkeyBytes)?,
            );
            self.pubkey_bytes.push(pubkey);

            self.indices.insert(pubkey, i);
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
}

/// Wrapper for a public key stored in the database.
///
/// Keyed by the validator index as `Hash256::from_low_u64_be(index)`.
struct DatabasePubkey(PublicKeyBytes);

impl StoreItem for DatabasePubkey {
    fn db_column() -> DBColumn {
        DBColumn::PubkeyCache
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.0.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Ok(Self(PublicKeyBytes::from_ssz_bytes(bytes)?))
    }
}

impl DatabasePubkey {
    fn key_for_index(index: usize) -> Hash256 {
        Hash256::from_low_u64_be(index as u64)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{BeaconChainHarness, EphemeralHarnessType};
    use logging::test_logger;
    use std::sync::Arc;
    use store::HotColdDB;
    use types::{BeaconState, EthSpec, Keypair, MainnetEthSpec};

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
        Arc::new(
            HotColdDB::open_ephemeral(<_>::default(), E::default_spec(), test_logger()).unwrap(),
        )
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
        check_cache_get(&cache, &keypairs[..]);
        drop(cache);

        // Re-init the cache from the store.
        let cache = ValidatorPubkeyCache::load_from_store(store).expect("should open cache");
        check_cache_get(&cache, &keypairs[..]);
    }
}

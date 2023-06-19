use crate::{DBColumn, Error, HotColdDB, ItemStore, StoreItem, StoreOp};
use bls::PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN;
use smallvec::SmallVec;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use types::{BeaconState, EthSpec, Hash256, PublicKey, PublicKeyBytes};

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
#[derive(Debug)]
pub struct ValidatorPubkeyCache<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    pubkeys: Vec<PublicKey>,
    indices: HashMap<PublicKeyBytes, usize>,
    validators: Vec<Arc<PublicKeyBytes>>,
    _phantom: PhantomData<(E, Hot, Cold)>,
}

// Temp value.
impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Default
    for ValidatorPubkeyCache<E, Hot, Cold>
{
    fn default() -> Self {
        ValidatorPubkeyCache {
            pubkeys: vec![],
            indices: HashMap::new(),
            validators: vec![],
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> ValidatorPubkeyCache<E, Hot, Cold> {
    /// Create a new public key cache using the keys in `state.validators`.
    ///
    /// The new cache will be updated with the keys from `state` and immediately written to disk.
    pub fn new(state: &BeaconState<E>, store: &HotColdDB<E, Hot, Cold>) -> Result<Self, Error> {
        let mut cache = Self {
            pubkeys: vec![],
            indices: HashMap::new(),
            validators: vec![],
            _phantom: PhantomData,
        };

        let store_ops = cache.import_new_pubkeys(state)?;
        store.do_atomically(store_ops)?;

        Ok(cache)
    }

    /// Load the pubkey cache from the given on-disk database.
    pub fn load_from_store(store: &HotColdDB<E, Hot, Cold>) -> Result<Self, Error> {
        let mut pubkeys = vec![];
        let mut indices = HashMap::new();
        let mut validators = vec![];

        for validator_index in 0.. {
            if let Some(db_validator) =
                store.get_item(&DatabaseValidator::key_for_index(validator_index))?
            {
                let (pubkey, pubkey_bytes) =
                    DatabaseValidator::into_immutable_validator(&db_validator)?;
                pubkeys.push(pubkey);
                indices.insert(pubkey_bytes, validator_index);
                validators.push(Arc::new(pubkey_bytes));
            } else {
                break;
            }
        }

        Ok(ValidatorPubkeyCache {
            pubkeys,
            indices,
            validators,
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
        state: &BeaconState<E>,
    ) -> Result<Vec<StoreOp<'static, E>>, Error> {
        if state.validators().len() > self.validators.len() {
            self.import(
                state
                    .validators()
                    .iter_from(self.pubkeys.len())?
                    .map(|v| v.pubkey.clone()),
            )
        } else {
            Ok(vec![])
        }
    }

    /// Adds zero or more validators to `self`.
    fn import<I>(&mut self, validator_keys: I) -> Result<Vec<StoreOp<'static, E>>, Error>
    where
        I: Iterator<Item = Arc<PublicKeyBytes>> + ExactSizeIterator,
    {
        self.validators.reserve(validator_keys.len());
        self.pubkeys.reserve(validator_keys.len());
        self.indices.reserve(validator_keys.len());

        let mut store_ops = Vec::with_capacity(validator_keys.len());
        for pubkey_bytes in validator_keys {
            let i = self.pubkeys.len();

            if self.indices.contains_key(&pubkey_bytes) {
                return Err(Error::DuplicateValidatorPublicKey);
            }

            let pubkey = (&*pubkey_bytes)
                .try_into()
                .map_err(Error::InvalidValidatorPubkeyBytes)?;

            // Stage the new validator key for writing to disk.
            // It will be committed atomically when the block that introduced it is written to disk.
            // Notably it is NOT written while the write lock on the cache is held.
            // See: https://github.com/sigp/lighthouse/issues/2327
            store_ops.push(StoreOp::KeyValueOp(
                DatabaseValidator::from_immutable_validator(&pubkey, &pubkey_bytes)
                    .as_kv_store_op(DatabaseValidator::key_for_index(i))?,
            ));

            self.pubkeys.push(pubkey);
            self.indices.insert(*pubkey_bytes, i);
            self.validators.push(pubkey_bytes);
        }

        Ok(store_ops)
    }

    /// Get the public key for a validator with index `i`.
    pub fn get(&self, i: usize) -> Option<&PublicKey> {
        self.pubkeys.get(i)
    }

    /// Get the immutable validator with index `i`.
    pub fn get_validator_pubkey(&self, i: usize) -> Option<Arc<PublicKeyBytes>> {
        self.validators.get(i).cloned()
    }

    /// Get the `PublicKey` for a validator with `PublicKeyBytes`.
    pub fn get_pubkey_from_pubkey_bytes(&self, pubkey: &PublicKeyBytes) -> Option<&PublicKey> {
        self.get_index(pubkey).and_then(|index| self.get(index))
    }

    /// Get the public key (in bytes form) for a validator with index `i`.
    pub fn get_pubkey_bytes(&self, i: usize) -> Option<&PublicKeyBytes> {
        self.validators.get(i).map(|pubkey_bytes| &**pubkey_bytes)
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
#[derive(Encode, Decode)]
struct DatabaseValidator {
    pubkey: SmallVec<[u8; PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN]>,
}

impl StoreItem for DatabaseValidator {
    fn db_column() -> DBColumn {
        DBColumn::PubkeyCache
    }

    fn as_store_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.as_ssz_bytes())
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

impl DatabaseValidator {
    fn key_for_index(index: usize) -> Hash256 {
        Hash256::from_low_u64_be(index as u64)
    }

    // FIXME(sproul): remove param
    fn from_immutable_validator(pubkey: &PublicKey, _validator: &PublicKeyBytes) -> Self {
        DatabaseValidator {
            pubkey: pubkey.serialize_uncompressed().into(),
        }
    }

    #[allow(clippy::wrong_self_convention)]
    fn into_immutable_validator(&self) -> Result<(PublicKey, PublicKeyBytes), Error> {
        let pubkey = PublicKey::deserialize_uncompressed(&self.pubkey)
            .map_err(Error::InvalidValidatorPubkeyBytes)?;
        let pubkey_bytes = pubkey.compress();
        Ok((pubkey, pubkey_bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{HotColdDB, MemoryStore};
    use beacon_chain::test_utils::BeaconChainHarness;
    use logging::test_logger;
    use std::sync::Arc;
    use types::{BeaconState, EthSpec, Keypair, MainnetEthSpec};

    type E = MainnetEthSpec;
    type Store = MemoryStore<E>;

    fn get_state(validator_count: usize) -> (BeaconState<E>, Vec<Keypair>) {
        let harness = BeaconChainHarness::builder(MainnetEthSpec)
            .default_spec()
            .deterministic_keypairs(validator_count)
            .fresh_ephemeral_store()
            .build();

        harness.advance_slot();

        (harness.get_current_state(), harness.validator_keypairs)
    }

    fn get_store() -> Arc<HotColdDB<E, Store, Store>> {
        Arc::new(
            HotColdDB::open_ephemeral(<_>::default(), E::default_spec(), test_logger()).unwrap(),
        )
    }

    #[allow(clippy::needless_range_loop)]
    fn check_cache_get(cache: &ValidatorPubkeyCache<E, Store, Store>, keypairs: &[Keypair]) {
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

        let mut cache = ValidatorPubkeyCache::new(&state, &store).expect("should create cache");

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
        let cache = ValidatorPubkeyCache::new(&state, &store).expect("should create cache");
        check_cache_get(&cache, &keypairs[..]);
        drop(cache);

        // Re-init the cache from the store.
        let mut cache = ValidatorPubkeyCache::load_from_store(&store).expect("should open cache");
        check_cache_get(&cache, &keypairs[..]);

        // Add some more keypairs.
        let (state, keypairs) = get_state(12);
        let ops = cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        store.do_atomically(ops).unwrap();
        check_cache_get(&cache, &keypairs[..]);
        drop(cache);

        // Re-init the cache from the store.
        let cache = ValidatorPubkeyCache::load_from_store(&store).expect("should open cache");
        check_cache_get(&cache, &keypairs[..]);
    }
}

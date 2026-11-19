use crate::errors::BeaconChainError;
use crate::{BeaconChainTypes, BeaconStore};
use bls::PublicKey;
use fixed_bytes::FixedBytesExtended;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::per_block_processing::signature_sets;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use store::{DBColumn, Error as StoreError, StoreItem, StoreOp};
use tracing::instrument;
use types::{BeaconState, BeaconStateError, Hash256, XmssPublicKey};

/// Cached XMSS keys by validator index, with reverse lookup by public key.
///
/// This cache tracks appended indices. For an operation tied to a specific state, consult
/// that state's registry because an index can refer to different validators in different states.
pub struct ValidatorPubkeyCache<T: BeaconChainTypes> {
    pubkeys: Vec<XmssPublicKey>,
    indices: HashMap<XmssPublicKey, usize>,
    _phantom: PhantomData<T>,
}

impl<T: BeaconChainTypes> ValidatorPubkeyCache<T> {
    fn empty() -> Self {
        Self {
            pubkeys: Vec::new(),
            indices: HashMap::new(),
            _phantom: PhantomData,
        }
    }

    /// Create a new cache from the validator registry and immediately write it to disk.
    #[instrument(name = "validator_pubkey_cache_new", skip_all)]
    pub fn new(
        state: &BeaconState<T::EthSpec>,
        store: BeaconStore<T>,
    ) -> Result<Self, BeaconChainError> {
        let mut cache = Self::empty();
        let store_ops = cache.import_new_pubkeys(state)?;
        store.do_atomically_with_block_and_blobs_cache(store_ops)?;
        Ok(cache)
    }

    /// Load the pubkey cache from the given on-disk database.
    #[instrument(name = "validator_pubkey_cache_load_from_store", skip_all)]
    pub fn load_from_store(store: BeaconStore<T>) -> Result<Self, BeaconChainError> {
        let mut cache = Self::empty();
        for validator_index in 0.. {
            let Some(DatabasePubkey { pubkey }) =
                store.get_item(&DatabasePubkey::key_for_index(validator_index))?
            else {
                break;
            };
            if cache.indices.insert(pubkey, validator_index).is_some() {
                return Err(BeaconChainError::DuplicateValidatorPublicKey);
            }
            cache.pubkeys.push(pubkey);
        }
        Ok(cache)
    }

    /// Add any newly appended validator keys from the registry.
    ///
    /// The caller must commit the returned I/O batch as part of block import.
    #[instrument(skip_all)]
    pub fn import_new_pubkeys(
        &mut self,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<Vec<StoreOp<'static, T::EthSpec>>, BeaconChainError> {
        if state.validators().len() <= self.len() {
            return Ok(vec![]);
        }
        let validator_keys = state
            .validators()
            .iter_from(self.len())?
            .map(|v| v.pubkey)
            .collect::<Vec<_>>();
        let mut seen = HashSet::with_capacity(validator_keys.len());
        for &pubkey in &validator_keys {
            if self.indices.contains_key(&pubkey) || !seen.insert(pubkey) {
                return Err(BeaconChainError::DuplicateValidatorPublicKey);
            }
        }

        self.pubkeys.reserve(validator_keys.len());
        self.indices.reserve(validator_keys.len());
        let mut store_ops = Vec::with_capacity(validator_keys.len());
        for pubkey in validator_keys {
            let index = self.pubkeys.len();
            store_ops.push(StoreOp::KeyValueOp(
                DatabasePubkey::from_pubkey(&pubkey)
                    .as_kv_store_op(DatabasePubkey::key_for_index(index)),
            ));
            self.pubkeys.push(pubkey);
            self.indices.insert(pubkey, index);
        }
        Ok(store_ops)
    }

    pub fn get(&self, index: usize) -> Option<&XmssPublicKey> {
        self.pubkeys.get(index)
    }

    /// Return an explicit error when a BLS verification path tries to use the XMSS cache.
    pub fn get_bls(&self, index: usize) -> signature_sets::Result<&PublicKey> {
        self.get(index)
            .ok_or(signature_sets::Error::ValidatorUnknown(index as u64))?;
        Err(BeaconStateError::BlsRegistryKeysUnavailable.into())
    }

    pub fn get_index(&self, pubkey: &XmssPublicKey) -> Option<usize> {
        self.indices.get(pubkey).copied()
    }

    pub fn len(&self) -> usize {
        self.pubkeys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pubkeys.is_empty()
    }
}

/// XMSS key stored under the validator index as `Hash256::from_low_u64_be(index)`.
#[derive(Encode, Decode)]
pub struct DatabasePubkey {
    pubkey: XmssPublicKey,
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

    pub fn from_pubkey(pubkey: &XmssPublicKey) -> Self {
        Self { pubkey: *pubkey }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::EphemeralHarnessType;
    use std::sync::Arc;
    use store::HotColdDB;
    use types::{Eth1Data, EthSpec, Spec, Validator};

    type T = EphemeralHarnessType<Spec>;

    fn state_with_keys(count: u8) -> BeaconState<Spec> {
        let mut state = BeaconState::new(0, Eth1Data::default(), &Spec::default_spec());
        for i in 0..count {
            state
                .validators_mut()
                .push(Validator {
                    pubkey: [i; 32].into(),
                    ..Validator::default()
                })
                .unwrap();
        }
        state
    }

    fn store() -> BeaconStore<T> {
        Arc::new(HotColdDB::open_ephemeral(<_>::default(), Arc::new(Spec::default_spec())).unwrap())
    }

    fn check_cache(cache: &ValidatorPubkeyCache<T>, count: u8) {
        assert_eq!(cache.len(), usize::from(count));
        for i in 0..count {
            let pubkey = XmssPublicKey::from([i; 32]);
            assert_eq!(cache.get(usize::from(i)), Some(&pubkey));
            assert_eq!(cache.get_index(&pubkey), Some(usize::from(i)));
        }
        assert_eq!(cache.get(usize::from(count)), None);
    }

    #[test]
    fn initial_and_incremental_persistence() {
        let store = store();
        let cache = ValidatorPubkeyCache::new(&state_with_keys(32), store.clone()).unwrap();
        check_cache(&cache, 32);
        assert!(matches!(
            cache.get_bls(0),
            Err(signature_sets::Error::BeaconStateError(
                BeaconStateError::BlsRegistryKeysUnavailable
            ))
        ));

        let mut cache = ValidatorPubkeyCache::load_from_store(store.clone()).unwrap();
        check_cache(&cache, 32);
        assert!(
            cache
                .import_new_pubkeys(&state_with_keys(32))
                .unwrap()
                .is_empty()
        );

        let ops = cache.import_new_pubkeys(&state_with_keys(48)).unwrap();
        store.do_atomically_with_block_and_blobs_cache(ops).unwrap();
        check_cache(&cache, 48);

        let cache = ValidatorPubkeyCache::load_from_store(store).unwrap();
        check_cache(&cache, 48);
    }

    #[test]
    fn duplicate_key_does_not_partially_update_cache() {
        let mut cache = ValidatorPubkeyCache::new(&state_with_keys(2), store()).unwrap();
        let mut state = state_with_keys(4);
        state.validators_mut().get_mut(3).unwrap().pubkey = XmssPublicKey::empty();
        assert!(matches!(
            cache.import_new_pubkeys(&state),
            Err(BeaconChainError::DuplicateValidatorPublicKey)
        ));
        check_cache(&cache, 2);
    }
}

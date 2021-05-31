use crate::errors::BeaconChainError;
use crate::{BeaconChainTypes, BeaconStore};
use parking_lot::{Mutex, RwLock, RwLockReadGuard};
use ssz::{Decode, DecodeError, Encode};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use store::{DBColumn, Error as StoreError, StoreItem};
use types::{BeaconState, Hash256, PublicKey, PublicKeyBytes};

/// The volatile components of the `ValidatorPubkeyCache` (i.e., not the non-volatile database or
/// file-backing).
pub struct VolatilePubkeyCache {
    pubkeys: Vec<PublicKey>,
    indices: HashMap<PublicKeyBytes, usize>,
    pubkey_bytes: Vec<PublicKeyBytes>,
}

impl VolatilePubkeyCache {
    /// Get the public key for a validator with index `i`.
    pub fn get(&self, i: usize) -> Option<&PublicKey> {
        self.pubkeys.get(i)
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
}

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
    volatile: RwLock<VolatilePubkeyCache>,
    backing: Mutex<PubkeyCacheBacking<T>>,
}

/// Abstraction over on-disk backing.
///
/// `File` backing is legacy, `Database` is current.
enum PubkeyCacheBacking<T: BeaconChainTypes> {
    File(ValidatorPubkeyCacheFile),
    Database(BeaconStore<T>),
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
        let cache = Self {
            volatile: RwLock::new(VolatilePubkeyCache {
                pubkeys: vec![],
                indices: HashMap::new(),
                pubkey_bytes: vec![],
            }),
            backing: Mutex::new(PubkeyCacheBacking::Database(store)),
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
                pubkeys.push((&pubkey).try_into().map_err(Error::PubkeyDecode)?);
                pubkey_bytes.push(pubkey);
                indices.insert(pubkey, validator_index);
            } else {
                break;
            }
        }

        Ok(ValidatorPubkeyCache {
            volatile: RwLock::new(VolatilePubkeyCache {
                pubkeys,
                indices,
                pubkey_bytes,
            }),
            backing: Mutex::new(PubkeyCacheBacking::Database(store)),
        })
    }

    /// DEPRECATED: used only for migration
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, BeaconChainError> {
        ValidatorPubkeyCacheFile::open(&path)
            .and_then(ValidatorPubkeyCacheFile::into_cache)
            .map_err(Into::into)
    }

    /// Convert a cache using `File` backing to one using `Database` backing.
    ///
    /// This will write all of the keys from `existing_cache` to `store`.
    pub fn convert(existing_cache: Self, store: BeaconStore<T>) -> Result<Self, BeaconChainError> {
        let volatile = existing_cache.volatile.read();
        let result = ValidatorPubkeyCache {
            volatile: RwLock::new(VolatilePubkeyCache {
                pubkeys: Vec::with_capacity(volatile.pubkeys.len()),
                indices: HashMap::with_capacity(volatile.indices.len()),
                pubkey_bytes: Vec::with_capacity(volatile.indices.len()),
            }),
            backing: Mutex::new(PubkeyCacheBacking::Database(store)),
        };
        result.import(volatile.pubkeys.iter().map(PublicKeyBytes::from))?;
        Ok(result)
    }

    /// Scan the given `state` and add any new validator public keys.
    ///
    /// Does not delete any keys from `self` if they don't appear in `state`.
    pub fn import_new_pubkeys(
        &self,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<(), BeaconChainError> {
        self.import(state.validators.iter().map(|v| v.pubkey))
    }

    /// Adds zero or more validators to `self`.
    fn import<I>(&self, validator_keys: I) -> Result<(), BeaconChainError>
    where
        I: Iterator<Item = PublicKeyBytes> + ExactSizeIterator,
    {
        // Lock the backing to prevent modification from another thread.
        let mut backing = self.backing.lock();

        let num_current_pubkeys = self.volatile.read().pubkeys.len();
        let num_new = if let Some(new) = validator_keys
            .len()
            .checked_sub(num_current_pubkeys)
            .filter(|n| *n > 0)
        {
            new
        } else {
            // Nothing to do.
            return Ok(());
        };

        /*
         * First Phase:
         *
         * Update the backing and decompress the public keys whilst still allowing read-access to
         * the volatile components of the cache.
         */

        let mut new_pubkeys = Vec::with_capacity(num_new);
        for (i, pubkey) in validator_keys.enumerate().skip(num_current_pubkeys) {
            // The item is written to disk _before_ it is written into the volatile struct.
            //
            // This means that a pubkey cache read from disk will always be equivalent to or
            // _later than_ the cache that was running in the previous instance of Lighthouse.
            //
            // The motivation behind this ordering is that we do not want to have states that
            // reference a pubkey that is not in our cache. However, it's fine to have pubkeys
            // that are never referenced in a state.
            match &mut *backing {
                PubkeyCacheBacking::File(persistence_file) => {
                    persistence_file.append(i, &pubkey)?;
                }
                PubkeyCacheBacking::Database(store) => {
                    store.put_item(&DatabasePubkey::key_for_index(i), &DatabasePubkey(pubkey))?;
                }
            }

            // Do the decompression *before* taking the write-lock on the volatile components. This
            // ensures other components can still read from the existing cache whilst lengthy
            // decompression is happening.
            let pubkey_decompressed = (&pubkey)
                .try_into()
                .map_err(BeaconChainError::InvalidValidatorPubkeyBytes)?;

            new_pubkeys.push((i, pubkey, pubkey_decompressed));
        }

        /*
         * Second Phase:
         *
         * Update the volatile components, preventing read-access to the cache for as little time as
         * possible.
         */

        let mut volatile = self.volatile.write();

        volatile.pubkey_bytes.reserve(num_new);
        volatile.pubkeys.reserve(num_new);
        volatile.indices.reserve(num_new);

        for (i, pubkey_compressed, pubkey_decompressed) in new_pubkeys {
            if volatile.indices.contains_key(&pubkey_compressed) {
                return Err(BeaconChainError::DuplicateValidatorPublicKey);
            }
            volatile.pubkeys.push(pubkey_decompressed);
            volatile.pubkey_bytes.push(pubkey_compressed);
            volatile.indices.insert(pubkey_compressed, i);
        }

        Ok(())
    }

    /// Get the public key for a validator with index `i`.
    pub fn get(&self, i: usize) -> Option<&PublicKey> {
        self.pubkeys.get(i)
    }

    /// Get the `PublicKey` for a validator with `PublicKeyBytes`.
    pub fn get_pubkey_from_pubkey_bytes(&self, pubkey: &PublicKeyBytes) -> Option<&PublicKey> {
        self.get_index(pubkey)
            .map(|index| self.get(index))
            .flatten()
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

    pub fn volatile_cache(&self) -> RwLockReadGuard<VolatilePubkeyCache> {
        self.volatile.read()
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

/// Allows for maintaining an on-disk copy of the `ValidatorPubkeyCache`. The file is raw SSZ bytes
/// (not ASCII encoded).
///
/// ## Writes
///
/// Each entry is simply appended to the file.
///
/// ## Reads
///
/// The whole file is parsed as an SSZ "variable list" of objects.
///
/// This parsing method is possible because the items in the list are fixed-length SSZ objects.
struct ValidatorPubkeyCacheFile(File);

#[derive(Debug)]
enum Error {
    Io(io::Error),
    Ssz(DecodeError),
    PubkeyDecode(bls::Error),
    /// The file read from disk does not have a contiguous list of validator public keys. The file
    /// has become corrupted.
    InconsistentIndex {
        _expected: Option<usize>,
        _found: usize,
    },
}

impl From<Error> for BeaconChainError {
    fn from(e: Error) -> BeaconChainError {
        BeaconChainError::ValidatorPubkeyCacheFileError(format!("{:?}", e))
    }
}

impl ValidatorPubkeyCacheFile {
    /// Opens an existing file for reading and writing.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .append(true)
            .open(path)
            .map(Self)
            .map_err(Error::Io)
    }

    /// Append a public key to file.
    ///
    /// The provided `index` should each be one greater than the previous and start at 0.
    /// Otherwise, the file will become corrupted and unable to be converted into a cache .
    pub fn append(&mut self, index: usize, pubkey: &PublicKeyBytes) -> Result<(), Error> {
        append_to_file(&mut self.0, index, pubkey)
    }

    /// Creates a `ValidatorPubkeyCache` by reading and parsing the underlying file.
    pub fn into_cache<T: BeaconChainTypes>(mut self) -> Result<ValidatorPubkeyCache<T>, Error> {
        let mut bytes = vec![];
        self.0.read_to_end(&mut bytes).map_err(Error::Io)?;

        let list: Vec<(usize, PublicKeyBytes)> = Vec::from_ssz_bytes(&bytes).map_err(Error::Ssz)?;

        let mut last = None;
        let mut pubkeys = Vec::with_capacity(list.len());
        let mut indices = HashMap::with_capacity(list.len());
        let mut pubkey_bytes = Vec::with_capacity(list.len());

        for (index, pubkey) in list {
            let expected = last.map(|n| n + 1);
            if expected.map_or(true, |expected| index == expected) {
                last = Some(index);
                pubkeys.push((&pubkey).try_into().map_err(Error::PubkeyDecode)?);
                pubkey_bytes.push(pubkey);
                indices.insert(pubkey, index);
            } else {
                return Err(Error::InconsistentIndex {
                    _expected: expected,
                    _found: index,
                });
            }
        }

        Ok(ValidatorPubkeyCache {
            volatile: RwLock::new(VolatilePubkeyCache {
                pubkeys,
                indices,
                pubkey_bytes,
            }),
            backing: Mutex::new(PubkeyCacheBacking::File(self)),
        })
    }
}

fn append_to_file(file: &mut File, index: usize, pubkey: &PublicKeyBytes) -> Result<(), Error> {
    let mut line = Vec::with_capacity(index.ssz_bytes_len() + pubkey.ssz_bytes_len());

    index.ssz_append(&mut line);
    pubkey.ssz_append(&mut line);

    file.write_all(&line).map_err(Error::Io)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{BeaconChainHarness, EphemeralHarnessType};
    use logging::test_logger;
    use std::sync::Arc;
    use store::HotColdDB;
    use tempfile::tempdir;
    use types::{
        test_utils::generate_deterministic_keypair, BeaconState, EthSpec, Keypair, MainnetEthSpec,
    };

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
                let volatile_cache = cache.volatile_cache();
                let pubkey = volatile_cache.get(i).expect("pubkey should be present");
                assert_eq!(pubkey, &keypairs[i].pk, "pubkey should match cache");

                let pubkey_bytes: PublicKeyBytes = pubkey.clone().into();

                assert_eq!(
                    i,
                    cache
                        .volatile_cache()
                        .get_index(&pubkey_bytes)
                        .expect("should resolve index"),
                    "index should match cache"
                );
            } else {
                assert_eq!(
                    cache.volatile_cache().get(i),
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

        let cache = ValidatorPubkeyCache::new(&state, store).expect("should create cache");

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

        // Re-init the cache from the file.
        let cache =
            ValidatorPubkeyCache::load_from_store(store.clone()).expect("should open cache");
        check_cache_get(&cache, &keypairs[..]);

        // Add some more keypairs.
        let (state, keypairs) = get_state(12);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        check_cache_get(&cache, &keypairs[..]);
        drop(cache);

        // Re-init the cache from the file.
        let cache = ValidatorPubkeyCache::load_from_store(store).expect("should open cache");
        check_cache_get(&cache, &keypairs[..]);
    }

    #[test]
    fn invalid_persisted_file() {
        let dir = tempdir().expect("should create tempdir");
        let path = dir.path().join("cache.ssz");
        let pubkey = generate_deterministic_keypair(0).pk.into();

        let mut file = File::create(&path).expect("should create file");
        append_to_file(&mut file, 0, &pubkey).expect("should write to file");
        drop(file);

        let cache = ValidatorPubkeyCache::<T>::load_from_file(&path).expect("should open cache");
        drop(cache);

        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&path)
            .expect("should open file");

        append_to_file(&mut file, 42, &pubkey).expect("should write bad data to file");
        drop(file);

        assert!(
            ValidatorPubkeyCache::<T>::load_from_file(&path).is_err(),
            "should not parse invalid file"
        );
    }
}

use crate::errors::BeaconChainError;
use ssz::{Decode, DecodeError, Encode};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use types::{BeaconState, EthSpec, PublicKey, PublicKeyBytes, Validator};

/// Provides a mapping of `validator_index -> validator_publickey`.
///
/// This cache exists for two reasons:
///
/// 1. To avoid reading a `BeaconState` from disk each time we need a public key.
/// 2. To reduce the amount of public key _decompression_ required. A `BeaconState` stores public
///    keys in compressed form and they are needed in decompressed form for signature verification.
///    Decompression is expensive when many keys are involved.
///
/// The cache has a `persistence_file` that it uses to maintain a persistent, on-disk
/// copy of itself. This allows it to be restored between process invocations.
pub struct ValidatorPubkeyCache {
    pubkeys: Vec<PublicKey>,
    indices: HashMap<PublicKeyBytes, usize>,
    persitence_file: ValidatorPubkeyCacheFile,
}

impl ValidatorPubkeyCache {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, BeaconChainError> {
        ValidatorPubkeyCacheFile::open(&path)
            .and_then(ValidatorPubkeyCacheFile::into_cache)
            .map_err(Into::into)
    }

    /// Create a new public key cache using the keys in `state.validators`.
    ///
    /// Also creates a new persistence file, returning an error if there is already a file at
    /// `persistence_path`.
    pub fn new<T: EthSpec, P: AsRef<Path>>(
        state: &BeaconState<T>,
        persistence_path: P,
    ) -> Result<Self, BeaconChainError> {
        if persistence_path.as_ref().exists() {
            return Err(BeaconChainError::ValidatorPubkeyCacheFileError(format!(
                "Persistence file already exists: {:?}",
                persistence_path.as_ref()
            )));
        }

        let mut cache = Self {
            persitence_file: ValidatorPubkeyCacheFile::create(persistence_path)?,
            pubkeys: vec![],
            indices: HashMap::new(),
        };

        cache.import_new_pubkeys(state)?;

        Ok(cache)
    }

    /// Scan the given `state` and add any new validator public keys.
    ///
    /// Does not delete any keys from `self` if they don't appear in `state`.
    pub fn import_new_pubkeys<T: EthSpec>(
        &mut self,
        state: &BeaconState<T>,
    ) -> Result<(), BeaconChainError> {
        if state.validators.len() > self.pubkeys.len() {
            self.import(&state.validators[self.pubkeys.len()..])
        } else {
            Ok(())
        }
    }

    /// Adds zero or more validators to `self`.
    fn import(&mut self, validators: &[Validator]) -> Result<(), BeaconChainError> {
        self.pubkeys.reserve(validators.len());
        self.indices.reserve(validators.len());

        for v in validators.iter() {
            let i = self.pubkeys.len();

            if self.indices.contains_key(&v.pubkey) {
                return Err(BeaconChainError::DuplicateValidatorPublicKey);
            }

            // The item is written to disk (the persistence file) _before_ it is written into
            // the local struct.
            //
            // This means that a pubkey cache read from disk will always be equivalent to or
            // _later than_ the cache that was running in the previous instance of Lighthouse.
            //
            // The motivation behind this ordering is that we do not want to have states that
            // reference a pubkey that is not in our cache. However, it's fine to have pubkeys
            // that are never referenced in a state.
            self.persitence_file.append(i, &v.pubkey)?;

            self.pubkeys.push(
                (&v.pubkey)
                    .try_into()
                    .map_err(BeaconChainError::InvalidValidatorPubkeyBytes)?,
            );

            self.indices.insert(v.pubkey.clone(), i);
        }

        Ok(())
    }

    /// Get the public key for a validator with index `i`.
    pub fn get(&self, i: usize) -> Option<&PublicKey> {
        self.pubkeys.get(i)
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
    IoError(io::Error),
    SszError(DecodeError),
    /// The file read from disk does not have a contiguous list of validator public keys. The file
    /// has become corrupted.
    InconsistentIndex {
        expected: Option<usize>,
        found: usize,
    },
}

impl From<Error> for BeaconChainError {
    fn from(e: Error) -> BeaconChainError {
        BeaconChainError::ValidatorPubkeyCacheFileError(format!("{:?}", e))
    }
}

impl ValidatorPubkeyCacheFile {
    /// Creates a file for reading and writing.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map(Self)
            .map_err(Error::IoError)
    }

    /// Opens an existing file for reading and writing.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .append(true)
            .open(path)
            .map(Self)
            .map_err(Error::IoError)
    }

    /// Append a public key to file.
    ///
    /// The provided `index` should each be one greater than the previous and start at 0.
    /// Otherwise, the file will become corrupted and unable to be converted into a cache .
    pub fn append(&mut self, index: usize, pubkey: &PublicKeyBytes) -> Result<(), Error> {
        append_to_file(&mut self.0, index, pubkey)
    }

    /// Creates a `ValidatorPubkeyCache` by reading and parsing the underlying file.
    pub fn into_cache(mut self) -> Result<ValidatorPubkeyCache, Error> {
        let mut bytes = vec![];
        self.0.read_to_end(&mut bytes).map_err(Error::IoError)?;

        let list: Vec<(usize, PublicKeyBytes)> =
            Vec::from_ssz_bytes(&bytes).map_err(Error::SszError)?;

        let mut last = None;
        let mut pubkeys = Vec::with_capacity(list.len());
        let mut indices = HashMap::new();

        for (index, pubkey) in list {
            let expected = last.map(|n| n + 1);
            if expected.map_or(true, |expected| index == expected) {
                last = Some(index);
                pubkeys.push((&pubkey).try_into().map_err(Error::SszError)?);
                indices.insert(pubkey, index);
            } else {
                return Err(Error::InconsistentIndex {
                    expected,
                    found: index,
                });
            }
        }

        Ok(ValidatorPubkeyCache {
            pubkeys,
            indices,
            persitence_file: self,
        })
    }
}

fn append_to_file(file: &mut File, index: usize, pubkey: &PublicKeyBytes) -> Result<(), Error> {
    let mut line = Vec::with_capacity(index.ssz_bytes_len() + pubkey.ssz_bytes_len());

    index.ssz_append(&mut line);
    pubkey.ssz_append(&mut line);

    file.write_all(&mut line).map_err(Error::IoError)
}

#[cfg(test)]
mod test {
    use super::*;
    use tempfile::tempdir;
    use types::{
        test_utils::{generate_deterministic_keypair, TestingBeaconStateBuilder},
        BeaconState, EthSpec, Keypair, MainnetEthSpec,
    };

    fn get_state(validator_count: usize) -> (BeaconState<MainnetEthSpec>, Vec<Keypair>) {
        let spec = MainnetEthSpec::default_spec();
        let builder =
            TestingBeaconStateBuilder::from_deterministic_keypairs(validator_count, &spec);
        builder.build()
    }

    fn check_cache_get(cache: &ValidatorPubkeyCache, keypairs: &[Keypair]) {
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

        let dir = tempdir().expect("should create tempdir");
        let path = dir.path().join("cache.ssz");

        let mut cache = ValidatorPubkeyCache::new(&state, path).expect("should create cache");

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

        let dir = tempdir().expect("should create tempdir");
        let path = dir.path().join("cache.ssz");

        // Create a new cache.
        let cache = ValidatorPubkeyCache::new(&state, &path).expect("should create cache");
        check_cache_get(&cache, &keypairs[..]);
        drop(cache);

        // Re-init the cache from the file.
        let mut cache = ValidatorPubkeyCache::load_from_file(&path).expect("should open cache");
        check_cache_get(&cache, &keypairs[..]);

        // Add some more keypairs.
        let (state, keypairs) = get_state(12);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        check_cache_get(&cache, &keypairs[..]);
        drop(cache);

        // Re-init the cache from the file.
        let cache = ValidatorPubkeyCache::load_from_file(&path).expect("should open cache");
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

        let cache = ValidatorPubkeyCache::load_from_file(&path).expect("should open cache");
        drop(cache);

        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&path)
            .expect("should open file");

        append_to_file(&mut file, 42, &pubkey).expect("should write bad data to file");
        drop(file);

        assert!(
            ValidatorPubkeyCache::load_from_file(&path).is_err(),
            "should not parse invalid file"
        );
    }
}

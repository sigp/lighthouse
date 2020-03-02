use crate::errors::BeaconChainError;
use ssz::{Decode, DecodeError, Encode};
use std::convert::TryInto;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use types::{BeaconState, EthSpec, PublicKey, PublicKeyBytes};

/// Provides a mapping of `validator_index -> validator_publickey`.
///
/// This cache exists for two reasons:
///
/// 1. To avoid reading a `BeaconState` from disk each time we need a public key.
/// 2. To reduce the amount of public key _decompression_ required. A `BeaconState` stores public
///    keys in compressed form and they are needed in decompressed form for signature verification.
///    Decompression is expensive when may keys are involved.
///
/// The cache has a `persistence_file` that it uses to maintain a persistent, on-disk copy of
/// itself. This allows it to be restored between process invocations.
pub struct ValidatorPubkeyCache {
    pubkeys: Vec<PublicKey>,
    persitence_file: ValidatorPubkeyCacheFile,
}

impl ValidatorPubkeyCache {
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

        Ok(Self {
            persitence_file: ValidatorPubkeyCacheFile::load(persistence_path)
                .map_err(|e| format!("PubkeyCacheFileError: {:?}", e))
                .map_err(BeaconChainError::ValidatorPubkeyCacheFileError)?,
            pubkeys: state
                .validators
                .iter()
                .map(|v| {
                    (&v.pubkey)
                        .try_into()
                        .map_err(BeaconChainError::InvalidValidatorPubkeyBytes)
                })
                .collect::<Result<Vec<_>, BeaconChainError>>()?,
        })
    }

    /// Scan the given `state` and add any new validator public keys.
    ///
    /// Does not delete any keys from `self` if they don't appear in `state`.
    pub fn import_new_pubkeys<T: EthSpec>(
        &mut self,
        state: &BeaconState<T>,
    ) -> Result<(), BeaconChainError> {
        state
            .validators
            .iter()
            .skip(self.pubkeys.len())
            .try_for_each(|v| {
                let i = self.pubkeys.len();

                // The item is written to disk (the persistence file) _before_ it is written into
                // the local struct.
                //
                // This means that a pubkey cache read from disk will always be equivalent to or
                // _later than_ the cache that was running in the previous instance of Lighthouse.
                //
                // The motivation behind this ordering is that we do not want to have states that
                // reference a pubkey that is not in our cache. However, it's fine to have pubkeys
                // that are never referenced in a state.

                self.persitence_file
                    .append(i, &v.pubkey)
                    .map_err(|e| format!("PubkeyCacheFileError: {:?}", e))
                    .map_err(BeaconChainError::ValidatorPubkeyCacheFileError)?;

                self.pubkeys.push(
                    (&v.pubkey)
                        .try_into()
                        .map_err(BeaconChainError::InvalidValidatorPubkeyBytes)?,
                );
                Ok(())
            })
    }

    /// Get the public key for a validator with index `i`.
    pub fn get(&self, i: usize) -> Option<&PublicKey> {
        self.pubkeys.get(i)
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
/// This parsing method is possible because the items in the list are fixed-length SSZ objects).
pub struct ValidatorPubkeyCacheFile(File);

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    SszError(DecodeError),
    /// The file read from disk does not have a contiguous list of validator public keys. The file
    /// has become corrupted.
    InconsistentIndex {
        expected: Option<usize>,
        found: usize,
    },
}

impl ValidatorPubkeyCacheFile {
    /// Open the underlying file for reading and writing.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        File::open(path).map(Self).map_err(Error::IoError)
    }

    /// Append a public key to file.
    ///
    /// The provided `index` should each be one greater than the previous and start at 0.
    /// Otherwise, the file will become corrupted and unable to be converted into a cache .
    pub fn append(&mut self, index: usize, pubkey: &PublicKeyBytes) -> Result<(), Error> {
        let mut line = (index, pubkey.as_bytes()).as_ssz_bytes();
        self.0.write_all(&mut line).map_err(Error::IoError)
    }

    /// Creates a `ValidatorPubkeyCache` by reading and parsing the underlying file.
    pub fn into_cache(mut self) -> Result<ValidatorPubkeyCache, Error> {
        let mut bytes = vec![];
        self.0.read_to_end(&mut bytes).map_err(Error::IoError)?;

        let list: Vec<(usize, PublicKeyBytes)> =
            Vec::from_ssz_bytes(&bytes).map_err(Error::SszError)?;

        let mut last = None;
        let mut pubkeys = Vec::with_capacity(list.len());

        for (index, pubkey) in list {
            let expected = last.map(|n| n + 1);

            if expected.map_or(true, |expected| index == expected) {
                last = Some(index);
                pubkeys.push((&pubkey).try_into().map_err(Error::SszError)?);
            } else {
                return Err(Error::InconsistentIndex {
                    expected,
                    found: index,
                });
            }
        }

        Ok(ValidatorPubkeyCache {
            pubkeys,
            persitence_file: self,
        })
    }
}

use super::*;
use crate::case_result::compare_result;
use crate::cases::common::SszStaticType;
use crate::decode::{snappy_decode_file, yaml_decode_file};
use serde_derive::Deserialize;
use ssz::Decode;
use tree_hash::TreeHash;
use types::{BeaconBlock, BeaconState, ForkName, Hash256, SignedBeaconBlock};

#[derive(Debug, Clone, Deserialize)]
struct SszStaticRoots {
    root: String,
    signing_root: Option<String>,
}

/// Runner for types that implement `ssz::Decode`.
#[derive(Debug, Clone)]
pub struct SszStatic<T> {
    roots: SszStaticRoots,
    serialized: Vec<u8>,
    value: T,
}

/// Runner for `BeaconState` (with tree hash cache).
#[derive(Debug, Clone)]
pub struct SszStaticTHC<T> {
    roots: SszStaticRoots,
    serialized: Vec<u8>,
    value: T,
}

/// Runner for types that require a `ChainSpec` to be decoded (`BeaconBlock`, etc).
#[derive(Debug, Clone)]
pub struct SszStaticWithSpec<T> {
    roots: SszStaticRoots,
    serialized: Vec<u8>,
    value: T,
}

fn load_from_dir<T: SszStaticType>(path: &Path) -> Result<(SszStaticRoots, Vec<u8>, T), Error> {
    let roots = yaml_decode_file(&path.join("roots.yaml"))?;
    let serialized = snappy_decode_file(&path.join("serialized.ssz_snappy"))
        .expect("serialized.ssz_snappy exists");
    let value = yaml_decode_file(&path.join("value.yaml"))?;

    Ok((roots, serialized, value))
}

impl<T: SszStaticType> LoadCase for SszStatic<T> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        load_from_dir(path).map(|(roots, serialized, value)| Self {
            roots,
            serialized,
            value,
        })
    }
}

impl<T: SszStaticType> LoadCase for SszStaticTHC<T> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        load_from_dir(path).map(|(roots, serialized, value)| Self {
            roots,
            serialized,
            value,
        })
    }
}

impl<T: SszStaticType> LoadCase for SszStaticWithSpec<T> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        load_from_dir(path).map(|(roots, serialized, value)| Self {
            roots,
            serialized,
            value,
        })
    }
}

pub fn check_serialization<T: SszStaticType>(
    value: &T,
    serialized: &[u8],
    deserializer: impl FnOnce(&[u8]) -> Result<T, ssz::DecodeError>,
) -> Result<(), Error> {
    // Check serialization
    let serialized_result = value.as_ssz_bytes();
    compare_result::<usize, Error>(&Ok(value.ssz_bytes_len()), &Some(serialized.len()))?;
    compare_result::<Vec<u8>, Error>(&Ok(serialized_result), &Some(serialized.to_vec()))?;

    // Check deserialization
    let deserialized_result = deserializer(serialized);
    compare_result(&deserialized_result, &Some(value.clone()))?;

    Ok(())
}

pub fn check_tree_hash(expected_str: &str, actual_root: &[u8]) -> Result<(), Error> {
    let expected_root = hex::decode(&expected_str[2..])
        .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let expected_root = Hash256::from_slice(&expected_root);
    let tree_hash_root = Hash256::from_slice(actual_root);
    compare_result::<Hash256, Error>(&Ok(tree_hash_root), &Some(expected_root))
}

impl<T: SszStaticType + Decode> Case for SszStatic<T> {
    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        check_serialization(&self.value, &self.serialized, T::from_ssz_bytes)?;
        check_tree_hash(&self.roots.root, self.value.tree_hash_root().as_bytes())?;
        Ok(())
    }
}

impl<E: EthSpec> Case for SszStaticTHC<BeaconState<E>> {
    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let spec = &testing_spec::<E>(fork_name);
        check_serialization(&self.value, &self.serialized, |bytes| {
            BeaconState::from_ssz_bytes(bytes, spec)
        })?;
        check_tree_hash(&self.roots.root, self.value.tree_hash_root().as_bytes())?;

        let mut state = self.value.clone();
        state.initialize_tree_hash_cache();
        let cached_tree_hash_root = state.update_tree_hash_cache().unwrap();
        check_tree_hash(&self.roots.root, cached_tree_hash_root.as_bytes())?;

        Ok(())
    }
}

impl<E: EthSpec> Case for SszStaticWithSpec<BeaconBlock<E>> {
    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let spec = &testing_spec::<E>(fork_name);
        check_serialization(&self.value, &self.serialized, |bytes| {
            BeaconBlock::from_ssz_bytes(bytes, spec)
        })?;
        check_tree_hash(&self.roots.root, self.value.tree_hash_root().as_bytes())?;
        Ok(())
    }
}

impl<E: EthSpec> Case for SszStaticWithSpec<SignedBeaconBlock<E>> {
    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let spec = &testing_spec::<E>(fork_name);
        check_serialization(&self.value, &self.serialized, |bytes| {
            SignedBeaconBlock::from_ssz_bytes(bytes, spec)
        })?;
        check_tree_hash(&self.roots.root, self.value.tree_hash_root().as_bytes())?;
        Ok(())
    }
}

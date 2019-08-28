use super::*;
use crate::case_result::compare_result;
use serde_derive::Deserialize;
use ssz::{Decode, Encode};
use std::fmt::Debug;
use std::fs;
use tree_hash::{SignedRoot, TreeHash};
use types::Hash256;

#[derive(Debug, Clone, Deserialize)]
struct SszStaticRoots {
    root: String,
    signing_root: Option<String>,
}

impl YamlDecode for SszStaticRoots {
    fn yaml_decode(yaml: &str) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(yaml).unwrap())
    }
}

#[derive(Debug, Clone)]
pub struct SszStatic<T> {
    roots: SszStaticRoots,
    serialized: Vec<u8>,
    value: T,
}

#[derive(Debug, Clone)]
pub struct SszStaticSR<T> {
    roots: SszStaticRoots,
    serialized: Vec<u8>,
    value: T,
}

// Trait alias for all deez bounds
pub trait SszStaticType:
    serde::de::DeserializeOwned + Decode + Encode + TreeHash + Clone + PartialEq + Debug
{
}

impl<T> SszStaticType for T where
    T: serde::de::DeserializeOwned + Decode + Encode + TreeHash + Clone + PartialEq + Debug
{
}

fn load_from_dir<T: SszStaticType>(path: &Path) -> Result<(SszStaticRoots, Vec<u8>, T), Error> {
    // FIXME: set description/name
    let roots = SszStaticRoots::yaml_decode_file(&path.join("roots.yaml"))?;

    let serialized = fs::read(&path.join("serialized.ssz")).expect("serialized.ssz exists");

    let yaml = fs::read_to_string(&path.join("value.yaml")).expect("value.yaml exists");
    let value =
        serde_yaml::from_str(&yaml).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

    Ok((roots, serialized, value))
}

impl<T: SszStaticType> LoadCase for SszStatic<T> {
    fn load_from_dir(path: &Path) -> Result<Self, Error> {
        load_from_dir(path).map(|(roots, serialized, value)| Self {
            roots,
            serialized,
            value,
        })
    }
}

impl<T: SszStaticType + SignedRoot> LoadCase for SszStaticSR<T> {
    fn load_from_dir(path: &Path) -> Result<Self, Error> {
        load_from_dir(path).map(|(roots, serialized, value)| Self {
            roots,
            serialized,
            value,
        })
    }
}

fn check_serialization<T: SszStaticType>(value: &T, serialized: &[u8]) -> Result<(), Error> {
    // Check serialization
    let serialized_result = value.as_ssz_bytes();
    compare_result::<Vec<u8>, Error>(&Ok(serialized_result), &Some(serialized.to_vec()))?;

    // Check deserialization
    let deserialized_result = T::from_ssz_bytes(serialized);
    compare_result(&deserialized_result, &Some(value.clone()))?;

    Ok(())
}

fn check_tree_hash(expected_str: &str, actual_root: Vec<u8>) -> Result<(), Error> {
    let expected_root = hex::decode(&expected_str[2..])
        .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let expected_root = Hash256::from_slice(&expected_root);
    let tree_hash_root = Hash256::from_slice(&actual_root);
    compare_result::<Hash256, Error>(&Ok(tree_hash_root), &Some(expected_root))
}

impl<T: SszStaticType> Case for SszStatic<T> {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        check_serialization(&self.value, &self.serialized)?;
        check_tree_hash(&self.roots.root, self.value.tree_hash_root())?;
        Ok(())
    }
}

impl<T: SszStaticType + SignedRoot> Case for SszStaticSR<T> {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        check_serialization(&self.value, &self.serialized)?;
        check_tree_hash(&self.roots.root, self.value.tree_hash_root())?;
        check_tree_hash(
            &self
                .roots
                .signing_root
                .as_ref()
                .expect("signed root exists"),
            self.value.signed_root(),
        )?;
        Ok(())
    }
}

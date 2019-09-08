use super::*;
use crate::case_result::compare_result;
use crate::cases::common::SszStaticType;
use crate::decode::yaml_decode_file;
use serde_derive::Deserialize;
use std::fs;
use tree_hash::SignedRoot;
use types::Hash256;

#[derive(Debug, Clone, Deserialize)]
struct SszStaticRoots {
    root: String,
    signing_root: Option<String>,
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

fn load_from_dir<T: SszStaticType>(path: &Path) -> Result<(SszStaticRoots, Vec<u8>, T), Error> {
    let roots = yaml_decode_file(&path.join("roots.yaml"))?;
    let serialized = fs::read(&path.join("serialized.ssz")).expect("serialized.ssz exists");
    let value = yaml_decode_file(&path.join("value.yaml"))?;

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

pub fn check_serialization<T: SszStaticType>(value: &T, serialized: &[u8]) -> Result<(), Error> {
    // Check serialization
    let serialized_result = value.as_ssz_bytes();
    compare_result::<usize, Error>(&Ok(value.ssz_bytes_len()), &Some(serialized.len()))?;
    compare_result::<Vec<u8>, Error>(&Ok(serialized_result), &Some(serialized.to_vec()))?;

    // Check deserialization
    let deserialized_result = T::from_ssz_bytes(serialized);
    compare_result(&deserialized_result, &Some(value.clone()))?;

    Ok(())
}

pub fn check_tree_hash(expected_str: &str, actual_root: Vec<u8>) -> Result<(), Error> {
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

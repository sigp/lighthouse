use crate::test_utils::{RngCore, TestRandom};
use serde_derive::{Deserialize, Serialize};
use ssz::{Decodable, DecodeError, Encodable, SszStream};
use std::ops::{Deref, DerefMut};
use tree_hash::TreeHash;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct TreeHashVector<T>(Vec<T>);

impl<T> From<Vec<T>> for TreeHashVector<T> {
    fn from(vec: Vec<T>) -> TreeHashVector<T> {
        TreeHashVector(vec)
    }
}

impl<T> Into<Vec<T>> for TreeHashVector<T> {
    fn into(self) -> Vec<T> {
        self.0
    }
}

impl<T> Deref for TreeHashVector<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Vec<T> {
        &self.0
    }
}

impl<T> DerefMut for TreeHashVector<T> {
    fn deref_mut(&mut self) -> &mut Vec<T> {
        &mut self.0
    }
}

impl<T> tree_hash::TreeHash for TreeHashVector<T>
where
    T: TreeHash,
{
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        tree_hash::standard_tree_hash::vec_tree_hash_root(self)
    }
}

impl<T> Encodable for TreeHashVector<T>
where
    T: Encodable,
{
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(self)
    }
}

impl<T> Decodable for TreeHashVector<T>
where
    T: Decodable,
{
    fn ssz_decode(bytes: &[u8], index: usize) -> Result<(Self, usize), DecodeError> {
        ssz::decode_ssz_list(bytes, index).and_then(|(vec, i)| Ok((vec.into(), i)))
    }
}

impl<T: RngCore, U> TestRandom<T> for TreeHashVector<U>
where
    U: TestRandom<T>,
{
    fn random_for_test(rng: &mut T) -> Self {
        Vec::random_for_test(rng).into()
    }
}

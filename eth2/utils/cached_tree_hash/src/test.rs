use crate::impls::hash256_iter;
use crate::{CachedTreeHash, Error, Hash256, TreeHashCache};
use eth2_hashing::ZERO_HASHES;
use quickcheck_macros::quickcheck;
use ssz_types::{
    typenum::{Unsigned, U16, U255, U256, U257},
    FixedVector, VariableList,
};
use tree_hash::TreeHash;

fn int_hashes(start: u64, end: u64) -> Vec<Hash256> {
    (start..end).map(Hash256::from_low_u64_le).collect()
}

type List16 = VariableList<Hash256, U16>;
type Vector16 = FixedVector<Hash256, U16>;
type Vector16u64 = FixedVector<u64, U16>;

#[test]
fn max_leaves() {
    let depth = 4;
    let max_len = 2u64.pow(depth as u32);
    let mut cache = TreeHashCache::new(depth);
    assert!(cache
        .recalculate_merkle_root(hash256_iter(&int_hashes(0, max_len - 1)))
        .is_ok());
    assert!(cache
        .recalculate_merkle_root(hash256_iter(&int_hashes(0, max_len)))
        .is_ok());
    assert_eq!(
        cache.recalculate_merkle_root(hash256_iter(&int_hashes(0, max_len + 1))),
        Err(Error::TooManyLeaves)
    );
    assert_eq!(
        cache.recalculate_merkle_root(hash256_iter(&int_hashes(0, max_len * 2))),
        Err(Error::TooManyLeaves)
    );
}

#[test]
fn cannot_shrink() {
    let init_len = 12;
    let list1 = List16::new(int_hashes(0, init_len)).unwrap();
    let list2 = List16::new(int_hashes(0, init_len - 1)).unwrap();

    let mut cache = List16::new_tree_hash_cache();
    assert!(list1.recalculate_tree_hash_root(&mut cache).is_ok());
    assert_eq!(
        list2.recalculate_tree_hash_root(&mut cache),
        Err(Error::CannotShrink)
    );
}

#[test]
fn empty_leaves() {
    let depth = 20;
    let mut cache = TreeHashCache::new(depth);
    assert_eq!(
        cache
            .recalculate_merkle_root(vec![].into_iter())
            .unwrap()
            .as_bytes(),
        &ZERO_HASHES[depth][..]
    );
}

#[test]
fn fixed_vector_hash256() {
    let len = 16;
    let vec = Vector16::new(int_hashes(0, len)).unwrap();

    let mut cache = Vector16::new_tree_hash_cache();

    assert_eq!(
        Hash256::from_slice(&vec.tree_hash_root()),
        vec.recalculate_tree_hash_root(&mut cache).unwrap()
    );
}

#[test]
fn fixed_vector_u64() {
    let len = 16;
    let vec = Vector16u64::new((0..len).collect()).unwrap();

    let mut cache = Vector16u64::new_tree_hash_cache();

    assert_eq!(
        Hash256::from_slice(&vec.tree_hash_root()),
        vec.recalculate_tree_hash_root(&mut cache).unwrap()
    );
}

#[test]
fn variable_list_hash256() {
    let len = 13;
    let list = List16::new(int_hashes(0, len)).unwrap();

    let mut cache = List16::new_tree_hash_cache();

    assert_eq!(
        Hash256::from_slice(&list.tree_hash_root()),
        list.recalculate_tree_hash_root(&mut cache).unwrap()
    );
}

#[quickcheck]
fn quickcheck_variable_list_h256_256(leaves_and_skips: Vec<(u64, bool)>) -> bool {
    variable_list_h256_test::<U256>(leaves_and_skips)
}

#[quickcheck]
fn quickcheck_variable_list_h256_255(leaves_and_skips: Vec<(u64, bool)>) -> bool {
    variable_list_h256_test::<U255>(leaves_and_skips)
}

#[quickcheck]
fn quickcheck_variable_list_h256_257(leaves_and_skips: Vec<(u64, bool)>) -> bool {
    variable_list_h256_test::<U257>(leaves_and_skips)
}

fn variable_list_h256_test<Len: Unsigned>(leaves_and_skips: Vec<(u64, bool)>) -> bool {
    let leaves: Vec<_> = leaves_and_skips
        .iter()
        .map(|(l, _)| Hash256::from_low_u64_be(*l))
        .take(Len::to_usize())
        .collect();

    let mut list: VariableList<Hash256, Len>;
    let mut cache = VariableList::<Hash256, Len>::new_tree_hash_cache();

    for (end, (_, update_cache)) in leaves_and_skips.into_iter().enumerate() {
        list = VariableList::new(leaves[..end].to_vec()).unwrap();

        if update_cache
            && list
                .recalculate_tree_hash_root(&mut cache)
                .unwrap()
                .as_bytes()
                != &list.tree_hash_root()[..]
        {
            return false;
        }
    }
    true
}

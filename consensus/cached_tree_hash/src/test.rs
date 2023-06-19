use crate::impls::hash256_iter;
use crate::{CacheArena, CachedTreeHash, Error, Hash256, TreeHashCache};
use ethereum_hashing::ZERO_HASHES;
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
    let arena = &mut CacheArena::default();
    let depth = 4;
    let max_len = 2u64.pow(depth as u32);
    let mut cache = TreeHashCache::new(arena, depth, 2);
    assert!(cache
        .recalculate_merkle_root(arena, hash256_iter(&int_hashes(0, max_len - 1)))
        .is_ok());
    assert!(cache
        .recalculate_merkle_root(arena, hash256_iter(&int_hashes(0, max_len)))
        .is_ok());
    assert_eq!(
        cache.recalculate_merkle_root(arena, hash256_iter(&int_hashes(0, max_len + 1))),
        Err(Error::TooManyLeaves)
    );
    assert_eq!(
        cache.recalculate_merkle_root(arena, hash256_iter(&int_hashes(0, max_len * 2))),
        Err(Error::TooManyLeaves)
    );
}

#[test]
fn cannot_shrink() {
    let arena = &mut CacheArena::default();
    let init_len = 12;
    let list1 = List16::new(int_hashes(0, init_len)).unwrap();
    let list2 = List16::new(int_hashes(0, init_len - 1)).unwrap();

    let mut cache = list1.new_tree_hash_cache(arena);
    assert!(list1.recalculate_tree_hash_root(arena, &mut cache).is_ok());
    assert_eq!(
        list2.recalculate_tree_hash_root(arena, &mut cache),
        Err(Error::CannotShrink)
    );
}

#[test]
fn empty_leaves() {
    let arena = &mut CacheArena::default();
    let depth = 20;
    let mut cache = TreeHashCache::new(arena, depth, 0);
    assert_eq!(
        cache
            .recalculate_merkle_root(arena, vec![].into_iter())
            .unwrap()
            .as_bytes(),
        &ZERO_HASHES[depth][..]
    );
}

#[test]
fn fixed_vector_hash256() {
    let arena = &mut CacheArena::default();
    let len = 16;
    let vec = Vector16::new(int_hashes(0, len)).unwrap();

    let mut cache = vec.new_tree_hash_cache(arena);

    assert_eq!(
        vec.tree_hash_root(),
        vec.recalculate_tree_hash_root(arena, &mut cache).unwrap()
    );
}

#[test]
fn fixed_vector_u64() {
    let arena = &mut CacheArena::default();
    let len = 16;
    let vec = Vector16u64::new((0..len).collect()).unwrap();

    let mut cache = vec.new_tree_hash_cache(arena);

    assert_eq!(
        vec.tree_hash_root(),
        vec.recalculate_tree_hash_root(arena, &mut cache).unwrap()
    );
}

#[test]
fn variable_list_hash256() {
    let arena = &mut CacheArena::default();
    let len = 13;
    let list = List16::new(int_hashes(0, len)).unwrap();

    let mut cache = list.new_tree_hash_cache(arena);

    assert_eq!(
        list.tree_hash_root(),
        list.recalculate_tree_hash_root(arena, &mut cache).unwrap()
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
    let arena = &mut CacheArena::default();
    let leaves: Vec<_> = leaves_and_skips
        .iter()
        .map(|(l, _)| Hash256::from_low_u64_be(*l))
        .take(Len::to_usize())
        .collect();

    let mut list: VariableList<Hash256, Len>;
    let init: VariableList<Hash256, Len> = VariableList::new(vec![]).unwrap();
    let mut cache = init.new_tree_hash_cache(arena);

    for (end, (_, update_cache)) in leaves_and_skips.into_iter().enumerate() {
        list = VariableList::new(leaves[..end].to_vec()).unwrap();

        if update_cache
            && list
                .recalculate_tree_hash_root(arena, &mut cache)
                .unwrap()
                .as_bytes()
                != &list.tree_hash_root()[..]
        {
            return false;
        }
    }
    true
}

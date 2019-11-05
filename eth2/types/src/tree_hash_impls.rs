//! This module contains custom implementations of `CachedTreeHash` for ETH2-specific types.
//!
//! It makes some assumptions about the layouts and update patterns of other structs in this
//! crate, and should be updated carefully whenever those structs are changed.
use crate::{Hash256, Validator};
use cached_tree_hash::{int_log, CachedTreeHash, Error, TreeHashCache};
use tree_hash::TreeHash;

/// Number of struct fields on `Validator`.
const NUM_VALIDATOR_FIELDS: usize = 8;

impl CachedTreeHash<TreeHashCache> for Validator {
    fn new_tree_hash_cache() -> TreeHashCache {
        TreeHashCache::new(int_log(NUM_VALIDATOR_FIELDS))
    }

    /// Efficiently tree hash a `Validator`, assuming it was updated by a valid state transition.
    ///
    /// Specifically, we assume that the `pubkey` and `withdrawal_credentials` fields are constant.
    fn recalculate_tree_hash_root(&self, cache: &mut TreeHashCache) -> Result<Hash256, Error> {
        // If the cache is empty, hash every field to fill it.
        if cache.leaves().is_empty() {
            return cache.recalculate_merkle_root(field_tree_hash_iter(self));
        }

        // Otherwise just check the fields which might have changed.
        let dirty_indices = cache
            .leaves()
            .iter_mut()
            .enumerate()
            .flat_map(|(i, leaf)| {
                // Fields pubkey and withdrawal_credentials are constant
                if i == 0 || i == 1 {
                    None
                } else {
                    let new_tree_hash = field_tree_hash_by_index(self, i);
                    if leaf.as_bytes() != &new_tree_hash[..] {
                        leaf.assign_from_slice(&new_tree_hash);
                        Some(i)
                    } else {
                        None
                    }
                }
            })
            .collect();

        cache.update_merkle_root(dirty_indices)
    }
}

/// Get the tree hash root of a validator field by its position/index in the struct.
fn field_tree_hash_by_index(v: &Validator, field_idx: usize) -> Vec<u8> {
    match field_idx {
        0 => v.pubkey.tree_hash_root(),
        1 => v.withdrawal_credentials.tree_hash_root(),
        2 => v.effective_balance.tree_hash_root(),
        3 => v.slashed.tree_hash_root(),
        4 => v.activation_eligibility_epoch.tree_hash_root(),
        5 => v.activation_epoch.tree_hash_root(),
        6 => v.exit_epoch.tree_hash_root(),
        7 => v.withdrawable_epoch.tree_hash_root(),
        _ => panic!(
            "Validator type only has {} fields, {} out of bounds",
            NUM_VALIDATOR_FIELDS, field_idx
        ),
    }
}

/// Iterator over the tree hash roots of `Validator` fields.
fn field_tree_hash_iter<'a>(
    v: &'a Validator,
) -> impl Iterator<Item = [u8; 32]> + ExactSizeIterator + 'a {
    (0..NUM_VALIDATOR_FIELDS)
        .map(move |i| field_tree_hash_by_index(v, i))
        .map(|tree_hash_root| {
            let mut res = [0; 32];
            res.copy_from_slice(&tree_hash_root[0..32]);
            res
        })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::TestRandom;
    use crate::Epoch;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    fn test_validator_tree_hash(v: &Validator) {
        let mut cache = Validator::new_tree_hash_cache();
        // With a fresh cache
        assert_eq!(
            &v.tree_hash_root()[..],
            v.recalculate_tree_hash_root(&mut cache).unwrap().as_bytes(),
            "{:?}",
            v
        );
        // With a completely up-to-date cache
        assert_eq!(
            &v.tree_hash_root()[..],
            v.recalculate_tree_hash_root(&mut cache).unwrap().as_bytes(),
            "{:?}",
            v
        );
    }

    #[test]
    fn default_validator() {
        test_validator_tree_hash(&Validator::default());
    }

    #[test]
    fn zeroed_validator() {
        let mut v = Validator::default();
        v.activation_eligibility_epoch = Epoch::from(0u64);
        v.activation_epoch = Epoch::from(0u64);
        test_validator_tree_hash(&v);
    }

    #[test]
    fn random_validators() {
        let mut rng = XorShiftRng::from_seed([0xf1; 16]);
        let num_validators = 1000;
        (0..num_validators)
            .map(|_| Validator::random_for_test(&mut rng))
            .for_each(|v| test_validator_tree_hash(&v));
    }
}

//! This module contains custom implementations of `CachedTreeHash` for ETH2-specific types.
//!
//! It makes some assumptions about the layouts and update patterns of other structs in this
//! crate, and should be updated carefully whenever those structs are changed.
use crate::{Epoch, Hash256, PublicKeyBytes, Validator};
use cached_tree_hash::{int_log, CacheArena, CachedTreeHash, Error, TreeHashCache};
use int_to_bytes::int_to_fixed_bytes32;
use tree_hash::merkle_root;

/// Number of struct fields on `Validator`.
const NUM_VALIDATOR_FIELDS: usize = 8;

impl CachedTreeHash<TreeHashCache> for Validator {
    fn new_tree_hash_cache(&self, arena: &mut CacheArena) -> TreeHashCache {
        TreeHashCache::new(arena, int_log(NUM_VALIDATOR_FIELDS), NUM_VALIDATOR_FIELDS)
    }

    /// Efficiently tree hash a `Validator`, assuming it was updated by a valid state transition.
    ///
    /// Specifically, we assume that the `pubkey` and `withdrawal_credentials` fields are constant.
    fn recalculate_tree_hash_root(
        &self,
        arena: &mut CacheArena,
        cache: &mut TreeHashCache,
    ) -> Result<Hash256, Error> {
        // Otherwise just check the fields which might have changed.
        let dirty_indices = cache
            .leaves()
            .iter_mut(arena)?
            .enumerate()
            .flat_map(|(i, leaf)| {
                // Fields pubkey and withdrawal_credentials are constant
                if (i == 0 || i == 1) && cache.initialized {
                    None
                } else if process_field_by_index(self, i, leaf, !cache.initialized) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();

        cache.update_merkle_root(arena, dirty_indices)
    }
}

fn process_field_by_index(
    v: &Validator,
    field_idx: usize,
    leaf: &mut Hash256,
    force_update: bool,
) -> bool {
    match field_idx {
        0 => process_pubkey_bytes_field(&v.pubkey, leaf, force_update),
        1 => process_slice_field(v.withdrawal_credentials.as_bytes(), leaf, force_update),
        2 => process_u64_field(v.effective_balance, leaf, force_update),
        3 => process_bool_field(v.slashed, leaf, force_update),
        4 => process_epoch_field(v.activation_eligibility_epoch, leaf, force_update),
        5 => process_epoch_field(v.activation_epoch, leaf, force_update),
        6 => process_epoch_field(v.exit_epoch, leaf, force_update),
        7 => process_epoch_field(v.withdrawable_epoch, leaf, force_update),
        _ => panic!(
            "Validator type only has {} fields, {} out of bounds",
            NUM_VALIDATOR_FIELDS, field_idx
        ),
    }
}

fn process_pubkey_bytes_field(
    val: &PublicKeyBytes,
    leaf: &mut Hash256,
    force_update: bool,
) -> bool {
    let new_tree_hash = merkle_root(val.as_serialized(), 0);
    process_slice_field(new_tree_hash.as_bytes(), leaf, force_update)
}

fn process_slice_field(new_tree_hash: &[u8], leaf: &mut Hash256, force_update: bool) -> bool {
    if force_update || leaf.as_bytes() != new_tree_hash {
        leaf.assign_from_slice(new_tree_hash);
        true
    } else {
        false
    }
}

fn process_u64_field(val: u64, leaf: &mut Hash256, force_update: bool) -> bool {
    let new_tree_hash = int_to_fixed_bytes32(val);
    process_slice_field(&new_tree_hash[..], leaf, force_update)
}

fn process_epoch_field(val: Epoch, leaf: &mut Hash256, force_update: bool) -> bool {
    process_u64_field(val.as_u64(), leaf, force_update)
}

fn process_bool_field(val: bool, leaf: &mut Hash256, force_update: bool) -> bool {
    process_u64_field(val as u64, leaf, force_update)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::TestRandom;
    use crate::Epoch;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use tree_hash::TreeHash;

    fn test_validator_tree_hash(v: &Validator) {
        let arena = &mut CacheArena::default();

        let mut cache = v.new_tree_hash_cache(arena);
        // With a fresh cache
        assert_eq!(
            &v.tree_hash_root()[..],
            v.recalculate_tree_hash_root(arena, &mut cache)
                .unwrap()
                .as_bytes(),
            "{:?}",
            v
        );
        // With a completely up-to-date cache
        assert_eq!(
            &v.tree_hash_root()[..],
            v.recalculate_tree_hash_root(arena, &mut cache)
                .unwrap()
                .as_bytes(),
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
        let v = Validator {
            activation_eligibility_epoch: Epoch::from(0u64),
            activation_epoch: Epoch::from(0u64),
            ..Default::default()
        };
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

    #[test]
    #[allow(clippy::assertions_on_constants)]
    pub fn smallvec_size_check() {
        // If this test fails we need to go and reassess the length of the `SmallVec` in
        // `cached_tree_hash::TreeHashCache`. If the size of the `SmallVec` is too slow we're going
        // to start doing heap allocations for each validator, this will fragment memory and slow
        // us down.
        assert!(NUM_VALIDATOR_FIELDS <= 8,);
    }
}

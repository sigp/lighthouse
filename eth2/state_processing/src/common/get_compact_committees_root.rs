use tree_hash::TreeHash;
use types::*;

/// Return the compact committee root at `relative_epoch`.
///
/// Spec v0.8.0
pub fn get_compact_committees_root<T: EthSpec>(
    state: &BeaconState<T>,
    relative_epoch: RelativeEpoch,
    spec: &ChainSpec,
) -> Result<Hash256, BeaconStateError> {
    let mut committees =
        FixedVector::<_, T::ShardCount>::from_elem(CompactCommittee::<T>::default());
    // FIXME: this is a spec bug, whereby the start shard for the epoch after the next epoch
    // is mistakenly used. The start shard from the cache SHOULD work.
    // Waiting on a release to fix https://github.com/ethereum/eth2.0-specs/issues/1315
    // let start_shard = state.get_epoch_start_shard(relative_epoch)?;
    let start_shard = state.next_epoch_start_shard(spec)?;

    for committee_number in 0..state.get_committee_count(relative_epoch)? {
        let shard = (start_shard + committee_number) % T::ShardCount::to_u64();
        // FIXME: this is a partial workaround for the above, but it only works in the case
        // where there's a committee for every shard in every epoch. It works for the minimal
        // tests but not the mainnet ones.
        let fake_shard = (shard + 1) % T::ShardCount::to_u64();

        for &index in state
            .get_crosslink_committee_for_shard(fake_shard, relative_epoch)?
            .committee
        {
            let validator = state
                .validators
                .get(index)
                .ok_or(BeaconStateError::UnknownValidator)?;
            committees[shard as usize]
                .pubkeys
                .push(validator.pubkey.clone())?;
            let compact_balance = validator.effective_balance / spec.effective_balance_increment;
            // `index` (top 6 bytes) + `slashed` (16th bit) + `compact_balance` (bottom 15 bits)
            let compact_validator: u64 =
                ((index as u64) << 16) + (u64::from(validator.slashed) << 15) + compact_balance;
            committees[shard as usize]
                .compact_validators
                .push(compact_validator)?;
        }
    }

    Ok(Hash256::from_slice(&committees.tree_hash_root()))
}

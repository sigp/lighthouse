use super::db::ClientDB;
use super::types::{AttestationData, BeaconState};
use super::{Error, Invalid, Outcome};

/// Check that an attestation is valid with reference to some state.
pub fn validate_attestation_data_shard_block_hash<T>(
    data: &AttestationData,
    state: &BeaconState,
) -> Result<Outcome, Error>
where
    T: ClientDB + Sized,
{
    /*
     * The `shard_block_hash` in the state's `latest_crosslinks` must match either the
     * `latest_crosslink_hash` or the `shard_block_hash` on the attestation.
     *
     * TODO: figure out the reasoning behind this.
     */
    match state.latest_crosslinks.get(data.shard as usize) {
        None => reject!(Invalid::UnknownShard),
        Some(crosslink) => {
            let local_shard_block_hash = crosslink.shard_block_hash;
            let shard_block_hash_is_permissable = {
                (local_shard_block_hash == data.latest_crosslink_hash)
                    || (local_shard_block_hash == data.shard_block_hash)
            };
            verify_or!(
                shard_block_hash_is_permissable,
                reject!(Invalid::ShardBlockHashMismatch)
            );
        }
    };
    accept!()
}

#[cfg(test)]
mod tests {
    /*
     * TODO: Implement tests.
     *
     * These tests will require the `BeaconBlock` and `BeaconBlockBody` updates, which are not
     * yet included in the code base. Adding tests now will result in duplicated work.
     *
     * https://github.com/sigp/lighthouse/issues/97
     */
}

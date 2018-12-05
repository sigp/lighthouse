use super::db::stores::{BeaconBlockAtSlotError, BeaconBlockStore};
use super::db::ClientDB;
use super::types::Hash256;
use super::types::{AttestationData, BeaconState};
use super::{Error, Invalid, Outcome};
use std::sync::Arc;

/// Check that an attestation is valid with reference to some state.
pub fn validate_attestation_data_for_state<T>(
    data: &AttestationData,
    chain_tip_block_hash: &Hash256,
    state: &BeaconState,
    block_store: &Arc<BeaconBlockStore<T>>,
) -> Result<Outcome, Error>
where
    T: ClientDB + Sized,
{
    /*
     * The attestation's `justified_slot` must be the same as the last justified slot known to this
     * client.
     *
     * In the case that an attestation references a slot _before_ the latest state transition, it
     * is acceptable for the attestation to reference the previous known `justified_slot`. If this
     * were not the case, all attestations created _prior_ to the last state recalculation would be
     * rejected if a block was justified in that state recalculation. It is both ideal and likely
     * that blocks will be justified during a state recalcuation.
     */
    {
        let permissable_justified_slot = if data.slot >= state.latest_state_recalculation_slot {
            state.justified_slot
        } else {
            state.previous_justified_slot
        };
        verify_or!(
            data.justified_slot == permissable_justified_slot,
            reject!(Invalid::JustifiedSlotImpermissable)
        );
    }

    /*
     * The `justified_block_hash` in the attestation must match exactly the hash of the block at
     * that slot in the local chain.
     *
     * This condition also infers that the `justified_slot` specified in attestation must exist
     * locally.
     */
    match block_hash_at_slot(chain_tip_block_hash, data.justified_slot, block_store)? {
        None => reject!(Invalid::JustifiedBlockNotInChain),
        Some(local_justified_block_hash) => {
            verify_or!(
                data.justified_block_hash == local_justified_block_hash,
                reject!(Invalid::JustifiedBlockHashMismatch)
            );
        }
    };

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

/// Returns the hash (or None) of a block at a slot in the chain that is specified by
/// `chain_tip_hash`.
///
/// Given that the database stores multiple chains, it is possible for there to be multiple blocks
/// at the given slot. `chain_tip_hash` specifies exactly which chain should be used.
fn block_hash_at_slot<T>(
    chain_tip_hash: &Hash256,
    slot: u64,
    block_store: &Arc<BeaconBlockStore<T>>,
) -> Result<Option<Hash256>, Error>
where
    T: ClientDB + Sized,
{
    match block_store.block_at_slot(&chain_tip_hash, slot)? {
        None => Ok(None),
        Some((hash_bytes, _)) => Ok(Some(Hash256::from(&hash_bytes[..]))),
    }
}

impl From<BeaconBlockAtSlotError> for Error {
    fn from(e: BeaconBlockAtSlotError) -> Self {
        match e {
            BeaconBlockAtSlotError::DBError(s) => Error::DBError(s),
            _ => Error::UnableToLookupBlockAtSlot,
        }
    }
}

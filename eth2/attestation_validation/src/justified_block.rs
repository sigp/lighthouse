use super::db::stores::{BeaconBlockAtSlotError, BeaconBlockStore};
use super::db::ClientDB;
use super::types::AttestationData;
use super::types::Hash256;
use super::{Error, Invalid, Outcome};
use std::sync::Arc;

/// Verify that a attestation's `data.justified_block_hash` matches the local hash of the block at the
/// attestation's `data.justified_slot`.
///
/// `chain_tip_block_hash` is the tip of the chain in which the justified block hash should exist
/// locally. As Lightouse stores multiple chains locally, it is possible to have multiple blocks at
/// the same slot. `chain_tip_block_hash` serves to restrict the lookup to a single chain, where
/// each slot may have exactly zero or one blocks.
pub fn validate_attestation_justified_block_hash<T>(
    data: &AttestationData,
    chain_tip_block_hash: &Hash256,
    block_store: &Arc<BeaconBlockStore<T>>,
) -> Result<Outcome, Error>
where
    T: ClientDB + Sized,
{
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

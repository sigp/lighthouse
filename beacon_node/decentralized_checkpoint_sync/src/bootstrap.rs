use crate::{
    LightClientStore, LightClientStoreSchema, LightClientSyncError, VerifiedFinalizedHeader,
    beacon_header, validate_light_client_header,
};
use merkle_proof::verify_merkle_proof;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{
    ChainSpec, EthSpec, ForkName, Hash256, LightClientBootstrap, LightClientHeader,
    light_client::consts::{
        CURRENT_SYNC_COMMITTEE_INDEX, CURRENT_SYNC_COMMITTEE_INDEX_ELECTRA,
        CURRENT_SYNC_COMMITTEE_PROOF_LEN, CURRENT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA,
    },
};

/// Initialize a light-client store from a trusted finalized block root and untrusted bootstrap.
///
/// The caller must obtain `trusted_block_root` through a trusted source and supply the correct
/// chain specification. This verifies the bootstrap against that root; it does not establish
/// finality or freshness of the root itself.
///
/// `data_fork` is the bootstrap's decoded (or locally upgraded) format, as in
/// [`validate_light_client_header`]. `store_schema` may be newer than that format. Headers retain
/// their original enum variants. No trusted value or store is returned unless every check passes.
///
/// Follows [Altair initialization] with Electra's slot-dependent committee index and normalized
/// Merkle branches, pinned to consensus-specs v1.7.0-alpha.14.
///
/// [Altair initialization]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/altair/light-client/sync-protocol.md#initialize_light_client_store
pub fn initialize_light_client_store<E: EthSpec>(
    trusted_block_root: Hash256,
    bootstrap: &LightClientBootstrap<E>,
    data_fork: ForkName,
    store_schema: LightClientStoreSchema,
    spec: &ChainSpec,
) -> Result<LightClientStore<E>, LightClientSyncError> {
    let bootstrap_schema = LightClientStoreSchema::try_from(data_fork)?;
    if bootstrap_schema > store_schema {
        return Err(LightClientSyncError::IncompatibleStoreSchema {
            bootstrap_schema,
            store_schema,
        });
    }

    let (header, committee, branch) = match bootstrap {
        LightClientBootstrap::Altair(inner) => (
            LightClientHeader::Altair(inner.header.clone()),
            &inner.current_sync_committee,
            inner.current_sync_committee_branch.as_ref(),
        ),
        LightClientBootstrap::Capella(inner) => (
            LightClientHeader::Capella(inner.header.clone()),
            &inner.current_sync_committee,
            inner.current_sync_committee_branch.as_ref(),
        ),
        LightClientBootstrap::Deneb(inner) => (
            LightClientHeader::Deneb(inner.header.clone()),
            &inner.current_sync_committee,
            inner.current_sync_committee_branch.as_ref(),
        ),
        LightClientBootstrap::Electra(inner) => (
            LightClientHeader::Electra(inner.header.clone()),
            &inner.current_sync_committee,
            inner.current_sync_committee_branch.as_ref(),
        ),
        LightClientBootstrap::Fulu(inner) => (
            LightClientHeader::Fulu(inner.header.clone()),
            &inner.current_sync_committee,
            inner.current_sync_committee_branch.as_ref(),
        ),
    };

    validate_light_client_header(&header, data_fork, spec)?;
    let beacon = beacon_header(&header);
    let actual = beacon.canonical_root();
    if actual != trusted_block_root {
        return Err(LightClientSyncError::BootstrapRootMismatch {
            expected: trusted_block_root,
            actual,
        });
    }

    // The state layout belongs to the beacon slot, not the possibly upgraded bootstrap schema.
    let fork = spec.fork_name_at_slot::<E>(beacon.slot);
    let (index, depth) = if fork.electra_enabled() {
        (
            CURRENT_SYNC_COMMITTEE_INDEX_ELECTRA,
            CURRENT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA,
        )
    } else {
        (
            CURRENT_SYNC_COMMITTEE_INDEX,
            CURRENT_SYNC_COMMITTEE_PROOF_LEN,
        )
    };
    verify_current_sync_committee_proof(
        committee.tree_hash_root(),
        branch,
        index,
        depth,
        beacon.state_root,
    )?;

    let checkpoint_header = VerifiedFinalizedHeader::from_trusted_bootstrap(header, fork);
    Ok(LightClientStore::from_bootstrap(
        checkpoint_header,
        Arc::clone(committee),
        store_schema,
    ))
}

fn verify_current_sync_committee_proof(
    leaf: Hash256,
    branch: &[Hash256],
    index: usize,
    depth: usize,
    root: Hash256,
) -> Result<(), LightClientSyncError> {
    let extra = branch
        .len()
        .checked_sub(depth)
        .ok_or(LightClientSyncError::InvalidCurrentSyncCommitteeProof)?;
    let (padding, proof) = branch
        .split_at_checked(extra)
        .ok_or(LightClientSyncError::InvalidCurrentSyncCommitteeProof)?;
    // Upgrading a pre-Electra branch adds zero padding at the start, not an extra tree level.
    if padding.iter().any(|node| *node != Hash256::default())
        || !verify_merkle_proof(leaf, proof, depth, index, root)
    {
        return Err(LightClientSyncError::InvalidCurrentSyncCommitteeProof);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

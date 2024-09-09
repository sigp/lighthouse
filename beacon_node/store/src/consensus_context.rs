use ssz_derive::{Decode, Encode};
use state_processing::ConsensusContext;
use std::collections::HashMap;
use types::{EthSpec, Hash256, IndexedAttestation, Slot};

/// The consensus context is stored on disk as part of the data availability overflow cache.
///
/// We use this separate struct to keep the on-disk format stable in the presence of changes to the
/// in-memory `ConsensusContext`. You MUST NOT change the fields of this struct without
/// superstructing it and implementing a schema migration.
#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct OnDiskConsensusContext<E: EthSpec> {
    /// Slot to act as an identifier/safeguard
    slot: Slot,
    /// Proposer index of the block at `slot`.
    proposer_index: Option<u64>,
    /// Block root of the block at `slot`.
    current_block_root: Option<Hash256>,
    /// We keep the indexed attestations in the *in-memory* version of this struct so that we don't
    /// need to regenerate them if roundtripping via this type *without* going to disk.
    ///
    /// They are not part of the on-disk format.
    #[ssz(skip_serializing, skip_deserializing)]
    indexed_attestations: HashMap<Hash256, IndexedAttestation<E>>,
}

impl<E: EthSpec> OnDiskConsensusContext<E> {
    pub fn from_consensus_context(ctxt: ConsensusContext<E>) -> Self {
        // Match exhaustively on fields here so we are forced to *consider* updating the on-disk
        // format when the `ConsensusContext` fields change.
        let ConsensusContext {
            slot,
            previous_epoch: _,
            current_epoch: _,
            proposer_index,
            current_block_root,
            indexed_attestations,
            indexed_payload_attestations: _,
            // TODO(EIP-77342): add indexed_payload_attestations to the on-disk format.
        } = ctxt;
        OnDiskConsensusContext {
            slot,
            proposer_index,
            current_block_root,
            indexed_attestations,
        }
    }

    pub fn into_consensus_context(self) -> ConsensusContext<E> {
        let OnDiskConsensusContext {
            slot,
            proposer_index,
            current_block_root,
            indexed_attestations,
        } = self;

        let mut ctxt = ConsensusContext::new(slot);

        if let Some(proposer_index) = proposer_index {
            ctxt = ctxt.set_proposer_index(proposer_index);
        }
        if let Some(block_root) = current_block_root {
            ctxt = ctxt.set_current_block_root(block_root);
        }
        ctxt.set_indexed_attestations(indexed_attestations)
    }
}

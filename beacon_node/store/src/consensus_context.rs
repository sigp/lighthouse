use ssz_derive::{Decode, Encode};
use state_processing::ConsensusContext;
use types::{EthSpec, Hash256, Slot};

/// The consensus context is stored on disk as part of the data availability overflow cache.
///
/// We use this separate struct to keep the on-disk format stable in the presence of changes to the
/// in-memory `ConsensusContext`. You MUST NOT change the fields of this struct without
/// superstructing it and implementing a schema migration.
#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct OnDiskConsensusContext {
    /// Slot to act as an identifier/safeguard
    slot: Slot,
    /// Proposer index of the block at `slot`.
    proposer_index: Option<u64>,
    /// Block root of the block at `slot`.
    current_block_root: Option<Hash256>,
}

impl OnDiskConsensusContext {
    pub fn from_consensus_context<E: EthSpec>(ctxt: &ConsensusContext<E>) -> Self {
        // Match exhaustively on fields here so we are forced to *consider* updating the on-disk
        // format when the `ConsensusContext` fields change.
        let &ConsensusContext {
            slot,
            previous_epoch: _,
            current_epoch: _,
            proposer_index,
            current_block_root,
            indexed_attestations: _,
        } = ctxt;
        OnDiskConsensusContext {
            slot,
            proposer_index,
            current_block_root,
        }
    }

    pub fn into_consensus_context<E: EthSpec>(self) -> ConsensusContext<E> {
        let OnDiskConsensusContext {
            slot,
            proposer_index,
            current_block_root,
        } = self;

        let mut ctxt = ConsensusContext::new(slot);

        if let Some(proposer_index) = proposer_index {
            ctxt = ctxt.set_proposer_index(proposer_index);
        }
        if let Some(block_root) = current_block_root {
            ctxt = ctxt.set_current_block_root(block_root);
        }
        ctxt
    }
}

//! The SSZ form of the Engine API `NewPayloadRequest`, whose root an EIP-8025 proof commits to.
//!
//! The `execution_layer` crate has a borrowed `NewPayloadRequest` for talking to an engine. This
//! one is the spec container: owned, and merkleized, because `get_execution_proof` needs its
//! `hash_tree_root` as the proof's public input.

use crate::{EthSpec, ExecutionPayloadGloas, ExecutionRequestsGloas, ForkName, Hash256};
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

/// Versioned hashes of the blobs an execution payload carries (Deneb `VersionedHashes`).
pub type VersionedHashes<E> = VariableList<Hash256, <E as EthSpec>::MaxBlobCommitmentsPerBlock>;

/// Gloas `NewPayloadRequest`, as EIP-7688 made it a progressive container.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(bound = "E: EthSpec")]
#[context_deserialize(ForkName)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1, 1))]
pub struct NewPayloadRequestSsz<E: EthSpec> {
    pub execution_payload: ExecutionPayloadGloas<E>,
    pub versioned_hashes: VersionedHashes<E>,
    pub parent_beacon_block_root: Hash256,
    pub execution_requests: ExecutionRequestsGloas<E>,
}

//! The spec `NewPayloadRequest`, owned and merkleized. The `execution_layer` one is borrowed.

use crate::{
    EthSpec, ExecutionPayloadGloas, ExecutionRequestsGloas, ForkName, Hash256, VersionedHash,
};
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

/// Spec type `VersionedHashes`.
pub type VersionedHashes<E> =
    VariableList<VersionedHash, <E as EthSpec>::MaxBlobCommitmentsPerBlock>;

/// Spec type `NewPayloadRequest`.
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

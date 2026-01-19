use std::sync::Arc;
use types::{
    BeaconState, ChainSpec, DataColumnSidecarList, EthSpec, ExecutionBlockHash, Hash256,
    SignedBeaconBlock, SignedExecutionPayloadEnvelope,
};

#[derive(PartialEq)]
pub struct EnvelopeImportData<E: EthSpec> {
    pub block_root: Hash256,
    pub block: Arc<SignedBeaconBlock<E>>,
    pub post_state: Box<BeaconState<E>>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct AvailableEnvelope<E: EthSpec> {
    // TODO(EIP-7732): rename to execution_block_hash
    block_hash: ExecutionBlockHash,
    envelope: Arc<SignedExecutionPayloadEnvelope<E>>,
    columns: DataColumnSidecarList<E>,
    /// Timestamp at which this block first became available (UNIX timestamp, time since 1970).
    columns_available_timestamp: Option<std::time::Duration>,
    pub spec: Arc<ChainSpec>,
}
pub enum MaybeAvailableEnvelope<E: EthSpec> {
    Available(AvailableEnvelope<E>),
    AvailabilityPending {
        block_hash: ExecutionBlockHash,
        envelope: Arc<SignedExecutionPayloadEnvelope<E>>,
    },
}

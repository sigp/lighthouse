use crate::{
    GossipAggregatePackage, GossipAttestationPackage, SendOnDrop,
    work_reprocessing_queue::ReprocessQueueMessage,
};
use std::{
    fmt::{Debug, Formatter},
    pin::Pin,
};
use strum::IntoStaticStr;
use types::{EthSpec, Hash256, SingleAttestation, Slot};

pub type AsyncFn = Pin<Box<dyn Future<Output = ()> + Send + Sync>>;
pub type BlockingFn = Box<dyn FnOnce() + Send + Sync>;
pub type BlockingFnWithManualSendOnIdle = Box<dyn FnOnce(SendOnDrop) + Send + Sync>;
pub enum BlockingOrAsync {
    Blocking(BlockingFn),
    Async(AsyncFn),
}
pub type GossipAttestationBatch = Vec<GossipAttestationPackage<SingleAttestation>>;

/// Indicates the type of work to be performed and therefore its priority and
/// queuing specifics.
pub enum Work<E: EthSpec> {
    GossipAttestation {
        attestation: Box<GossipAttestationPackage<SingleAttestation>>,
        process_individual:
            Box<dyn FnOnce(GossipAttestationPackage<SingleAttestation>) + Send + Sync>,
        process_batch: Box<dyn FnOnce(GossipAttestationBatch) + Send + Sync>,
    },
    UnknownBlockAttestation {
        process_fn: BlockingFn,
    },
    GossipAttestationBatch {
        attestations: GossipAttestationBatch,
        process_batch: Box<dyn FnOnce(GossipAttestationBatch) + Send + Sync>,
    },
    GossipAggregate {
        aggregate: Box<GossipAggregatePackage<E>>,
        process_individual: Box<dyn FnOnce(GossipAggregatePackage<E>) + Send + Sync>,
        process_batch: Box<dyn FnOnce(Vec<GossipAggregatePackage<E>>) + Send + Sync>,
    },
    UnknownBlockAggregate {
        process_fn: BlockingFn,
    },
    UnknownLightClientOptimisticUpdate {
        parent_root: Hash256,
        process_fn: BlockingFn,
    },
    GossipAggregateBatch {
        aggregates: Vec<GossipAggregatePackage<E>>,
        process_batch: Box<dyn FnOnce(Vec<GossipAggregatePackage<E>>) + Send + Sync>,
    },
    GossipBlock(AsyncFn),
    GossipBlobSidecar(AsyncFn),
    GossipDataColumnSidecar(AsyncFn),
    DelayedImportBlock {
        beacon_block_slot: Slot,
        beacon_block_root: Hash256,
        process_fn: AsyncFn,
    },
    GossipVoluntaryExit(BlockingFn),
    GossipProposerSlashing(BlockingFn),
    GossipAttesterSlashing(BlockingFn),
    GossipSyncSignature(BlockingFn),
    GossipSyncContribution(BlockingFn),
    GossipLightClientFinalityUpdate(BlockingFn),
    GossipLightClientOptimisticUpdate(BlockingFn),
    RpcBlock {
        process_fn: AsyncFn,
    },
    RpcBlobs {
        process_fn: AsyncFn,
    },
    RpcCustodyColumn(AsyncFn),
    ColumnReconstruction(AsyncFn),
    IgnoredRpcBlock {
        process_fn: BlockingFn,
    },
    ChainSegment(AsyncFn),
    ChainSegmentBackfill(BlockingFn),
    Status(BlockingFn),
    BlocksByRangeRequest(AsyncFn),
    BlocksByRootsRequest(AsyncFn),
    BlobsByRangeRequest(BlockingFn),
    BlobsByRootsRequest(BlockingFn),
    DataColumnsByRootsRequest(BlockingFn),
    DataColumnsByRangeRequest(BlockingFn),
    GossipBlsToExecutionChange(BlockingFn),
    LightClientBootstrapRequest(BlockingFn),
    LightClientOptimisticUpdateRequest(BlockingFn),
    LightClientFinalityUpdateRequest(BlockingFn),
    LightClientUpdatesByRangeRequest(BlockingFn),
    ApiRequestP0(BlockingOrAsync),
    ApiRequestP1(BlockingOrAsync),
    Reprocess(ReprocessQueueMessage),
}

impl<E: EthSpec> Work<E> {
    pub fn get_work_category(&self) -> WorkCategory {
        WorkCategory::get_category(self.to_type())
    }
}

impl<E: EthSpec> Debug for Work<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Into::<&'static str>::into(self.to_type()))
    }
}

#[derive(IntoStaticStr, PartialEq, Eq, Debug, Clone)]
#[strum(serialize_all = "snake_case")]
pub enum WorkType {
    GossipAttestation,
    GossipAttestationToConvert,
    UnknownBlockAttestation,
    GossipAttestationBatch,
    GossipAggregate,
    UnknownBlockAggregate,
    UnknownLightClientOptimisticUpdate,
    GossipAggregateBatch,
    GossipBlock,
    GossipBlobSidecar,
    GossipDataColumnSidecar,
    DelayedImportBlock,
    GossipVoluntaryExit,
    GossipProposerSlashing,
    GossipAttesterSlashing,
    GossipSyncSignature,
    GossipSyncContribution,
    GossipLightClientFinalityUpdate,
    GossipLightClientOptimisticUpdate,
    RpcBlock,
    RpcBlobs,
    RpcCustodyColumn,
    ColumnReconstruction,
    IgnoredRpcBlock,
    ChainSegment,
    ChainSegmentBackfill,
    Status,
    BlocksByRangeRequest,
    BlocksByRootsRequest,
    BlobsByRangeRequest,
    BlobsByRootsRequest,
    DataColumnsByRootsRequest,
    DataColumnsByRangeRequest,
    GossipBlsToExecutionChange,
    LightClientBootstrapRequest,
    LightClientOptimisticUpdateRequest,
    LightClientFinalityUpdateRequest,
    LightClientUpdatesByRangeRequest,
    ApiRequestP0,
    ApiRequestP1,
    Reprocess,
}

#[derive(PartialEq, Eq, Debug)]
pub enum WorkCategory {
    // Work that is IO bound, i.e. network requests, disk operations, external services etc.
    IoBound,
    // Work that is CPU bound
    CpuBound,
}

impl WorkCategory {
    pub fn get_category(work_type: WorkType) -> Self {
        match work_type {
            // IO bound tasks
            WorkType::GossipAttestationToConvert
            | WorkType::UnknownLightClientOptimisticUpdate
            | WorkType::GossipVoluntaryExit
            | WorkType::GossipProposerSlashing
            | WorkType::GossipAttesterSlashing
            | WorkType::GossipSyncSignature
            | WorkType::GossipSyncContribution
            | WorkType::GossipLightClientFinalityUpdate
            | WorkType::GossipLightClientOptimisticUpdate
            | WorkType::IgnoredRpcBlock
            | WorkType::Status
            | WorkType::BlocksByRangeRequest
            | WorkType::BlocksByRootsRequest
            | WorkType::BlobsByRangeRequest
            | WorkType::BlobsByRootsRequest
            | WorkType::DataColumnsByRootsRequest
            | WorkType::DataColumnsByRangeRequest
            | WorkType::GossipBlsToExecutionChange
            | WorkType::LightClientBootstrapRequest
            | WorkType::LightClientOptimisticUpdateRequest
            | WorkType::LightClientFinalityUpdateRequest
            | WorkType::LightClientUpdatesByRangeRequest
            | WorkType::ApiRequestP0
            | WorkType::ApiRequestP1
            | WorkType::Reprocess => Self::IoBound,
            // CPU bound tasks
            WorkType::GossipBlock
            | WorkType::UnknownBlockAttestation
            | WorkType::UnknownBlockAggregate
            | WorkType::GossipAttestation
            | WorkType::GossipAttestationBatch
            | WorkType::GossipAggregate
            | WorkType::GossipAggregateBatch
            | WorkType::GossipBlobSidecar
            | WorkType::GossipDataColumnSidecar
            | WorkType::DelayedImportBlock
            | WorkType::RpcBlock
            | WorkType::RpcBlobs
            | WorkType::RpcCustodyColumn
            | WorkType::ColumnReconstruction
            | WorkType::ChainSegment
            | WorkType::ChainSegmentBackfill => Self::CpuBound,
        }
    }
}

impl<E: EthSpec> Work<E> {
    pub fn str_id(&self) -> &'static str {
        self.to_type().into()
    }

    /// Provides a `&str` that uniquely identifies each enum variant.
    pub fn to_type(&self) -> WorkType {
        match self {
            Work::GossipAttestation { .. } => WorkType::GossipAttestation,
            Work::GossipAttestationBatch { .. } => WorkType::GossipAttestationBatch,
            Work::GossipAggregate { .. } => WorkType::GossipAggregate,
            Work::GossipAggregateBatch { .. } => WorkType::GossipAggregateBatch,
            Work::GossipBlock(_) => WorkType::GossipBlock,
            Work::GossipBlobSidecar(_) => WorkType::GossipBlobSidecar,
            Work::GossipDataColumnSidecar(_) => WorkType::GossipDataColumnSidecar,
            Work::DelayedImportBlock { .. } => WorkType::DelayedImportBlock,
            Work::GossipVoluntaryExit(_) => WorkType::GossipVoluntaryExit,
            Work::GossipProposerSlashing(_) => WorkType::GossipProposerSlashing,
            Work::GossipAttesterSlashing(_) => WorkType::GossipAttesterSlashing,
            Work::GossipSyncSignature(_) => WorkType::GossipSyncSignature,
            Work::GossipSyncContribution(_) => WorkType::GossipSyncContribution,
            Work::GossipLightClientFinalityUpdate(_) => WorkType::GossipLightClientFinalityUpdate,
            Work::GossipLightClientOptimisticUpdate(_) => {
                WorkType::GossipLightClientOptimisticUpdate
            }
            Work::GossipBlsToExecutionChange(_) => WorkType::GossipBlsToExecutionChange,
            Work::RpcBlock { .. } => WorkType::RpcBlock,
            Work::RpcBlobs { .. } => WorkType::RpcBlobs,
            Work::RpcCustodyColumn { .. } => WorkType::RpcCustodyColumn,
            Work::ColumnReconstruction(_) => WorkType::ColumnReconstruction,
            Work::IgnoredRpcBlock { .. } => WorkType::IgnoredRpcBlock,
            Work::ChainSegment { .. } => WorkType::ChainSegment,
            Work::ChainSegmentBackfill(_) => WorkType::ChainSegmentBackfill,
            Work::Status(_) => WorkType::Status,
            Work::BlocksByRangeRequest(_) => WorkType::BlocksByRangeRequest,
            Work::BlocksByRootsRequest(_) => WorkType::BlocksByRootsRequest,
            Work::BlobsByRangeRequest(_) => WorkType::BlobsByRangeRequest,
            Work::BlobsByRootsRequest(_) => WorkType::BlobsByRootsRequest,
            Work::DataColumnsByRootsRequest(_) => WorkType::DataColumnsByRootsRequest,
            Work::DataColumnsByRangeRequest(_) => WorkType::DataColumnsByRangeRequest,
            Work::LightClientBootstrapRequest(_) => WorkType::LightClientBootstrapRequest,
            Work::LightClientOptimisticUpdateRequest(_) => {
                WorkType::LightClientOptimisticUpdateRequest
            }
            Work::LightClientFinalityUpdateRequest(_) => WorkType::LightClientFinalityUpdateRequest,
            Work::LightClientUpdatesByRangeRequest(_) => WorkType::LightClientUpdatesByRangeRequest,
            Work::UnknownBlockAttestation { .. } => WorkType::UnknownBlockAttestation,
            Work::UnknownBlockAggregate { .. } => WorkType::UnknownBlockAggregate,
            Work::UnknownLightClientOptimisticUpdate { .. } => {
                WorkType::UnknownLightClientOptimisticUpdate
            }
            Work::ApiRequestP0 { .. } => WorkType::ApiRequestP0,
            Work::ApiRequestP1 { .. } => WorkType::ApiRequestP1,
            Work::Reprocess { .. } => WorkType::Reprocess,
        }
    }
}

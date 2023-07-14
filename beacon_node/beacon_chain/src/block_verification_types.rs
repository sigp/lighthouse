use crate::blob_verification::GossipVerifiedBlobList;
use crate::data_availability_checker::AvailabilityCheckError;
pub use crate::data_availability_checker::{AvailableBlock, MaybeAvailableBlock};
use crate::{data_availability_checker, GossipVerifiedBlock, PayloadVerificationOutcome};
use derivative::Derivative;
use ssz_derive::{Decode, Encode};
use state_processing::ConsensusContext;
use std::sync::Arc;
use types::{
    blob_sidecar::BlobIdentifier, ssz_tagged_beacon_state, ssz_tagged_signed_beacon_block,
    ssz_tagged_signed_beacon_block_arc,
};
use types::{
    BeaconBlockRef, BeaconState, BlindedPayload, BlobSidecarList, Epoch, EthSpec, Hash256,
    SignedBeaconBlock, SignedBeaconBlockHeader, Slot,
};
use crate::eth1_finalization_cache::Eth1FinalizationData;

#[derive(Debug, Clone, Derivative)]
#[derivative(Hash(bound = "E: EthSpec"))]
pub struct RpcBlock<E: EthSpec> {
    block: RpcBlockInner<E>,
}

#[derive(Debug, Clone, Derivative)]
#[derivative(Hash(bound = "E: EthSpec"))]
enum RpcBlockInner<E: EthSpec> {
    /// Single block lookup response. This should potentially hit the data availability cache.
    Block(Arc<SignedBeaconBlock<E>>),
    /// This variant is used with parent lookups and by-range responses. It should have all blobs
    /// ordered, all block roots matching, and the correct number of blobs for this block.
    BlockAndBlobs(Arc<SignedBeaconBlock<E>>, BlobSidecarList<E>),
}

impl<E: EthSpec> RpcBlock<E> {
    pub fn new_without_blobs(block: Arc<SignedBeaconBlock<E>>) -> Self {
        Self {
            block: RpcBlockInner::Block(block),
        }
    }

    pub fn new(
        block: Arc<SignedBeaconBlock<E>>,
        blobs: Option<BlobSidecarList<E>>,
    ) -> Result<Self, AvailabilityCheckError> {
        if let Some(blobs) = blobs.as_ref() {
            data_availability_checker::consistency_checks( &block, blobs)?;
        }
        let inner = match blobs {
            Some(blobs) => RpcBlockInner::BlockAndBlobs(block, blobs),
            None => RpcBlockInner::Block(block),
        };
        Ok(Self { block: inner })
    }

    pub fn deconstruct(self) -> (Arc<SignedBeaconBlock<E>>, Option<BlobSidecarList<E>>) {
        match self.block {
            RpcBlockInner::Block(block) => (block, None),
            RpcBlockInner::BlockAndBlobs(block, blobs) => (block, Some(blobs)),
        }
    }
    pub fn n_blobs(&self) -> usize {
        match &self.block {
            RpcBlockInner::Block(_) => 0,
            RpcBlockInner::BlockAndBlobs(_, blobs) => blobs.len(),
        }
    }
}

impl<E: EthSpec> From<Arc<SignedBeaconBlock<E>>> for RpcBlock<E> {
    fn from(value: Arc<SignedBeaconBlock<E>>) -> Self {
        Self::new_without_blobs(value)
    }
}

impl<E: EthSpec> From<SignedBeaconBlock<E>> for RpcBlock<E> {
    fn from(value: SignedBeaconBlock<E>) -> Self {
        Self::new_without_blobs(Arc::new(value))
    }
}

pub enum ExecutedBlock<E: EthSpec> {
    Available(AvailableExecutedBlock<E>),
    AvailabilityPending(AvailabilityPendingExecutedBlock<E>),
}

impl<E: EthSpec> ExecutedBlock<E> {
    pub fn new(
        block: MaybeAvailableBlock<E>,
        import_data: BlockImportData<E>,
        payload_verification_outcome: PayloadVerificationOutcome,
    ) -> Self {
        match block {
            MaybeAvailableBlock::Available(available_block) => {
                Self::Available(AvailableExecutedBlock::new(
                    available_block,
                    import_data,
                    payload_verification_outcome,
                ))
            }
            MaybeAvailableBlock::AvailabilityPending(pending_block) => {
                Self::AvailabilityPending(AvailabilityPendingExecutedBlock::new(
                    pending_block,
                    import_data,
                    payload_verification_outcome,
                ))
            }
        }
    }

    pub fn as_block(&self) -> &SignedBeaconBlock<E> {
        match self {
            Self::Available(available) => available.block.block(),
            Self::AvailabilityPending(pending) => &pending.block,
        }
    }
}

#[derive(PartialEq)]
pub struct AvailableExecutedBlock<E: EthSpec> {
    pub block: AvailableBlock<E>,
    pub import_data: BlockImportData<E>,
    pub payload_verification_outcome: PayloadVerificationOutcome,
}

impl<E: EthSpec> AvailableExecutedBlock<E> {
    pub fn new(
        block: AvailableBlock<E>,
        import_data: BlockImportData<E>,
        payload_verification_outcome: PayloadVerificationOutcome,
    ) -> Self {
        Self {
            block,
            import_data,
            payload_verification_outcome,
        }
    }

    pub fn get_all_blob_ids(&self) -> Vec<BlobIdentifier> {
        let num_blobs_expected = self
            .block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_or(0, |commitments| commitments.len());
        let mut blob_ids = Vec::with_capacity(num_blobs_expected);
        for i in 0..num_blobs_expected {
            blob_ids.push(BlobIdentifier {
                block_root: self.import_data.block_root,
                index: i as u64,
            });
        }
        blob_ids
    }
}

#[derive(Encode, Decode, Clone)]
pub struct AvailabilityPendingExecutedBlock<E: EthSpec> {
    #[ssz(with = "ssz_tagged_signed_beacon_block_arc")]
    pub block: Arc<SignedBeaconBlock<E>>,
    pub import_data: BlockImportData<E>,
    pub payload_verification_outcome: PayloadVerificationOutcome,
}

impl<E: EthSpec> AvailabilityPendingExecutedBlock<E> {
    pub fn new(
        block: Arc<SignedBeaconBlock<E>>,
        import_data: BlockImportData<E>,
        payload_verification_outcome: PayloadVerificationOutcome,
    ) -> Self {
        Self {
            block,
            import_data,
            payload_verification_outcome,
        }
    }

    pub fn num_blobs_expected(&self) -> usize {
        self.block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_or(0, |commitments| commitments.len())
    }

    pub fn get_all_blob_ids(&self) -> Vec<BlobIdentifier> {
        let block_root = self.import_data.block_root;
        self.block
            .get_filtered_blob_ids(Some(block_root), |_, _| true)
    }

    pub fn get_filtered_blob_ids(
        &self,
        filter: impl Fn(usize, Hash256) -> bool,
    ) -> Vec<BlobIdentifier> {
        self.block
            .get_filtered_blob_ids(Some(self.import_data.block_root), filter)
    }
}

#[derive(Debug, PartialEq, Encode, Decode, Clone)]
// TODO (mark): investigate using an Arc<state> / Arc<parent_block>
//              here to make this cheaper to clone
pub struct BlockImportData<E: EthSpec> {
    pub block_root: Hash256,
    #[ssz(with = "ssz_tagged_beacon_state")]
    pub state: BeaconState<E>,
    #[ssz(with = "ssz_tagged_signed_beacon_block")]
    pub parent_block: SignedBeaconBlock<E, BlindedPayload<E>>,
    pub parent_eth1_finalization_data: Eth1FinalizationData,
    pub confirmed_state_roots: Vec<Hash256>,
    pub consensus_context: ConsensusContext<E>,
}

pub type GossipVerifiedBlockContents<T> =
    (GossipVerifiedBlock<T>, Option<GossipVerifiedBlobList<T>>);

/// Trait for common block operations.
pub trait AsBlock<E: EthSpec> {
    fn slot(&self) -> Slot;
    fn epoch(&self) -> Epoch;
    fn parent_root(&self) -> Hash256;
    fn state_root(&self) -> Hash256;
    fn signed_block_header(&self) -> SignedBeaconBlockHeader;
    fn message(&self) -> BeaconBlockRef<E>;
    fn as_block(&self) -> &SignedBeaconBlock<E>;
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>>;
    fn canonical_root(&self) -> Hash256;
    fn into_rpc_block(self) -> RpcBlock<E>;
}

impl<E: EthSpec> AsBlock<E> for Arc<SignedBeaconBlock<E>> {
    fn slot(&self) -> Slot {
        SignedBeaconBlock::slot(self)
    }

    fn epoch(&self) -> Epoch {
        SignedBeaconBlock::epoch(self)
    }

    fn parent_root(&self) -> Hash256 {
        SignedBeaconBlock::parent_root(self)
    }

    fn state_root(&self) -> Hash256 {
        SignedBeaconBlock::state_root(self)
    }

    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        SignedBeaconBlock::signed_block_header(self)
    }

    fn message(&self) -> BeaconBlockRef<E> {
        SignedBeaconBlock::message(self)
    }

    fn as_block(&self) -> &SignedBeaconBlock<E> {
        self
    }

    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        Arc::<SignedBeaconBlock<E>>::clone(self)
    }

    fn canonical_root(&self) -> Hash256 {
        SignedBeaconBlock::canonical_root(self)
    }

    fn into_rpc_block(self) -> RpcBlock<E> {
        RpcBlock::new_without_blobs(self)
    }
}

impl<E: EthSpec> AsBlock<E> for MaybeAvailableBlock<E> {
    fn slot(&self) -> Slot {
        self.as_block().slot()
    }
    fn epoch(&self) -> Epoch {
        self.as_block().epoch()
    }
    fn parent_root(&self) -> Hash256 {
        self.as_block().parent_root()
    }
    fn state_root(&self) -> Hash256 {
        self.as_block().state_root()
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.as_block().signed_block_header()
    }
    fn message(&self) -> BeaconBlockRef<E> {
        self.as_block().message()
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self {
            MaybeAvailableBlock::Available(block) => block.as_block(),
            MaybeAvailableBlock::AvailabilityPending(block) => block,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self {
            MaybeAvailableBlock::Available(block) => block.block_cloned(),
            MaybeAvailableBlock::AvailabilityPending(block) => block.clone(),
        }
    }
    fn canonical_root(&self) -> Hash256 {
        self.as_block().canonical_root()
    }

    fn into_rpc_block(self) -> RpcBlock<E> {
        match self {
            MaybeAvailableBlock::Available(available_block) => available_block.into_rpc_block(),
            MaybeAvailableBlock::AvailabilityPending(block) => RpcBlock::new_without_blobs(block),
        }
    }
}

impl<E: EthSpec> AsBlock<E> for AvailableBlock<E> {
    fn slot(&self) -> Slot {
        self.block().slot()
    }

    fn epoch(&self) -> Epoch {
        self.block().epoch()
    }

    fn parent_root(&self) -> Hash256 {
        self.block().parent_root()
    }

    fn state_root(&self) -> Hash256 {
        self.block().state_root()
    }

    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.block().signed_block_header()
    }

    fn message(&self) -> BeaconBlockRef<E> {
        self.block().message()
    }

    fn as_block(&self) -> &SignedBeaconBlock<E> {
        self.block()
    }

    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        AvailableBlock::block_cloned(self)
    }

    fn canonical_root(&self) -> Hash256 {
        self.block().canonical_root()
    }

    fn into_rpc_block(self) -> RpcBlock<E> {
        let (block, blobs_opt) = self.deconstruct();
        // Circumvent the constructor here, because an Available block will have already had
        // consistency checks performed.
        let inner = match blobs_opt {
            None => RpcBlockInner::Block(block),
            Some(blobs) => RpcBlockInner::BlockAndBlobs(block, blobs),
        };
        RpcBlock { block: inner }
    }
}

impl<E: EthSpec> AsBlock<E> for RpcBlock<E> {
    fn slot(&self) -> Slot {
        self.as_block().slot()
    }
    fn epoch(&self) -> Epoch {
        self.as_block().epoch()
    }
    fn parent_root(&self) -> Hash256 {
        self.as_block().parent_root()
    }
    fn state_root(&self) -> Hash256 {
        self.as_block().state_root()
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.as_block().signed_block_header()
    }
    fn message(&self) -> BeaconBlockRef<E> {
        self.as_block().message()
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self.block {
            RpcBlockInner::Block(block) => block,
            RpcBlockInner::BlockAndBlobs(block, _) => block,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self.block {
            RpcBlockInner::Block(block) => block.clone(),
            RpcBlockInner::BlockAndBlobs(block, _) => block.clone(),
        }
    }
    fn canonical_root(&self) -> Hash256 {
        self.as_block().canonical_root()
    }

    fn into_rpc_block(self) -> RpcBlock<E> {
        self
    }
}
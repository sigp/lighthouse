use crate::data_availability_checker::{AvailabilityCheckError, DataAvailabilityChecker};
pub use crate::data_availability_checker::{
    AvailableBlock, AvailableBlockData, MaybeAvailableBlock,
};
use crate::{BeaconChainTypes, PayloadVerificationOutcome};
use educe::Educe;
use state_processing::ConsensusContext;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use types::data::BlobIdentifier;
use types::{
    BeaconBlockRef, BeaconState, BlindedPayload, ChainSpec, Epoch, EthSpec, Hash256,
    SignedBeaconBlock, SignedBeaconBlockHeader, Slot,
};

/// A block that has been received over RPC. It has 2 internal variants:
///
/// 1. `FullyAvailable`: A fully available block. This can either be a pre-deneb block, a
///    post-Deneb block with blobs, a post-Fulu block with the columns the node is required to custody,
///    or a post-Deneb block that doesn't require blobs/columns. Hence, it is fully self contained w.r.t
///    verification. i.e. this block has all the required data to get verified and imported into fork choice.
///
/// 2. `BlockOnly`: This is a post-deneb block that requires blobs to be considered fully available.
#[derive(Clone, Educe)]
#[educe(Hash(bound(E: EthSpec)))]
pub enum RpcBlock<E: EthSpec> {
    FullyAvailable(AvailableBlock<E>),
    BlockOnly {
        block: Arc<SignedBeaconBlock<E>>,
        block_root: Hash256,
    },
}

impl<E: EthSpec> Debug for RpcBlock<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RpcBlock({:?})", self.block_root())
    }
}

impl<E: EthSpec> RpcBlock<E> {
    pub fn block_root(&self) -> Hash256 {
        match self {
            RpcBlock::FullyAvailable(available_block) => available_block.block_root(),
            RpcBlock::BlockOnly { block_root, .. } => *block_root,
        }
    }

    pub fn as_block(&self) -> &SignedBeaconBlock<E> {
        match self {
            RpcBlock::FullyAvailable(available_block) => available_block.block(),
            RpcBlock::BlockOnly { block, .. } => block,
        }
    }

    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match self {
            RpcBlock::FullyAvailable(available_block) => available_block.block_cloned(),
            RpcBlock::BlockOnly { block, .. } => block.clone(),
        }
    }

    pub fn block_data(&self) -> Option<&AvailableBlockData<E>> {
        match self {
            RpcBlock::FullyAvailable(available_block) => Some(available_block.data()),
            RpcBlock::BlockOnly { .. } => None,
        }
    }
}

impl<E: EthSpec> RpcBlock<E> {
    /// Constructs an `RpcBlock` from a block and optional availability data.
    ///
    /// This function creates an RpcBlock which can be in one of two states:
    /// - `FullyAvailable`: When `block_data` is provided, the block contains all required
    ///   data for verification.
    /// - `BlockOnly`: When `block_data` is `None`, the block may still need additional
    ///   data to be considered fully available (used during block lookups or when blobs
    ///   will arrive separately).
    ///
    /// # Validation
    ///
    /// When `block_data` is provided, this function validates that:
    /// - Block data is not provided when not required.
    /// - Required blobs are present and match the expected count.
    /// - Required custody columns are included based on the nodes custody requirements.
    ///
    /// # Errors
    ///
    /// Returns `AvailabilityCheckError` if:
    /// - `InvalidAvailableBlockData`: Block data is provided but not required.
    /// - `MissingBlobs`: Block requires blobs but they are missing or incomplete.
    /// - `MissingCustodyColumns`: Block requires custody columns but they are incomplete.
    pub fn new<T>(
        block: Arc<SignedBeaconBlock<E>>,
        block_data: Option<AvailableBlockData<E>>,
        da_checker: &DataAvailabilityChecker<T>,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, AvailabilityCheckError>
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        match block_data {
            Some(block_data) => Ok(RpcBlock::FullyAvailable(AvailableBlock::new(
                block, block_data, da_checker, spec,
            )?)),
            None => Ok(RpcBlock::BlockOnly {
                block_root: block.canonical_root(),
                block,
            }),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn deconstruct(
        self,
    ) -> (
        Hash256,
        Arc<SignedBeaconBlock<E>>,
        Option<AvailableBlockData<E>>,
    ) {
        match self {
            RpcBlock::FullyAvailable(available_block) => {
                let (block_root, block, block_data) = available_block.deconstruct();
                (block_root, block, Some(block_data))
            }
            RpcBlock::BlockOnly { block, block_root } => (block_root, block, None),
        }
    }

    pub fn n_blobs(&self) -> usize {
        if let Some(block_data) = self.block_data() {
            match block_data {
                AvailableBlockData::NoData | AvailableBlockData::DataColumns(_) => 0,
                AvailableBlockData::Blobs(blobs) => blobs.len(),
            }
        } else {
            0
        }
    }

    pub fn n_data_columns(&self) -> usize {
        if let Some(block_data) = self.block_data() {
            match block_data {
                AvailableBlockData::NoData | AvailableBlockData::Blobs(_) => 0,
                AvailableBlockData::DataColumns(columns) => columns.len(),
            }
        } else {
            0
        }
    }
}

/// A block that has gone through all pre-deneb block processing checks including block processing
/// and execution by an EL client. This block hasn't necessarily completed data availability checks.
///
///
/// It contains 2 variants:
/// 1. `Available`: This block has been executed and also contains all data to consider it a
///    fully available block. i.e. for post-deneb, this implies that this contains all the
///    required blobs.
/// 2. `AvailabilityPending`: This block hasn't received all required blobs to consider it a
///    fully available block.
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
            MaybeAvailableBlock::AvailabilityPending {
                block_root: _,
                block: pending_block,
            } => Self::AvailabilityPending(AvailabilityPendingExecutedBlock::new(
                pending_block,
                import_data,
                payload_verification_outcome,
            )),
        }
    }

    pub fn as_block(&self) -> &SignedBeaconBlock<E> {
        match self {
            Self::Available(available) => available.block.block(),
            Self::AvailabilityPending(pending) => &pending.block,
        }
    }

    pub fn block_root(&self) -> Hash256 {
        match self {
            ExecutedBlock::AvailabilityPending(pending) => pending.import_data.block_root,
            ExecutedBlock::Available(available) => available.import_data.block_root,
        }
    }
}

/// A block that has completed all pre-deneb block processing checks including verification
/// by an EL client **and** has all requisite blob data to be imported into fork choice.
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

/// A block that has completed all pre-deneb block processing checks, verification
/// by an EL client but does not have all requisite blob data to get imported into
/// fork choice.
pub struct AvailabilityPendingExecutedBlock<E: EthSpec> {
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

    pub fn as_block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }

    pub fn num_blobs_expected(&self) -> usize {
        self.block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_or(0, |commitments| commitments.len())
    }
}

#[derive(Debug, PartialEq)]
pub struct BlockImportData<E: EthSpec> {
    pub block_root: Hash256,
    pub state: BeaconState<E>,
    pub parent_block: SignedBeaconBlock<E, BlindedPayload<E>>,
    pub consensus_context: ConsensusContext<E>,
}

impl<E: EthSpec> BlockImportData<E> {
    pub fn __new_for_test(
        block_root: Hash256,
        state: BeaconState<E>,
        parent_block: SignedBeaconBlock<E, BlindedPayload<E>>,
    ) -> Self {
        Self {
            block_root,
            state,
            parent_block,
            consensus_context: ConsensusContext::new(Slot::new(0)),
        }
    }
}

/// Trait for common block operations.
pub trait AsBlock<E: EthSpec> {
    fn slot(&self) -> Slot;
    fn epoch(&self) -> Epoch;
    fn parent_root(&self) -> Hash256;
    fn state_root(&self) -> Hash256;
    fn signed_block_header(&self) -> SignedBeaconBlockHeader;
    fn message(&self) -> BeaconBlockRef<'_, E>;
    fn as_block(&self) -> &SignedBeaconBlock<E>;
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>>;
    fn canonical_root(&self) -> Hash256;
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

    fn message(&self) -> BeaconBlockRef<'_, E> {
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
    fn message(&self) -> BeaconBlockRef<'_, E> {
        self.as_block().message()
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self {
            MaybeAvailableBlock::Available(block) => block.as_block(),
            MaybeAvailableBlock::AvailabilityPending { block, .. } => block,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self {
            MaybeAvailableBlock::Available(block) => block.block_cloned(),
            MaybeAvailableBlock::AvailabilityPending { block, .. } => block.clone(),
        }
    }
    fn canonical_root(&self) -> Hash256 {
        self.as_block().canonical_root()
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

    fn message(&self) -> BeaconBlockRef<'_, E> {
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
    fn message(&self) -> BeaconBlockRef<'_, E> {
        self.as_block().message()
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match self {
            Self::BlockOnly {
                block,
                block_root: _,
            } => block,
            Self::FullyAvailable(available_block) => available_block.block(),
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match self {
            RpcBlock::FullyAvailable(available_block) => available_block.block_cloned(),
            RpcBlock::BlockOnly {
                block,
                block_root: _,
            } => block.clone(),
        }
    }
    fn canonical_root(&self) -> Hash256 {
        self.as_block().canonical_root()
    }
}

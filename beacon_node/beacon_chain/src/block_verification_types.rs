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

/// A wrapper around a `SignedBeaconBlock`. This varaint is constructed
/// when lookup sync only fetches a single block. It does not contain
/// any blobs or data columns.
pub struct LookupBlock<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    block_root: Hash256,
}

impl<E: EthSpec> LookupBlock<E> {
    pub fn new(block: Arc<SignedBeaconBlock<E>>) -> Self {
        let block_root = block.canonical_root();
        Self { block, block_root }
    }

    pub fn block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }

    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.block.clone()
    }
}

/// A fully available block that has been constructed by range sync.
/// The block contains all the data required to import into fork choice.
/// This includes any and all blobs/columns required, including zero if
/// none are required. This can happen if the block is pre-deneb or if
/// it's simply past the DA boundary.
#[derive(Clone, Educe)]
#[educe(Hash(bound(E: EthSpec)))]
pub struct RangeSyncBlock<E: EthSpec> {
    block: AvailableBlock<E>,
}

impl<E: EthSpec> Debug for RangeSyncBlock<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RpcBlock({:?})", self.block_root())
    }
}

impl<E: EthSpec> RangeSyncBlock<E> {
    pub fn block_root(&self) -> Hash256 {
        self.block.block_root()
    }

    pub fn as_block(&self) -> &SignedBeaconBlock<E> {
        self.block.block()
    }

    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.block.block_cloned()
    }

    pub fn block_data(&self) -> &AvailableBlockData<E> {
        self.block.data()
    }
}

impl<E: EthSpec> RangeSyncBlock<E> {
    /// Constructs an `RangeSyncBlock` from a block and availability data.
    ///
    /// # Errors
    ///
    /// Returns `AvailabilityCheckError` if:
    /// - `InvalidAvailableBlockData`: Block data is provided but not required.
    /// - `MissingBlobs`: Block requires blobs but they are missing or incomplete.
    /// - `MissingCustodyColumns`: Block requires custody columns but they are incomplete.
    pub fn new<T>(
        block: Arc<SignedBeaconBlock<E>>,
        block_data: AvailableBlockData<E>,
        da_checker: &DataAvailabilityChecker<T>,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, AvailabilityCheckError>
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        let available_block = AvailableBlock::new(block, block_data, da_checker, spec)?;
        Ok(Self {
            block: available_block,
        })
    }

    #[allow(clippy::type_complexity)]
    pub fn deconstruct(self) -> (Hash256, Arc<SignedBeaconBlock<E>>, AvailableBlockData<E>) {
        self.block.deconstruct()
    }

    pub fn n_blobs(&self) -> usize {
        match self.block_data() {
            AvailableBlockData::NoData | AvailableBlockData::DataColumns(_) => 0,
            AvailableBlockData::Blobs(blobs) => blobs.len(),
        }
    }

    pub fn n_data_columns(&self) -> usize {
        match self.block_data() {
            AvailableBlockData::NoData | AvailableBlockData::Blobs(_) => 0,
            AvailableBlockData::DataColumns(columns) => columns.len(),
        }
    }

    pub fn into_available_block(self) -> AvailableBlock<E> {
        self.block
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

#[derive(Clone, Debug, PartialEq)]
pub struct BlockImportData<E: EthSpec> {
    pub block_root: Hash256,
    pub state: BeaconState<E>,
    pub parent_block: SignedBeaconBlock<E, BlindedPayload<E>>,
    pub consensus_context: ConsensusContext<E>,
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

impl<E: EthSpec> AsBlock<E> for RangeSyncBlock<E> {
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
        self.block.as_block()
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.block.block_cloned()
    }
    fn canonical_root(&self) -> Hash256 {
        self.block.block_root()
    }
}

impl<E: EthSpec> AsBlock<E> for LookupBlock<E> {
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
        self.block_cloned()
    }
    fn canonical_root(&self) -> Hash256 {
        self.block_root
    }
}

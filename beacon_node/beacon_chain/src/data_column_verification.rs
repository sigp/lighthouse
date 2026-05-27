use crate::block_verification::{
    BlockSlashInfo, get_validator_pubkey_cache, process_block_slash_info,
};
use crate::data_availability_checker::MissingCellsError;
use crate::kzg_utils::{
    reconstruct_data_columns, validate_data_columns_with_commitments, validate_full_data_columns,
    validate_partial_data_columns,
};
use crate::observed_data_sidecars::{
    Error as ObservedDataSidecarsError, ObservationKey, ObservationStrategy, Observe,
};
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, metrics};
use educe::Educe;
use fork_choice::ProtoBlock;
use kzg::{Error as KzgError, Kzg};
use proto_array::Block;
use slot_clock::{SlotClock, timestamp_now};
use ssz_derive::Encode;
use ssz_types::VariableList;
use std::iter;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use store::DatabaseBlock;
use tracing::{debug, instrument};
use tree_hash::TreeHash;
use types::data::{
    ColumnIndex, PartialDataColumn, PartialDataColumnHeader, PartialDataColumnSidecar,
    PartialDataColumnSidecarError,
};
use types::{
    BeaconStateError, ChainSpec, DataColumnSidecar, DataColumnSubnetId, EthSpec, Hash256,
    KzgCommitment, PartialDataColumnSidecarRef, SignedBeaconBlockHeader, SignedExecutionPayloadBid,
    Slot,
};

/// An error occurred while validating a gossip data column.
#[derive(Debug)]
pub enum GossipDataColumnError {
    /// Internal logic error: the column sidecar variant does not match the expected fork.
    /// This is not a peer fault and should not be used to penalize peers.
    InvalidVariant,
    /// There was an error whilst processing the data column. It is not known if it is
    /// valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this data column due to an internal error. It's
    /// unclear if the data column is valid.
    BeaconChainError(Box<BeaconChainError>),
    /// The proposal signature in invalid.
    ///
    /// ## Peer scoring
    ///
    /// The data column is invalid and the peer is faulty.
    ProposalSignatureInvalid,
    /// The proposal_index corresponding to data column.beacon_block_root is not known.
    ///
    /// ## Peer scoring
    ///
    /// The data column is invalid and the peer is faulty.
    UnknownValidator(u64),
    /// The provided data column is not from a later slot than its parent.
    ///
    /// ## Peer scoring
    ///
    /// The data column is invalid and the peer is faulty.
    IsNotLaterThanParent {
        data_column_slot: Slot,
        parent_slot: Slot,
    },
    /// The kzg verification failed.
    ///
    /// ## Peer scoring
    ///
    /// The data column sidecar is invalid and the peer is faulty.
    InvalidKzgProof(kzg::Error),
    /// The column mismatches the cached (possibly partial) column.
    /// This is equivalent to failed kzg verification.
    ///
    /// ## Peer scoring
    ///
    /// The data column sidecar is invalid and the peer is faulty.
    MismatchesCachedColumn,
    /// The column was gossiped over an incorrect subnet.
    ///
    /// ## Peer scoring
    ///
    /// The column is invalid or the peer is faulty.
    InvalidSubnetId { received: u64, expected: u64 },
    /// The column sidecar is from a slot that is later than the current slot (with respect to the
    /// gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    FutureSlot {
        message_slot: Slot,
        latest_permissible_slot: Slot,
    },
    /// The sidecar corresponds to a slot older than the finalized head slot.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this column is valid, but this column is for a finalized slot and is
    /// therefore useless to us.
    PastFinalizedSlot {
        column_slot: Slot,
        finalized_slot: Slot,
    },
    /// The pubkey cache timed out.
    ///
    /// ## Peer scoring
    ///
    /// The column sidecar may be valid, this is an internal error.
    PubkeyCacheTimeout,
    /// The proposer index specified in the sidecar does not match the locally computed
    /// proposer index.
    ///
    /// ## Peer scoring
    ///
    /// The column is invalid and the peer is faulty.
    ProposerIndexMismatch { sidecar: usize, local: usize },
    /// The provided columns's parent block is unknown.
    ///
    /// ## Peer scoring
    ///
    /// We cannot process the columns without validating its parent, the peer isn't necessarily faulty.
    ParentUnknown { parent_root: Hash256, slot: Slot },
    /// The block referenced by the data column is unknown.
    ///
    /// ## Peer scoring
    ///
    /// We cannot process the column without the referenced block, the peer isn't necessarily faulty.
    BlockRootUnknown { block_root: Hash256, slot: Slot },
    /// The data column slot does not match its referenced block slot.
    ///
    /// ## Peer scoring
    ///
    /// The column sidecar is invalid and the peer is faulty.
    BlockSlotMismatch {
        block_slot: Slot,
        data_column_slot: Slot,
    },
    /// The column conflicts with finalization, no need to propagate.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this column is valid, but it conflicts with finality and shouldn't be
    /// imported.
    NotFinalizedDescendant { block_parent_root: Hash256 },
    /// Invalid kzg commitment inclusion proof
    ///
    /// ## Peer scoring
    ///
    /// The column sidecar is invalid and the peer is faulty
    InvalidInclusionProof,
    /// A column has already been seen for the given observation key and index.
    ///
    /// ## Peer scoring
    ///
    /// The peer isn't faulty, but we do not forward it over gossip.
    PriorKnown {
        observation_key: ObservationKey,
        index: ColumnIndex,
    },
    /// A column has already been processed from non-gossip source and have not yet been seen on
    /// the gossip network.
    /// This column should be accepted and forwarded over gossip.
    PriorKnownUnpublished,
    /// Data column index must be between 0 and `NUMBER_OF_COLUMNS` (exclusive).
    ///
    /// ## Peer scoring
    ///
    /// The column sidecar is invalid and the peer is faulty
    InvalidColumnIndex(u64),
    /// Data column not expected for a block with empty kzg commitments.
    ///
    /// ## Peer scoring
    ///
    /// The column sidecar is invalid and the peer is faulty
    UnexpectedDataColumn,
    /// The data column length must be equal to the number of commitments, otherwise the
    /// sidecar is invalid.
    ///
    /// ## Peer scoring
    ///
    /// The column sidecar is invalid and the peer is faulty
    InconsistentCommitmentsLength {
        cells_len: usize,
        commitments_len: usize,
    },
    /// The data column length must be equal to the number of proofs, otherwise the
    /// sidecar is invalid.
    ///
    /// ## Peer scoring
    ///
    /// The column sidecar is invalid and the peer is faulty
    InconsistentProofsLength { cells_len: usize, proofs_len: usize },
    /// The number of KZG commitments exceeds the maximum number of blobs allowed for the fork. The
    /// sidecar is invalid.
    ///
    /// ## Peer scoring
    /// The column sidecar is invalid and the peer is faulty
    MaxBlobsPerBlockExceeded {
        max_blobs_per_block: usize,
        commitments_len: usize,
    },

    /// An internal error occurred.
    ///
    /// ## Peer scoring
    /// This is an internal issue, the peer isn't at fault.
    InternalError(String),
}

impl From<BeaconChainError> for GossipDataColumnError {
    fn from(e: BeaconChainError) -> Self {
        GossipDataColumnError::BeaconChainError(e.into())
    }
}

impl From<BeaconStateError> for GossipDataColumnError {
    fn from(e: BeaconStateError) -> Self {
        GossipDataColumnError::BeaconChainError(BeaconChainError::BeaconStateError(e).into())
    }
}

#[derive(Debug)]
pub enum GossipPartialDataColumnError {
    GossipDataColumnError(GossipDataColumnError),
    /// Partial messages are disabled and we can not validate them.
    ///
    /// ## Peer scoring
    /// A peer sent us a partial message even though we did not advertize support for it, penalize
    /// it
    PartialColumnsDisabled,
    /// There was an unexpected error while performing an operation on the partial data column.
    InternalError(PartialDataColumnSidecarError),
    /// The partial data column does not contain a header, and we do not have it cached.
    ///
    /// ## Peer scoring
    /// The peer SHOULD send us the header on the first partial message, but is not required to.
    /// Still, the peer incorrectly assumed that we have the header, and sent us data we can not
    /// process due to that. Penalize it slightly.
    MissingHeader,
    /// The partial data column header does not match the valid one we have already cached.
    ///
    /// ## Peer scoring
    /// The column sidecar is invalid and the peer is faulty
    HeaderMismatches,
    /// The partial data column header block root does not match the group id.
    ///
    /// ## Peer scoring
    /// The column sidecar is invalid and the peer is faulty
    HeaderIncorrectRoot {
        group_id: Hash256,
        header_hash: Hash256,
    },
    /// The partial message has neither a header nor cells.
    ///
    /// ## Peer scoring
    /// The column sidecar is invalid and the peer is faulty
    EmptyMessage,
    /// The partial message has a count of proofs anc/or cells that is inconsistent with the bitmap.
    ///
    /// ## Peer scoring
    /// The column sidecar is invalid and the peer is faulty
    InconsistentPresentCount {
        bitmap_popcount: usize,
        cells_len: usize,
        proofs_len: usize,
    },
    /// The partial message has a bitmap length that is inconsistent with the number of commitments.
    ///
    /// ## Peer scoring
    /// The column sidecar is invalid and the peer is faulty
    InconsistentCommitmentsLength {
        bitmap_len: usize,
        commitments_len: usize,
    },
}

impl From<GossipDataColumnError> for GossipPartialDataColumnError {
    fn from(e: GossipDataColumnError) -> Self {
        GossipPartialDataColumnError::GossipDataColumnError(e)
    }
}

impl From<BeaconChainError> for GossipPartialDataColumnError {
    fn from(e: BeaconChainError) -> Self {
        GossipDataColumnError::from(e).into()
    }
}

impl From<BeaconStateError> for GossipPartialDataColumnError {
    fn from(e: BeaconStateError) -> Self {
        GossipDataColumnError::from(e).into()
    }
}

/// A wrapper around a `DataColumnSidecar` that indicates it has been approved for re-gossiping on
/// the p2p network.
#[derive(Debug, Clone)]
pub struct GossipVerifiedDataColumn<T: BeaconChainTypes, O: ObservationStrategy = Observe> {
    block_root: Hash256,
    data_column: KzgVerifiedDataColumn<T::EthSpec>,
    _phantom: PhantomData<O>,
}

impl<T: BeaconChainTypes, O: ObservationStrategy> GossipVerifiedDataColumn<T, O> {
    pub fn new(
        column_sidecar: Arc<DataColumnSidecar<T::EthSpec>>,
        subnet_id: DataColumnSubnetId,
        chain: &BeaconChain<T>,
    ) -> Result<Self, GossipDataColumnError> {
        let data_column = match column_sidecar.as_ref() {
            DataColumnSidecar::Fulu(column_sidecar_fulu) => {
                let header = &column_sidecar_fulu.signed_block_header;
                // We only process slashing info if the gossip verification failed
                // since we do not process the data column any further in that case.
                validate_data_column_sidecar_for_gossip_fulu::<T, O>(
                    column_sidecar.clone(),
                    subnet_id,
                    chain,
                )
                .map_err(|e| {
                    process_block_slash_info::<_, GossipDataColumnError>(
                        chain,
                        BlockSlashInfo::from_early_error_data_column(header.clone(), e),
                    )
                })?
            }
            DataColumnSidecar::Gloas(_) => validate_data_column_sidecar_for_gossip_gloas::<T, O>(
                column_sidecar.clone(),
                subnet_id,
                chain,
            )?,
        };

        Ok(GossipVerifiedDataColumn {
            block_root: column_sidecar.block_root(),
            data_column,
            _phantom: PhantomData,
        })
    }

    /// Create a `GossipVerifiedDataColumn` from `DataColumnSidecar` for block production ONLY.
    /// When publishing a block constructed locally, the EL will have already verified the cell proofs.
    /// When publishing a block constructed externally, there will be no columns here.
    pub fn new_for_block_publishing(
        column_sidecar: Arc<DataColumnSidecar<T::EthSpec>>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, GossipDataColumnError> {
        match column_sidecar.as_ref() {
            DataColumnSidecar::Fulu(data_column_fulu) => {
                verify_data_column_sidecar_with_commitments_len(
                    &column_sidecar,
                    data_column_fulu.kzg_commitments.len(),
                    &chain.spec,
                )?;
            }
            DataColumnSidecar::Gloas(_) => {
                let bid = load_gloas_payload_bid(column_sidecar.block_root(), chain)?.ok_or(
                    GossipDataColumnError::BlockRootUnknown {
                        block_root: column_sidecar.block_root(),
                        slot: column_sidecar.slot(),
                    },
                )?;
                verify_data_column_sidecar_with_commitments_len(
                    &column_sidecar,
                    bid.message.blob_kzg_commitments.len(),
                    &chain.spec,
                )?;
            }
        }

        // Check if the data column is already in the DA checker cache. This happens when data columns
        // are made available through the `engine_getBlobs` method.  If it exists in the cache, we know
        // it has already passed the gossip checks, even though this particular instance hasn't been
        // seen / published on the gossip network yet (passed the `verify_is_unknown_sidecar` check above).
        // In this case, we should accept it for gossip propagation.
        verify_is_unknown_sidecar(chain, &column_sidecar)?;

        // Check if this column contains any cells not already in the cache. If all cells are
        // already cached, reject as `PriorKnownUnpublished` to avoid redundant processing.
        match missing_cells_for_column_sidecar(chain, &column_sidecar)? {
            Some(_) => Ok(Self {
                block_root: column_sidecar.block_root(),
                data_column: KzgVerifiedDataColumn::from_execution_verified(column_sidecar),
                _phantom: Default::default(),
            }),
            None => {
                if O::observe() {
                    observe_gossip_data_column(&column_sidecar, chain)?;
                }
                Err(GossipDataColumnError::PriorKnownUnpublished)
            }
        }
    }

    /// Create a `GossipVerifiedDataColumn` from `DataColumnSidecar` for testing ONLY.
    pub fn __new_for_testing(column_sidecar: Arc<DataColumnSidecar<T::EthSpec>>) -> Self {
        Self {
            block_root: column_sidecar.block_root(),
            data_column: KzgVerifiedDataColumn::__new_for_testing(column_sidecar),
            _phantom: Default::default(),
        }
    }

    pub fn as_data_column(&self) -> &DataColumnSidecar<T::EthSpec> {
        self.data_column.as_data_column()
    }

    /// This is cheap as we're calling clone on an Arc
    pub fn clone_data_column(&self) -> Arc<DataColumnSidecar<T::EthSpec>> {
        self.data_column.clone_data_column()
    }

    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    pub fn slot(&self) -> Slot {
        self.data_column.data.slot()
    }

    pub fn index(&self) -> ColumnIndex {
        *self.data_column.data.index()
    }

    pub fn into_inner(self) -> KzgVerifiedDataColumn<T::EthSpec> {
        self.data_column
    }
}

/// Wrapper over a `DataColumnSidecar` for which we have completed kzg verification.
#[derive(Debug, Educe, Clone)]
#[educe(PartialEq, Eq)]
pub struct KzgVerifiedDataColumn<E: EthSpec> {
    data: Arc<DataColumnSidecar<E>>,
    seen_timestamp: Duration,
}

impl<E: EthSpec> KzgVerifiedDataColumn<E> {
    /// Mark a data column as KZG verified. Caller must ONLY use this on columns constructed
    /// from EL blobs.
    pub fn from_execution_verified(data_column: Arc<DataColumnSidecar<E>>) -> Self {
        Self {
            data: data_column,
            seen_timestamp: timestamp_now(),
        }
    }

    /// Create a `KzgVerifiedDataColumn` from `DataColumnSidecar` for testing ONLY.
    pub(crate) fn __new_for_testing(data_column: Arc<DataColumnSidecar<E>>) -> Self {
        Self {
            data: data_column,
            seen_timestamp: timestamp_now(),
        }
    }

    pub fn from_batch_with_scoring(
        data_columns: Vec<Arc<DataColumnSidecar<E>>>,
        kzg: &Kzg,
    ) -> Result<Vec<Self>, (Option<ColumnIndex>, KzgError)> {
        let seen_timestamp = timestamp_now();
        verify_kzg_for_data_column_list(data_columns.iter(), kzg)?;
        Ok(data_columns
            .into_iter()
            .map(|column| Self {
                data: column,
                seen_timestamp,
            })
            .collect())
    }

    pub fn from_batch_with_scoring_and_commitments(
        data_columns: Vec<Arc<DataColumnSidecar<E>>>,
        kzg_commitments: &[KzgCommitment],
        kzg: &Kzg,
    ) -> Result<Vec<Self>, (Option<ColumnIndex>, KzgError)> {
        let _timer = metrics::start_timer(&metrics::KZG_VERIFICATION_DATA_COLUMN_BATCH_TIMES);
        let seen_timestamp = timestamp_now();
        validate_data_columns_with_commitments(kzg, data_columns.iter(), kzg_commitments)?;
        Ok(data_columns
            .into_iter()
            .map(|column| Self {
                data: column,
                seen_timestamp,
            })
            .collect())
    }

    pub fn to_data_column(self) -> Arc<DataColumnSidecar<E>> {
        self.data
    }
    pub fn as_data_column(&self) -> &DataColumnSidecar<E> {
        &self.data
    }
    /// This is cheap as we're calling clone on an Arc
    pub fn clone_data_column(&self) -> Arc<DataColumnSidecar<E>> {
        self.data.clone()
    }

    pub fn index(&self) -> ColumnIndex {
        *self.data.index()
    }
}

/// Wrapper over a `VerifiablePartialDataColumn` for which we have completed kzg verification.
#[derive(Debug, Educe, Clone)]
#[educe(PartialEq, Eq)]
pub struct KzgVerifiedPartialDataColumn<E: EthSpec> {
    data: Arc<PartialDataColumn<E>>,
    latest_cell_timestamp: Duration,
}

impl<E: EthSpec> KzgVerifiedPartialDataColumn<E> {
    /// Create a `KzgVerifiedPartialDataColumn` for testing ONLY.
    pub(crate) fn __new_for_testing(data_column: Arc<PartialDataColumn<E>>) -> Self {
        Self {
            data: data_column,
            latest_cell_timestamp: timestamp_now(),
        }
    }

    /// Mark a partial data column as KZG verified. Caller must ONLY use this on columns constructed
    /// from EL blobs.
    pub fn from_execution_verified(data_column: Arc<PartialDataColumn<E>>) -> Self {
        Self {
            data: data_column,
            latest_cell_timestamp: timestamp_now(),
        }
    }

    pub fn to_data_column(self) -> Arc<PartialDataColumn<E>> {
        self.data
    }

    pub fn as_data_column(&self) -> &PartialDataColumn<E> {
        &self.data
    }

    pub fn index(&self) -> ColumnIndex {
        self.data.index
    }

    pub fn block_root(&self) -> Hash256 {
        self.data.block_root
    }
}

/// Wrapper over a `PartialDataColumnHeader` for which we have completed gossip verification.
#[derive(Debug, Educe, Clone)]
#[educe(PartialEq, Eq)]
pub struct GossipVerifiedPartialDataColumnHeader<E: EthSpec> {
    header: Arc<PartialDataColumnHeader<E>>,
    previously_cached: bool,
}

impl<E: EthSpec> GossipVerifiedPartialDataColumnHeader<E> {
    pub fn new<T: BeaconChainTypes<EthSpec = E>>(
        group_id: Hash256,
        header: PartialDataColumnHeader<E>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, GossipPartialDataColumnError> {
        let column_slot = header.slot();
        if header.kzg_commitments.is_empty() {
            return Err(GossipDataColumnError::UnexpectedDataColumn.into());
        }

        let header_hash = header.signed_block_header.message.canonical_root();
        if group_id != header_hash {
            return Err(GossipPartialDataColumnError::HeaderIncorrectRoot {
                group_id,
                header_hash,
            });
        }

        verify_sidecar_not_from_future_slot(chain, column_slot)?;
        verify_slot_greater_than_latest_finalized_slot(chain, column_slot)?;
        verify_partial_column_header_inclusion_proof(&header)?;
        let parent_block = verify_parent_block_and_finalized_descendant(
            header.signed_block_header.message.parent_root,
            column_slot,
            chain,
        )?;
        verify_slot_higher_than_parent(&parent_block, column_slot)?;
        verify_proposer_and_signature(&header.signed_block_header, &parent_block, chain)?;

        let header = Arc::new(header);

        // Cache the valid header
        let Some(assembler) = chain.data_availability_checker.partial_assembler() else {
            return Err(GossipPartialDataColumnError::PartialColumnsDisabled);
        };
        let newly_cached = assembler.init(group_id, header.clone());

        chain
            .observed_slashable
            .write()
            .observe_slashable(
                column_slot,
                header.signed_block_header.message.proposer_index,
                header_hash,
            )
            .map_err(BeaconChainError::from)?;

        Ok(Self {
            header,
            previously_cached: !newly_cached,
        })
    }

    pub fn new_from_cached(header: Arc<PartialDataColumnHeader<E>>) -> Self {
        Self {
            header,
            previously_cached: true,
        }
    }

    pub fn was_cached(&self) -> bool {
        self.previously_cached
    }

    pub fn as_header(&self) -> &PartialDataColumnHeader<E> {
        &self.header
    }

    pub fn into_header(self) -> Arc<PartialDataColumnHeader<E>> {
        self.header
    }
}

pub type CustodyDataColumnList<E> =
    VariableList<CustodyDataColumn<E>, <E as EthSpec>::NumberOfColumns>;

/// Data column that we must custody
#[derive(Debug, Educe, Clone, Encode)]
#[educe(PartialEq, Eq, Hash(bound(E: EthSpec)))]
#[ssz(struct_behaviour = "transparent")]
pub struct CustodyDataColumn<E: EthSpec> {
    data: Arc<DataColumnSidecar<E>>,
}

impl<E: EthSpec> CustodyDataColumn<E> {
    /// Mark a column as custody column. Caller must ensure that our current custody requirements
    /// include this column
    pub fn from_asserted_custody(data: Arc<DataColumnSidecar<E>>) -> Self {
        Self { data }
    }

    pub fn into_inner(self) -> Arc<DataColumnSidecar<E>> {
        self.data
    }
    pub fn as_data_column(&self) -> &Arc<DataColumnSidecar<E>> {
        &self.data
    }
    /// This is cheap as we're calling clone on an Arc
    pub fn clone_arc(&self) -> Arc<DataColumnSidecar<E>> {
        self.data.clone()
    }
    pub fn index(&self) -> u64 {
        *self.data.index()
    }
}

/// Data column that we must custody and has completed kzg verification.
/// Wraps a full `DataColumnSidecar`.
#[derive(Debug, Educe, Clone)]
#[educe(PartialEq, Eq)]
pub struct KzgVerifiedCustodyDataColumn<E: EthSpec> {
    data: Arc<DataColumnSidecar<E>>,
    seen_timestamp: Duration,
}

impl<E: EthSpec> KzgVerifiedCustodyDataColumn<E> {
    /// Mark a column as custody column. Caller must ensure that our current custody requirements
    /// include this column
    pub fn from_asserted_custody(kzg_verified: KzgVerifiedDataColumn<E>) -> Self {
        Self {
            seen_timestamp: kzg_verified.seen_timestamp,
            data: kzg_verified.to_data_column(),
        }
    }

    pub fn reconstruct_columns(
        kzg: &Kzg,
        partial_set_of_columns: Vec<Arc<DataColumnSidecar<E>>>,
        kzg_commitments: &[KzgCommitment],
        spec: &ChainSpec,
    ) -> Result<Vec<KzgVerifiedCustodyDataColumn<E>>, KzgError> {
        let all_data_columns =
            reconstruct_data_columns(kzg, partial_set_of_columns, kzg_commitments, spec)?;

        let seen_timestamp = timestamp_now();

        Ok(all_data_columns
            .into_iter()
            .map(|data| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(KzgVerifiedDataColumn {
                    data,
                    seen_timestamp,
                })
            })
            .collect::<Vec<_>>())
    }

    pub fn into_inner(self) -> Arc<DataColumnSidecar<E>> {
        self.data
    }

    pub fn as_data_column(&self) -> &DataColumnSidecar<E> {
        &self.data
    }
    pub fn clone_arc(&self) -> Arc<DataColumnSidecar<E>> {
        self.data.clone()
    }
    pub fn index(&self) -> ColumnIndex {
        *self.data.index()
    }

    pub fn seen_timestamp(&self) -> Duration {
        self.seen_timestamp
    }
}

/// Partial data column that we must custody and has completed kzg verification.
/// Wraps a `VerifiablePartialDataColumn`.
#[derive(Debug, Educe, Clone)]
#[educe(PartialEq, Eq)]
pub struct KzgVerifiedCustodyPartialDataColumn<E: EthSpec> {
    data: Arc<PartialDataColumn<E>>,
    latest_cell_timestamp: Duration,
}

impl<E: EthSpec> KzgVerifiedCustodyPartialDataColumn<E> {
    /// Mark a partial column as custody column. Caller must ensure that our current custody requirements
    /// include this column
    pub fn from_asserted_custody(kzg_verified: KzgVerifiedPartialDataColumn<E>) -> Self {
        Self {
            latest_cell_timestamp: kzg_verified.latest_cell_timestamp,
            data: kzg_verified.to_data_column(),
        }
    }

    pub fn into_inner(self) -> Arc<PartialDataColumn<E>> {
        self.data
    }

    pub fn as_data_column(&self) -> &PartialDataColumn<E> {
        &self.data
    }

    pub fn index(&self) -> ColumnIndex {
        self.data.index
    }

    /// Merge two verified partial data columns.
    ///
    /// Each column must be internally consistent. Additionally, the columns to be merged must have
    /// the same block root and index.
    /// An error is returned if the columns are internally inconsistent or incompatible for merging.
    ///
    /// If both columns contain the same cell, the cell from `self` is used - however, as they are
    /// KZG verified, they will be the same.
    pub fn merge(&self, other: &Self) -> Result<Self, PartialDataColumnSidecarError> {
        let self_sidecar = &self.data.sidecar;
        let other_sidecar = &other.data.sidecar;

        // Check that each sidecar is internally consistent by checking the lengths.
        self_sidecar.verify_len()?;
        other_sidecar.verify_len()?;
        if self.data.block_root != other.data.block_root || self.data.index != other.data.index {
            return Err(PartialDataColumnSidecarError::ConflictingData);
        }
        if self_sidecar.cells_present_bitmap.len() != other_sidecar.cells_present_bitmap.len() {
            return Err(PartialDataColumnSidecarError::DifferingLengths {
                lhs_len: self_sidecar.cells_present_bitmap.len(),
                rhs_len: other_sidecar.cells_present_bitmap.len(),
            });
        }

        let new_bitmap = self_sidecar
            .cells_present_bitmap
            .union(&other_sidecar.cells_present_bitmap);
        let len = new_bitmap.num_set_bits();
        let mut new_column = Vec::with_capacity(len);
        let mut new_proofs = Vec::with_capacity(len);
        let mut self_iter = self_sidecar
            .column
            .iter()
            .zip(self_sidecar.kzg_proofs.iter());
        let mut other_iter = other_sidecar
            .column
            .iter()
            .zip(other_sidecar.kzg_proofs.iter());

        for presence_bits in self_sidecar
            .cells_present_bitmap
            .iter()
            .zip(other_sidecar.cells_present_bitmap.iter())
        {
            match presence_bits {
                (false, false) => {}
                (true, other) => {
                    let (cell, proof) = self_iter
                        .next()
                        .ok_or(PartialDataColumnSidecarError::UnexpectedBounds)?;
                    new_column.push(cell.clone());
                    new_proofs.push(*proof);
                    if other {
                        other_iter
                            .next()
                            .ok_or(PartialDataColumnSidecarError::UnexpectedBounds)?;
                    }
                }
                (false, true) => {
                    let (cell, proof) = other_iter
                        .next()
                        .ok_or(PartialDataColumnSidecarError::UnexpectedBounds)?;
                    new_column.push(cell.clone());
                    new_proofs.push(*proof);
                }
            }
        }

        Ok(Self {
            data: Arc::new(PartialDataColumn {
                block_root: self.data.block_root,
                index: self.data.index,
                sidecar: PartialDataColumnSidecar {
                    cells_present_bitmap: new_bitmap,
                    column: new_column
                        .try_into()
                        .map_err(|_| PartialDataColumnSidecarError::UnexpectedBounds)?,
                    kzg_proofs: new_proofs
                        .try_into()
                        .map_err(|_| PartialDataColumnSidecarError::UnexpectedBounds)?,
                    header: if self_sidecar.header.is_some() {
                        self_sidecar.header.clone()
                    } else {
                        other_sidecar.header.clone()
                    },
                },
            }),
            latest_cell_timestamp: self.latest_cell_timestamp.max(other.latest_cell_timestamp),
        })
    }

    pub fn try_clone_full(
        &self,
        header: &PartialDataColumnHeader<E>,
    ) -> Option<KzgVerifiedCustodyDataColumn<E>> {
        self.data
            .try_clone_full(header)
            .map(|data| KzgVerifiedCustodyDataColumn {
                data: Arc::new(data),
                seen_timestamp: self.latest_cell_timestamp,
            })
    }

    /// Try to convert the partial data column into a full one, returning None if the conversion
    /// fails.
    /// May clone the column if the Arc cannot be unwrapped.
    pub fn try_into_full(
        self,
        header: &PartialDataColumnHeader<E>,
    ) -> Option<KzgVerifiedCustodyDataColumn<E>> {
        match Arc::try_unwrap(self.data) {
            Ok(data) => data.try_into_full(header),
            Err(data) => data.try_clone_full(header),
        }
        .map(|data| KzgVerifiedCustodyDataColumn {
            data: Arc::new(data),
            seen_timestamp: self.latest_cell_timestamp,
        })
    }
}

/// Complete kzg verification for a `DataColumnSidecar`.
///
/// Returns an error if the kzg verification check fails.
#[instrument(skip_all, level = "debug")]
pub fn verify_kzg_for_data_column<E: EthSpec>(
    data_column: Arc<DataColumnSidecar<E>>,
    cells_to_verify: PartialDataColumnSidecarRef<E>,
    kzg: &Kzg,
    seen_timestamp: Duration,
) -> Result<KzgVerifiedDataColumn<E>, (Option<ColumnIndex>, KzgError)> {
    let _timer = metrics::start_timer(&metrics::KZG_VERIFICATION_DATA_COLUMN_SINGLE_TIMES);
    let Ok(kzg_commitments) = data_column.kzg_commitments() else {
        return Err((
            Some(*data_column.index()),
            KzgError::InconsistentArrayLength("todo(gloas)".to_string()),
        ));
    };
    validate_partial_data_columns(
        kzg,
        iter::once((*data_column.index(), cells_to_verify)),
        kzg_commitments,
    )?;
    Ok(KzgVerifiedDataColumn {
        data: data_column,
        seen_timestamp,
    })
}

#[instrument(skip_all, level = "debug")]
pub fn verify_kzg_for_data_column_with_commitments<E: EthSpec>(
    data_column: Arc<DataColumnSidecar<E>>,
    cells_to_verify: PartialDataColumnSidecarRef<E>,
    kzg_commitments: &[KzgCommitment],
    kzg: &Kzg,
    seen_timestamp: Duration,
) -> Result<KzgVerifiedDataColumn<E>, (Option<ColumnIndex>, KzgError)> {
    let _timer = metrics::start_timer(&metrics::KZG_VERIFICATION_DATA_COLUMN_SINGLE_TIMES);
    validate_partial_data_columns(
        kzg,
        iter::once((*data_column.index(), cells_to_verify)),
        kzg_commitments,
    )?;
    Ok(KzgVerifiedDataColumn {
        data: data_column,
        seen_timestamp,
    })
}

/// Complete kzg verification for a `VerifiablePartialDataColumn`.
///
/// Returns an error if the kzg verification check fails.
#[instrument(skip_all, level = "debug")]
pub fn verify_kzg_for_partial_data_column<E: EthSpec>(
    data_column: Arc<PartialDataColumn<E>>,
    cells_to_verify: PartialDataColumnSidecarRef<E>,
    header: &GossipVerifiedPartialDataColumnHeader<E>,
    kzg: &Kzg,
    seen_timestamp: Duration,
) -> Result<KzgVerifiedPartialDataColumn<E>, GossipPartialDataColumnError> {
    let _timer = metrics::start_timer(&metrics::KZG_VERIFICATION_DATA_COLUMN_SINGLE_TIMES);
    validate_partial_data_columns(
        kzg,
        iter::once((data_column.index, cells_to_verify)),
        header.header.kzg_commitments.as_ref(),
    )
    .map_err(|(_, e)| GossipDataColumnError::InvalidKzgProof(e))?;
    Ok(KzgVerifiedPartialDataColumn {
        data: data_column,
        latest_cell_timestamp: seen_timestamp,
    })
}

/// Complete kzg verification for a list of `DataColumnSidecar`s.
/// Returns an error for the first `DataColumnSidecar`s that fails kzg verification.
///
/// Note: This function should be preferred over calling `verify_kzg_for_data_column`
/// in a loop since this function kzg verifies a list of data columns more efficiently.
pub fn verify_kzg_for_data_column_list<'a, E: EthSpec, I>(
    data_column_iter: I,
    kzg: &'a Kzg,
) -> Result<(), (Option<ColumnIndex>, KzgError)>
where
    I: Iterator<Item = &'a Arc<DataColumnSidecar<E>>> + Clone,
{
    let _timer = metrics::start_timer(&metrics::KZG_VERIFICATION_DATA_COLUMN_BATCH_TIMES);
    validate_full_data_columns(kzg, data_column_iter)?;
    Ok(())
}

#[instrument(
    skip_all,
    name = "validate_data_column_sidecar_for_gossip",
    level = "debug"
)]
pub fn validate_data_column_sidecar_for_gossip_fulu<T: BeaconChainTypes, O: ObservationStrategy>(
    data_column: Arc<DataColumnSidecar<T::EthSpec>>,
    subnet: DataColumnSubnetId,
    chain: &BeaconChain<T>,
) -> Result<KzgVerifiedDataColumn<T::EthSpec>, GossipDataColumnError> {
    let DataColumnSidecar::Fulu(data_column_fulu) = data_column.as_ref() else {
        return Err(GossipDataColumnError::InvalidVariant);
    };

    let column_slot = data_column.slot();

    verify_data_column_sidecar_with_commitments_len(
        &data_column,
        data_column_fulu.kzg_commitments.len(),
        &chain.spec,
    )?;
    verify_index_matches_subnet(&data_column, subnet, &chain.spec)?;
    verify_sidecar_not_from_future_slot(chain, column_slot)?;
    verify_slot_greater_than_latest_finalized_slot(chain, column_slot)?;
    verify_is_unknown_sidecar(chain, &data_column)?;

    // Check if the data column is already in the DA checker cache. This happens when data columns
    // are made available through the `engine_getBlobs` method and/or partial messages have arrived.
    // If it exists in the cache, we know it has already passed the gossip checks, even though this
    // particular instance hasn't been seen / published on the gossip network yet (passed the
    // `verify_is_unknown_sidecar` check above). In this case, we should accept it for gossip
    // propagation.
    let Some(cells_to_kzg_verify) = chain
        .data_availability_checker
        .missing_cells_for_column_sidecar(&data_column)
        .map_err(|err| match err {
            MissingCellsError::MismatchesCachedColumn => {
                GossipDataColumnError::MismatchesCachedColumn
            }
            MissingCellsError::UnexpectedError(e) => GossipDataColumnError::InternalError(format!(
                "An unexpected error occurred while validating fulu data columns. {:?}",
                e
            )),
        })?
    else {
        // Observe this data column so we don't process it again.
        if O::observe() {
            observe_gossip_data_column(&data_column, chain)?;
        }
        return Err(GossipDataColumnError::PriorKnownUnpublished);
    };

    verify_column_inclusion_proof(&data_column)?;
    let parent_block = verify_parent_block_and_finalized_descendant(
        data_column_fulu.block_parent_root(),
        column_slot,
        chain,
    )?;
    verify_slot_higher_than_parent(&parent_block, column_slot)?;
    verify_proposer_and_signature(&data_column_fulu.signed_block_header, &parent_block, chain)?;

    let kzg_verified = verify_kzg_for_data_column(
        data_column.clone(),
        cells_to_kzg_verify,
        &chain.kzg,
        chain.slot_clock.now_duration().unwrap_or_default(),
    )
    .map_err(|(_, e)| GossipDataColumnError::InvalidKzgProof(e))?;

    chain
        .observed_slashable
        .write()
        .observe_slashable(
            column_slot,
            data_column_fulu.block_proposer_index(),
            data_column.block_root(),
        )
        .map_err(|e| GossipDataColumnError::BeaconChainError(Box::new(e.into())))?;

    if O::observe() {
        observe_gossip_data_column(&data_column, chain)?;
    }

    Ok(kzg_verified)
}

#[instrument(
    skip_all,
    name = "validate_data_column_sidecar_for_gossip_gloas",
    level = "debug"
)]
pub fn validate_data_column_sidecar_for_gossip_gloas<
    T: BeaconChainTypes,
    O: ObservationStrategy,
>(
    data_column: Arc<DataColumnSidecar<T::EthSpec>>,
    subnet: DataColumnSubnetId,
    chain: &BeaconChain<T>,
) -> Result<KzgVerifiedDataColumn<T::EthSpec>, GossipDataColumnError> {
    let DataColumnSidecar::Gloas(_) = data_column.as_ref() else {
        return Err(GossipDataColumnError::InvalidVariant);
    };

    let column_slot = data_column.slot();

    if *data_column.index() >= T::EthSpec::number_of_columns() as u64 {
        return Err(GossipDataColumnError::InvalidColumnIndex(
            *data_column.index(),
        ));
    }
    verify_index_matches_subnet(&data_column, subnet, &chain.spec)?;
    verify_sidecar_not_from_future_slot(chain, column_slot)?;
    verify_slot_greater_than_latest_finalized_slot(chain, column_slot)?;
    verify_is_unknown_sidecar(chain, &data_column)?;

    let bid = load_gloas_payload_bid(data_column.block_root(), chain)?.ok_or(
        GossipDataColumnError::BlockRootUnknown {
            block_root: data_column.block_root(),
            slot: column_slot,
        },
    )?;
    if bid.message.slot != column_slot {
        return Err(GossipDataColumnError::BlockSlotMismatch {
            block_slot: bid.message.slot,
            data_column_slot: column_slot,
        });
    }
    let kzg_commitments = &bid.message.blob_kzg_commitments;
    verify_data_column_sidecar_with_commitments_len(
        &data_column,
        kzg_commitments.len(),
        &chain.spec,
    )?;

    let Some(cells_to_kzg_verify) = missing_cells_for_column_sidecar(chain, &data_column)? else {
        // Observe this data column so we don't process it again.
        if O::observe() {
            observe_gossip_data_column(&data_column, chain)?;
        }
        return Err(GossipDataColumnError::PriorKnownUnpublished);
    };

    let kzg = &chain.kzg;
    let seen_timestamp = chain.slot_clock.now_duration().unwrap_or_default();
    let kzg_verified = verify_kzg_for_data_column_with_commitments(
        data_column.clone(),
        cells_to_kzg_verify,
        kzg_commitments.as_ref(),
        kzg,
        seen_timestamp,
    )
    .map_err(|(_, e)| GossipDataColumnError::InvalidKzgProof(e))?;

    if O::observe() {
        observe_gossip_data_column(&data_column, chain)?;
    }

    Ok(kzg_verified)
}

#[instrument(skip_all, level = "debug")]
pub fn validate_partial_data_column_sidecar_for_gossip<T: BeaconChainTypes>(
    mut column: Box<PartialDataColumn<T::EthSpec>>,
    chain: &BeaconChain<T>,
    seen_timestamp: Duration,
) -> PartialColumnVerificationResult<T::EthSpec> {
    let block_root = column.block_root;

    // Remove the header (if any) to avoid wasted memory.
    let header = column.sidecar.header.take();

    let header = if let Some(header) = header {
        // Header was sent, so it is required to be valid
        match chain.verify_partial_data_column_header_for_gossip(block_root, header) {
            Ok(verified) => verified,
            Err(err) => {
                return PartialColumnVerificationResult::Err(err);
            }
        }
    } else {
        let Some(assembler) = chain.data_availability_checker.partial_assembler() else {
            return PartialColumnVerificationResult::Err(
                GossipPartialDataColumnError::PartialColumnsDisabled,
            );
        };

        // There is no header, so we check if we have a cached one to use
        let Some(header) = assembler
            .get_header(&column.block_root)
            .map(GossipVerifiedPartialDataColumnHeader::new_from_cached)
        else {
            return PartialColumnVerificationResult::Err(
                GossipPartialDataColumnError::MissingHeader,
            );
        };

        // If there was no header, there must be at least one cell.
        if column.sidecar.column.is_empty() {
            return PartialColumnVerificationResult::ErrWithValidHeader {
                err: GossipPartialDataColumnError::EmptyMessage,
                header,
            };
        }

        header
    };

    // The number of cells nad proofs must match the population count of the bitmap.
    let bitmap_popcount = column.sidecar.cells_present_bitmap.num_set_bits();
    let cells_len = column.sidecar.column.len();
    let proofs_len = column.sidecar.kzg_proofs.len();
    if bitmap_popcount != cells_len || bitmap_popcount != proofs_len {
        return PartialColumnVerificationResult::ErrWithValidHeader {
            err: GossipPartialDataColumnError::InconsistentPresentCount {
                bitmap_popcount,
                cells_len,
                proofs_len,
            },
            header,
        };
    }

    let bitmap_len = column.sidecar.cells_present_bitmap.len();
    let commitments_len = header.as_header().kzg_commitments.len();
    if bitmap_len != commitments_len {
        return PartialColumnVerificationResult::ErrWithValidHeader {
            err: GossipPartialDataColumnError::InconsistentCommitmentsLength {
                bitmap_len,
                commitments_len,
            },
            header,
        };
    }

    let column = Arc::from(column);
    let cells_to_kzg_verify = match chain
        .data_availability_checker
        .missing_cells_for_partial_column_sidecar(&column)
    {
        Ok(Some(cells_to_kzg_verify)) => cells_to_kzg_verify,
        Ok(None) => {
            return PartialColumnVerificationResult::ErrWithValidHeader {
                err: GossipDataColumnError::PriorKnownUnpublished.into(),
                header,
            };
        }
        Err(MissingCellsError::MismatchesCachedColumn) => {
            return PartialColumnVerificationResult::ErrWithValidHeader {
                err: GossipDataColumnError::MismatchesCachedColumn.into(),
                header,
            };
        }
        Err(MissingCellsError::UnexpectedError(e)) => {
            return PartialColumnVerificationResult::ErrWithValidHeader {
                err: GossipDataColumnError::InternalError(format!(
                    "An unexpected error occurred while validating partial data columns: {:?}",
                    e
                ))
                .into(),
                header,
            };
        }
    };

    // We do not have to check block related data here, as we create the verifiable column from
    // gossip accepted block
    let kzg = &chain.kzg;
    let column = match verify_kzg_for_partial_data_column(
        column.clone(),
        cells_to_kzg_verify,
        &header,
        kzg,
        seen_timestamp,
    ) {
        Ok(column) => column,
        Err(err) => {
            return PartialColumnVerificationResult::ErrWithValidHeader { err, header };
        }
    };

    PartialColumnVerificationResult::Ok { column, header }
}

/// The result of a `validate_partial_data_column_sidecar_for_gossip` call. Any headers returned
/// herein were cached during this call or previously cached.
pub enum PartialColumnVerificationResult<E: EthSpec> {
    /// Verification succeeded fully.
    Ok {
        column: KzgVerifiedPartialDataColumn<E>,
        header: GossipVerifiedPartialDataColumnHeader<E>,
    },
    /// Verification of the column failed, but the header is valid.
    ErrWithValidHeader {
        err: GossipPartialDataColumnError,
        header: GossipVerifiedPartialDataColumnHeader<E>,
    },
    /// Verification of the column or header failed, and no valid header was cached previously.
    Err(GossipPartialDataColumnError),
}

fn verify_data_column_sidecar_with_commitments_len<E: EthSpec>(
    data_column: &DataColumnSidecar<E>,
    commitments_len: usize,
    spec: &ChainSpec,
) -> Result<(), GossipDataColumnError> {
    if *data_column.index() >= E::number_of_columns() as u64 {
        return Err(GossipDataColumnError::InvalidColumnIndex(
            *data_column.index(),
        ));
    }

    if commitments_len == 0 {
        return Err(GossipDataColumnError::UnexpectedDataColumn);
    }

    let cells_len = data_column.column().len();
    let proofs_len = data_column.kzg_proofs().len();
    let max_blobs_per_block = spec.max_blobs_per_block(data_column.epoch()) as usize;

    if commitments_len > max_blobs_per_block {
        return Err(GossipDataColumnError::MaxBlobsPerBlockExceeded {
            max_blobs_per_block,
            commitments_len,
        });
    }

    if cells_len != commitments_len {
        return Err(GossipDataColumnError::InconsistentCommitmentsLength {
            cells_len,
            commitments_len,
        });
    }

    if cells_len != proofs_len {
        return Err(GossipDataColumnError::InconsistentProofsLength {
            cells_len,
            proofs_len,
        });
    }

    Ok(())
}

/// Loads the Gloas payload bid for `block_root` from the `pending_payload_cache`, the
/// `early_attester_cache`, or the on-disk store (in that order).
///
/// TODO(gloas): the store fallback is a synchronous disk read and several callers run inside
/// `async` gossip / RPC validation paths. Move the disk path off the async runtime (e.g. behind
/// `spawn_blocking`) — or restructure callers to fetch the bid before entering async — once the
/// gossip pipeline is reworked for Gloas. The cache and early-attester paths are short
/// in-memory locks and acceptable as-is.
pub(crate) fn load_gloas_payload_bid<T: BeaconChainTypes>(
    block_root: Hash256,
    chain: &BeaconChain<T>,
) -> Result<Option<Arc<SignedExecutionPayloadBid<T::EthSpec>>>, BeaconChainError> {
    if let Some(bid) = chain.pending_payload_cache.get_bid(&block_root) {
        return Ok(Some(bid));
    }

    let bid = if let Some(block) = chain.early_attester_cache.get_block(block_root) {
        Arc::new(
            block
                .message()
                .body()
                .signed_execution_payload_bid()
                .map_err(BeaconChainError::BeaconStateError)?
                .clone(),
        )
    } else {
        match chain
            .store
            .try_get_full_block(&block_root)
            .map_err(BeaconChainError::DBError)?
        {
            Some(DatabaseBlock::Full(block)) => Arc::new(
                block
                    .message()
                    .body()
                    .signed_execution_payload_bid()
                    .map_err(BeaconChainError::BeaconStateError)?
                    .clone(),
            ),
            Some(DatabaseBlock::Blinded(block)) => Arc::new(
                block
                    .message()
                    .body()
                    .signed_execution_payload_bid()
                    .map_err(BeaconChainError::BeaconStateError)?
                    .clone(),
            ),
            None => {
                return Ok(None);
            }
        }
    };

    chain
        .pending_payload_cache
        .insert_bid(block_root, bid.clone());

    Ok(Some(bid))
}

fn missing_cells_for_column_sidecar<'a, T: BeaconChainTypes>(
    chain: &'_ BeaconChain<T>,
    data_column: &'a DataColumnSidecar<T::EthSpec>,
) -> Result<Option<PartialDataColumnSidecarRef<'a, T::EthSpec>>, GossipDataColumnError> {
    let result = if chain
        .spec
        .fork_name_at_slot::<T::EthSpec>(data_column.slot())
        .gloas_enabled()
    {
        chain
            .pending_payload_cache
            .missing_cells_for_column_sidecar(data_column)
    } else {
        chain
            .data_availability_checker
            .missing_cells_for_column_sidecar(data_column)
    };

    result.map_err(|err| match err {
        MissingCellsError::MismatchesCachedColumn => GossipDataColumnError::MismatchesCachedColumn,
        MissingCellsError::UnexpectedError(e) => GossipDataColumnError::InternalError(format!(
            "An unexpected error occurred while calculating missing partial cells {:?}",
            e
        )),
    })
}

/// Verify that `column_sidecar` is not yet known, i.e. this is the first time `column_sidecar` has been received for the tuple:
/// `(block_header.slot, block_header.proposer_index, column_sidecar.index)`
fn verify_is_unknown_sidecar<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    column_sidecar: &DataColumnSidecar<T::EthSpec>,
) -> Result<(), GossipDataColumnError> {
    if let Some(observation_key) = chain
        .observed_column_sidecars
        .read()
        .observation_key_is_known(column_sidecar)
        .map_err(|e: ObservedDataSidecarsError| {
            GossipDataColumnError::BeaconChainError(Box::new(e.into()))
        })?
    {
        return Err(GossipDataColumnError::PriorKnown {
            observation_key,
            index: *column_sidecar.index(),
        });
    }
    Ok(())
}

fn verify_column_inclusion_proof<E: EthSpec>(
    data_column: &DataColumnSidecar<E>,
) -> Result<(), GossipDataColumnError> {
    let _timer = metrics::start_timer(&metrics::DATA_COLUMN_SIDECAR_INCLUSION_PROOF_VERIFICATION);

    let DataColumnSidecar::Fulu(data_column_fulu) = data_column else {
        return Err(GossipDataColumnError::InvalidVariant);
    };

    if !data_column_fulu.verify_inclusion_proof() {
        return Err(GossipDataColumnError::InvalidInclusionProof);
    }

    Ok(())
}

fn verify_partial_column_header_inclusion_proof<E: EthSpec>(
    header: &PartialDataColumnHeader<E>,
) -> Result<(), GossipDataColumnError> {
    let _timer = metrics::start_timer(&metrics::DATA_COLUMN_SIDECAR_INCLUSION_PROOF_VERIFICATION);
    if !header.verify_inclusion_proof() {
        return Err(GossipDataColumnError::InvalidInclusionProof);
    }

    Ok(())
}

fn verify_slot_higher_than_parent(
    parent_block: &Block,
    data_column_slot: Slot,
) -> Result<(), GossipDataColumnError> {
    if parent_block.slot >= data_column_slot {
        return Err(GossipDataColumnError::IsNotLaterThanParent {
            data_column_slot,
            parent_slot: parent_block.slot,
        });
    }
    Ok(())
}

fn verify_parent_block_and_finalized_descendant<T: BeaconChainTypes>(
    block_parent_root: Hash256,
    slot: Slot,
    chain: &BeaconChain<T>,
) -> Result<ProtoBlock, GossipDataColumnError> {
    let fork_choice = chain.canonical_head.fork_choice_read_lock();

    // We have already verified that the column is past finalization, so we can
    // just check fork choice for the block's parent.
    let Some(parent_block) = fork_choice.get_block(&block_parent_root) else {
        return Err(GossipDataColumnError::ParentUnknown {
            parent_root: block_parent_root,
            slot,
        });
    };

    // Do not process a column that does not descend from the finalized root.
    // We just loaded the parent_block, so we can be sure that it exists in fork choice.
    if !fork_choice.is_finalized_checkpoint_or_descendant(block_parent_root) {
        return Err(GossipDataColumnError::NotFinalizedDescendant { block_parent_root });
    }

    Ok(parent_block)
}

fn verify_proposer_and_signature<T: BeaconChainTypes>(
    signed_block_header: &SignedBeaconBlockHeader,
    parent_block: &ProtoBlock,
    chain: &BeaconChain<T>,
) -> Result<(), GossipDataColumnError> {
    let column_slot = signed_block_header.message.slot;
    let slots_per_epoch = T::EthSpec::slots_per_epoch();
    let column_epoch = column_slot.epoch(slots_per_epoch);
    let block_root = signed_block_header.message.tree_hash_root();
    let block_parent_root = signed_block_header.message.parent_root;

    let proposer_shuffling_root =
        parent_block.proposer_shuffling_root_for_child_block(column_epoch, &chain.spec);

    let proposer = chain.with_proposer_cache(
        proposer_shuffling_root,
        column_epoch,
        |proposers| proposers.get_slot::<T::EthSpec>(column_slot),
        || {
            debug!(
                %block_root,
                "Proposer shuffling cache miss for column verification"
            );
            // We assume that the `Pending` state has the same shufflings as a `Full` state
            // for the same block. Analysis: https://hackmd.io/@dapplion/gloas_dependant_root
            chain
                .store
                .get_advanced_hot_state(block_parent_root, column_slot, parent_block.state_root)
                .map_err(|e| GossipDataColumnError::BeaconChainError(Box::new(e.into())))?
                .ok_or_else(|| {
                    GossipDataColumnError::BeaconChainError(Box::new(
                        BeaconChainError::DBInconsistent(format!(
                            "Missing state for parent block {block_parent_root:?}",
                        )),
                    ))
                })
        },
    )?;
    let proposer_index = proposer.index;
    let fork = proposer.fork;

    // Signature verify the signed block header.
    let signature_is_valid = {
        let pubkey_cache = get_validator_pubkey_cache(chain)
            .map_err(|_| GossipDataColumnError::PubkeyCacheTimeout)?;

        let pubkey = pubkey_cache
            .get(proposer_index)
            .ok_or_else(|| GossipDataColumnError::UnknownValidator(proposer_index as u64))?;
        signed_block_header.verify_signature::<T::EthSpec>(
            pubkey,
            &fork,
            chain.genesis_validators_root,
            &chain.spec,
        )
    };

    if !signature_is_valid {
        return Err(GossipDataColumnError::ProposalSignatureInvalid);
    }

    let column_proposer_index = signed_block_header.message.proposer_index;
    if proposer_index != column_proposer_index as usize {
        return Err(GossipDataColumnError::ProposerIndexMismatch {
            sidecar: column_proposer_index as usize,
            local: proposer_index,
        });
    }

    Ok(())
}

fn verify_index_matches_subnet<E: EthSpec>(
    data_column: &DataColumnSidecar<E>,
    subnet: DataColumnSubnetId,
    spec: &ChainSpec,
) -> Result<(), GossipDataColumnError> {
    let expected_subnet = DataColumnSubnetId::from_column_index(*data_column.index(), spec);
    if expected_subnet != subnet {
        return Err(GossipDataColumnError::InvalidSubnetId {
            received: subnet.into(),
            expected: expected_subnet.into(),
        });
    }
    Ok(())
}

fn verify_slot_greater_than_latest_finalized_slot<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    column_slot: Slot,
) -> Result<(), GossipDataColumnError> {
    let latest_finalized_slot = chain
        .head()
        .finalized_checkpoint()
        .epoch
        .start_slot(T::EthSpec::slots_per_epoch());
    if column_slot <= latest_finalized_slot {
        return Err(GossipDataColumnError::PastFinalizedSlot {
            column_slot,
            finalized_slot: latest_finalized_slot,
        });
    }
    Ok(())
}

fn verify_sidecar_not_from_future_slot<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    column_slot: Slot,
) -> Result<(), GossipDataColumnError> {
    let latest_permissible_slot = chain
        .slot_clock
        .now_with_future_tolerance(chain.spec.maximum_gossip_clock_disparity())
        .ok_or(BeaconChainError::UnableToReadSlot)?;
    if column_slot > latest_permissible_slot {
        return Err(GossipDataColumnError::FutureSlot {
            message_slot: column_slot,
            latest_permissible_slot,
        });
    }
    Ok(())
}

pub fn observe_gossip_data_column<T: BeaconChainTypes>(
    data_column_sidecar: &DataColumnSidecar<T::EthSpec>,
    chain: &BeaconChain<T>,
) -> Result<(), GossipDataColumnError> {
    // Pre-gloas: Now the signature is valid, store the proposal so we don't accept another data column sidecar
    // with the same `ColumnIndex`.
    // Post-gloas: The block associated with the sidecar has already been imported into fork choice. Store the
    // columns `beacon_block_root` so we don't accept another data column sidecar with the same `ColumnIndex`.
    // It's important to double-check that the `Observationkey` still
    // hasn't been observed so we don't have a race-condition when verifying two sidecars
    // simultaneously.
    //
    // Note: If this DataColumnSidecar goes on to fail full verification, we do not evict it from the
    // seen_cache as alternate data_column_sidecars for the same identifier can still be retrieved over
    // rpc. Evicting them from this cache would allow faster propagation over gossip. So we
    // allow retrieval of potentially valid sidecars over rpc, but try to punish the proposer for
    // signing invalid messages. Issue for more background
    // https://github.com/ethereum/consensus-specs/issues/3261
    if let Some(observation_key) = chain
        .observed_column_sidecars
        .write()
        .observe_sidecar(data_column_sidecar)
        .map_err(|e: ObservedDataSidecarsError| {
            GossipDataColumnError::BeaconChainError(Box::new(e.into()))
        })?
    {
        return Err(GossipDataColumnError::PriorKnown {
            observation_key,
            index: *data_column_sidecar.index(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::ChainConfig;
    use crate::data_column_verification::{
        GossipDataColumnError, GossipPartialDataColumnError, GossipVerifiedDataColumn,
        GossipVerifiedPartialDataColumnHeader, KzgVerifiedCustodyPartialDataColumn,
        PartialColumnVerificationResult, validate_data_column_sidecar_for_gossip_fulu,
        validate_partial_data_column_sidecar_for_gossip,
    };
    use crate::observed_data_sidecars::Observe;
    use crate::test_utils::{
        BeaconChainHarness, EphemeralHarnessType, fork_name_from_env,
        generate_data_column_sidecars_from_block, test_spec,
    };
    use eth2::types::BlobsBundle;
    use execution_layer::test_utils::generate_blobs;
    use kzg::KzgProof;
    use ssz::BitList;
    use ssz_types::VariableList;
    use std::sync::Arc;
    use std::time::UNIX_EPOCH;
    use types::{
        Cell, CellBitmap, DataColumnSidecar, DataColumnSidecarFulu, DataColumnSubnetId, EthSpec,
        ForkName, MainnetEthSpec, PartialDataColumn, PartialDataColumnHeader,
        PartialDataColumnSidecar,
    };

    type E = MainnetEthSpec;

    // TODO(gloas) make this generic over gloas/fulu
    #[tokio::test]
    async fn test_validate_data_column_sidecar_for_gossip_fulu() {
        // Setting up harness is slow, we initialise once and use it for all gossip validation tests.
        let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.into())
            .deterministic_keypairs(64)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();
        harness.advance_slot();

        let verify_fn = |column_sidecar: DataColumnSidecar<E>| {
            let col_index = *column_sidecar.index();
            validate_data_column_sidecar_for_gossip_fulu::<_, Observe>(
                Arc::new(column_sidecar),
                DataColumnSubnetId::from_column_index(col_index, &harness.spec),
                &harness.chain,
            )
        };
        empty_data_column_sidecars_fails_validation_fulu(&harness, &verify_fn).await;
        data_column_sidecar_commitments_exceed_max_blobs_per_block(&harness, &verify_fn).await;
    }

    // TODO(gloas) make this generic over gloas/fulu
    #[tokio::test]
    async fn test_new_for_block_publishing_fulu() {
        // Setting up harness is slow, we initialise once and use it for all gossip validation tests.
        let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.into())
            .deterministic_keypairs(64)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();
        harness.advance_slot();

        let verify_fn = |column_sidecar: DataColumnSidecar<E>| {
            GossipVerifiedDataColumn::<_>::new_for_block_publishing(
                column_sidecar.into(),
                &harness.chain,
            )
        };
        empty_data_column_sidecars_fails_validation_fulu(&harness, &verify_fn).await;
        data_column_sidecar_commitments_exceed_max_blobs_per_block(&harness, &verify_fn).await;
    }

    // TODO(gloas) make this generic over gloas/fulu
    async fn empty_data_column_sidecars_fails_validation_fulu<D>(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
        verify_fn: &impl Fn(DataColumnSidecar<E>) -> Result<D, GossipDataColumnError>,
    ) {
        let slot = harness.get_current_slot();
        let state = harness.get_current_state();
        let ((block, _blobs_opt), _state) = harness
            .make_block_with_modifier(state, slot, |block| {
                *block.body_mut().blob_kzg_commitments_mut().unwrap() = vec![].try_into().unwrap();
            })
            .await;

        let index = 0;
        let column_sidecar: DataColumnSidecar<E> = DataColumnSidecar::Fulu(DataColumnSidecarFulu {
            index,
            column: vec![].try_into().unwrap(),
            kzg_commitments: vec![].try_into().unwrap(),
            kzg_proofs: vec![].try_into().unwrap(),
            signed_block_header: block.signed_block_header(),
            kzg_commitments_inclusion_proof: block
                .message()
                .body()
                .kzg_commitments_merkle_proof()
                .unwrap(),
        });

        let result = verify_fn(column_sidecar);
        assert!(matches!(
            result.err(),
            Some(GossipDataColumnError::UnexpectedDataColumn)
        ));
    }

    async fn data_column_sidecar_commitments_exceed_max_blobs_per_block<D>(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
        verify_fn: &impl Fn(DataColumnSidecar<E>) -> Result<D, GossipDataColumnError>,
    ) {
        let slot = harness.get_current_slot();
        let epoch = slot.epoch(E::slots_per_epoch());
        let state = harness.get_current_state();
        let max_blobs_per_block = harness.spec.max_blobs_per_block(epoch) as usize;
        let fork = harness.spec.fork_name_at_epoch(epoch);

        // Generate data column sidecar with blob count exceeding max_blobs_per_block.
        let blob_count = max_blobs_per_block + 1;
        let BlobsBundle::<E> {
            commitments: preloaded_commitments_single,
            proofs: _,
            blobs: _,
        } = generate_blobs(1, fork).unwrap().0;

        let ((block, _blobs_opt), _state) = harness
            .make_block_with_modifier(state, slot, |block| {
                *block.body_mut().blob_kzg_commitments_mut().unwrap() =
                    vec![preloaded_commitments_single[0]; blob_count]
                        .try_into()
                        .unwrap();
            })
            .await;

        let column_sidecar = generate_data_column_sidecars_from_block(&block, &harness.spec)
            .into_iter()
            .next()
            .unwrap();

        let result = verify_fn(Arc::try_unwrap(column_sidecar).unwrap());
        assert!(matches!(
            result.err(),
            Some(GossipDataColumnError::MaxBlobsPerBlockExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn test_partial_message_verification_fulu() {
        let spec = if fork_name_from_env().is_some() {
            Arc::new(test_spec::<E>())
        } else {
            Arc::new(ForkName::Fulu.make_genesis_spec(E::default_spec()))
        };

        // Only run these tests if columns are enabled.
        if !spec.is_fulu_scheduled() {
            return;
        }
        // Gloas is not supported yet.
        if spec.is_gloas_scheduled() {
            return;
        }

        let chain_config = ChainConfig {
            enable_partial_columns: true,
            ..Default::default()
        };
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec)
            .deterministic_keypairs(64)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .chain_config(chain_config)
            .build();

        partial_empty_message_without_cells_returns_error(&harness).await;
        partial_inconsistent_present_count_returns_error(&harness).await;
        partial_inconsistent_max_count_returns_error(&harness).await;
        partial_header_with_empty_commitments_fails(&harness).await;
        partial_header_root_mismatch_fails(&harness).await;
        partial_header_with_invalid_inclusion_proof_fails(&harness).await;
    }

    /// Build a block containing 1 blob and pre-cache the header in the partial assembler.
    async fn add_block_and_header(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    ) -> (types::Hash256, Arc<PartialDataColumnHeader<E>>) {
        harness.advance_slot();
        // Generate a block with 1 blob so we have valid data columns.
        let fork = harness
            .spec
            .fork_name_at_epoch(harness.get_current_slot().epoch(E::slots_per_epoch()));
        let BlobsBundle::<E> {
            commitments,
            proofs: _,
            blobs: _,
        } = generate_blobs(1, fork).unwrap().0;

        let slot = harness.get_current_slot();
        let state = harness.get_current_state();
        let ((block, _blobs_opt), _state) = harness
            .make_block_with_modifier(state, slot, |block| {
                *block.body_mut().blob_kzg_commitments_mut().unwrap() =
                    vec![commitments[0]].try_into().unwrap();
            })
            .await;

        let block_root = block.canonical_root();
        let header: PartialDataColumnHeader<E> = block.as_ref().try_into().unwrap();
        let header = Arc::new(header);

        // Pre-cache the header in the partial assembler so headerless partials can be verified.
        harness
            .chain
            .data_availability_checker
            .partial_assembler()
            .unwrap()
            .init(block_root, header.clone());

        (block_root, header)
    }

    async fn partial_empty_message_without_cells_returns_error(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    ) {
        let (block_root, header) = add_block_and_header(harness).await;

        // Create a headerless partial with no cells — should trigger EmptyMessage.
        let num_commitments = header.kzg_commitments.len();
        let empty_bitmap =
            BitList::<<E as EthSpec>::MaxBlobCommitmentsPerBlock>::with_capacity(num_commitments)
                .unwrap();

        let column = PartialDataColumn {
            block_root,
            index: 0,
            sidecar: PartialDataColumnSidecar {
                cells_present_bitmap: empty_bitmap,
                column: vec![].try_into().unwrap(),
                kzg_proofs: vec![].try_into().unwrap(),
                header: None.into(),
            },
        };

        let result = validate_partial_data_column_sidecar_for_gossip(
            Box::new(column),
            &harness.chain,
            UNIX_EPOCH.elapsed().unwrap(),
        );
        assert!(
            matches!(
                result,
                PartialColumnVerificationResult::ErrWithValidHeader {
                    err: GossipPartialDataColumnError::EmptyMessage,
                    ..
                }
            ),
            "Expected EmptyMessage"
        );
    }

    async fn partial_inconsistent_present_count_returns_error(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    ) {
        let (block_root, header) = add_block_and_header(harness).await;

        // Create a bitmap that says 2 bits are set, but only provide 1 cell/proof.
        let num_commitments = header.kzg_commitments.len();
        let mut bitmap =
            BitList::<<E as EthSpec>::MaxBlobCommitmentsPerBlock>::with_capacity(num_commitments)
                .unwrap();
        bitmap.set(0, true).unwrap();

        let column = PartialDataColumn {
            block_root,
            index: 0,
            sidecar: PartialDataColumnSidecar {
                cells_present_bitmap: bitmap,
                column: vec![types::Cell::<E>::default()].try_into().unwrap(),
                // Provide 2 proofs but only 1 cell ← mismatch with popcount=1
                kzg_proofs: vec![types::KzgProof::empty(), types::KzgProof::empty()]
                    .try_into()
                    .unwrap(),
                header: None.into(),
            },
        };

        let result = validate_partial_data_column_sidecar_for_gossip(
            Box::new(column),
            &harness.chain,
            UNIX_EPOCH.elapsed().unwrap(),
        );
        assert!(
            matches!(
                result,
                PartialColumnVerificationResult::ErrWithValidHeader {
                    err: GossipPartialDataColumnError::InconsistentPresentCount { .. },
                    ..
                }
            ),
            "Expected InconsistentPresentCount"
        );
    }

    async fn partial_inconsistent_max_count_returns_error(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    ) {
        let (block_root, _header) = add_block_and_header(harness).await;

        // Create a bitmap with length different from the number of commitments in the header.
        // Header has 1 commitment, but we use a bitmap with capacity 3.
        let mut bitmap =
            BitList::<<E as EthSpec>::MaxBlobCommitmentsPerBlock>::with_capacity(3).unwrap();
        bitmap.set(0, true).unwrap();

        let column = PartialDataColumn {
            block_root,
            index: 0,
            sidecar: PartialDataColumnSidecar {
                cells_present_bitmap: bitmap,
                column: vec![types::Cell::<E>::default()].try_into().unwrap(),
                kzg_proofs: vec![types::KzgProof::empty()].try_into().unwrap(),
                header: None.into(),
            },
        };

        let result = validate_partial_data_column_sidecar_for_gossip(
            Box::new(column),
            &harness.chain,
            UNIX_EPOCH.elapsed().unwrap(),
        );
        assert!(
            matches!(
                result,
                PartialColumnVerificationResult::ErrWithValidHeader {
                    err: GossipPartialDataColumnError::InconsistentCommitmentsLength { .. },
                    ..
                }
            ),
            "Expected InconsistentMaxCount"
        );
    }

    async fn partial_header_with_empty_commitments_fails(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    ) {
        let slot = harness.get_current_slot();
        let state = harness.get_current_state();
        let ((block, _), _) = harness
            .make_block_with_modifier(state, slot, |block| {
                *block.body_mut().blob_kzg_commitments_mut().unwrap() = vec![].try_into().unwrap();
            })
            .await;

        let block_root = block.canonical_root();
        let header: PartialDataColumnHeader<E> = block.as_ref().try_into().unwrap();
        assert!(header.kzg_commitments.is_empty());

        let result =
            GossipVerifiedPartialDataColumnHeader::new(block_root, header, &*harness.chain);
        assert!(
            matches!(
                result,
                Err(GossipPartialDataColumnError::GossipDataColumnError(
                    GossipDataColumnError::UnexpectedDataColumn
                ))
            ),
            "Expected UnexpectedDataColumn, got: {result:?}"
        );
    }

    async fn partial_header_root_mismatch_fails(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    ) {
        let (_block_root, header) = add_block_and_header(harness).await;

        // Use a wrong group_id (not matching the header's block root)
        let wrong_root = types::Hash256::repeat_byte(0xff);
        let header = PartialDataColumnHeader::clone(&header);

        let result =
            GossipVerifiedPartialDataColumnHeader::new(wrong_root, header, &*harness.chain);
        assert!(
            matches!(
                result,
                Err(GossipPartialDataColumnError::HeaderIncorrectRoot { .. })
            ),
            "Expected HeaderIncorrectRoot, got: {result:?}"
        );
    }

    async fn partial_header_with_invalid_inclusion_proof_fails(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    ) {
        let (block_root, header) = add_block_and_header(harness).await;

        // Corrupt the inclusion proof
        let mut header = PartialDataColumnHeader::clone(&header);
        header.kzg_commitments_inclusion_proof[0] = types::Hash256::repeat_byte(0xaa);

        let result =
            GossipVerifiedPartialDataColumnHeader::new(block_root, header, &*harness.chain);
        assert!(
            matches!(
                result,
                Err(GossipPartialDataColumnError::GossipDataColumnError(
                    GossipDataColumnError::InvalidInclusionProof
                ))
            ),
            "Expected InvalidInclusionProof, got: {result:?}"
        );
    }

    // -- merge tests --

    fn make_cell(marker: u8) -> Cell<E> {
        let mut cell = Cell::<E>::default();
        cell[0] = marker;
        cell
    }

    fn make_partial_with_marker(
        total_blobs: usize,
        present_indices: &[usize],
        marker_base: u8,
    ) -> KzgVerifiedCustodyPartialDataColumn<E> {
        let mut bitmap = CellBitmap::<E>::with_capacity(total_blobs).unwrap();
        for &idx in present_indices {
            bitmap.set(idx, true).unwrap();
        }

        let column: VariableList<_, _> = present_indices
            .iter()
            .map(|&idx| make_cell(marker_base.wrapping_add(idx as u8)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let proofs: VariableList<_, _> = present_indices
            .iter()
            .map(|_| KzgProof::empty())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        KzgVerifiedCustodyPartialDataColumn {
            data: Arc::new(PartialDataColumn {
                block_root: Default::default(),
                index: 0,
                sidecar: PartialDataColumnSidecar {
                    cells_present_bitmap: bitmap,
                    column,
                    kzg_proofs: proofs,
                    header: None.into(),
                },
            }),
            latest_cell_timestamp: Default::default(),
        }
    }

    fn make_partial(
        total_blobs: usize,
        present_indices: &[usize],
    ) -> KzgVerifiedCustodyPartialDataColumn<E> {
        make_partial_with_marker(total_blobs, present_indices, 0)
    }

    #[test]
    fn merge_disjoint_partials() {
        let a = make_partial(6, &[0, 2]);
        let b = make_partial(6, &[1, 3]);
        let merged = a.merge(&b).unwrap();
        assert_eq!(merged.data.sidecar.column.len(), 4);
        assert_eq!(merged.data.sidecar.kzg_proofs.len(), 4);
        for i in 0..4 {
            assert!(merged.data.sidecar.cells_present_bitmap.get(i).unwrap());
        }
        assert!(!merged.data.sidecar.cells_present_bitmap.get(4).unwrap());
    }

    #[test]
    fn merge_overlapping_partials_prefers_self() {
        let a = make_partial_with_marker(4, &[0, 1], 0);
        let b = make_partial_with_marker(4, &[1, 2], 100);
        let merged = a.merge(&b).unwrap();
        assert_eq!(merged.data.sidecar.column.len(), 3);
        // Cell at bitmap index 1 is the second cell in the merged column.
        // It should come from `a` (marker_base=0, so marker=0+1=1), not `b` (marker=100+1=101).
        assert_eq!(merged.data.sidecar.column[1][0], 1);
    }

    #[test]
    fn merge_with_empty_other() {
        let a = make_partial(4, &[0, 2]);
        let b = make_partial(4, &[]);
        let merged = a.merge(&b).unwrap();
        assert_eq!(merged.data.sidecar.column.len(), 2);
        assert_eq!(
            merged.data.sidecar.cells_present_bitmap,
            a.data.sidecar.cells_present_bitmap
        );
    }
}

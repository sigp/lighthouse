use crate::block_verification::{
    cheap_state_advance_to_obtain_committees, get_validator_pubkey_cache, process_block_slash_info,
    BlockSlashInfo,
};
use crate::kzg_utils::{reconstruct_data_columns, validate_data_columns};
use crate::observed_data_sidecars::{ObservationStrategy, Observe};
use crate::{metrics, BeaconChain, BeaconChainError, BeaconChainTypes};
use derivative::Derivative;
use fork_choice::ProtoBlock;
use kzg::{Error as KzgError, Kzg};
use proto_array::Block;
use slasher::test_utils::E;
use slog::debug;
use slot_clock::SlotClock;
use ssz_derive::{Decode, Encode};
use std::iter;
use std::marker::PhantomData;
use std::sync::Arc;
use types::data_column_sidecar::{ColumnIndex, DataColumnIdentifier};
use types::{
    BeaconStateError, ChainSpec, DataColumnSidecar, DataColumnSubnetId, EthSpec, Hash256,
    RuntimeVariableList, SignedBeaconBlockHeader, Slot,
};

/// An error occurred while validating a gossip data column.
#[derive(Debug)]
pub enum GossipDataColumnError {
    /// There was an error whilst processing the data column. It is not known if it is
    /// valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this data column due to an internal error. It's
    /// unclear if the data column is valid.
    BeaconChainError(BeaconChainError),
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
    ParentUnknown { parent_root: Hash256 },
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
    /// A column has already been seen for the given `(sidecar.block_root, sidecar.index)` tuple
    /// over gossip or no gossip sources.
    ///
    /// ## Peer scoring
    ///
    /// The peer isn't faulty, but we do not forward it over gossip.
    PriorKnown {
        proposer: u64,
        slot: Slot,
        index: ColumnIndex,
    },
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
    /// The data column length must be equal to the number of commitments/proofs, otherwise the
    /// sidecar is invalid.
    ///
    /// ## Peer scoring
    ///
    /// The column sidecar is invalid and the peer is faulty
    InconsistentCommitmentsOrProofLength,
}

impl From<BeaconChainError> for GossipDataColumnError {
    fn from(e: BeaconChainError) -> Self {
        GossipDataColumnError::BeaconChainError(e)
    }
}

impl From<BeaconStateError> for GossipDataColumnError {
    fn from(e: BeaconStateError) -> Self {
        GossipDataColumnError::BeaconChainError(BeaconChainError::BeaconStateError(e))
    }
}

/// A wrapper around a `DataColumnSidecar` that indicates it has been approved for re-gossiping on
/// the p2p network.
#[derive(Debug)]
pub struct GossipVerifiedDataColumn<T: BeaconChainTypes, O: ObservationStrategy = Observe> {
    block_root: Hash256,
    data_column: KzgVerifiedDataColumn<T::EthSpec>,
    _phantom: PhantomData<O>,
}

impl<T: BeaconChainTypes, O: ObservationStrategy> GossipVerifiedDataColumn<T, O> {
    pub fn new(
        column_sidecar: Arc<DataColumnSidecar<T::EthSpec>>,
        subnet_id: u64,
        chain: &BeaconChain<T>,
    ) -> Result<Self, GossipDataColumnError> {
        let header = column_sidecar.signed_block_header.clone();
        // We only process slashing info if the gossip verification failed
        // since we do not process the data column any further in that case.
        validate_data_column_sidecar_for_gossip::<T, O>(column_sidecar, subnet_id, chain).map_err(
            |e| {
                process_block_slash_info::<_, GossipDataColumnError>(
                    chain,
                    BlockSlashInfo::from_early_error_data_column(header, e),
                )
            },
        )
    }

    pub fn id(&self) -> DataColumnIdentifier {
        DataColumnIdentifier {
            block_root: self.block_root,
            index: self.data_column.index(),
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
        self.data_column.data.index
    }

    pub fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.data_column.data.signed_block_header.clone()
    }

    pub fn into_inner(self) -> KzgVerifiedDataColumn<T::EthSpec> {
        self.data_column
    }
}

/// Wrapper over a `DataColumnSidecar` for which we have completed kzg verification.
#[derive(Debug, Derivative, Clone, Encode, Decode)]
#[derivative(PartialEq, Eq)]
#[ssz(struct_behaviour = "transparent")]
pub struct KzgVerifiedDataColumn<E: EthSpec> {
    data: Arc<DataColumnSidecar<E>>,
}

impl<E: EthSpec> KzgVerifiedDataColumn<E> {
    pub fn new(data_column: Arc<DataColumnSidecar<E>>, kzg: &Kzg) -> Result<Self, KzgError> {
        verify_kzg_for_data_column(data_column, kzg)
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
        self.data.index
    }
}

pub type CustodyDataColumnList<E> = RuntimeVariableList<CustodyDataColumn<E>>;

/// Data column that we must custody
#[derive(Debug, Derivative, Clone, Encode, Decode)]
#[derivative(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
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
        self.data.index
    }
}

/// Data column that we must custody and has completed kzg verification
#[derive(Debug, Derivative, Clone, Encode, Decode)]
#[derivative(PartialEq, Eq)]
#[ssz(struct_behaviour = "transparent")]
pub struct KzgVerifiedCustodyDataColumn<E: EthSpec> {
    data: Arc<DataColumnSidecar<E>>,
}

impl<E: EthSpec> KzgVerifiedCustodyDataColumn<E> {
    /// Mark a column as custody column. Caller must ensure that our current custody requirements
    /// include this column
    pub fn from_asserted_custody(kzg_verified: KzgVerifiedDataColumn<E>) -> Self {
        Self {
            data: kzg_verified.to_data_column(),
        }
    }

    /// Verify a column already marked as custody column
    pub fn new(data_column: CustodyDataColumn<E>, kzg: &Kzg) -> Result<Self, KzgError> {
        verify_kzg_for_data_column(data_column.clone_arc(), kzg)?;
        Ok(Self {
            data: data_column.data,
        })
    }

    pub fn reconstruct_columns(
        kzg: &Kzg,
        partial_set_of_columns: &[Self],
        spec: &ChainSpec,
    ) -> Result<Vec<KzgVerifiedCustodyDataColumn<E>>, KzgError> {
        let all_data_columns = reconstruct_data_columns(
            kzg,
            &partial_set_of_columns
                .iter()
                .map(|d| d.clone_arc())
                .collect::<Vec<_>>(),
            spec,
        )?;

        Ok(all_data_columns
            .into_iter()
            .map(|data| {
                KzgVerifiedCustodyDataColumn::from_asserted_custody(KzgVerifiedDataColumn { data })
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
        self.data.index
    }
}

/// Complete kzg verification for a `DataColumnSidecar`.
///
/// Returns an error if the kzg verification check fails.
pub fn verify_kzg_for_data_column<E: EthSpec>(
    data_column: Arc<DataColumnSidecar<E>>,
    kzg: &Kzg,
) -> Result<KzgVerifiedDataColumn<E>, KzgError> {
    let _timer = metrics::start_timer(&metrics::KZG_VERIFICATION_DATA_COLUMN_SINGLE_TIMES);
    validate_data_columns(kzg, iter::once(&data_column))?;
    Ok(KzgVerifiedDataColumn { data: data_column })
}

/// Complete kzg verification for a list of `DataColumnSidecar`s.
/// Returns an error if any of the `DataColumnSidecar`s fails kzg verification.
///
/// Note: This function should be preferred over calling `verify_kzg_for_data_column`
/// in a loop since this function kzg verifies a list of data columns more efficiently.
pub fn verify_kzg_for_data_column_list<'a, E: EthSpec, I>(
    data_column_iter: I,
    kzg: &'a Kzg,
) -> Result<(), KzgError>
where
    I: Iterator<Item = &'a Arc<DataColumnSidecar<E>>> + Clone,
{
    let _timer = metrics::start_timer(&metrics::KZG_VERIFICATION_DATA_COLUMN_BATCH_TIMES);
    validate_data_columns(kzg, data_column_iter)?;
    Ok(())
}

pub fn validate_data_column_sidecar_for_gossip<T: BeaconChainTypes, O: ObservationStrategy>(
    data_column: Arc<DataColumnSidecar<T::EthSpec>>,
    subnet: u64,
    chain: &BeaconChain<T>,
) -> Result<GossipVerifiedDataColumn<T, O>, GossipDataColumnError> {
    let column_slot = data_column.slot();
    verify_data_column_sidecar(&data_column, &chain.spec)?;
    verify_index_matches_subnet(&data_column, subnet, &chain.spec)?;
    verify_sidecar_not_from_future_slot(chain, column_slot)?;
    verify_slot_greater_than_latest_finalized_slot(chain, column_slot)?;
    verify_is_first_sidecar(chain, &data_column)?;
    verify_column_inclusion_proof(&data_column)?;
    let parent_block = verify_parent_block_and_finalized_descendant(data_column.clone(), chain)?;
    verify_slot_higher_than_parent(&parent_block, column_slot)?;
    verify_proposer_and_signature(&data_column, &parent_block, chain)?;
    let kzg = &chain.kzg;
    let kzg_verified_data_column = verify_kzg_for_data_column(data_column.clone(), kzg)
        .map_err(GossipDataColumnError::InvalidKzgProof)?;

    chain
        .observed_slashable
        .write()
        .observe_slashable(
            column_slot,
            data_column.block_proposer_index(),
            data_column.block_root(),
        )
        .map_err(|e| GossipDataColumnError::BeaconChainError(e.into()))?;

    if O::observe() {
        observe_gossip_data_column(&kzg_verified_data_column.data, chain)?;
    }

    Ok(GossipVerifiedDataColumn {
        block_root: data_column.block_root(),
        data_column: kzg_verified_data_column,
        _phantom: PhantomData,
    })
}

/// Verify if the data column sidecar is valid.
fn verify_data_column_sidecar<E: EthSpec>(
    data_column: &DataColumnSidecar<E>,
    spec: &ChainSpec,
) -> Result<(), GossipDataColumnError> {
    if data_column.index >= spec.number_of_columns as u64 {
        return Err(GossipDataColumnError::InvalidColumnIndex(data_column.index));
    }
    if data_column.kzg_commitments.is_empty() {
        return Err(GossipDataColumnError::UnexpectedDataColumn);
    }
    if data_column.column.len() != data_column.kzg_commitments.len()
        || data_column.column.len() != data_column.kzg_proofs.len()
    {
        return Err(GossipDataColumnError::InconsistentCommitmentsOrProofLength);
    }

    Ok(())
}

// Verify that this is the first column sidecar received for the tuple:
// (block_header.slot, block_header.proposer_index, column_sidecar.index)
fn verify_is_first_sidecar<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    data_column: &DataColumnSidecar<T::EthSpec>,
) -> Result<(), GossipDataColumnError> {
    if chain
        .observed_column_sidecars
        .read()
        .proposer_is_known(data_column)
        .map_err(|e| GossipDataColumnError::BeaconChainError(e.into()))?
    {
        return Err(GossipDataColumnError::PriorKnown {
            proposer: data_column.block_proposer_index(),
            slot: data_column.slot(),
            index: data_column.index,
        });
    }
    Ok(())
}

fn verify_column_inclusion_proof<E: EthSpec>(
    data_column: &DataColumnSidecar<E>,
) -> Result<(), GossipDataColumnError> {
    let _timer = metrics::start_timer(&metrics::DATA_COLUMN_SIDECAR_INCLUSION_PROOF_VERIFICATION);
    if !data_column.verify_inclusion_proof() {
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
    data_column: Arc<DataColumnSidecar<T::EthSpec>>,
    chain: &BeaconChain<T>,
) -> Result<ProtoBlock, GossipDataColumnError> {
    let fork_choice = chain.canonical_head.fork_choice_read_lock();

    // We have already verified that the column is past finalization, so we can
    // just check fork choice for the block's parent.
    let block_parent_root = data_column.block_parent_root();
    let Some(parent_block) = fork_choice.get_block(&block_parent_root) else {
        return Err(GossipDataColumnError::ParentUnknown {
            parent_root: block_parent_root,
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
    data_column: &DataColumnSidecar<T::EthSpec>,
    parent_block: &ProtoBlock,
    chain: &BeaconChain<T>,
) -> Result<(), GossipDataColumnError> {
    let column_slot = data_column.slot();
    let column_epoch = column_slot.epoch(E::slots_per_epoch());
    let column_index = data_column.index;
    let block_root = data_column.block_root();
    let block_parent_root = data_column.block_parent_root();

    let proposer_shuffling_root =
        if parent_block.slot.epoch(T::EthSpec::slots_per_epoch()) == column_epoch {
            parent_block
                .next_epoch_shuffling_id
                .shuffling_decision_block
        } else {
            parent_block.root
        };

    let proposer_opt = chain
        .beacon_proposer_cache
        .lock()
        .get_slot::<T::EthSpec>(proposer_shuffling_root, column_slot);

    let (proposer_index, fork) = if let Some(proposer) = proposer_opt {
        (proposer.index, proposer.fork)
    } else {
        debug!(
            chain.log,
            "Proposer shuffling cache miss for column verification";
            "block_root" => %block_root,
            "index" => %column_index,
        );
        let (parent_state_root, mut parent_state) = chain
            .store
            .get_advanced_hot_state(block_parent_root, column_slot, parent_block.state_root)
            .map_err(|e| GossipDataColumnError::BeaconChainError(e.into()))?
            .ok_or_else(|| {
                BeaconChainError::DBInconsistent(format!(
                    "Missing state for parent block {block_parent_root:?}",
                ))
            })?;

        let state = cheap_state_advance_to_obtain_committees::<_, GossipDataColumnError>(
            &mut parent_state,
            Some(parent_state_root),
            column_slot,
            &chain.spec,
        )?;

        let proposers = state.get_beacon_proposer_indices(&chain.spec)?;
        let proposer_index = *proposers
            .get(column_slot.as_usize() % T::EthSpec::slots_per_epoch() as usize)
            .ok_or_else(|| BeaconChainError::NoProposerForSlot(column_slot))?;

        // Prime the proposer shuffling cache with the newly-learned value.
        chain.beacon_proposer_cache.lock().insert(
            column_epoch,
            proposer_shuffling_root,
            proposers,
            state.fork(),
        )?;
        (proposer_index, state.fork())
    };

    // Signature verify the signed block header.
    let signature_is_valid = {
        let pubkey_cache = get_validator_pubkey_cache(chain)
            .map_err(|_| GossipDataColumnError::PubkeyCacheTimeout)?;

        let pubkey = pubkey_cache
            .get(proposer_index)
            .ok_or_else(|| GossipDataColumnError::UnknownValidator(proposer_index as u64))?;
        let signed_block_header = &data_column.signed_block_header;
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

    let column_proposer_index = data_column.block_proposer_index();
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
    subnet: u64,
    spec: &ChainSpec,
) -> Result<(), GossipDataColumnError> {
    let expected_subnet: u64 =
        DataColumnSubnetId::from_column_index::<E>(data_column.index as usize, spec).into();
    if expected_subnet != subnet {
        return Err(GossipDataColumnError::InvalidSubnetId {
            received: subnet,
            expected: expected_subnet,
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
    // Now the signature is valid, store the proposal so we don't accept another data column sidecar
    // with the same `DataColumnIdentifier`.  It's important to double-check that the proposer still
    // hasn't been observed so we don't have a race-condition when verifying two blocks
    // simultaneously.
    //
    // Note: If this DataColumnSidecar goes on to fail full verification, we do not evict it from the
    // seen_cache as alternate data_column_sidecars for the same identifier can still be retrieved over
    // rpc. Evicting them from this cache would allow faster propagation over gossip. So we
    // allow retrieval of potentially valid blocks over rpc, but try to punish the proposer for
    // signing invalid messages. Issue for more background
    // https://github.com/ethereum/consensus-specs/issues/3261
    if chain
        .observed_column_sidecars
        .write()
        .observe_sidecar(data_column_sidecar)
        .map_err(|e| GossipDataColumnError::BeaconChainError(e.into()))?
    {
        return Err(GossipDataColumnError::PriorKnown {
            proposer: data_column_sidecar.block_proposer_index(),
            slot: data_column_sidecar.slot(),
            index: data_column_sidecar.index,
        });
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::data_column_verification::{
        validate_data_column_sidecar_for_gossip, GossipDataColumnError,
    };
    use crate::observed_data_sidecars::Observe;
    use crate::test_utils::BeaconChainHarness;
    use types::{DataColumnSidecar, EthSpec, ForkName, MainnetEthSpec};

    type E = MainnetEthSpec;

    #[tokio::test]
    async fn empty_data_column_sidecars_fails_validation() {
        let spec = ForkName::latest().make_genesis_spec(E::default_spec());
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.into())
            .deterministic_keypairs(64)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();
        harness.advance_slot();

        let slot = harness.get_current_slot();
        let state = harness.get_current_state();
        let ((block, _blobs_opt), _state) = harness
            .make_block_with_modifier(state, slot, |block| {
                *block.body_mut().blob_kzg_commitments_mut().unwrap() = vec![].into();
            })
            .await;

        let index = 0;
        let column_sidecar = DataColumnSidecar::<E> {
            index,
            column: vec![].into(),
            kzg_commitments: vec![].into(),
            kzg_proofs: vec![].into(),
            signed_block_header: block.signed_block_header(),
            kzg_commitments_inclusion_proof: block
                .message()
                .body()
                .kzg_commitments_merkle_proof()
                .unwrap(),
        };

        let result = validate_data_column_sidecar_for_gossip::<_, Observe>(
            column_sidecar.into(),
            index,
            &harness.chain,
        );
        assert!(matches!(
            result.err(),
            Some(GossipDataColumnError::UnexpectedDataColumn)
        ));
    }
}

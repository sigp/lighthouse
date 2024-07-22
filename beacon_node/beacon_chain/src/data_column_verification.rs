use crate::block_verification::{process_block_slash_info, BlockSlashInfo};
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use derivative::Derivative;
use kzg::{Error as KzgError, Kzg};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use types::data_column_sidecar::{ColumnIndex, DataColumnIdentifier};
use types::{
    BeaconStateError, DataColumnSidecar, EthSpec, Hash256, RuntimeVariableList,
    SignedBeaconBlockHeader, Slot,
};

/// An error occurred while validating a gossip data column.
#[derive(Debug)]
pub enum GossipDataColumnError<E: EthSpec> {
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
    /// `Kzg` struct hasn't been initialized. This is an internal error.
    ///
    /// ## Peer scoring
    ///
    /// The peer isn't faulty, This is an internal error.
    KzgNotInitialized,
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
    ParentUnknown(Arc<DataColumnSidecar<E>>),
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
}

impl<E: EthSpec> From<BeaconChainError> for GossipDataColumnError<E> {
    fn from(e: BeaconChainError) -> Self {
        GossipDataColumnError::BeaconChainError(e)
    }
}

impl<E: EthSpec> From<BeaconStateError> for GossipDataColumnError<E> {
    fn from(e: BeaconStateError) -> Self {
        GossipDataColumnError::BeaconChainError(BeaconChainError::BeaconStateError(e))
    }
}

pub type GossipVerifiedDataColumnList<T> = RuntimeVariableList<GossipVerifiedDataColumn<T>>;

/// A wrapper around a `DataColumnSidecar` that indicates it has been approved for re-gossiping on
/// the p2p network.
#[derive(Debug)]
pub struct GossipVerifiedDataColumn<T: BeaconChainTypes> {
    block_root: Hash256,
    data_column: KzgVerifiedDataColumn<T::EthSpec>,
}

impl<T: BeaconChainTypes> GossipVerifiedDataColumn<T> {
    pub fn new(
        column_sidecar: Arc<DataColumnSidecar<T::EthSpec>>,
        subnet_id: u64,
        chain: &BeaconChain<T>,
    ) -> Result<Self, GossipDataColumnError<T::EthSpec>> {
        let header = column_sidecar.signed_block_header.clone();
        // We only process slashing info if the gossip verification failed
        // since we do not process the data column any further in that case.
        validate_data_column_sidecar_for_gossip(column_sidecar, subnet_id, chain).map_err(|e| {
            process_block_slash_info::<_, GossipDataColumnError<T::EthSpec>>(
                chain,
                BlockSlashInfo::from_early_error_data_column(header, e),
            )
        })
    }

    pub fn id(&self) -> DataColumnIdentifier {
        DataColumnIdentifier {
            block_root: self.block_root,
            index: self.data_column.data_column_index(),
        }
    }

    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }

    pub fn slot(&self) -> Slot {
        self.data_column.data.slot()
    }

    pub fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        self.data_column.data.signed_block_header.clone()
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
    pub fn as_data_column(&self) -> &DataColumnSidecar<E> {
        &self.data
    }
    /// This is cheap as we're calling clone on an Arc
    pub fn clone_data_column(&self) -> Arc<DataColumnSidecar<E>> {
        self.data.clone()
    }

    pub fn data_column_index(&self) -> u64 {
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
    pub fn index(&self) -> ColumnIndex {
        self.data.index
    }
}

/// Complete kzg verification for a `DataColumnSidecar`.
///
/// Returns an error if the kzg verification check fails.
pub fn verify_kzg_for_data_column<E: EthSpec>(
    data_column: Arc<DataColumnSidecar<E>>,
    _kzg: &Kzg,
) -> Result<KzgVerifiedDataColumn<E>, KzgError> {
    // TODO(das): KZG verification to be implemented
    Ok(KzgVerifiedDataColumn { data: data_column })
}

/// Complete kzg verification for a list of `DataColumnSidecar`s.
/// Returns an error if any of the `DataColumnSidecar`s fails kzg verification.
///
/// Note: This function should be preferred over calling `verify_kzg_for_data_column`
/// in a loop since this function kzg verifies a list of data columns more efficiently.
pub fn verify_kzg_for_data_column_list<'a, E: EthSpec, I>(
    _data_column_iter: I,
    _kzg: &'a Kzg,
) -> Result<(), KzgError>
where
    I: Iterator<Item = &'a Arc<DataColumnSidecar<E>>> + Clone,
{
    // TODO(das): implement KZG verification
    Ok(())
}

pub fn validate_data_column_sidecar_for_gossip<T: BeaconChainTypes>(
    data_column: Arc<DataColumnSidecar<T::EthSpec>>,
    _subnet: u64,
    chain: &BeaconChain<T>,
) -> Result<GossipVerifiedDataColumn<T>, GossipDataColumnError<T::EthSpec>> {
    // TODO(das): implement gossip verification
    let kzg = chain
        .kzg
        .clone()
        .ok_or(GossipDataColumnError::KzgNotInitialized)?;
    let kzg_verified_data_column = verify_kzg_for_data_column(data_column.clone(), &kzg)
        .map_err(GossipDataColumnError::InvalidKzgProof)?;
    Ok(GossipVerifiedDataColumn {
        block_root: data_column.block_root(),
        data_column: kzg_verified_data_column,
    })
}

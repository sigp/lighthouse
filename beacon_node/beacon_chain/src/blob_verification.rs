use derivative::Derivative;
use slot_clock::SlotClock;
use std::sync::Arc;
use tokio::task::JoinHandle;
use ssz_types::VariableList;

use crate::beacon_chain::{BeaconChain, BeaconChainTypes, MAXIMUM_GOSSIP_CLOCK_DISPARITY};
use crate::block_verification::PayloadVerificationOutcome;
use crate::{kzg_utils, BeaconChainError, BlockError};
use state_processing::per_block_processing::eip4844::eip4844::verify_kzg_commitments_against_transactions;
use types::{
    BeaconBlockRef, BeaconStateError, BlobsSidecar, EthSpec, Hash256, KzgCommitment,
    SignedBeaconBlock, SignedBeaconBlockHeader, Slot,
    Transactions,
};
use types::{Epoch, ExecPayload};
use types::blob_sidecar::BlobSidecar;

#[derive(Debug)]
pub enum BlobError {
    /// The blob sidecar is from a slot that is later than the current slot (with respect to the
    /// gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    FutureSlot {
        message_slot: Slot,
        latest_permissible_slot: Slot,
    },

    /// The blob sidecar has a different slot than the block.
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    SlotMismatch {
        blob_slot: Slot,
        block_slot: Slot,
    },

    /// No kzg ccommitment associated with blob sidecar.
    KzgCommitmentMissing,

    /// No transactions in block
    TransactionsMissing,

    /// Blob transactions in the block do not correspond to the kzg commitments.
    TransactionCommitmentMismatch,

    TrustedSetupNotInitialized,

    InvalidKzgProof,

    KzgError(kzg::Error),

    /// There was an error whilst processing the sync contribution. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this sync committee message due to an internal error. It's unclear if the
    /// sync committee message is valid.
    BeaconChainError(BeaconChainError),
    /// No blobs for the specified block where we would expect blobs.
    UnavailableBlobs,
    /// Blobs provided for a pre-Eip4844 fork.
    InconsistentFork,
}

impl From<BeaconChainError> for BlobError {
    fn from(e: BeaconChainError) -> Self {
        BlobError::BeaconChainError(e)
    }
}

impl From<BeaconStateError> for BlobError {
    fn from(e: BeaconStateError) -> Self {
        BlobError::BeaconChainError(BeaconChainError::BeaconStateError(e))
    }
}

pub fn validate_blob_for_gossip<T: BeaconChainTypes>(
    block_wrapper: BlockWrapper<T::EthSpec>,
    block_root: Hash256,
    chain: &BeaconChain<T>,
) -> Result<AvailabilityPendingBlock<T::EthSpec>, BlobError> {
    if let BlockWrapper::BlockAndBlobs(ref block, ref blobs_sidecar) = block_wrapper {
        let blob_slot = blobs_sidecar.beacon_block_slot;
        // Do not gossip or process blobs from future or past slots.
        let latest_permissible_slot = chain
            .slot_clock
            .now_with_future_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
            .ok_or(BeaconChainError::UnableToReadSlot)?;
        if blob_slot > latest_permissible_slot {
            return Err(BlobError::FutureSlot {
                message_slot: latest_permissible_slot,
                latest_permissible_slot: blob_slot,
            });
        }

        if blob_slot != block.slot() {
            return Err(BlobError::SlotMismatch {
                blob_slot,
                block_slot: block.slot(),
            });
        }
    }

    block_wrapper.into_availablilty_pending_block(block_root, chain)
}

pub fn verify_data_availability<T: BeaconChainTypes>(
    blob_sidecar: &BlobsSidecar<T::EthSpec>,
    kzg_commitments: &[KzgCommitment],
    transactions: &Transactions<T::EthSpec>,
    block_slot: Slot,
    block_root: Hash256,
    chain: &BeaconChain<T>,
) -> Result<(), BlobError> {
    if verify_kzg_commitments_against_transactions::<T::EthSpec>(transactions, kzg_commitments)
        .is_err()
    {
        return Err(BlobError::TransactionCommitmentMismatch);
    }

    // Validatate that the kzg proof is valid against the commitments and blobs
    let kzg = chain
        .kzg
        .as_ref()
        .ok_or(BlobError::TrustedSetupNotInitialized)?;

    todo!("use `kzg_utils::validate_blobs` once the function is updated")
    // if !kzg_utils::validate_blobs_sidecar(
    //     kzg,
    //     block_slot,
    //     block_root,
    //     kzg_commitments,
    //     blob_sidecar,
    // )
    // .map_err(BlobError::KzgError)?
    // {
    //     return Err(BlobError::InvalidKzgProof);
    // }
    // Ok(())
}

#[derive(Copy, Clone)]
pub enum DataAvailabilityCheckRequired {
    Yes,
    No,
}

impl<T: BeaconChainTypes> BlockWrapper<T::EthSpec> {
    fn into_availablilty_pending_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<AvailabilityPendingBlock<T::EthSpec>, BlobError> {
        match self {
            BlockWrapper::Block(block) => {
                AvailabilityPendingBlock::new(block, block_root, da_check_required)
            }
            BlockWrapper::BlockAndBlobs(block, blobs_sidecar) => {


                AvailabilityPendingBlock::new_with_blobs(block, blobs_sidecar, da_check_required)
            }
        }
    }
}

pub trait IntoAvailableBlock<T: BeaconChainTypes> {
    fn into_available_block(
        self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<AvailableBlock<T::EthSpec>, BlobError>;
}

/// A wrapper over a [`SignedBeaconBlock`] or a [`SignedBeaconBlockAndBlobsSidecar`].  An
/// `AvailableBlock` has passed any required data availability checks and should be used in
/// consensus.
#[derive(Clone, Debug, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: BeaconChainTypes"))]
pub struct AvailabilityPendingBlock<T: BeaconChainTypes> {
    block: Arc<SignedBeaconBlock<T::EthSpec>>,
    data_availability_handle: DataAvailabilityHandle<T::EthSpec>,
}

/// Used to await the result of data availability check.
type DataAvailabilityHandle<E> = JoinHandle<Result<Option<Blobs<E>>, BlobError>>;

#[derive(Clone, Debug, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: BeaconChainTypes"))]
pub struct AvailableBlock<T: BeaconChainTypes> {
    block: Arc<SignedBeaconBlock<T::EthSpec>>,
    blobs: Blobs<T::EthSpec>,
}

impl <T: BeaconChainTypes> AvailableBlock<T> {
    pub fn blobs(&self) -> Option<Arc<BlobsSidecar<T>>> {
        match &self.blobs {
            Blobs::NotRequired | Blobs::None => None,
            Blobs::Available(block_sidecar) => {
                Some(block_sidecar.clone())
            }
        }
    }

    pub fn deconstruct(self) -> (Arc<SignedBeaconBlock<T::EthSpec>>, Option<Arc<BlobsSidecar<T::EthSpec>>>) {
        match self.blobs {
            Blobs::NotRequired | Blobs::None => (self.block, None),
            Blobs::Available(blob_sidecars) => {
                (self.block, Some(blob_sidecars))
            }
        }
    }
}

pub enum Blobs<E: EthSpec> {
    /// These blobs are available.
    Available(VariableList<Arc<BlobSidecar<E>>, E::MaxBlobsPerBlock>),
    /// This block is from outside the data availability boundary or the block is from prior
    /// to the eip4844 fork.
    NotRequired,
    /// The block doesn't have any blob transactions.
    None,
}

//TODO(sean) add block root to the availability pending block?
impl<T: BeaconChainTypes> AvailabilityPendingBlock<T> {
    pub fn new(
        beacon_block: Arc<SignedBeaconBlock<T::EthSpec>>,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlobError> {
        let data_availability_boundary = chain.data_availability_boundary();
        let da_check_required =
            data_availability_boundary.map_or(DataAvailabilityCheckRequired::No, |boundary| {
                if chain.epoch()? >= boundary {
                    DataAvailabilityCheckRequired::Yes
                } else {
                    DataAvailabilityCheckRequired::No
                }
            });

        match beacon_block.as_ref() {
            // No data availability check required prior to Eip4844.
            SignedBeaconBlock::Base(_)
            | SignedBeaconBlock::Altair(_)
            | SignedBeaconBlock::Capella(_)
            | SignedBeaconBlock::Merge(_) => {
                Ok(AvailabilityPendingBlock {
                    block: beacon_block ,
                    data_availability_handle: async{ Ok(Some(Blobs::NotRequired))}
                })
            }
            SignedBeaconBlock::Eip4844(_) => {
                match da_check_required {
                    DataAvailabilityCheckRequired::Yes => {
                        // Attempt to reconstruct empty blobs here.
                        let blobs_sidecar = beacon_block
                            .reconstruct_empty_blobs(Some(block_root))
                            .map(Arc::new)?;
                        Ok(AvailableBlock(AvailableBlockInner::BlockAndBlob(
                            SignedBeaconBlockAndBlobsSidecar {
                                beacon_block,
                                blobs_sidecar,
                            },
                        )))
                    }
                    DataAvailabilityCheckRequired::No => {
                        AvailabilityPendingBlock {
                            block: beacon_block,
                            data_availability_handle: async{ Ok(Some(Blobs::NotRequired))}
                        }
                    }
                }
            }
        }
    }

    /// This function is private because an `AvailableBlock` should be
    /// constructed via the `into_available_block` method.
    //TODO(sean) do we want this to optionally cricumvent the beacon cache?
    fn new_with_blobs(
        beacon_block: Arc<SignedBeaconBlock<T::EthSpec>>,
        blobs_sidecar: Arc<BlobsSidecar<T::EthSpec>>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlobError> {
        let data_availability_boundary = chain.data_availability_boundary();
        let da_check_required =
            data_availability_boundary.map_or(DataAvailabilityCheckRequired::No, |boundary| {
                if chain.epoch()? >= boundary {
                    DataAvailabilityCheckRequired::Yes
                } else {
                    DataAvailabilityCheckRequired::No
                }
            });
        match beacon_block.as_ref() {
            // This method shouldn't be called with a pre-Eip4844 block.
            SignedBeaconBlock::Base(_)
            | SignedBeaconBlock::Altair(_)
            | SignedBeaconBlock::Capella(_)
            | SignedBeaconBlock::Merge(_) => Err(BlobError::InconsistentFork),
            SignedBeaconBlock::Eip4844(_) => {
                match da_check_required {
                    DataAvailabilityCheckRequired::Yes => Ok(AvailableBlock{
                            block: beacon_block,
                            blobs: Blobs::Available(blobs_sidecar),
                        }
                    ),
                    DataAvailabilityCheckRequired::No => {
                        // Blobs were not verified so we drop them, we'll instead just pass around
                        // an available `Eip4844` block without blobs.
                        Ok(AvailableBlock{
                           block: beacon_block,
                            blobs: Blobs::NotRequired
                        })
                    }
                }
            }
        }
    }

}

pub trait IntoBlockWrapper<E: EthSpec>: AsBlock<E> {
    fn into_block_wrapper(self) -> BlockWrapper<E>;
}

impl<E: EthSpec> IntoBlockWrapper<E> for BlockWrapper<E> {
    fn into_block_wrapper(self) -> BlockWrapper<E> {
        self
    }
}

impl<E: EthSpec> IntoBlockWrapper<E> for AvailabilityPendingBlock<E> {
    fn into_block_wrapper(self) -> BlockWrapper<E> {
        let (block, blobs) = self.deconstruct();
        if let Some(blobs) = blobs {
            BlockWrapper::BlockAndBlobs(block, blobs)
        } else {
            BlockWrapper::Block(block)
        }
    }
}

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
}

impl<E: EthSpec> AsBlock<E> for BlockWrapper<E> {
    fn slot(&self) -> Slot {
        match self {
            BlockWrapper::Block(block) => block.slot(),
            BlockWrapper::BlockAndBlobs(block, _) => block.slot(),
        }
    }
    fn epoch(&self) -> Epoch {
        match self {
            BlockWrapper::Block(block) => block.epoch(),
            BlockWrapper::BlockAndBlobs(block, _) => block.epoch(),
        }
    }
    fn parent_root(&self) -> Hash256 {
        match self {
            BlockWrapper::Block(block) => block.parent_root(),
            BlockWrapper::BlockAndBlobs(block, _) => block.parent_root(),
        }
    }
    fn state_root(&self) -> Hash256 {
        match self {
            BlockWrapper::Block(block) => block.state_root(),
            BlockWrapper::BlockAndBlobs(block, _) => block.state_root(),
        }
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        match &self {
            BlockWrapper::Block(block) => block.signed_block_header(),
            BlockWrapper::BlockAndBlobs(block, _) => block.signed_block_header(),
        }
    }
    fn message(&self) -> BeaconBlockRef<E> {
        match &self {
            BlockWrapper::Block(block) => block.message(),
            BlockWrapper::BlockAndBlobs(block, _) => block.message(),
        }
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self {
            BlockWrapper::Block(block) => &block,
            BlockWrapper::BlockAndBlobs(block, _) => &block,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self {
            BlockWrapper::Block(block) => block.clone(),
            BlockWrapper::BlockAndBlobs(block, _) => block.clone(),
        }
    }
    fn canonical_root(&self) -> Hash256 {
        match &self {
            BlockWrapper::Block(block) => block.canonical_root(),
            BlockWrapper::BlockAndBlob(block, _) => block.canonical_root(),
        }
    }
}

impl<E: EthSpec> AsBlock<E> for &BlockWrapper<E> {
    fn slot(&self) -> Slot {
        match self {
            BlockWrapper::Block(block) => block.slot(),
            BlockWrapper::BlockAndBlobs(block, _) => block.slot(),
        }
    }
    fn epoch(&self) -> Epoch {
        match self {
            BlockWrapper::Block(block) => block.epoch(),
            BlockWrapper::BlockAndBlobs(block, _) => block.epoch(),
        }
    }
    fn parent_root(&self) -> Hash256 {
        match self {
            BlockWrapper::Block(block) => block.parent_root(),
            BlockWrapper::BlockAndBlobs(block, _) => block.parent_root(),
        }
    }
    fn state_root(&self) -> Hash256 {
        match self {
            BlockWrapper::Block(block) => block.state_root(),
            BlockWrapper::BlockAndBlobs(block, _) => block.state_root(),
        }
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        match &self {
            BlockWrapper::Block(block) => block.signed_block_header(),
            BlockWrapper::BlockAndBlobs(block, _) => block.signed_block_header(),
        }
    }
    fn message(&self) -> BeaconBlockRef<E> {
        match &self {
            BlockWrapper::Block(block) => block.message(),
            BlockWrapper::BlockAndBlobs(block, _) => block.message(),
        }
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self {
            BlockWrapper::Block(block) => &block,
            BlockWrapper::BlockAndBlobs(block, _) => &block,
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self {
            BlockWrapper::Block(block) => block.clone(),
            BlockWrapper::BlockAndBlobs(block, _) => block.clone(),
        }
    }
    fn canonical_root(&self) -> Hash256 {
        match &self {
            BlockWrapper::Block(block) => block.canonical_root(),
            BlockWrapper::BlockAndBlob(block, _) => block.canonical_root(),
        }
    }
}

impl<E: EthSpec> AsBlock<E> for AvailabilityPendingBlock<E> {
    fn slot(&self) -> Slot {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.slot(),
            AvailableBlockInner::BlockAndBlob(block_sidecar_pair) => {
                block_sidecar_pair.beacon_block.slot()
            }
        }
    }
    fn epoch(&self) -> Epoch {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.epoch(),
            AvailableBlockInner::BlockAndBlob(block_sidecar_pair) => {
                block_sidecar_pair.beacon_block.epoch()
            }
        }
    }
    fn parent_root(&self) -> Hash256 {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.parent_root(),
            AvailableBlockInner::BlockAndBlob(block_sidecar_pair) => {
                block_sidecar_pair.beacon_block.parent_root()
            }
        }
    }
    fn state_root(&self) -> Hash256 {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.state_root(),
            AvailableBlockInner::BlockAndBlob(block_sidecar_pair) => {
                block_sidecar_pair.beacon_block.state_root()
            }
        }
    }
    fn signed_block_header(&self) -> SignedBeaconBlockHeader {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.signed_block_header(),
            AvailableBlockInner::BlockAndBlob(block_sidecar_pair) => {
                block_sidecar_pair.beacon_block.signed_block_header()
            }
        }
    }
    fn message(&self) -> BeaconBlockRef<E> {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.message(),
            AvailableBlockInner::BlockAndBlob(block_sidecar_pair) => {
                block_sidecar_pair.beacon_block.message()
            }
        }
    }
    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match &self.0 {
            AvailableBlockInner::Block(block) => block,
            AvailableBlockInner::BlockAndBlob(block_sidecar_pair) => {
                &block_sidecar_pair.beacon_block
            }
        }
    }
    fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.clone(),
            AvailableBlockInner::BlockAndBlob(block_sidecar_pair) => {
                block_sidecar_pair.beacon_block.clone()
            }
        }
    }
    fn canonical_root(&self) -> Hash256 {
        match &self.0 {
            AvailableBlockInner::Block(block) => block.canonical_root(),
            AvailableBlockInner::BlockAndBlob(block_sidecar_pair) => {
                block_sidecar_pair.beacon_block.canonical_root()
            }
        }
    }
}

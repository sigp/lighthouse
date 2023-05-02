use crate::sync::block_lookups::parent_lookup::LookupDownloadStatus;
use crate::sync::block_lookups::{RootBlobsTuple, RootBlockTuple};
use beacon_chain::blob_verification::BlockWrapper;
use beacon_chain::data_availability_checker::DataAvailabilityChecker;
use beacon_chain::{get_block_root, BeaconChainTypes};
use lighthouse_network::rpc::methods::BlobsByRootRequest;
use lighthouse_network::{rpc::BlocksByRootRequest, PeerId};
use rand::seq::IteratorRandom;
use ssz_types::VariableList;
use std::collections::HashSet;
use std::sync::Arc;
use store::Hash256;
use strum::IntoStaticStr;
use types::blob_sidecar::{BlobIdentifier, FixedBlobSidecarList};
use types::{BlobSidecar, SignedBeaconBlock};

use super::{PeerSource, ResponseType};

pub struct SingleBlockLookup<const MAX_ATTEMPTS: u8, T: BeaconChainTypes> {
    pub requested_block_root: Hash256,
    pub requested_ids: Vec<BlobIdentifier>,
    pub downloaded_blobs: FixedBlobSidecarList<T::EthSpec>,
    pub downloaded_block: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
    pub block_request_state: SingleLookupRequestState<MAX_ATTEMPTS>,
    pub blob_request_state: SingleLookupRequestState<MAX_ATTEMPTS>,
    pub da_checker: Arc<DataAvailabilityChecker<T::EthSpec, T::SlotClock>>,
}

/// Object representing a single block lookup request.
///
//previously assumed we would have a single block. Now we may have the block but not the blobs
#[derive(PartialEq, Eq, Debug)]
pub struct SingleLookupRequestState<const MAX_ATTEMPTS: u8> {
    /// State of this request.
    pub state: State,
    /// Peers that should have this block or blob.
    pub available_peers: HashSet<PeerId>,
    /// Peers that mar or may not have this block or blob.
    pub potential_peers: HashSet<PeerId>,
    /// Peers from which we have requested this block.
    pub used_peers: HashSet<PeerId>,
    /// How many times have we attempted to process this block or blob.
    failed_processing: u8,
    /// How many times have we attempted to download this block or blob.
    failed_downloading: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    AwaitingDownload,
    Downloading { peer_id: PeerSource },
    Processing { peer_id: PeerSource },
}

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupVerifyError {
    RootMismatch,
    NoBlockReturned,
    ExtraBlocksReturned,
    UnrequestedBlobId,
    ExtraBlobsReturned,
    NotEnoughBlobsReturned,
    InvalidIndex(u64),
    /// We don't have enough information to know
    /// whether the peer is at fault or simply missed
    /// what was requested on gossip.
    BenignFailure,
}

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupRequestError {
    /// Too many failed attempts
    TooManyAttempts {
        /// The failed attempts were primarily due to processing failures.
        cannot_process: bool,
    },
    NoPeers,
}

impl<const MAX_ATTEMPTS: u8, T: BeaconChainTypes> SingleBlockLookup<MAX_ATTEMPTS, T> {
    pub fn new(
        requested_block_root: Hash256,
        peer_source: PeerSource,
        da_checker: Arc<DataAvailabilityChecker<T::EthSpec, T::SlotClock>>,
    ) -> Self {
        Self {
            requested_block_root,
            requested_ids: <_>::default(),
            downloaded_block: None,
            downloaded_blobs: <_>::default(),
            block_request_state: SingleLookupRequestState::new(peer_source),
            blob_request_state: SingleLookupRequestState::new(peer_source),
            da_checker,
        }
    }

    pub fn get_downloaded_block(&mut self) -> Option<BlockWrapper<T::EthSpec>> {
        if self.requested_ids.is_empty() {
            if let Some(block) = self.downloaded_block.take() {
                return Some(BlockWrapper::BlockAndBlobs(
                    block,
                    self.downloaded_blobs.clone(),
                ));
            }
        }
        None
    }

    pub fn add_blob(
        &mut self,
        blob: Arc<BlobSidecar<T::EthSpec>>,
    ) -> Result<LookupDownloadStatus<T::EthSpec>, LookupVerifyError> {
        let block_root = blob.block_root;

        if let Some(blob_opt) = self.downloaded_blobs.get_mut(blob.index as usize) {
            *blob_opt = Some(blob.clone());

            if let Some(block) = self.downloaded_block.as_ref() {
                let result = self.da_checker.wrap_block(
                    block_root,
                    block.clone(),
                    self.downloaded_blobs.clone(),
                );
                Ok(LookupDownloadStatus::from(result))
            } else {
                Ok(LookupDownloadStatus::SearchBlock(block_root))
            }
        } else {
            Err(LookupVerifyError::InvalidIndex(blob.index))
        }
    }

    pub fn add_blobs(
        &mut self,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
    ) -> LookupDownloadStatus<T::EthSpec> {
        for (index, blob_opt) in self.downloaded_blobs.iter_mut().enumerate() {
            if let Some(Some(downloaded_blob)) = blobs.get(index) {
                *blob_opt = Some(downloaded_blob.clone());
            }
        }

        if let Some(block) = self.downloaded_block.as_ref() {
            self.da_checker
                .wrap_block(block_root, block.clone(), blobs)
                .into()
        } else {
            LookupDownloadStatus::SearchBlock(block_root)
        }
    }

    pub fn add_block(
        &mut self,
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> LookupDownloadStatus<T::EthSpec> {
        self.downloaded_block = Some(block.clone());

        self.da_checker
            .wrap_block(block_root, block, self.downloaded_blobs.clone())
            .into()
    }

    pub fn add_block_wrapper(
        &mut self,
        block_root: Hash256,
        block: BlockWrapper<T::EthSpec>,
    ) -> LookupDownloadStatus<T::EthSpec> {
        match block {
            BlockWrapper::Block(block) => self.add_block(block_root, block),
            BlockWrapper::BlockAndBlobs(block, blobs) => {
                self.downloaded_block = Some(block);
                self.add_blobs(block_root, blobs)
            }
        }
    }

    /// Verifies if the received block matches the requested one.
    /// Returns the block for processing if the response is what we expected.
    pub fn verify_block(
        &mut self,
        block: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Result<Option<RootBlockTuple<T::EthSpec>>, LookupVerifyError> {
        match self.block_request_state.state {
            State::AwaitingDownload => {
                self.block_request_state.register_failure_downloading();
                Err(LookupVerifyError::ExtraBlocksReturned)
            }
            State::Downloading { peer_id } => match block {
                Some(block) => {
                    // Compute the block root using this specific function so that we can get timing
                    // metrics.
                    let block_root = get_block_root(&block);
                    if block_root != self.requested_block_root {
                        // return an error and drop the block
                        // NOTE: we take this is as a download failure to prevent counting the
                        // attempt as a chain failure, but simply a peer failure.
                        self.block_request_state.register_failure_downloading();
                        Err(LookupVerifyError::RootMismatch)
                    } else {
                        // Return the block for processing.
                        self.block_request_state.state = State::Processing { peer_id };
                        Ok(Some((block_root, block)))
                    }
                }
                None => {
                    if peer_id.should_have_block() {
                        self.block_request_state.register_failure_downloading();
                        Err(LookupVerifyError::NoBlockReturned)
                    } else {
                        Err(LookupVerifyError::BenignFailure)
                    }
                }
            },
            State::Processing { peer_id: _ } => match block {
                Some(_) => {
                    // We sent the block for processing and received an extra block.
                    self.block_request_state.register_failure_downloading();
                    Err(LookupVerifyError::ExtraBlocksReturned)
                }
                None => {
                    // This is simply the stream termination and we are already processing the
                    // block
                    Ok(None)
                }
            },
        }
    }

    pub fn verify_blob(
        &mut self,
        blob: Option<Arc<BlobSidecar<T::EthSpec>>>,
    ) -> Result<Option<RootBlobsTuple<T::EthSpec>>, LookupVerifyError> {
        match self.blob_request_state.state {
            State::AwaitingDownload => {
                self.blob_request_state.register_failure_downloading();
                Err(LookupVerifyError::ExtraBlobsReturned)
            }
            State::Downloading {
                peer_id: peer_source,
            } => match blob {
                Some(blob) => {
                    let received_id = blob.id();
                    if !self.requested_ids.contains(&received_id) {
                        self.blob_request_state.register_failure_downloading();
                        Err(LookupVerifyError::UnrequestedBlobId)
                    } else {
                        // State should remain downloading until we receive the stream terminator.
                        self.requested_ids.retain(|id| *id != received_id);
                        if let Some(blob_opt) = self.downloaded_blobs.get_mut(blob.index as usize) {
                            *blob_opt = Some(blob);
                            Ok(Some((
                                self.requested_block_root,
                                self.downloaded_blobs.clone(),
                            )))
                        } else {
                            Err(LookupVerifyError::InvalidIndex(blob.index))
                        }
                    }
                }
                None => {
                    let downloaded_all_blobs = self.downloaded_all_blobs();
                    if peer_source.should_have_blobs() && !downloaded_all_blobs {
                        return Err(LookupVerifyError::NotEnoughBlobsReturned);
                    } else if !downloaded_all_blobs {
                        return Err(LookupVerifyError::BenignFailure);
                    }
                    self.blob_request_state.state = State::Processing {
                        peer_id: peer_source,
                    };
                    Ok(Some((
                        self.requested_block_root,
                        self.downloaded_blobs.clone(),
                    )))
                }
            },
            State::Processing { peer_id: _ } => match blob {
                Some(_) => {
                    // We sent the blob for processing and received an extra blob.
                    self.blob_request_state.register_failure_downloading();
                    Err(LookupVerifyError::ExtraBlobsReturned)
                }
                None => {
                    // This is simply the stream termination and we are already processing the
                    // block
                    Ok(None)
                }
            },
        }
    }

    fn downloaded_all_blobs(&self) -> bool {
        let expected_num_blobs = self
            .downloaded_block
            .as_ref()
            .map(|block| {
                block
                    .message()
                    .body()
                    .blob_kzg_commitments()
                    .map_or(0, |commitments| commitments.len())
            })
            .unwrap_or(0);
        let downloaded_enough_blobs = expected_num_blobs
            == self
                .downloaded_blobs
                .iter()
                .map(|blob_opt| blob_opt.is_some())
                .count();
        downloaded_enough_blobs
    }

    pub fn request_block(
        &mut self,
    ) -> Result<Option<(PeerId, BlocksByRootRequest)>, LookupRequestError> {
        if self.da_checker.has_block(&self.requested_block_root) || self.downloaded_block.is_some()
        {
            return Ok(None);
        }

        debug_assert!(matches!(
            self.block_request_state.state,
            State::AwaitingDownload
        ));
        if self.block_request_state.failed_attempts() >= MAX_ATTEMPTS {
            Err(LookupRequestError::TooManyAttempts {
                cannot_process: self.block_request_state.failed_processing
                    >= self.block_request_state.failed_downloading,
            })
        } else if let Some(&peer_id) = self
            .block_request_state
            .available_peers
            .iter()
            .choose(&mut rand::thread_rng())
        {
            let request = BlocksByRootRequest {
                block_roots: VariableList::from(vec![self.requested_block_root]),
            };
            self.block_request_state.used_peers.insert(peer_id);
            let peer_source = PeerSource::Attestation(peer_id);
            self.block_request_state.state = State::Downloading {
                peer_id: peer_source,
            };
            Ok(Some((peer_id, request)))
        } else if let Some(&peer_id) = self
            .block_request_state
            .potential_peers
            .iter()
            .choose(&mut rand::thread_rng())
        {
            let request = BlocksByRootRequest {
                block_roots: VariableList::from(vec![self.requested_block_root]),
            };
            self.block_request_state.used_peers.insert(peer_id);
            let peer_source = PeerSource::Gossip(peer_id);
            self.block_request_state.state = State::Downloading {
                peer_id: peer_source,
            };
            Ok(Some((peer_id, request)))
        } else {
            Err(LookupRequestError::NoPeers)
        }
    }

    pub fn request_blobs(
        &mut self,
    ) -> Result<Option<(PeerId, BlobsByRootRequest)>, LookupRequestError> {
        let missing_ids = self
            .da_checker
            .get_missing_blob_ids(&self.requested_block_root);
        if missing_ids.is_empty() || self.downloaded_block.is_some() {
            return Ok(None);
        }

        debug_assert!(matches!(
            self.blob_request_state.state,
            State::AwaitingDownload
        ));
        if self.blob_request_state.failed_attempts() >= MAX_ATTEMPTS {
            Err(LookupRequestError::TooManyAttempts {
                cannot_process: self.blob_request_state.failed_processing
                    >= self.blob_request_state.failed_downloading,
            })
        } else if let Some(&peer_id) = self
            .blob_request_state
            .available_peers
            .iter()
            .choose(&mut rand::thread_rng())
        {
            let request = BlobsByRootRequest {
                blob_ids: VariableList::from(missing_ids.clone()),
            };
            self.blob_request_state.used_peers.insert(peer_id);
            let peer_source = PeerSource::Attestation(peer_id);
            self.requested_ids = missing_ids;
            self.blob_request_state.state = State::Downloading {
                peer_id: peer_source,
            };
            Ok(Some((peer_id, request)))
        } else if let Some(&peer_id) = self
            .blob_request_state
            .potential_peers
            .iter()
            .choose(&mut rand::thread_rng())
        {
            let request = BlobsByRootRequest {
                blob_ids: VariableList::from(missing_ids.clone()),
            };
            self.blob_request_state.used_peers.insert(peer_id);
            let peer_source = PeerSource::Gossip(peer_id);
            self.requested_ids = missing_ids;
            self.blob_request_state.state = State::Downloading {
                peer_id: peer_source,
            };
            Ok(Some((peer_id, request)))
        } else {
            Err(LookupRequestError::NoPeers)
        }
    }

    pub fn add_peer_if_useful(&mut self, block_root: &Hash256, peer_source: PeerSource) -> bool {
        if *block_root != self.requested_block_root {
            return false;
        }
        match peer_source {
            PeerSource::Attestation(peer_id) => {
                self.block_request_state.add_peer(&peer_id);
                self.blob_request_state.add_peer(&peer_id);
            }
            PeerSource::Gossip(peer_id) => {
                self.block_request_state.add_potential_peer(&peer_id);
                self.blob_request_state.add_potential_peer(&peer_id);
            }
        }
        true
    }

    pub fn processing_peer(&self, response_type: ResponseType) -> Result<PeerSource, ()> {
        match response_type {
            ResponseType::Block => self.block_request_state.processing_peer(),
            ResponseType::Blob => self.blob_request_state.processing_peer(),
        }
    }

    pub(crate) fn peer_source(
        &self,
        response_type: ResponseType,
        peer_id: PeerId,
    ) -> Option<PeerSource> {
        match response_type {
            ResponseType::Block => {
                if self.block_request_state.available_peers.contains(&peer_id) {
                    Some(PeerSource::Attestation(peer_id))
                } else if self.block_request_state.potential_peers.contains(&peer_id) {
                    Some(PeerSource::Gossip(peer_id))
                } else {
                    None
                }
            }
            ResponseType::Blob => {
                if self.blob_request_state.available_peers.contains(&peer_id) {
                    Some(PeerSource::Attestation(peer_id))
                } else if self.blob_request_state.potential_peers.contains(&peer_id) {
                    Some(PeerSource::Gossip(peer_id))
                } else {
                    None
                }
            }
        }
    }
}

impl<const MAX_ATTEMPTS: u8> SingleLookupRequestState<MAX_ATTEMPTS> {
    pub fn new(peer_source: PeerSource) -> Self {
        let (available_peers, potential_peers) = match peer_source {
            PeerSource::Attestation(peer_id) => (HashSet::from([peer_id]), HashSet::default()),
            PeerSource::Gossip(peer_id) => (HashSet::default(), HashSet::from([peer_id])),
        };
        Self {
            state: State::AwaitingDownload,
            available_peers,
            potential_peers,
            used_peers: HashSet::default(),
            failed_processing: 0,
            failed_downloading: 0,
        }
    }

    /// Registers a failure in processing a block.
    pub fn register_failure_processing(&mut self) {
        self.failed_processing = self.failed_processing.saturating_add(1);
        self.state = State::AwaitingDownload;
    }

    /// Registers a failure in downloading a block. This might be a peer disconnection or a wrong
    /// block.
    pub fn register_failure_downloading(&mut self) {
        self.failed_downloading = self.failed_downloading.saturating_add(1);
        self.state = State::AwaitingDownload;
    }

    /// The total number of failures, whether it be processing or downloading.
    pub fn failed_attempts(&self) -> u8 {
        self.failed_processing + self.failed_downloading
    }

    pub fn add_peer(&mut self, peer_id: &PeerId) {
        self.potential_peers.remove(peer_id);
        self.available_peers.insert(*peer_id);
    }

    pub fn add_potential_peer(&mut self, peer_id: &PeerId) {
        if self.available_peers.contains(peer_id) {
            self.potential_peers.insert(*peer_id);
        }
    }

    /// If a peer disconnects, this request could be failed. If so, an error is returned
    pub fn check_peer_disconnected(&mut self, dc_peer_id: &PeerId) -> Result<(), ()> {
        self.available_peers.remove(dc_peer_id);
        self.potential_peers.remove(dc_peer_id);
        if let State::Downloading { peer_id } = &self.state {
            if peer_id.as_peer_id() == dc_peer_id {
                // Peer disconnected before providing a block
                self.register_failure_downloading();
                return Err(());
            }
        }
        Ok(())
    }

    pub fn processing_peer(&self) -> Result<PeerSource, ()> {
        if let State::Processing { peer_id } = &self.state {
            Ok(*peer_id)
        } else {
            Err(())
        }
    }
}

impl<const MAX_ATTEMPTS: u8, T: BeaconChainTypes> slog::Value
    for SingleBlockLookup<MAX_ATTEMPTS, T>
{
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str("request", key)?;
        serializer.emit_arguments("hash", &format_args!("{}", self.requested_block_root))?;
        serializer.emit_arguments("blob_ids", &format_args!("{:?}", self.requested_ids))?;
        serializer.emit_arguments(
            "block_request_state",
            &format_args!("{:?}", self.block_request_state),
        )?;
        serializer.emit_arguments(
            "blob_request_state",
            &format_args!("{:?}", self.blob_request_state),
        )?;
        slog::Result::Ok(())
    }
}

impl<const MAX_ATTEMPTS: u8> slog::Value for SingleLookupRequestState<MAX_ATTEMPTS> {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str("request_state", key)?;
        match &self.state {
            State::AwaitingDownload => {
                "awaiting_download".serialize(record, "state", serializer)?
            }
            State::Downloading { peer_id } => {
                serializer.emit_arguments("downloading_peer", &format_args!("{}", peer_id))?
            }
            State::Processing { peer_id } => {
                serializer.emit_arguments("processing_peer", &format_args!("{}", peer_id))?
            }
        }
        serializer.emit_u8("failed_downloads", self.failed_downloading)?;
        serializer.emit_u8("failed_processing", self.failed_processing)?;
        slog::Result::Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_chain::builder::Witness;
    use beacon_chain::eth1_chain::CachingEth1Backend;
    use slot_clock::{SlotClock, TestingSlotClock};
    use std::time::Duration;
    use store::MemoryStore;
    use types::{
        test_utils::{SeedableRng, TestRandom, XorShiftRng},
        EthSpec, MinimalEthSpec as E, SignedBeaconBlock, Slot,
    };

    fn rand_block() -> SignedBeaconBlock<E> {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        SignedBeaconBlock::from_block(
            types::BeaconBlock::Base(types::BeaconBlockBase {
                ..<_>::random_for_test(&mut rng)
            }),
            types::Signature::random_for_test(&mut rng),
        )
    }
    type T = Witness<TestingSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

    #[test]
    fn test_happy_path() {
        let peer_id = PeerId::random();
        let block = rand_block();
        let spec = E::default_spec();
        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            Duration::from_secs(spec.seconds_per_slot),
        );
        let da_checker = Arc::new(DataAvailabilityChecker::new(slot_clock, None, spec));
        let mut sl = SingleBlockLookup::<4, T>::new(block.canonical_root(), peer_id, da_checker);
        sl.request_block().unwrap();
        sl.verify_block(Some(block.into())).unwrap().unwrap();
    }

    #[test]
    fn test_block_lookup_failures() {
        const FAILURES: u8 = 3;
        let peer_id = PeerId::random();
        let block = rand_block();
        let spec = E::default_spec();
        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            Duration::from_secs(spec.seconds_per_slot),
        );

        let da_checker = Arc::new(DataAvailabilityChecker::new(slot_clock, None, spec));

        let mut sl =
            SingleBlockLookup::<FAILURES, T>::new(block.canonical_root(), peer_id, da_checker);
        for _ in 1..FAILURES {
            sl.request_block().unwrap();
            sl.block_request_state.register_failure_downloading();
        }

        // Now we receive the block and send it for processing
        sl.request_block().unwrap();
        sl.verify_block(Some(block.into())).unwrap().unwrap();

        // One processing failure maxes the available attempts
        sl.block_request_state.register_failure_processing();
        assert_eq!(
            sl.request_block(),
            Err(LookupRequestError::TooManyAttempts {
                cannot_process: false
            })
        )
    }
}

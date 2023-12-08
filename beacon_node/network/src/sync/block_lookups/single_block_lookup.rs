use super::PeerId;
use crate::sync::block_lookups::common::{Lookup, RequestState};
use crate::sync::block_lookups::Id;
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::data_availability_checker::{
    AvailabilityCheckError, DataAvailabilityChecker, MissingBlobs,
};
use beacon_chain::data_availability_checker::{AvailabilityView, ChildComponents};
use beacon_chain::BeaconChainTypes;
use lighthouse_network::PeerAction;
use slog::{trace, Logger};
use std::collections::HashSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use store::Hash256;
use strum::IntoStaticStr;
use types::blob_sidecar::FixedBlobSidecarList;
use types::EthSpec;

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    AwaitingDownload,
    Downloading { peer_id: PeerId },
    Processing { peer_id: PeerId },
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
}

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupRequestError {
    /// Too many failed attempts
    TooManyAttempts {
        /// The failed attempts were primarily due to processing failures.
        cannot_process: bool,
    },
    NoPeers,
    SendFailed(&'static str),
}

pub struct SingleBlockLookup<L: Lookup, T: BeaconChainTypes> {
    pub id: Id,
    pub block_request_state: BlockRequestState<L>,
    pub blob_request_state: BlobRequestState<L, T::EthSpec>,
    pub da_checker: Arc<DataAvailabilityChecker<T>>,
    /// Only necessary for requests triggered by an `UnknownBlockParent` or `UnknownBlockParent`
    /// because any blocks or blobs without parents won't hit the data availability cache.
    pub child_components: Option<ChildComponents<T::EthSpec>>,
}

impl<L: Lookup, T: BeaconChainTypes> SingleBlockLookup<L, T> {
    pub fn new(
        requested_block_root: Hash256,
        child_components: Option<ChildComponents<T::EthSpec>>,
        peers: &[PeerId],
        da_checker: Arc<DataAvailabilityChecker<T>>,
        id: Id,
    ) -> Self {
        let is_deneb = da_checker.is_deneb();
        Self {
            id,
            block_request_state: BlockRequestState::new(requested_block_root, peers),
            blob_request_state: BlobRequestState::new(requested_block_root, peers, is_deneb),
            da_checker,
            child_components,
        }
    }

    /// Get the block root that is being requested.
    pub fn block_root(&self) -> Hash256 {
        self.block_request_state.requested_block_root
    }

    /// Check the block root matches the requested block root.
    pub fn is_for_block(&self, block_root: Hash256) -> bool {
        self.block_root() == block_root
    }

    /// Update the requested block, this should only be used in a chain of parent lookups to request
    /// the next parent.
    pub fn update_requested_parent_block(&mut self, block_root: Hash256) {
        self.block_request_state.requested_block_root = block_root;
        self.block_request_state.state.state = State::AwaitingDownload;
        self.blob_request_state.state.state = State::AwaitingDownload;
        self.child_components = Some(ChildComponents::empty(block_root));
    }

    /// Get all unique peers across block and blob requests.
    pub fn all_peers(&self) -> HashSet<PeerId> {
        let mut all_peers = self.block_request_state.state.used_peers.clone();
        all_peers.extend(self.blob_request_state.state.used_peers.clone());
        all_peers
    }

    /// Send the necessary requests for blocks and/or blobs. This will check whether we have
    /// downloaded the block and/or blobs already and will not send requests if so. It will also
    /// inspect the request state or blocks and blobs to ensure we are not already processing or
    /// downloading the block and/or blobs.
    pub fn request_block_and_blobs(
        &mut self,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        let block_root = self.block_root();
        let block_already_downloaded = self.block_already_downloaded();
        let blobs_already_downloaded = self.blobs_already_downloaded();

        if block_already_downloaded && blobs_already_downloaded {
            trace!(cx.log, "Lookup request already completed"; "block_root"=> ?block_root);
            return Ok(());
        }
        let id = self.id;
        self.block_request_state
            .build_request_and_send(id, block_already_downloaded, cx)?;
        self.blob_request_state
            .build_request_and_send(id, blobs_already_downloaded, cx)
    }

    /// Returns a `CachedChild`, which is a wrapper around a `RpcBlock` that is either:
    ///
    /// 1. `NotRequired`: there is no child caching required for this lookup.
    /// 2. `DownloadIncomplete`: Child caching is required, but all components are not yet downloaded.
    /// 3. `Ok`: The child is required and we have downloaded it.
    /// 4. `Err`: The child is required, but has failed consistency checks.
    pub fn get_cached_child_block(&self) -> CachedChild<T::EthSpec> {
        if let Some(components) = self.child_components.as_ref() {
            let Some(block) = components.downloaded_block.as_ref() else {
                return CachedChild::DownloadIncomplete;
            };

            if !self.missing_blob_ids().is_empty() {
                return CachedChild::DownloadIncomplete;
            }

            match RpcBlock::new_from_fixed(
                self.block_request_state.requested_block_root,
                block.clone(),
                components.downloaded_blobs.clone(),
            ) {
                Ok(rpc_block) => CachedChild::Ok(rpc_block),
                Err(e) => CachedChild::Err(e),
            }
        } else {
            CachedChild::NotRequired
        }
    }

    /// Accepts a verified response, and adds it to the child components if required. This method
    /// returns a `CachedChild` which provides a completed block + blob response if all components have been
    /// received, or information about whether the child is required and if it has been downloaded.
    pub fn add_response<R: RequestState<L, T>>(
        &mut self,
        verified_response: R::VerifiedResponseType,
    ) -> CachedChild<T::EthSpec> {
        if let Some(child_components) = self.child_components.as_mut() {
            R::add_to_child_components(verified_response, child_components);
            self.get_cached_child_block()
        } else {
            CachedChild::NotRequired
        }
    }

    /// Add a child component to the lookup request. Merges with any existing child components.
    pub fn add_child_components(&mut self, components: ChildComponents<T::EthSpec>) {
        if let Some(ref mut existing_components) = self.child_components {
            let ChildComponents {
                block_root: _,
                downloaded_block,
                downloaded_blobs,
            } = components;
            if let Some(block) = downloaded_block {
                existing_components.merge_block(block);
            }
            existing_components.merge_blobs(downloaded_blobs);
        } else {
            self.child_components = Some(components);
        }
    }

    /// Add all given peers to both block and blob request states.
    pub fn add_peer(&mut self, peer_id: PeerId) {
        self.block_request_state.state.add_peer(&peer_id);
        self.blob_request_state.state.add_peer(&peer_id);
    }

    /// Add all given peers to both block and blob request states.
    pub fn add_peers(&mut self, peers: &[PeerId]) {
        for peer in peers {
            self.add_peer(*peer);
        }
    }

    /// Returns true if the block has already been downloaded.
    pub fn both_components_downloaded(&self) -> bool {
        self.block_request_state.state.component_downloaded
            && self.blob_request_state.state.component_downloaded
    }

    /// Returns true if the block has already been downloaded.
    pub fn both_components_processed(&self) -> bool {
        self.block_request_state.state.component_processed
            && self.blob_request_state.state.component_processed
    }

    /// Checks both the block and blob request states to see if the peer is disconnected.
    ///
    /// Returns true if the lookup should be dropped.
    pub fn should_drop_lookup_on_disconnected_peer(
        &mut self,
        peer_id: &PeerId,
        cx: &SyncNetworkContext<T>,
        log: &Logger,
    ) -> bool {
        let block_root = self.block_root();
        let block_peer_disconnected = self
            .block_request_state
            .state
            .check_peer_disconnected(peer_id)
            .is_err();
        let blob_peer_disconnected = self
            .blob_request_state
            .state
            .check_peer_disconnected(peer_id)
            .is_err();

        if block_peer_disconnected || blob_peer_disconnected {
            if let Err(e) = self.request_block_and_blobs(cx) {
                trace!(log, "Single lookup failed on peer disconnection"; "block_root" => ?block_root, "error" => ?e);
                return true;
            }
        }
        false
    }

    /// Returns `true` if the block has already been downloaded.
    pub(crate) fn block_already_downloaded(&self) -> bool {
        if let Some(components) = self.child_components.as_ref() {
            components.block_exists()
        } else {
            self.da_checker.has_block(&self.block_root())
        }
    }

    /// Updates the `requested_ids` field of the `BlockRequestState` with the most recent picture
    /// of which blobs still need to be requested. Returns `true` if there are no more blobs to
    /// request.
    pub(crate) fn blobs_already_downloaded(&mut self) -> bool {
        self.update_blobs_request();
        self.blob_request_state.requested_ids.is_empty()
    }

    /// Updates this request with the most recent picture of which blobs still need to be requested.
    pub fn update_blobs_request(&mut self) {
        self.blob_request_state.requested_ids = self.missing_blob_ids();
    }

    /// If `child_components` is `Some`, we know block components won't hit the data
    /// availability cache, so we don't check its processing cache unless `child_components`
    /// is `None`.
    pub(crate) fn missing_blob_ids(&self) -> MissingBlobs {
        let block_root = self.block_root();
        if let Some(components) = self.child_components.as_ref() {
            self.da_checker.get_missing_blob_ids(block_root, components)
        } else {
            let Some(processing_availability_view) =
                self.da_checker.get_processing_components(block_root)
            else {
                return MissingBlobs::new_without_block(block_root, self.da_checker.is_deneb());
            };
            self.da_checker
                .get_missing_blob_ids(block_root, &processing_availability_view)
        }
    }

    /// Penalizes a blob peer if it should have blobs but didn't return them to us.     
    pub fn penalize_blob_peer(&mut self, cx: &SyncNetworkContext<T>) {
        if let Ok(blob_peer) = self.blob_request_state.state.processing_peer() {
            cx.report_peer(
                blob_peer,
                PeerAction::MidToleranceError,
                "single_blob_failure",
            );
        }
    }

    /// This failure occurs on download, so register a failure downloading, penalize the peer
    /// and clear the blob cache.
    pub fn handle_consistency_failure(&mut self, cx: &SyncNetworkContext<T>) {
        self.penalize_blob_peer(cx);
        if let Some(cached_child) = self.child_components.as_mut() {
            cached_child.clear_blobs();
        }
        self.blob_request_state.state.register_failure_downloading()
    }

    /// This failure occurs after processing, so register a failure processing, penalize the peer
    /// and clear the blob cache.
    pub fn handle_availability_check_failure(&mut self, cx: &SyncNetworkContext<T>) {
        self.penalize_blob_peer(cx);
        if let Some(cached_child) = self.child_components.as_mut() {
            cached_child.clear_blobs();
        }
        self.blob_request_state.state.register_failure_processing()
    }
}

/// The state of the blob request component of a `SingleBlockLookup`.
pub struct BlobRequestState<L: Lookup, T: EthSpec> {
    /// The latest picture of which blobs still need to be requested. This includes information
    /// from both block/blobs downloaded in the network layer and any blocks/blobs that exist in
    /// the data availability checker.
    pub requested_ids: MissingBlobs,
    /// Where we store blobs until we receive the stream terminator.
    pub blob_download_queue: FixedBlobSidecarList<T>,
    pub state: SingleLookupRequestState,
    _phantom: PhantomData<L>,
}

impl<L: Lookup, E: EthSpec> BlobRequestState<L, E> {
    pub fn new(block_root: Hash256, peer_source: &[PeerId], is_deneb: bool) -> Self {
        let default_ids = MissingBlobs::new_without_block(block_root, is_deneb);
        Self {
            requested_ids: default_ids,
            blob_download_queue: <_>::default(),
            state: SingleLookupRequestState::new(peer_source),
            _phantom: PhantomData,
        }
    }
}

/// The state of the block request component of a `SingleBlockLookup`.
pub struct BlockRequestState<L: Lookup> {
    pub requested_block_root: Hash256,
    pub state: SingleLookupRequestState,
    _phantom: PhantomData<L>,
}

impl<L: Lookup> BlockRequestState<L> {
    pub fn new(block_root: Hash256, peers: &[PeerId]) -> Self {
        Self {
            requested_block_root: block_root,
            state: SingleLookupRequestState::new(peers),
            _phantom: PhantomData,
        }
    }
}

/// This is the status of cached components for a lookup if they are required. It provides information
/// about whether we should send a responses immediately for processing, whether we require more
/// responses, or whether all cached components have been received and the reconstructed block
/// should be sent for processing.
pub enum CachedChild<E: EthSpec> {
    /// All child components have been received, this is the reconstructed block, including all.
    /// It has been checked for consistency between blobs and block, but no consensus checks have
    /// been performed and no kzg verification has been performed.
    Ok(RpcBlock<E>),
    /// All child components have not yet been received.
    DownloadIncomplete,
    /// Child components should not be cached, send this directly for processing.
    NotRequired,
    /// There was an error during consistency checks between block and blobs.
    Err(AvailabilityCheckError),
}
/// Object representing the state of a single block or blob lookup request.
#[derive(PartialEq, Eq, Debug)]
pub struct SingleLookupRequestState {
    /// State of this request.
    pub state: State,
    /// Peers that should have this block or blob.
    pub available_peers: HashSet<PeerId>,
    /// Peers from which we have requested this block.
    pub used_peers: HashSet<PeerId>,
    /// How many times have we attempted to process this block or blob.
    pub failed_processing: u8,
    /// How many times have we attempted to download this block or blob.
    pub failed_downloading: u8,
    /// Whether or not we have downloaded this block or blob.
    pub component_downloaded: bool,
    /// Whether or not we have processed this block or blob.
    pub component_processed: bool,
    /// Should be incremented everytime this request is retried. The purpose of this is to
    /// differentiate retries of the same block/blob request within a lookup. We currently penalize
    /// peers and retry requests prior to receiving the stream terminator. This means responses
    /// from a prior request may arrive after a new request has been sent, this counter allows
    /// us to differentiate these two responses.
    pub req_counter: u32,
}

impl SingleLookupRequestState {
    pub fn new(peers: &[PeerId]) -> Self {
        let mut available_peers = HashSet::default();
        for peer in peers.iter().copied() {
            available_peers.insert(peer);
        }

        Self {
            state: State::AwaitingDownload,
            available_peers,
            used_peers: HashSet::default(),
            failed_processing: 0,
            failed_downloading: 0,
            component_downloaded: false,
            component_processed: false,
            req_counter: 0,
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

    /// This method should be used for peers wrapped in `PeerId::BlockAndBlobs`.
    pub fn add_peer(&mut self, peer_id: &PeerId) {
        self.available_peers.insert(*peer_id);
    }

    /// If a peer disconnects, this request could be failed. If so, an error is returned
    pub fn check_peer_disconnected(&mut self, dc_peer_id: &PeerId) -> Result<(), ()> {
        self.available_peers.remove(dc_peer_id);
        if let State::Downloading { peer_id } = &self.state {
            if peer_id == dc_peer_id {
                // Peer disconnected before providing a block
                self.register_failure_downloading();
                return Err(());
            }
        }
        Ok(())
    }

    /// Returns the id peer we downloaded from if we have downloaded a verified block, otherwise
    /// returns an error.
    pub fn processing_peer(&self) -> Result<PeerId, ()> {
        if let State::Processing { peer_id } = &self.state {
            Ok(*peer_id)
        } else {
            Err(())
        }
    }
}

impl<L: Lookup, T: BeaconChainTypes> slog::Value for SingleBlockLookup<L, T> {
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str("request", key)?;
        serializer.emit_arguments("lookup_type", &format_args!("{:?}", L::lookup_type()))?;
        serializer.emit_arguments("hash", &format_args!("{}", self.block_root()))?;
        serializer.emit_arguments(
            "blob_ids",
            &format_args!("{:?}", self.blob_request_state.requested_ids.indices()),
        )?;
        serializer.emit_arguments(
            "block_request_state.state",
            &format_args!("{:?}", self.block_request_state.state),
        )?;
        serializer.emit_arguments(
            "blob_request_state.state",
            &format_args!("{:?}", self.blob_request_state.state),
        )?;
        slog::Result::Ok(())
    }
}

impl slog::Value for SingleLookupRequestState {
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
    use crate::sync::block_lookups::common::LookupType;
    use crate::sync::block_lookups::common::{Lookup, RequestState};
    use beacon_chain::builder::Witness;
    use beacon_chain::eth1_chain::CachingEth1Backend;
    use sloggers::null::NullLoggerBuilder;
    use sloggers::Build;
    use slot_clock::{SlotClock, TestingSlotClock};
    use std::time::Duration;
    use store::{HotColdDB, MemoryStore, StoreConfig};
    use types::{
        test_utils::{SeedableRng, TestRandom, XorShiftRng},
        ChainSpec, EthSpec, MinimalEthSpec as E, SignedBeaconBlock, Slot,
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

    struct TestLookup1;

    impl Lookup for TestLookup1 {
        const MAX_ATTEMPTS: u8 = 3;

        fn lookup_type() -> LookupType {
            panic!()
        }
    }

    struct TestLookup2;

    impl Lookup for TestLookup2 {
        const MAX_ATTEMPTS: u8 = 4;

        fn lookup_type() -> LookupType {
            panic!()
        }
    }

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
        let log = NullLoggerBuilder.build().expect("logger should build");
        let store =
            HotColdDB::open_ephemeral(StoreConfig::default(), ChainSpec::minimal(), log.clone())
                .expect("store");
        let da_checker = Arc::new(
            DataAvailabilityChecker::new(slot_clock, None, store.into(), &log, spec.clone())
                .expect("data availability checker"),
        );
        let mut sl = SingleBlockLookup::<TestLookup1, T>::new(
            block.canonical_root(),
            None,
            &[peer_id],
            da_checker,
            1,
        );
        <BlockRequestState<TestLookup1> as RequestState<TestLookup1, T>>::build_request(
            &mut sl.block_request_state,
            &spec,
        )
        .unwrap();
        sl.block_request_state.state.state = State::Downloading { peer_id };

        <BlockRequestState<TestLookup1> as RequestState<TestLookup1, T>>::verify_response(
            &mut sl.block_request_state,
            block.canonical_root(),
            Some(block.into()),
        )
        .unwrap()
        .unwrap();
    }

    #[test]
    fn test_block_lookup_failures() {
        let peer_id = PeerId::random();
        let block = rand_block();
        let spec = E::default_spec();
        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            Duration::from_secs(spec.seconds_per_slot),
        );
        let log = NullLoggerBuilder.build().expect("logger should build");
        let store =
            HotColdDB::open_ephemeral(StoreConfig::default(), ChainSpec::minimal(), log.clone())
                .expect("store");

        let da_checker = Arc::new(
            DataAvailabilityChecker::new(slot_clock, None, store.into(), &log, spec.clone())
                .expect("data availability checker"),
        );

        let mut sl = SingleBlockLookup::<TestLookup2, T>::new(
            block.canonical_root(),
            None,
            &[peer_id],
            da_checker,
            1,
        );
        for _ in 1..TestLookup2::MAX_ATTEMPTS {
            <BlockRequestState<TestLookup2> as RequestState<TestLookup2, T>>::build_request(
                &mut sl.block_request_state,
                &spec,
            )
            .unwrap();
            sl.block_request_state.state.register_failure_downloading();
        }

        // Now we receive the block and send it for processing
        <BlockRequestState<TestLookup2> as RequestState<TestLookup2, T>>::build_request(
            &mut sl.block_request_state,
            &spec,
        )
        .unwrap();
        sl.block_request_state.state.state = State::Downloading { peer_id };

        <BlockRequestState<TestLookup2> as RequestState<TestLookup2, T>>::verify_response(
            &mut sl.block_request_state,
            block.canonical_root(),
            Some(block.into()),
        )
        .unwrap()
        .unwrap();

        // One processing failure maxes the available attempts
        sl.block_request_state.state.register_failure_processing();
        assert_eq!(
            <BlockRequestState<TestLookup2> as RequestState<TestLookup2, T>>::build_request(
                &mut sl.block_request_state,
                &spec
            ),
            Err(LookupRequestError::TooManyAttempts {
                cannot_process: false
            })
        )
    }
}

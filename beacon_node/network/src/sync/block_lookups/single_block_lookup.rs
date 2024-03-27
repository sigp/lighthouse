use super::PeerId;
use crate::sync::block_lookups::common::RequestState;
use crate::sync::block_lookups::Id;
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::data_availability_checker::{DataAvailabilityChecker, MissingBlobs};
use beacon_chain::BeaconChainTypes;
use lighthouse_network::PeerAction;
use slog::{trace, Logger};
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use store::Hash256;
use strum::IntoStaticStr;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{EthSpec, SignedBeaconBlock};

#[derive(Debug, PartialEq, Eq)]
pub enum State<T> {
    AwaitingDownload,
    Downloading {
        peer_id: PeerId,
    },
    UnknownParent {
        peer_id: PeerId,
        value: T,
        parent_root: Option<Hash256>,
        seen_timestamp: Duration,
    },
    Processing {
        peer_id: PeerId,
        value: T,
        parent_root: Option<Hash256>,
        seen_timestamp: Duration,
    },
    Poisoned,
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
    PreviousFailure,
}

pub struct SingleBlockLookup<T: BeaconChainTypes> {
    pub id: Id,
    pub block_request_state: BlockRequestState<T::EthSpec>,
    pub blob_request_state: BlobRequestState<T::EthSpec>,
    pub da_checker: Arc<DataAvailabilityChecker<T>>,
}

impl<T: BeaconChainTypes> SingleBlockLookup<T> {
    pub fn new(
        requested_block_root: Hash256,
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

    /// Get all unique peers across block and blob requests.
    pub fn all_peers(&self) -> Vec<PeerId> {
        let mut all_peers = self.block_request_state.state.used_peers.clone();
        all_peers.extend(self.blob_request_state.state.used_peers.clone());
        all_peers.iter().cloned().collect()
    }

    /// Send the necessary requests for blocks and/or blobs. This will check whether we have
    /// downloaded the block and/or blobs already and will not send requests if so. It will also
    /// inspect the request state or blocks and blobs to ensure we are not already processing or
    /// downloading the block and/or blobs.
    pub fn request_block_and_blobs(
        &mut self,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        let block_already_downloaded = self.block_already_downloaded();
        let blobs_already_downloaded = self.blobs_already_downloaded();

        if !block_already_downloaded {
            self.block_request_state
                .build_request_and_send(self.id, cx)?;
        }
        if !blobs_already_downloaded {
            self.blob_request_state
                .build_request_and_send(self.id, cx)?;
        }
        Ok(())
    }

    pub fn process_block_and_blobs(
        &mut self,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), LookupRequestError> {
        self.block_request_state
            .send_cached_for_processing(self.id, self.block_root(), cx)?;
        self.block_request_state
            .send_cached_for_processing(self.id, self.block_root(), cx)?;
        Ok(())
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

    pub fn check_peer_disconnected(&mut self, peer_id: &PeerId) -> Result<(), ()> {
        self.block_request_state
            .state
            .check_peer_disconnected(peer_id)?;
        self.blob_request_state
            .state
            .check_peer_disconnected(peer_id)
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
        let request_peer_disconnected = self.check_peer_disconnected(peer_id).is_err();

        if request_peer_disconnected {
            if let Err(e) = self.request_block_and_blobs(cx) {
                trace!(log, "Single lookup failed on peer disconnection"; "block_root" => ?block_root, "error" => ?e);
                return true;
            }
        }
        false
    }

    /// Returns `true` if the block has already been downloaded.
    pub(crate) fn block_already_downloaded(&self) -> bool {
        self.da_checker.has_block(&self.block_root())
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
        let Some(processing_availability_view) =
            self.da_checker.get_processing_components(block_root)
        else {
            return MissingBlobs::new_without_block(block_root, self.da_checker.is_deneb());
        };
        self.da_checker
            .get_missing_blob_ids(block_root, &processing_availability_view)
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

    /// This failure occurs after processing, so register a failure processing, penalize the peer
    /// and clear the blob cache.
    pub fn handle_availability_check_failure(&mut self, cx: &SyncNetworkContext<T>) {
        self.penalize_blob_peer(cx);
        self.blob_request_state.state.on_processing_failure()
    }

    /// Return the parent root of this reques's block header, if known
    pub fn parent_root(&self) -> Option<Hash256> {
        if let Some(parent_root) = self.block_request_state.state.parent_root() {
            Some(parent_root)
        } else if let Some(parent_root) = self.blob_request_state.state.parent_root() {
            Some(parent_root)
        } else {
            None
        }
    }
}

/// The state of the blob request component of a `SingleBlockLookup`.
pub struct BlobRequestState<E: EthSpec> {
    /// The latest picture of which blobs still need to be requested. This includes information
    /// from both block/blobs downloaded in the network layer and any blocks/blobs that exist in
    /// the data availability checker.
    pub requested_ids: MissingBlobs,
    /// Where we store blobs until we receive the stream terminator.
    pub blob_download_queue: FixedBlobSidecarList<E>,
    pub state: SingleLookupRequestState<FixedBlobSidecarList<E>>,
}

impl<E: EthSpec> BlobRequestState<E> {
    pub fn new(block_root: Hash256, peer_source: &[PeerId], is_deneb: bool) -> Self {
        let default_ids = MissingBlobs::new_without_block(block_root, is_deneb);
        Self {
            requested_ids: default_ids,
            blob_download_queue: <_>::default(),
            state: SingleLookupRequestState::new(peer_source),
        }
    }
}

/// The state of the block request component of a `SingleBlockLookup`.
pub struct BlockRequestState<E: EthSpec> {
    pub requested_block_root: Hash256,
    pub state: SingleLookupRequestState<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> BlockRequestState<E> {
    pub fn new(block_root: Hash256, peers: &[PeerId]) -> Self {
        Self {
            requested_block_root: block_root,
            state: SingleLookupRequestState::new(peers),
        }
    }
}

/// Object representing the state of a single block or blob lookup request.
#[derive(PartialEq, Eq, Debug)]
pub struct SingleLookupRequestState<T> {
    /// State of this request.
    state: State<T>,
    /// Peers that should have this block or blob.
    pub available_peers: HashSet<PeerId>,
    /// Peers from which we have requested this block.
    pub used_peers: HashSet<PeerId>,
    /// How many times have we attempted to process this block or blob.
    failed_processing: u8,
    /// How many times have we attempted to download this block or blob.
    failed_downloading: u8,
    /// Whether or not we have processed this block or blob.
    component_processed: bool,
    /// Should be incremented everytime this request is retried. The purpose of this is to
    /// differentiate retries of the same block/blob request within a lookup. We currently penalize
    /// peers and retry requests prior to receiving the stream terminator. This means responses
    /// from a prior request may arrive after a new request has been sent, this counter allows
    /// us to differentiate these two responses.
    req_counter: u32,
}

impl<T: Clone> SingleLookupRequestState<T> {
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
            component_processed: false,
            req_counter: 0,
        }
    }

    pub fn is_current_req_counter(&self, req_counter: u32) -> bool {
        self.req_counter == req_counter
    }

    pub fn on_download_start(&mut self, peer_id: PeerId) -> u32 {
        self.state = State::Downloading { peer_id };
        self.req_counter += 1;
        self.req_counter
    }

    pub fn is_awaiting_download(&self) -> bool {
        matches!(self.state, State::AwaitingDownload)
    }

    pub fn get_downloading_peer(&self) -> Option<PeerId> {
        if let State::Downloading { peer_id } = self.state {
            Some(peer_id)
        } else {
            None
        }
    }

    pub fn on_download_success(
        &mut self,
        peer_id: PeerId,
        parent_root: Option<Hash256>,
        value: T,
        seen_timestamp: Duration,
    ) {
        self.state = State::Processing {
            peer_id,
            parent_root,
            value,
            seen_timestamp,
        }
    }

    /// Registers a failure in processing a block.
    pub fn on_processing_failure(&mut self) {
        self.failed_processing = self.failed_processing.saturating_add(1);
        self.state = State::AwaitingDownload;
    }

    /// Registers a failure in downloading a block. This might be a peer disconnection or a wrong
    /// block.
    pub fn on_download_failure(&mut self) {
        self.failed_downloading = self.failed_downloading.saturating_add(1);
        self.state = State::AwaitingDownload;
    }

    pub fn on_unknown_parent(&mut self) {
        // TODO: What if the state is not correct? Handle this case
        match std::mem::replace(&mut self.state, State::Poisoned) {
            State::Processing {
                peer_id,
                value,
                parent_root,
                seen_timestamp,
            } => {
                self.state = State::UnknownParent {
                    peer_id,
                    value,
                    parent_root,
                    seen_timestamp,
                }
            }
            other => self.state = other,
        }
    }

    pub fn resolve_unknown_parent(&mut self) -> Option<(T, Duration)> {
        match std::mem::replace(&mut self.state, State::Poisoned) {
            State::UnknownParent {
                peer_id,
                value,
                parent_root,
                seen_timestamp,
            } => {
                self.state = State::Processing {
                    peer_id,
                    value: value.clone(),
                    parent_root,
                    seen_timestamp,
                };
                Some((value, seen_timestamp))
            }
            other => {
                self.state = other;
                None
            }
        }
    }

    pub fn on_component_processed(&mut self) {
        self.component_processed = true;
    }

    /// The total number of failures, whether it be processing or downloading.
    pub fn failed_attempts(&self) -> u8 {
        self.failed_processing + self.failed_downloading
    }

    pub fn more_failed_processing(&self) -> bool {
        self.failed_processing >= self.failed_downloading
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
                self.on_download_failure();
                return Err(());
            }
        }
        Ok(())
    }

    /// Returns the id peer we downloaded from if we have downloaded a verified block, otherwise
    /// returns an error.
    pub fn processing_peer(&self) -> Result<PeerId, ()> {
        if let State::Processing { peer_id, .. } = &self.state {
            Ok(*peer_id)
        } else {
            Err(())
        }
    }

    pub fn parent_root(&self) -> Option<Hash256> {
        match self.state {
            State::AwaitingDownload | State::Downloading { .. } | State::Poisoned => None,
            State::UnknownParent { parent_root, .. } | State::Processing { parent_root, .. } => {
                parent_root
            }
        }
    }
}

impl<T: BeaconChainTypes> slog::Value for SingleBlockLookup<T> {
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str("request", key)?;
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

impl<T> slog::Value for SingleLookupRequestState<T> {
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
            State::UnknownParent { peer_id, .. } => {
                serializer.emit_arguments("awaiting_process_peer", &format_args!("{}", peer_id))?
            }
            State::Processing { peer_id, .. } => {
                serializer.emit_arguments("processing_peer", &format_args!("{}", peer_id))?
            }
            State::Poisoned => {} // Should never happen
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
    use beacon_chain::builder::Witness;
    use beacon_chain::eth1_chain::CachingEth1Backend;
    use sloggers::null::NullLoggerBuilder;
    use sloggers::Build;
    use slot_clock::{SlotClock, TestingSlotClock};
    use std::time::Duration;
    use store::{HotColdDB, MemoryStore, StoreConfig};
    use types::{
        test_utils::{SeedableRng, TestRandom, XorShiftRng},
        ChainSpec, MinimalEthSpec as E, SignedBeaconBlock, Slot,
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
            sl.block_request_state.state.on_download_failure();
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
        sl.block_request_state.state.on_processing_failure();
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

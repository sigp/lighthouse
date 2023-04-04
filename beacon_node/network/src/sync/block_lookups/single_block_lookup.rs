use super::RootBlockTuple;
use beacon_chain::blob_verification::AsBlock;
use beacon_chain::blob_verification::BlockWrapper;
use beacon_chain::get_block_root;
use lighthouse_network::{rpc::BlocksByRootRequest, PeerId, Request};
use rand::seq::IteratorRandom;
use ssz_types::VariableList;
use std::collections::HashSet;
use std::sync::Arc;
use store::{EthSpec, Hash256};
use strum::IntoStaticStr;
use lighthouse_network::rpc::methods::BlobsByRootRequest;
use types::blob_sidecar::BlobIdentifier;
use types::{BlobSidecar, SignedBeaconBlock};

pub type SingleBlockRequest<const MAX_ATTEMPTS: u8> = SingleLookupRequest<MAX_ATTEMPTS, Hash256>;
pub type SingleBlobRequest<const MAX_ATTEMPTS: u8> = SingleLookupRequest<MAX_ATTEMPTS, Vec<BlobIdentifier>>;

/// Object representing a single block lookup request.
///
//previously assumed we would have a single block. Now we may have the block but not the blobs
#[derive(PartialEq, Eq)]
pub struct SingleLookupRequest<const MAX_ATTEMPTS: u8, T: RequestableThing> {
    /// The hash of the requested block.
    pub requested_thing: T,
    /// State of this request.
    pub state: State,
    /// Peers that should have this block.
    pub available_peers: HashSet<PeerId>,
    /// Peers from which we have requested this block.
    pub used_peers: HashSet<PeerId>,
    /// How many times have we attempted to process this block.
    failed_processing: u8,
    /// How many times have we attempted to download this block.
    failed_downloading: u8,
}

pub trait RequestableThing {
    type Request;
    type Response<T: EthSpec>;
    type WrappedResponse<T: EthSpec>;
    fn verify_response<T: EthSpec>(&self, response: &Self::Response<T>) -> bool;
    fn make_request(&self) -> Self::Request;
    fn wrapped_response<T: EthSpec>(&self,  response: Self::Response<T>) -> Self::WrappedResponse<T>;
    fn is_useful(&self, other: &Self) -> bool;
}

impl RequestableThing for Hash256 {
    type Request = BlocksByRootRequest;
    type Response<T: EthSpec> = Arc<SignedBeaconBlock<T>>;
    type WrappedResponse<T: EthSpec> = RootBlockTuple<T>;
    fn verify_response<T: EthSpec>(&self, response: &Self::Response<T>) -> bool{
        // Compute the block root using this specific function so that we can get timing
        // metrics.
        let block_root = get_block_root(response);
        *self == block_root
    }
    fn make_request(&self) -> Self::Request{
        let request = BlocksByRootRequest {
            block_roots: VariableList::from(vec![*self]),
        };
        request
    }
    fn wrapped_response<T: EthSpec>(&self, response: Self::Response<T>) -> Self::WrappedResponse<T> {
        (*self, response)
    }

    fn is_useful(&self, other: &Self) -> bool {
       self == other
    }
}

impl RequestableThing for Vec<BlobIdentifier>{
    type Request = BlobsByRootRequest;
    type Response<T: EthSpec> = Arc<BlobSidecar<T>>;
    type WrappedResponse<T: EthSpec> = Arc<BlobSidecar<T>>;

    fn verify_response<T: EthSpec>(&self, response: &Self::Response<T>) -> bool{
        true
    }
    fn make_request(&self) -> Self::Request{
        todo!()
    }

    fn wrapped_response<T: EthSpec>(&self, response: Self::Response<T>) -> Self::WrappedResponse<T> {
       response
    }

    fn is_useful(&self, other: &Self) -> bool {
       todo!()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    AwaitingDownload,
    Downloading { peer_id: PeerId },
    Processing { peer_id: PeerId },
}

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum VerifyError {
    RootMismatch,
    NoBlockReturned,
    ExtraBlocksReturned,
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

impl<const MAX_ATTEMPTS: u8, T: RequestableThing> SingleLookupRequest<MAX_ATTEMPTS, T> {
    pub fn new(requested_thing: T, peer_id: PeerId) -> Self {
        Self {
            requested_thing,
            state: State::AwaitingDownload,
            available_peers: HashSet::from([peer_id]),
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

    pub fn add_peer(&mut self, requested_thing: &T, peer_id: &PeerId) -> bool {
        let is_useful = self.requested_thing.is_useful(requested_thing);
        if is_useful {
            self.available_peers.insert(*peer_id);
        }
        is_useful
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

    /// Verifies if the received block matches the requested one.
    /// Returns the block for processing if the response is what we expected.
    pub fn verify_block<E: EthSpec>(
        &mut self,
        block: Option<T::Response<E>>,
    ) -> Result<Option<T::WrappedResponse<E>>, VerifyError> {
        match self.state {
            State::AwaitingDownload => {
                self.register_failure_downloading();
                Err(VerifyError::ExtraBlocksReturned)
            }
            State::Downloading { peer_id } => match block {
                Some(block) => {
                    if self.requested_thing.verify_response(&block) {
                        // return an error and drop the block
                        // NOTE: we take this is as a download failure to prevent counting the
                        // attempt as a chain failure, but simply a peer failure.
                        self.register_failure_downloading();
                        Err(VerifyError::RootMismatch)
                    } else {
                        // Return the block for processing.
                        self.state = State::Processing { peer_id };
                        Ok(Some(self.requested_thing.wrapped_response(block)))
                    }
                }
                None => {
                    self.register_failure_downloading();
                    Err(VerifyError::NoBlockReturned)
                }
            },
            State::Processing { peer_id: _ } => match block {
                Some(_) => {
                    // We sent the block for processing and received an extra block.
                    self.register_failure_downloading();
                    Err(VerifyError::ExtraBlocksReturned)
                }
                None => {
                    // This is simply the stream termination and we are already processing the
                    // block
                    Ok(None)
                }
            },
        }
    }

    pub fn request_block(&mut self) -> Result<(PeerId, T::Request), LookupRequestError> {
        debug_assert!(matches!(self.state, State::AwaitingDownload));
        if self.failed_attempts() >= MAX_ATTEMPTS {
            Err(LookupRequestError::TooManyAttempts {
                cannot_process: self.failed_processing >= self.failed_downloading,
            })
        } else if let Some(&peer_id) = self.available_peers.iter().choose(&mut rand::thread_rng()) {
            let request = self.requested_thing.make_request();

            self.state = State::Downloading { peer_id };
            self.used_peers.insert(peer_id);
            Ok((peer_id, request))
        } else {
            Err(LookupRequestError::NoPeers)
        }
    }

    pub fn processing_peer(&self) -> Result<PeerId, ()> {
        if let State::Processing { peer_id } = &self.state {
            Ok(*peer_id)
        } else {
            Err(())
        }
    }
}

impl<const MAX_ATTEMPTS: u8> slog::Value for SingleBlockRequest<MAX_ATTEMPTS> {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str("request", key)?;
        serializer.emit_arguments("hash", &format_args!("{}", self.requested_thing))?;
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
    use types::{
        test_utils::{SeedableRng, TestRandom, XorShiftRng},
        MinimalEthSpec as E, SignedBeaconBlock,
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

    #[test]
    fn test_happy_path() {
        let peer_id = PeerId::random();
        let block = rand_block();

        let mut sl = SingleBlockRequest::<4>::new(block.canonical_root(), peer_id);
        sl.request_block().unwrap();
        sl.verify_block(Some(block.into())).unwrap().unwrap();
    }

    #[test]
    fn test_block_lookup_failures() {
        const FAILURES: u8 = 3;
        let peer_id = PeerId::random();
        let block = rand_block();

        let mut sl = SingleBlockRequest::<FAILURES>::new(block.canonical_root(), peer_id);
        for _ in 1..FAILURES {
            sl.request_block().unwrap();
            sl.register_failure_downloading();
        }

        // Now we receive the block and send it for processing
        sl.request_block().unwrap();
        sl.verify_block(Some(block.into())).unwrap().unwrap();

        // One processing failure maxes the available attempts
        sl.register_failure_processing();
        assert_eq!(
            sl.request_block(),
            Err(LookupRequestError::TooManyAttempts {
                cannot_process: false
            })
        )
    }
}

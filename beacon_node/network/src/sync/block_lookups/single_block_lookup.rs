use std::collections::HashSet;

use lighthouse_network::{rpc::BlocksByRootRequest, PeerId};
use rand::seq::IteratorRandom;
use ssz_types::VariableList;
use store::{EthSpec, Hash256, SignedBeaconBlock};
use strum::IntoStaticStr;

/// Object representing a single block lookup request.
#[derive(PartialEq, Eq)]
pub struct SingleBlockRequest<const MAX_ATTEMPTS: u8> {
    /// The hash of the requested block.
    pub hash: Hash256,
    /// State of this request.
    pub state: State,
    /// Peers that should have this block.
    pub available_peers: HashSet<PeerId>,
    /// Peers from which we have requested this block.
    pub used_peers: HashSet<PeerId>,
    /// How many times have we attempted this block.
    pub failed_attempts: u8,
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
    TooManyAttempts,
    NoPeers,
}

impl<const MAX_ATTEMPTS: u8> SingleBlockRequest<MAX_ATTEMPTS> {
    pub fn new(hash: Hash256, peer_id: PeerId) -> Self {
        Self {
            hash,
            state: State::AwaitingDownload,
            available_peers: HashSet::from([peer_id]),
            used_peers: HashSet::default(),
            failed_attempts: 0,
        }
    }

    pub fn register_failure(&mut self) {
        self.failed_attempts += 1;
        self.state = State::AwaitingDownload;
    }

    pub fn add_peer(&mut self, hash: &Hash256, peer_id: &PeerId) -> bool {
        let is_useful = &self.hash == hash;
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
                self.register_failure();
                return Err(());
            }
        }
        Ok(())
    }

    /// Verifies if the received block matches the requested one.
    /// Returns the block for processing if the response is what we expected.
    pub fn verify_block<T: EthSpec>(
        &mut self,
        block: Option<Box<SignedBeaconBlock<T>>>,
    ) -> Result<Option<Box<SignedBeaconBlock<T>>>, VerifyError> {
        match self.state {
            State::AwaitingDownload => {
                self.register_failure();
                Err(VerifyError::ExtraBlocksReturned)
            }
            State::Downloading { peer_id } => match block {
                Some(block) => {
                    if block.canonical_root() != self.hash {
                        // return an error and drop the block
                        self.register_failure();
                        Err(VerifyError::RootMismatch)
                    } else {
                        // Return the block for processing.
                        self.state = State::Processing { peer_id };
                        Ok(Some(block))
                    }
                }
                None => {
                    self.register_failure();
                    Err(VerifyError::NoBlockReturned)
                }
            },
            State::Processing { peer_id: _ } => match block {
                Some(_) => {
                    // We sent the block for processing and received an extra block.
                    self.register_failure();
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

    pub fn request_block(&mut self) -> Result<(PeerId, BlocksByRootRequest), LookupRequestError> {
        debug_assert!(matches!(self.state, State::AwaitingDownload));
        if self.failed_attempts <= MAX_ATTEMPTS {
            if let Some(&peer_id) = self.available_peers.iter().choose(&mut rand::thread_rng()) {
                let request = BlocksByRootRequest {
                    block_roots: VariableList::from(vec![self.hash]),
                };
                self.state = State::Downloading { peer_id };
                self.used_peers.insert(peer_id);
                Ok((peer_id, request))
            } else {
                Err(LookupRequestError::NoPeers)
            }
        } else {
            Err(LookupRequestError::TooManyAttempts)
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
        serializer.emit_arguments("hash", &format_args!("{}", self.hash))?;
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
        slog::Result::Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use types::MinimalEthSpec as E;

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
        sl.verify_block(Some(Box::new(block))).unwrap().unwrap();
    }

    #[test]
    fn test_max_attempts() {
        let peer_id = PeerId::random();
        let block = rand_block();

        let mut sl = SingleBlockRequest::<4>::new(block.canonical_root(), peer_id);
        sl.register_failure();
    }
}

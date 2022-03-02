use std::collections::BTreeSet;

use lighthouse_network::{rpc::BlocksByRootRequest, PeerId};
use ssz_types::VariableList;
use store::{EthSpec, Hash256, SignedBeaconBlock};

pub const SINGLE_BLOCK_LOOKUP_ATTEMPTS: u8 = 3;

/// Object representing a single block lookup request.
#[derive(PartialEq, Eq)]
pub(crate) struct SingleBlockRequest<const MAX_ATTEMPTS: u8 = SINGLE_BLOCK_LOOKUP_ATTEMPTS> {
    /// The hash of the requested block.
    pub hash: Hash256,
    /// Whether a block was received from this request, or the peer returned an empty response.
    pub block_returned: bool,
    /// State of this request.
    pub state: State,
    /// Peers that should have this block.
    pub available_peers: BTreeSet<PeerId>,
    /// Hoy many times have we tried this request.
    // NOTE: not how many times times it has failed, just tried.
    pub attempts: u8,
}

#[derive(PartialEq, Eq)]
enum State {
    /// Request will be downloaded from this peer.
    AwaitingDownload(PeerId),
    /// The block is being downloaded from this peer.
    Downloading(PeerId),
    /// The block is being processed from this peer.
    Processing(PeerId),
}

impl<const MAX_ATTEMPTS: u8> SingleBlockRequest<MAX_ATTEMPTS> {
    pub fn new(hash: Hash256, peer_id: PeerId) -> Self {
        Self {
            hash,
            block_returned: false,
            state: State::AwaitingDownload(peer_id),
            available_peers: BTreeSet::from([peer_id]),
            attempts: 0,
        }
    }

    pub fn current_peer(&self) -> &PeerId {
        match &self.state {
            State::AwaitingDownload(peer_id)
            | State::Downloading(peer_id)
            | State::Processing(peer_id) => peer_id,
        }
    }

    /// Adds a peer to this request if the hash matches.
    pub fn add_peer(&mut self, hash: &Hash256, peer_id: &PeerId) -> bool {
        if &self.hash == hash {
            // Make sure the current peer is never in the _additional_ available peers.
            if self.current_peer() != peer_id {
                self.available_peers.insert(*peer_id);
            }
            true
        } else {
            false
        }
    }

    /// If a peer disconnects, this request could be failed.
    /// Returns Ok if the request is not affected by this peer's disconnection and an error
    /// informing if the request can be tried again othewise.
    pub fn check_peer_disconnected(&mut self, peer_id: &PeerId) -> Result<(), bool> {
        // Remove the peer from the available_peers
        self.available_peers.remove(peer_id);
        match &self.state {
            State::AwaitingDownload(current_peer) => {
                if current_peer == peer_id {
                    if let Some(&peer_id) = self.available_peers.iter().next() {
                        self.available_peers.remove(&peer_id);
                        self.state = State::AwaitingDownload(peer_id);
                        // The request had not started and we still can get the block from other
                        // peer.
                        return Ok(());
                    } else {
                        // Request needs to be removed since it needs to be downloaded but has no
                        // peers.
                        return Err(false);
                    }
                }
            }
            State::Downloading(current_peer) => {
                if current_peer == peer_id {
                    if let Some(&peer_id) = self.available_peers.iter().last() {
                        self.available_peers.remove(&peer_id);
                        self.state = State::AwaitingDownload(peer_id);
                        // This download failed but can be tried again
                        return Err(true);
                    }
                }
            }
            State::Processing(current_peer) => {
                // Nothing to do here. We can still process this block
            }
        }
        Ok(())
    }

    pub fn download_failed(&mut self) {
        if let State::Downloading(_peer_id) = self.state {
            if let Some(new_peer) = self.available_peers.iter().next() {
                self.state = State::AwaitingDownload(*new_peer);
            }
        }
    }

    pub fn request_block(&mut self) -> Result<(BlocksByRootRequest, PeerId), ()> {
        self.attempts += 1;
        if self.attempts <= MAX_ATTEMPTS {
            if let State::AwaitingDownload(peer_id) = self.state {
                let request = BlocksByRootRequest {
                    block_roots: VariableList::from(vec![self.hash]),
                };
                self.state = State::Downloading(peer_id);
                return Ok((request, peer_id));
            }
        }

        Err(())
    }

    /// Verifies if the received block matches the requested one.
    /// Returns the block for processing if the response is what we expected.
    pub fn verify_block<T: EthSpec>(
        &mut self,
        block: Option<Box<SignedBeaconBlock<T>>>,
    ) -> Result<Option<Box<SignedBeaconBlock<T>>>, &'static str> {
        match block {
            Some(block) => {
                if self.block_returned {
                    // In theory RPC should not allow this but better safe than sorry.
                    Err("extra block returned")
                } else {
                    self.block_returned = true;
                    if block.canonical_root() != self.hash {
                        // return an error and drop the block
                        Err("root mismatch")
                    } else {
                        // The request still needs to wait for the stream termination
                        Ok(Some(block))
                    }
                }
            }
            None => {
                if self.block_returned {
                    Ok(None)
                } else {
                    // Peer did not return the block
                    Err("no block returned")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_management() {
        let peer_id = PeerId::random();
        let hash = Hash256::random();
        // No peers fails the request
        let mut req = SingleBlockRequest::new(hash, peer_id);
        assert_eq!(req.check_peer_disconnected(&peer_id), Err(false));

        // Extra peer can be attempted
        let mut req = SingleBlockRequest::new(hash, peer_id);
        let second_peer = PeerId::random();
        req.add_peer(&hash, &second_peer);
        assert_eq!(req.check_peer_disconnected(&peer_id), Err(true));
        assert!(req.request_block().is_ok());
    }

    fn test_too_many_attempts() {
        // Regardless of extra peers, the request should fail after too many attempts
        const ATTEMPTS: u8 = 2;

        let hash = Hash256::random();
        let mut req = SingleBlockRequest::<ATTEMPTS>::new(hash, PeerId::random());
        for _ in 0..ATTEMPTS * 2 {
            req.add_peer(&hash, &PeerId::random());
        }
        assert_eq!(req.available_peers.len() as u8, ATTEMPTS * 2);

        for _ in 1..ATTEMPTS {
            req.download_failed();
            assert!(req.request_block().is_ok())
        }
        req.download_failed();
        assert!(req.request_block().is_ok())
    }
}

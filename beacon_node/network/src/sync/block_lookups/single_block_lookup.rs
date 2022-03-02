use std::collections::BTreeSet;

use lighthouse_network::PeerId;
use store::{EthSpec, Hash256, SignedBeaconBlock};

pub const SINGLE_BLOCK_LOOKUP_ATTEMPTS: u8 = 3;

/// Object representing a single block lookup request.
#[derive(PartialEq, Eq)]
pub(crate) struct SingleBlockRequest {
    /// The hash of the requested block.
    pub hash: Hash256,
    /// Whether a block was received from this request, or the peer returned an empty response.
    pub block_returned: bool,
    /// Peer handling this request.
    pub peer_id: PeerId,
    /// Peers that should have this block.
    pub available_peers: BTreeSet<PeerId>,
    /// Hoy many times have we tried this request.
    pub attempts: u8,
}

impl SingleBlockRequest {
    pub fn new(hash: Hash256, peer_id: PeerId) -> Self {
        Self {
            hash,
            block_returned: false,
            peer_id,
            available_peers: BTreeSet::new(),
            attempts: 0,
        }
    }

    /// Adds a peer to this request if the hash matches.
    pub fn add_peer(&mut self, hash: &Hash256, peer_id: &PeerId) -> bool {
        if &self.hash == hash {
            // Make sure the current peer is never in the _additional_ available peers.
            if &self.peer_id != peer_id {
                self.available_peers.insert(*peer_id);
            }
            true
        } else {
            false
        }
    }

    /// If a peer disconnects, this request could be failed. If so, an error is returned informing
    /// whether the request can be tried again with other peer.
    pub fn check_peer_disconnected(&mut self, peer_id: &PeerId) -> Result<(), bool> {
        if &self.peer_id == peer_id {
            self.attempts += 1;
            Err(!self.available_peers.is_empty())
        } else {
            self.available_peers.remove(peer_id);
            Ok(())
        }
    }

    /// Registers a request failure.
    pub fn request_failed(&mut self) {
        self.attempts += 1;
    }

    /// Assigns the next peer for an attempt, if the request can be retried.
    pub fn next_peer(&mut self) -> Option<PeerId> {
        if self.attempts < SINGLE_BLOCK_LOOKUP_ATTEMPTS {
            if let Some(&peer) = self.available_peers.iter().next() {
                self.available_peers.remove(&peer);
                self.peer_id = peer;
                return Some(self.peer_id);
            }
        }
        None
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
                    self.attempts += 1;
                    Err("extra block returned")
                } else {
                    self.block_returned = true;
                    if block.canonical_root() != self.hash {
                        self.attempts += 1;
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
                    self.attempts += 1;
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
        // No peers fails the request
        let mut req = SingleBlockRequest::new(Hash256::random(), PeerId::random());
        req.request_failed();
        assert_eq!(req.next_peer(), None);

        // Extra peer can be attempted
        let hash = Hash256::random();
        let mut req = SingleBlockRequest::new(hash, PeerId::random());
        let second_peer = PeerId::random();
        req.add_peer(&hash, &second_peer);
        req.request_failed();
        assert_eq!(req.next_peer(), Some(second_peer));
        req.request_failed();

        // Regardless of extra peers, no peer should be returned after too many attempts
        let hash = Hash256::random();
        let mut req = SingleBlockRequest::new(hash, PeerId::random());
        for _ in 0..SINGLE_BLOCK_LOOKUP_ATTEMPTS * 2 {
            req.add_peer(&hash, &PeerId::random());
        }
        assert_eq!(
            req.available_peers.len() as u8,
            SINGLE_BLOCK_LOOKUP_ATTEMPTS * 2
        );

        for _ in 1..SINGLE_BLOCK_LOOKUP_ATTEMPTS {
            req.request_failed();
            assert!(req.next_peer().is_some())
        }
        req.request_failed();
        assert!(req.next_peer().is_none())
    }
}

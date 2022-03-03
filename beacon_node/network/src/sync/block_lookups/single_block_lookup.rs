use lighthouse_network::{rpc::BlocksByRootRequest, PeerId};
use ssz_types::VariableList;
use store::{EthSpec, Hash256, SignedBeaconBlock};

/// Object representing a single block lookup request.
#[derive(PartialEq, Eq)]
pub(crate) struct SingleBlockRequest {
    /// The hash of the requested block.
    pub hash: Hash256,
    /// Whether a block was received from this request, or the peer returned an empty response.
    pub block_returned: bool,
    /// Peer handling this request.
    pub peer_id: PeerId,
}

enum VerifyError {
    RootMismatch,
    NoBlockReturned,
    ExtraBlocksReturned,
}

impl SingleBlockRequest {
    pub fn new(hash: Hash256, peer_id: PeerId) -> Self {
        Self {
            hash,
            block_returned: false,
            peer_id,
        }
    }

    /// If a peer disconnects, this request could be failed. If so, an error is returned informing
    /// whether the request can be tried again with other peer.
    pub fn check_peer_disconnected(&mut self, peer_id: &PeerId) -> Result<(), ()> {
        if &self.peer_id == peer_id {
            Err(())
        } else {
            Ok(())
        }
    }

    /// Verifies if the received block matches the requested one.
    /// Returns the block for processing if the response is what we expected.
    pub fn verify_block<T: EthSpec>(
        &mut self,
        block: Option<Box<SignedBeaconBlock<T>>>,
    ) -> Result<Option<Box<SignedBeaconBlock<T>>>, VerifyError> {
        match block {
            Some(block) => {
                if self.block_returned {
                    // In theory RPC should not allow this but better safe than sorry.
                    Err(VerifyError::ExtraBlocksReturned)
                } else {
                    self.block_returned = true;
                    if block.canonical_root() != self.hash {
                        // return an error and drop the block
                        Err(VerifyError::RootMismatch)
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
                    Err(VerifyError::NoBlockReturned)
                }
            }
        }
    }

    pub fn block_request(&self) -> (PeerId, BlocksByRootRequest) {
        let request = BlocksByRootRequest {
            block_roots: VariableList::from(vec![self.hash]),
        };
        (self.peer_id, request)
    }
}

use store::{EthSpec, Hash256, SignedBeaconBlock};

/// Object representing a single block lookup request.
#[derive(PartialEq, Eq)]
pub(crate) struct SingleBlockRequest {
    /// The hash of the requested block.
    pub hash: Hash256,
    /// Whether a block was received from this request, or the peer returned an empty response.
    pub block_returned: bool,
}

impl SingleBlockRequest {
    pub fn new(hash: Hash256) -> Self {
        Self {
            hash,
            block_returned: false,
        }
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

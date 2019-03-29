use crate::beacon_chain::BeaconChain;
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::PeerId;
use slog::{debug, error};
use ssz::TreeHash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use types::{BeaconBlock, BeaconBlockBody, BeaconBlockHeader, Hash256};

/// Provides a queue for fully and partially built `BeaconBlock`s.
///
/// The queue is fundamentally a `Vec<PartialBeaconBlock>` where no two items have the same
/// `item.block_root`. This struct it backed by a `Vec` not a `HashMap` for the following two
/// reasons:
///
/// - When we receive a `BeaconBlockBody`, the only way we can find it's matching
/// `BeaconBlockHeader` is to find a header such that `header.beacon_block_body ==
/// hash_tree_root(body)`. Therefore, if we used a `HashMap` we would need to use the root of
/// `BeaconBlockBody` as the key.
/// - It is possible for multiple distinct blocks to have identical `BeaconBlockBodies`. Therefore
/// we cannot use a `HashMap` keyed by the root of `BeaconBlockBody`.
pub struct ImportQueue {
    pub chain: Arc<BeaconChain>,
    /// Partially imported blocks, keyed by the root of `BeaconBlockBody`.
    pub partials: Vec<PartialBeaconBlock>,
    /// Time before a queue entry is considered state.
    pub stale_time: Duration,
    /// Logging
    log: slog::Logger,
}

impl ImportQueue {
    /// Return a new, empty queue.
    pub fn new(chain: Arc<BeaconChain>, stale_time: Duration, log: slog::Logger) -> Self {
        Self {
            chain,
            partials: vec![],
            stale_time,
            log,
        }
    }

    /// Completes all possible partials into `BeaconBlock` and returns them, sorted by increasing
    /// slot number.  Does not delete the partials from the queue, this must be done manually.
    ///
    /// Returns `(queue_index, block, sender)`:
    ///
    /// - `block_root`: may be used to remove the entry if it is successfully processed.
    /// - `block`: the completed block.
    /// - `sender`: the `PeerId` the provided the `BeaconBlockBody` which completed the partial.
    pub fn complete_blocks(&self) -> Vec<(Hash256, BeaconBlock, PeerId)> {
        let mut complete: Vec<(Hash256, BeaconBlock, PeerId)> = self
            .partials
            .iter()
            .filter_map(|partial| partial.clone().complete())
            .collect();

        // Sort the completable partials to be in ascending slot order.
        complete.sort_unstable_by(|a, b| a.1.slot.partial_cmp(&b.1.slot).unwrap());

        complete
    }

    /// Removes the first `PartialBeaconBlock` with a matching `block_root`, returning the partial
    /// if it exists.
    pub fn remove(&mut self, block_root: Hash256) -> Option<PartialBeaconBlock> {
        let position = self
            .partials
            .iter()
            .position(|p| p.block_root == block_root)?;
        Some(self.partials.remove(position))
    }

    /// Flushes all stale entries from the queue.
    ///
    /// An entry is stale if it has as a `inserted` time that is more than `self.stale_time` in the
    /// past.
    pub fn remove_stale(&mut self) {
        let stale_indices: Vec<usize> = self
            .partials
            .iter()
            .enumerate()
            .filter_map(|(i, partial)| {
                if partial.inserted + self.stale_time <= Instant::now() {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();

        if !stale_indices.is_empty() {
            debug!(
                self.log,
                "ImportQueue removing stale entries";
                "stale_items" => stale_indices.len(),
                "stale_time_seconds" => self.stale_time.as_secs()
            );
        }

        stale_indices.iter().for_each(|&i| {
            self.partials.remove(i);
        });
    }

    /// Returns `true` if `self.chain` has not yet processed this block.
    pub fn is_new_block(&self, block_root: &Hash256) -> bool {
        self.chain
            .is_new_block_root(&block_root)
            .unwrap_or_else(|_| {
                error!(self.log, "Unable to determine if block is new.");
                true
            })
    }

    /// Returns the index of the first new root in the list of block roots.
    pub fn first_new_root(&mut self, roots: &[BlockRootSlot]) -> Option<usize> {
        roots
            .iter()
            .position(|brs| self.is_new_block(&brs.block_root))
    }

    /// Adds the `headers` to the `partials` queue. Returns a list of `Hash256` block roots for
    /// which we should use to request `BeaconBlockBodies`.
    ///
    /// If a `header` is not in the queue and has not been processed by the chain it is added to
    /// the queue and it's block root is included in the output.
    ///
    /// If a `header` is already in the queue, but not yet processed by the chain the block root is
    /// included in the output and the `inserted` time for the partial record is set to
    /// `Instant::now()`. Updating the `inserted` time stops the partial from becoming stale.
    ///
    /// Presently the queue enforces that a `BeaconBlockHeader` _must_ be received before its
    /// `BeaconBlockBody`. This is not a natural requirement and we could enhance the queue to lift
    /// this restraint.
    pub fn enqueue_headers(
        &mut self,
        headers: Vec<BeaconBlockHeader>,
        sender: PeerId,
    ) -> Vec<Hash256> {
        let mut required_bodies: Vec<Hash256> = vec![];

        for header in headers {
            let block_root = Hash256::from_slice(&header.hash_tree_root()[..]);

            if self.is_new_block(&block_root) {
                self.insert_header(block_root, header, sender.clone());
                required_bodies.push(block_root)
            }
        }

        required_bodies
    }

    /// If there is a matching `header` for this `body`, adds it to the queue.
    ///
    /// If there is no `header` for the `body`, the body is simply discarded.
    pub fn enqueue_bodies(&mut self, bodies: Vec<BeaconBlockBody>, sender: PeerId) {
        for body in bodies {
            self.insert_body(body, sender.clone());
        }
    }

    /// Inserts a header to the queue.
    ///
    /// If the header already exists, the `inserted` time is set to `now` and not other
    /// modifications are made.
    fn insert_header(&mut self, block_root: Hash256, header: BeaconBlockHeader, sender: PeerId) {
        if let Some(i) = self
            .partials
            .iter()
            .position(|p| p.block_root == block_root)
        {
            self.partials[i].inserted = Instant::now();
        } else {
            self.partials.push(PartialBeaconBlock {
                block_root,
                header,
                body: None,
                inserted: Instant::now(),
                sender,
            })
        }
    }

    /// Updates an existing partial with the `body`.
    ///
    /// If there is no header for the `body`, the body is simply discarded.
    ///
    /// If the body already existed, the `inserted` time is set to `now`.
    fn insert_body(&mut self, body: BeaconBlockBody, sender: PeerId) {
        let body_root = Hash256::from_slice(&body.hash_tree_root()[..]);

        self.partials.iter_mut().for_each(|mut p| {
            if body_root == p.header.block_body_root {
                p.inserted = Instant::now();

                if p.body.is_none() {
                    p.body = Some(body.clone());
                    p.sender = sender.clone();
                }
            }
        });
    }
}

/// Individual components of a `BeaconBlock`, potentially all that are required to form a full
/// `BeaconBlock`.
#[derive(Clone, Debug)]
pub struct PartialBeaconBlock {
    /// `BeaconBlock` root.
    pub block_root: Hash256,
    pub header: BeaconBlockHeader,
    pub body: Option<BeaconBlockBody>,
    /// The instant at which this record was created or last meaningfully modified. Used to
    /// determine if an entry is stale and should be removed.
    pub inserted: Instant,
    /// The `PeerId` that last meaningfully contributed to this item.
    pub sender: PeerId,
}

impl PartialBeaconBlock {
    /// Consumes `self` and returns a full built `BeaconBlock`, it's root and the `sender`
    /// `PeerId`, if enough information exists to complete the block. Otherwise, returns `None`.
    pub fn complete(self) -> Option<(Hash256, BeaconBlock, PeerId)> {
        Some((
            self.block_root,
            self.header.into_block(self.body?),
            self.sender,
        ))
    }
}

use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::PeerId;
use slog::error;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tree_hash::TreeHash;
use types::{BeaconBlock, BeaconBlockBody, BeaconBlockHeader, EthSpec, Hash256, Slot};

/// Provides a queue for fully and partially built `BeaconBlock`s.
///
/// The queue is fundamentally a `Vec<PartialBeaconBlock>` where no two items have the same
/// `item.block_root`. This struct it backed by a `Vec` not a `HashMap` for the following two
/// reasons:
///
/// - When we receive a `BeaconBlockBody`, the only way we can find it's matching
/// `BeaconBlockHeader` is to find a header such that `header.beacon_block_body ==
/// tree_hash_root(body)`. Therefore, if we used a `HashMap` we would need to use the root of
/// `BeaconBlockBody` as the key.
/// - It is possible for multiple distinct blocks to have identical `BeaconBlockBodies`. Therefore
/// we cannot use a `HashMap` keyed by the root of `BeaconBlockBody`.
pub struct ImportQueue<T: BeaconChainTypes> {
    pub chain: Arc<BeaconChain<T>>,
    /// Partially imported blocks, keyed by the root of `BeaconBlockBody`.
    partials: HashMap<Hash256, PartialBeaconBlock<T::EthSpec>>,
    /// Time before a queue entry is considered state.
    pub stale_time: Duration,
    /// Logging
    log: slog::Logger,
}

impl<T: BeaconChainTypes> ImportQueue<T> {
    /// Return a new, empty queue.
    pub fn new(chain: Arc<BeaconChain<T>>, stale_time: Duration, log: slog::Logger) -> Self {
        Self {
            chain,
            partials: HashMap::new(),
            stale_time,
            log,
        }
    }

    /// Returns true of the if the `BlockRoot` is found in the `import_queue`.
    pub fn contains_block_root(&self, block_root: Hash256) -> bool {
        self.partials.contains_key(&block_root)
    }

    /// Attempts to complete the `BlockRoot` if it is found in the `import_queue`.
    ///
    /// Returns an Enum with a `PartialBeaconBlockCompletion`.
    /// Does not remove the `block_root` from the `import_queue`.
    pub fn attempt_complete_block(
        &self,
        block_root: Hash256,
    ) -> PartialBeaconBlockCompletion<T::EthSpec> {
        if let Some(partial) = self.partials.get(&block_root) {
            partial.attempt_complete()
        } else {
            PartialBeaconBlockCompletion::MissingRoot
        }
    }

    /// Removes the first `PartialBeaconBlock` with a matching `block_root`, returning the partial
    /// if it exists.
    pub fn remove(&mut self, block_root: Hash256) -> Option<PartialBeaconBlock<T::EthSpec>> {
        self.partials.remove(&block_root)
    }

    /// Flushes all stale entries from the queue.
    ///
    /// An entry is stale if it has as a `inserted` time that is more than `self.stale_time` in the
    /// past.
    pub fn remove_stale(&mut self) {
        let stale_time = self.stale_time;

        self.partials
            .retain(|_, partial| partial.inserted + stale_time > Instant::now())
    }

    /// Returns `true` if `self.chain` has not yet processed this block.
    pub fn chain_has_not_seen_block(&self, block_root: &Hash256) -> bool {
        self.chain
            .is_new_block_root(&block_root)
            .unwrap_or_else(|_| {
                error!(self.log, "Unable to determine if block is new.");
                true
            })
    }

    /// Adds the `block_roots` to the partials queue.
    ///
    /// If a `block_root` is not in the queue and has not been processed by the chain it is added
    /// to the queue and it's block root is included in the output.
    pub fn enqueue_block_roots(
        &mut self,
        block_roots: &[BlockRootSlot],
        sender: PeerId,
    ) -> Vec<BlockRootSlot> {
        // TODO: This will currently not return a `BlockRootSlot` if this root exists but there is no header.
        // It would be more robust if it did.
        let new_block_root_slots: Vec<BlockRootSlot> = block_roots
            .iter()
            // Ignore any roots already stored in the queue.
            .filter(|brs| !self.contains_block_root(brs.block_root))
            // Ignore any roots already processed by the chain.
            .filter(|brs| self.chain_has_not_seen_block(&brs.block_root))
            .cloned()
            .collect();

        self.partials.extend(
            new_block_root_slots
                .iter()
                .map(|brs| PartialBeaconBlock {
                    slot: brs.slot,
                    block_root: brs.block_root,
                    sender: sender.clone(),
                    header: None,
                    body: None,
                    inserted: Instant::now(),
                })
                .map(|partial| (partial.block_root, partial)),
        );

        new_block_root_slots
    }

    /// Adds the `headers` to the `partials` queue. Returns a list of `Hash256` block roots for
    /// which we should use to request `BeaconBlockBodies`.
    ///
    /// If a `header` is not in the queue and has not been processed by the chain it is added to
    /// the queue and it's block root is included in the output.
    ///
    /// If a `header` is already in the queue, but not yet processed by the chain the block root is
    /// not included in the output and the `inserted` time for the partial record is set to
    /// `Instant::now()`. Updating the `inserted` time stops the partial from becoming stale.
    pub fn enqueue_headers(
        &mut self,
        headers: Vec<BeaconBlockHeader>,
        sender: PeerId,
    ) -> Vec<Hash256> {
        let mut required_bodies: Vec<Hash256> = vec![];

        for header in headers {
            let block_root = Hash256::from_slice(&header.canonical_root()[..]);

            if self.chain_has_not_seen_block(&block_root)
                && !self.insert_header(block_root, header, sender.clone())
            {
                // If a body is empty
                required_bodies.push(block_root);
            }
        }

        required_bodies
    }

    /// If there is a matching `header` for this `body`, adds it to the queue.
    ///
    /// If there is no `header` for the `body`, the body is simply discarded.
    pub fn enqueue_bodies(
        &mut self,
        bodies: Vec<BeaconBlockBody<T::EthSpec>>,
        sender: PeerId,
    ) -> Option<Hash256> {
        let mut last_block_hash = None;
        for body in bodies {
            last_block_hash = self.insert_body(body, sender.clone());
        }

        last_block_hash
    }

    pub fn enqueue_full_blocks(&mut self, blocks: Vec<BeaconBlock<T::EthSpec>>, sender: PeerId) {
        for block in blocks {
            self.insert_full_block(block, sender.clone());
        }
    }

    /// Inserts a header to the queue.
    ///
    /// If the header already exists, the `inserted` time is set to `now` and not other
    /// modifications are made.
    /// Returns true is `body` exists.
    fn insert_header(
        &mut self,
        block_root: Hash256,
        header: BeaconBlockHeader,
        sender: PeerId,
    ) -> bool {
        let mut exists = false;
        self.partials
            .entry(block_root)
            .and_modify(|partial| {
                partial.header = Some(header.clone());
                partial.inserted = Instant::now();
                if partial.body.is_some() {
                    exists = true;
                }
            })
            .or_insert_with(|| PartialBeaconBlock {
                slot: header.slot,
                block_root,
                header: Some(header),
                body: None,
                inserted: Instant::now(),
                sender,
            });
        exists
    }

    /// Updates an existing partial with the `body`.
    ///
    /// If the body already existed, the `inserted` time is set to `now`.
    ///
    /// Returns the block hash of the inserted body
    fn insert_body(
        &mut self,
        body: BeaconBlockBody<T::EthSpec>,
        sender: PeerId,
    ) -> Option<Hash256> {
        let body_root = Hash256::from_slice(&body.tree_hash_root()[..]);
        let mut last_root = None;

        self.partials.iter_mut().for_each(|(root, mut p)| {
            if let Some(header) = &mut p.header {
                if body_root == header.body_root {
                    p.inserted = Instant::now();
                    p.body = Some(body.clone());
                    p.sender = sender.clone();
                    last_root = Some(*root);
                }
            }
        });

        last_root
    }

    /// Updates an existing `partial` with the completed block, or adds a new (complete) partial.
    ///
    /// If the partial already existed, the `inserted` time is set to `now`.
    fn insert_full_block(&mut self, block: BeaconBlock<T::EthSpec>, sender: PeerId) {
        let block_root = Hash256::from_slice(&block.canonical_root()[..]);

        let partial = PartialBeaconBlock {
            slot: block.slot,
            block_root,
            header: Some(block.block_header()),
            body: Some(block.body),
            inserted: Instant::now(),
            sender,
        };

        self.partials
            .entry(block_root)
            .and_modify(|existing_partial| *existing_partial = partial.clone())
            .or_insert(partial);
    }
}

/// Individual components of a `BeaconBlock`, potentially all that are required to form a full
/// `BeaconBlock`.
#[derive(Clone, Debug)]
pub struct PartialBeaconBlock<E: EthSpec> {
    pub slot: Slot,
    /// `BeaconBlock` root.
    pub block_root: Hash256,
    pub header: Option<BeaconBlockHeader>,
    pub body: Option<BeaconBlockBody<E>>,
    /// The instant at which this record was created or last meaningfully modified. Used to
    /// determine if an entry is stale and should be removed.
    pub inserted: Instant,
    /// The `PeerId` that last meaningfully contributed to this item.
    pub sender: PeerId,
}

impl<E: EthSpec> PartialBeaconBlock<E> {
    /// Attempts to build a block.
    ///
    /// Does not comsume the `PartialBeaconBlock`.
    pub fn attempt_complete(&self) -> PartialBeaconBlockCompletion<E> {
        if self.header.is_none() {
            PartialBeaconBlockCompletion::MissingHeader(self.slot)
        } else if self.body.is_none() {
            PartialBeaconBlockCompletion::MissingBody
        } else {
            PartialBeaconBlockCompletion::Complete(
                self.header
                    .clone()
                    .unwrap()
                    .into_block(self.body.clone().unwrap()),
            )
        }
    }
}

/// The result of trying to convert a `BeaconBlock` into a `PartialBeaconBlock`.
pub enum PartialBeaconBlockCompletion<E: EthSpec> {
    /// The partial contains a valid BeaconBlock.
    Complete(BeaconBlock<E>),
    /// The partial does not exist.
    MissingRoot,
    /// The partial contains a `BeaconBlockRoot` but no `BeaconBlockHeader`.
    MissingHeader(Slot),
    /// The partial contains a `BeaconBlockRoot` and `BeaconBlockHeader` but no `BeaconBlockBody`.
    MissingBody,
}

use beacon_chain::BeaconChain;
use db::ClientDB;
use parking_lot::RwLock;
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{BeaconBlock, FreeAttestation};

mod attester;
mod producer;

/// Connect directly to a borrowed `BeaconChain` instance so an attester/producer can request/submit
/// blocks/attestations.
///
/// `BeaconBlock`s and `FreeAttestation`s are not actually published to the `BeaconChain`, instead
/// they are stored inside this struct. This is to allow one to benchmark the submission of the
/// block/attestation directly, or modify it before submission.
pub struct DirectBeaconNode<T: ClientDB, U: SlotClock> {
    beacon_chain: Arc<BeaconChain<T, U>>,
    published_blocks: RwLock<Vec<BeaconBlock>>,
    published_attestations: RwLock<Vec<FreeAttestation>>,
}

impl<T: ClientDB, U: SlotClock> DirectBeaconNode<T, U> {
    pub fn new(beacon_chain: Arc<BeaconChain<T, U>>) -> Self {
        Self {
            beacon_chain,
            published_blocks: RwLock::new(vec![]),
            published_attestations: RwLock::new(vec![]),
        }
    }

    /// Get the last published block (if any).
    pub fn last_published_block(&self) -> Option<BeaconBlock> {
        Some(self.published_blocks.read().last()?.clone())
    }

    /// Get the last published attestation (if any).
    pub fn last_published_free_attestation(&self) -> Option<FreeAttestation> {
        Some(self.published_attestations.read().last()?.clone())
    }
}

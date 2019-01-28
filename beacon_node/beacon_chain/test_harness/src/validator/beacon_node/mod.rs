use beacon_chain::BeaconChain;
use db::ClientDB;
use parking_lot::RwLock;
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{AttestationData, BeaconBlock, Signature};

mod attester;
mod producer;

/// An attestation that hasn't been aggregated into an `Attestation`.
///
/// (attestation_data, signature, validator_index)
pub type FreeAttestation = (AttestationData, Signature, u64);

pub struct BenchingBeaconNode<T: ClientDB, U: SlotClock> {
    beacon_chain: Arc<BeaconChain<T, U>>,
    published_blocks: RwLock<Vec<BeaconBlock>>,
    published_attestations: RwLock<Vec<FreeAttestation>>,
}

impl<T: ClientDB, U: SlotClock> BenchingBeaconNode<T, U> {
    pub fn new(beacon_chain: Arc<BeaconChain<T, U>>) -> Self {
        Self {
            beacon_chain,
            published_blocks: RwLock::new(vec![]),
            published_attestations: RwLock::new(vec![]),
        }
    }

    pub fn last_published_block(&self) -> Option<BeaconBlock> {
        Some(self.published_blocks.read().last()?.clone())
    }
}

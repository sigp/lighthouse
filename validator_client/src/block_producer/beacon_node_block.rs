use crate::error::{PublishOutcome, ValidatorError};
use crate::service::BoxFut;
use types::{BeaconBlock, EthSpec, Signature, Slot};

/// Defines the methods required to produce and publish blocks on a Beacon Node. Abstracts the
/// actual beacon node.
pub trait BeaconNodeBlock: Send + Sync {
    /// Request that the node produces a block.
    ///
    /// Returns Ok(None) if the Beacon Node is unable to produce at the given slot.
    fn produce_beacon_block<T: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &Signature,
    ) -> BoxFut<BeaconBlock<T>, ValidatorError>;

    /// Request that the node publishes a block.
    ///
    /// Returns `true` if the publish was successful.
    fn publish_beacon_block<T: EthSpec>(
        &self,
        block: BeaconBlock<T>,
    ) -> BoxFut<PublishOutcome, ValidatorError>;
}

mod beacon_node_block;
mod grpc;

use self::beacon_node_block::BeaconNodeBlock;
pub use self::beacon_node_block::{BeaconNodeError, PublishOutcome};
pub use self::grpc::BeaconBlockGrpcClient;
use crate::signer::Signer;
use core::marker::PhantomData;
use slog::{error, info, trace, warn};
use std::sync::Arc;
use tree_hash::{SignedRoot, TreeHash};
use types::{BeaconBlock, ChainSpec, Domain, EthSpec, Fork, Slot};

#[derive(Debug, PartialEq)]
pub enum Error {
    BeaconNodeError(BeaconNodeError),
}

#[derive(Debug, PartialEq)]
pub enum ValidatorEvent {
    /// A new block was produced.
    BlockProduced(Slot),
    /// A new attestation was produced.
    AttestationProduced(Slot),
    /// A block was not produced as it would have been slashable.
    SlashableBlockNotProduced(Slot),
    /// An attestation was not produced as it would have been slashable.
    IndexedAttestationNotProduced(Slot),
    /// The Beacon Node was unable to produce a block at that slot.
    BeaconNodeUnableToProduceBlock(Slot),
    /// The signer failed to sign the message.
    SignerRejection(Slot),
    /// Publishing an attestation failed.
    PublishAttestationFailed,
    /// Beacon node rejected the attestation.
    InvalidAttestation,
}

/// This struct contains the logic for requesting and signing beacon blocks for a validator. The
/// validator can abstractly sign via the Signer trait object.
pub struct BlockProducer<'a, B: BeaconNodeBlock, S: Signer, E: EthSpec> {
    /// The current fork.
    pub fork: Fork,
    /// The current slot to produce a block for.
    pub slot: Slot,
    /// The current epoch.
    pub spec: Arc<ChainSpec>,
    /// The beacon node to connect to.
    pub beacon_node: Arc<B>,
    /// The signer to sign the block.
    pub signer: &'a S,
    /// Used for calculating epoch.
    pub slots_per_epoch: u64,
    /// Mere vessel for E.
    pub _phantom: PhantomData<E>,
    /// The logger, for logging
    pub log: slog::Logger,
}

impl<'a, B: BeaconNodeBlock, S: Signer, E: EthSpec> BlockProducer<'a, B, S, E> {
    /// Handle outputs and results from block production.
    pub fn handle_produce_block(&mut self) {
        match self.produce_block() {
            Ok(ValidatorEvent::BlockProduced(slot)) => info!(
                self.log,
                "Block produced";
                "validator" => format!("{}", self.signer),
                "slot" => slot,
            ),
            Err(e) => error!(self.log, "Block production error"; "Error" => format!("{:?}", e)),
            Ok(ValidatorEvent::SignerRejection(_slot)) => error!(self.log, "Block production error"; "Error" => "Signer Could not sign the block".to_string()),
            Ok(ValidatorEvent::SlashableBlockNotProduced(_slot)) => error!(self.log, "Block production error"; "Error" => "Rejected the block as it could have been slashed".to_string()),
            Ok(ValidatorEvent::BeaconNodeUnableToProduceBlock(_slot)) => error!(self.log, "Block production error"; "Error" => "Beacon node was unable to produce a block".to_string()),
            Ok(v) => warn!(self.log, "Unknown result for block production"; "Error" => format!("{:?}",v)),
        }
    }

    /// Produce a block at some slot.
    ///
    /// Assumes that a block is required at this slot (does not check the duties).
    ///
    /// Ensures the message is not slashable.
    ///
    /// !!! UNSAFE !!!
    ///
    /// The slash-protection code is not yet implemented. There is zero protection against
    /// slashing.
    pub fn produce_block(&mut self) -> Result<ValidatorEvent, Error> {
        let epoch = self.slot.epoch(self.slots_per_epoch);
        trace!(self.log, "Producing block"; "epoch" => epoch);

        let message = epoch.tree_hash_root();
        let randao_reveal = match self.signer.sign_message(
            &message,
            self.spec.get_domain(epoch, Domain::Randao, &self.fork),
        ) {
            None => {
                warn!(self.log, "Signing rejected"; "message" => format!("{:?}", message));
                return Ok(ValidatorEvent::SignerRejection(self.slot));
            }
            Some(signature) => signature,
        };

        if let Some(block) = self
            .beacon_node
            .produce_beacon_block(self.slot, &randao_reveal)?
        {
            if self.safe_to_produce(&block) {
                let slot = block.slot;
                let domain = self
                    .spec
                    .get_domain(epoch, Domain::BeaconProposer, &self.fork);
                if let Some(block) = self.sign_block(block, domain) {
                    self.beacon_node.publish_beacon_block(block)?;
                    Ok(ValidatorEvent::BlockProduced(slot))
                } else {
                    Ok(ValidatorEvent::SignerRejection(self.slot))
                }
            } else {
                Ok(ValidatorEvent::SlashableBlockNotProduced(self.slot))
            }
        } else {
            Ok(ValidatorEvent::BeaconNodeUnableToProduceBlock(self.slot))
        }
    }

    /// Consumes a block, returning that block signed by the validators private key.
    ///
    /// Important: this function will not check to ensure the block is not slashable. This must be
    /// done upstream.
    fn sign_block(&mut self, mut block: BeaconBlock<E>, domain: u64) -> Option<BeaconBlock<E>> {
        self.store_produce(&block);

        match self.signer.sign_message(&block.signed_root()[..], domain) {
            None => None,
            Some(signature) => {
                block.signature = signature;
                Some(block)
            }
        }
    }

    /// Returns `true` if signing a block is safe (non-slashable).
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn safe_to_produce(&self, _block: &BeaconBlock<E>) -> bool {
        // TODO: ensure the producer doesn't produce slashable blocks.
        // https://github.com/sigp/lighthouse/issues/160
        true
    }

    /// Record that a block was produced so that slashable votes may not be made in the future.
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn store_produce(&mut self, _block: &BeaconBlock<E>) {
        // TODO: record this block production to prevent future slashings.
        // https://github.com/sigp/lighthouse/issues/160
    }
}

impl From<BeaconNodeError> for Error {
    fn from(e: BeaconNodeError) -> Error {
        Error::BeaconNodeError(e)
    }
}

/* Old tests - Re-work for new logic
#[cfg(test)]
mod tests {
    use super::test_utils::{EpochMap, LocalSigner, SimulatedBeaconNode};
    use super::*;
    use slot_clock::TestingSlotClock;
    use types::{
        test_utils::{SeedableRng, TestRandom, XorShiftRng},
        Keypair,
    };

    // TODO: implement more thorough testing.
    // https://github.com/sigp/lighthouse/issues/160
    //
    // These tests should serve as a good example for future tests.

    #[test]
    pub fn polling() {
        let mut rng = XorShiftRng::from_seed([42; 16]);

        let spec = Arc::new(ChainSpec::mainnet());
        let slot_clock = Arc::new(TestingSlotClock::new(0));
        let beacon_node = Arc::new(SimulatedBeaconNode::default());
        let signer = Arc::new(LocalSigner::new(Keypair::random()));

        let mut epoch_map = EpochMap::new(T::slots_per_epoch());
        let produce_slot = Slot::new(100);
        let produce_epoch = produce_slot.epoch(T::slots_per_epoch());
        epoch_map.map.insert(produce_epoch, produce_slot);
        let epoch_map = Arc::new(epoch_map);

        let mut block_proposer = BlockProducer::new(
            spec.clone(),
            epoch_map.clone(),
            slot_clock.clone(),
            beacon_node.clone(),
            signer.clone(),
        );

        // Configure responses from the BeaconNode.
        beacon_node.set_next_produce_result(Ok(Some(BeaconBlock::random_for_test(&mut rng))));
        beacon_node.set_next_publish_result(Ok(PublishOutcome::ValidBlock));

        // One slot before production slot...
        slot_clock.set_slot(produce_slot.as_u64() - 1);
        assert_eq!(
            block_proposer.poll(),
            Ok(PollOutcome::BlockProductionNotRequired(produce_slot - 1))
        );

        // On the produce slot...
        slot_clock.set_slot(produce_slot.as_u64());
        assert_eq!(
            block_proposer.poll(),
            Ok(PollOutcome::BlockProduced(produce_slot.into()))
        );

        // Trying the same produce slot again...
        slot_clock.set_slot(produce_slot.as_u64());
        assert_eq!(
            block_proposer.poll(),
            Ok(PollOutcome::SlotAlreadyProcessed(produce_slot))
        );

        // One slot after the produce slot...
        slot_clock.set_slot(produce_slot.as_u64() + 1);
        assert_eq!(
            block_proposer.poll(),
            Ok(PollOutcome::BlockProductionNotRequired(produce_slot + 1))
        );

        // In an epoch without known duties...
        let slot = (produce_epoch.as_u64() + 1) * T::slots_per_epoch();
        slot_clock.set_slot(slot);
        assert_eq!(
            block_proposer.poll(),
            Ok(PollOutcome::ProducerDutiesUnknown(Slot::new(slot)))
        );
    }
}
*/

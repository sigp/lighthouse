pub mod test_utils;
mod traits;

use slot_clock::SlotClock;
use ssz::{SignedRoot, TreeHash};
use std::sync::Arc;
use types::{BeaconBlock, ChainSpec, Domain, Slot};

#[derive(Debug, PartialEq)]
pub enum Error {
    SlotClockError,
    SlotUnknowable,
    EpochMapPoisoned,
    SlotClockPoisoned,
    EpochLengthIsZero,
    BeaconNodeError(BeaconNodeError),
}

#[derive(Debug, PartialEq)]
pub enum BlockProducerEvent {
    /// A new block was produced.
    BlockProduced(Slot),
    /// A block was not produced as it would have been slashable.
    SlashableBlockNotProduced(Slot),
    /// The Beacon Node was unable to produce a block at that slot.
    BeaconNodeUnableToProduceBlock(Slot),
    /// The signer failed to sign the message.
    SignerRejection(Slot),
    /// The public key for this validator is not an active validator.
    ValidatorIsUnknown(Slot),
}

/// This struct contains the logic for requesting and signing beacon blocks for a validator. The
/// validator can abstractly sign via the Signer trait object.
pub struct BlockProducer<B: BeaconNode, S: Signer> {
    /// The current fork.
    pub fork: Fork,
    /// The current slot to produce a block for.
    pub slot: Slot,
    /// The current epoch.
    pub epoch: Epoch,
    /// The beacon node to connect to.
    pub beacon_node: Arc<B>,
    /// The signer to sign the block.
    pub signer: Arc<S>,
}

impl<B: BeaconNode, S: Signer> BlockProducer<B, S> {

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
    fn produce_block(&mut self) -> Result<BlockProducerEvent, Error> {

        let randao_reveal = {
            // TODO: add domain, etc to this message. Also ensure result matches `into_to_bytes32`.
            let message = slot.epoch(self.spec.slots_per_epoch).hash_tree_root();

            match self.signer.sign_randao_reveal(
                &message,
                self.spec
                    .get_domain(slot.epoch(self.spec.slots_per_epoch), Domain::Randao, &fork),
            ) {
                None => return Ok(PollOutcome::SignerRejection(slot)),
                Some(signature) => signature,
            }
        };

        if let Some(block) = self
            .beacon_node
            .produce_beacon_block(slot, &randao_reveal)?
        {
            if self.safe_to_produce(&block) {
                let domain = self.spec.get_domain(
                    slot.epoch(self.spec.slots_per_epoch),
                    Domain::BeaconBlock,
                    &fork,
                );
                if let Some(block) = self.sign_block(block, domain) {
                    self.beacon_node.publish_beacon_block(block)?;
                    Ok(PollOutcome::BlockProduced(slot))
                } else {
                    Ok(PollOutcome::SignerRejection(slot))
                }
            } else {
                Ok(PollOutcome::SlashableBlockNotProduced(slot))
            }
        } else {
            Ok(PollOutcome::BeaconNodeUnableToProduceBlock(slot))
        }
    }

    /// Consumes a block, returning that block signed by the validators private key.
    ///
    /// Important: this function will not check to ensure the block is not slashable. This must be
    /// done upstream.
    fn sign_block(&mut self, mut block: BeaconBlock, domain: u64) -> Option<BeaconBlock> {
        self.store_produce(&block);

        match self
            .signer
            .sign_block_proposal(&block.signed_root()[..], domain)
        {
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
    fn safe_to_produce(&self, _block: &BeaconBlock) -> bool {
        // TODO: ensure the producer doesn't produce slashable blocks.
        // https://github.com/sigp/lighthouse/issues/160
        true
    }

    /// Record that a block was produced so that slashable votes may not be made in the future.
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn store_produce(&mut self, _block: &BeaconBlock) {
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

        let spec = Arc::new(ChainSpec::foundation());
        let slot_clock = Arc::new(TestingSlotClock::new(0));
        let beacon_node = Arc::new(SimulatedBeaconNode::default());
        let signer = Arc::new(LocalSigner::new(Keypair::random()));

        let mut epoch_map = EpochMap::new(spec.slots_per_epoch);
        let produce_slot = Slot::new(100);
        let produce_epoch = produce_slot.epoch(spec.slots_per_epoch);
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
        let slot = (produce_epoch.as_u64() + 1) * spec.slots_per_epoch;
        slot_clock.set_slot(slot);
        assert_eq!(
            block_proposer.poll(),
            Ok(PollOutcome::ProducerDutiesUnknown(Slot::new(slot)))
        );
    }
}

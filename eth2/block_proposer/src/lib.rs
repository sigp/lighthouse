pub mod test_utils;
mod traits;

use slot_clock::SlotClock;
use ssz::ssz_encode;
use std::sync::Arc;
use types::{BeaconBlock, ChainSpec, PublicKey, Slot};

pub use self::traits::{
    BeaconNode, BeaconNodeError, DutiesReader, DutiesReaderError, PublishOutcome, Signer,
};

#[derive(Debug, PartialEq)]
pub enum PollOutcome {
    /// A new block was proposed.
    BlockProposed(Slot),
    /// A block was not proposed as it would have been slashable.
    SlashableBlockNotProposed(Slot),
    /// The validator duties did not require a block to be proposed.
    BlockProductionNotRequired(Slot),
    /// The duties for the present epoch were not found.
    ProposerDutiesUnknown(Slot),
    /// The slot has already been processed, execution was skipped.
    SlotAlreadyProcessed(Slot),
    /// The Beacon Node was unable to propose a block at that slot.
    BeaconNodeUnableToProposeBlock(Slot),
    /// The signer failed to sign the message.
    SignerRejection(Slot),
    /// The public key for this validator is not an active validator.
    ValidatorIsUnknown(Slot),
}

#[derive(Debug, PartialEq)]
pub enum Error {
    SlotClockError,
    SlotUnknowable,
    EpochMapPoisoned,
    SlotClockPoisoned,
    EpochLengthIsZero,
    BeaconNodeError(BeaconNodeError),
}

/// A polling state machine which performs block production duties, based upon some epoch duties
/// (`EpochDutiesMap`) and a concept of time (`SlotClock`).
///
/// Ensures that messages are not slashable.
///
/// Relies upon an external service to keep the `EpochDutiesMap` updated.
pub struct BlockProposer<T: SlotClock, U: BeaconNode, V: DutiesReader, W: Signer> {
    pub last_processed_slot: Option<Slot>,
    pubkey: PublicKey,
    spec: Arc<ChainSpec>,
    epoch_map: Arc<V>,
    slot_clock: Arc<T>,
    beacon_node: Arc<U>,
    signer: Arc<W>,
}

impl<T: SlotClock, U: BeaconNode, V: DutiesReader, W: Signer> BlockProposer<T, U, V, W> {
    /// Returns a new instance where `last_processed_slot == 0`.
    pub fn new(
        spec: Arc<ChainSpec>,
        pubkey: PublicKey,
        epoch_map: Arc<V>,
        slot_clock: Arc<T>,
        beacon_node: Arc<U>,
        signer: Arc<W>,
    ) -> Self {
        Self {
            last_processed_slot: None,
            pubkey,
            spec,
            epoch_map,
            slot_clock,
            beacon_node,
            signer,
        }
    }
}

impl<T: SlotClock, U: BeaconNode, V: DutiesReader, W: Signer> BlockProposer<T, U, V, W> {
    /// "Poll" to see if the validator is required to take any action.
    ///
    /// The slot clock will be read and any new actions undertaken.
    pub fn poll(&mut self) -> Result<PollOutcome, Error> {
        let slot = self
            .slot_clock
            .present_slot()
            .map_err(|_| Error::SlotClockError)?
            .ok_or(Error::SlotUnknowable)?;

        // If this is a new slot.
        if !self.is_processed_slot(slot) {
            let is_block_production_slot = match self.epoch_map.is_block_production_slot(slot) {
                Ok(result) => result,
                Err(DutiesReaderError::UnknownEpoch) => {
                    return Ok(PollOutcome::ProposerDutiesUnknown(slot));
                }
                Err(DutiesReaderError::UnknownValidator) => {
                    return Ok(PollOutcome::ValidatorIsUnknown(slot));
                }
                Err(DutiesReaderError::EpochLengthIsZero) => return Err(Error::EpochLengthIsZero),
                Err(DutiesReaderError::Poisoned) => return Err(Error::EpochMapPoisoned),
            };

            if is_block_production_slot {
                self.last_processed_slot = Some(slot);

                self.propose_block(slot)
            } else {
                Ok(PollOutcome::BlockProductionNotRequired(slot))
            }
        } else {
            Ok(PollOutcome::SlotAlreadyProcessed(slot))
        }
    }

    fn is_processed_slot(&self, slot: Slot) -> bool {
        match self.last_processed_slot {
            Some(processed_slot) if processed_slot >= slot => true,
            _ => false,
        }
    }

    /// Propose a block at some slot.
    ///
    /// Assumes that a block is required at this slot (does not check the duties).
    ///
    /// Ensures the message is not slashable.
    ///
    /// !!! UNSAFE !!!
    ///
    /// The slash-protection code is not yet implemented. There is zero protection against
    /// slashing.
    fn propose_block(&mut self, slot: Slot) -> Result<PollOutcome, Error> {
        let randao_reveal = {
            let proposer_nonce = self.beacon_node.proposer_nonce(&self.pubkey)?;

            // TODO: add domain, etc to this message.
            let message = ssz_encode(&proposer_nonce);

            match self.signer.sign_randao_reveal(&message) {
                None => return Ok(PollOutcome::SignerRejection(slot)),
                Some(signature) => signature,
            }
        };

        if let Some(block) = self
            .beacon_node
            .propose_beacon_block(slot, &randao_reveal)?
        {
            if self.safe_to_propose(&block) {
                if let Some(block) = self.sign_block(block) {
                    self.beacon_node.publish_beacon_block(block)?;
                    Ok(PollOutcome::BlockProposed(slot))
                } else {
                    Ok(PollOutcome::SignerRejection(slot))
                }
            } else {
                Ok(PollOutcome::SlashableBlockNotProposed(slot))
            }
        } else {
            Ok(PollOutcome::BeaconNodeUnableToProposeBlock(slot))
        }
    }

    /// Consumes a block, returning that block signed by the validators private key.
    ///
    /// Important: this function will not check to ensure the block is not slashable. This must be
    /// done upstream.
    fn sign_block(&mut self, mut block: BeaconBlock) -> Option<BeaconBlock> {
        self.store_propose(&block);

        match self
            .signer
            .sign_block_proposal(&block.proposal_root(&self.spec)[..])
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
    fn safe_to_propose(&self, _block: &BeaconBlock) -> bool {
        // TODO: ensure the proposer doesn't propose slashable blocks.
        // https://github.com/sigp/lighthouse/issues/160
        true
    }

    /// Record that a block was proposed so that slashable votes may not be made in the future.
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn store_propose(&mut self, _block: &BeaconBlock) {
        // TODO: record this block production to prevent future slashings.
        // https://github.com/sigp/lighthouse/issues/160
    }
}

impl From<BeaconNodeError> for Error {
    fn from(e: BeaconNodeError) -> Error {
        Error::BeaconNodeError(e)
    }
}

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

        let mut epoch_map = EpochMap::new(spec.epoch_length);
        let propose_slot = Slot::new(100);
        let propose_epoch = propose_slot.epoch(spec.epoch_length);
        epoch_map.map.insert(propose_epoch, propose_slot);
        let epoch_map = Arc::new(epoch_map);
        let keypair = Keypair::random();

        let mut block_proposer = BlockProposer::new(
            spec.clone(),
            keypair.pk.clone(),
            epoch_map.clone(),
            slot_clock.clone(),
            beacon_node.clone(),
            signer.clone(),
        );

        // Configure responses from the BeaconNode.
        beacon_node.set_next_propose_result(Ok(Some(BeaconBlock::random_for_test(&mut rng))));
        beacon_node.set_next_publish_result(Ok(PublishOutcome::ValidBlock));
        beacon_node.set_next_nonce_result(Ok(0));

        // One slot before production slot...
        slot_clock.set_slot(propose_slot.as_u64() - 1);
        assert_eq!(
            block_proposer.poll(),
            Ok(PollOutcome::BlockProductionNotRequired(propose_slot - 1))
        );

        // On the propose slot...
        slot_clock.set_slot(propose_slot.as_u64());
        assert_eq!(
            block_proposer.poll(),
            Ok(PollOutcome::BlockProposed(propose_slot.into()))
        );

        // Trying the same propose slot again...
        slot_clock.set_slot(propose_slot.as_u64());
        assert_eq!(
            block_proposer.poll(),
            Ok(PollOutcome::SlotAlreadyProcessed(propose_slot))
        );

        // One slot after the propose slot...
        slot_clock.set_slot(propose_slot.as_u64() + 1);
        assert_eq!(
            block_proposer.poll(),
            Ok(PollOutcome::BlockProductionNotRequired(propose_slot + 1))
        );

        // In an epoch without known duties...
        let slot = (propose_epoch.as_u64() + 1) * spec.epoch_length;
        slot_clock.set_slot(slot);
        assert_eq!(
            block_proposer.poll(),
            Ok(PollOutcome::ProposerDutiesUnknown(Slot::new(slot)))
        );
    }
}

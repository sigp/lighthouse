pub mod test_utils;
mod traits;

use slot_clock::SlotClock;
use std::sync::Arc;
use types::{AttestationData, FreeAttestation, Signature, Slot};

pub use self::traits::{
    BeaconNode, BeaconNodeError, DutiesReader, DutiesReaderError, PublishOutcome, Signer,
};

const PHASE_0_CUSTODY_BIT: bool = false;

#[derive(Debug, PartialEq)]
pub enum PollOutcome {
    AttestationProposed(Slot),
    AttestationNotRequired(Slot),
    SlashableAttestationNotProposed(Slot),
    BeaconNodeUnableToProposeAttestation(Slot),
    ProposerDutiesUnknown(Slot),
    SlotAlreadyProcessed(Slot),
    SignerRejection(Slot),
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
pub struct Attester<T: SlotClock, U: BeaconNode, V: DutiesReader, W: Signer> {
    pub last_processed_slot: Option<Slot>,
    duties: Arc<V>,
    slot_clock: Arc<T>,
    beacon_node: Arc<U>,
    signer: Arc<W>,
}

impl<T: SlotClock, U: BeaconNode, V: DutiesReader, W: Signer> Attester<T, U, V, W> {
    /// Returns a new instance where `last_processed_slot == 0`.
    pub fn new(duties: Arc<V>, slot_clock: Arc<T>, beacon_node: Arc<U>, signer: Arc<W>) -> Self {
        Self {
            last_processed_slot: None,
            duties,
            slot_clock,
            beacon_node,
            signer,
        }
    }
}

impl<T: SlotClock, U: BeaconNode, V: DutiesReader, W: Signer> Attester<T, U, V, W> {
    /// Poll the `BeaconNode` and propose an attestation if required.
    pub fn poll(&mut self) -> Result<PollOutcome, Error> {
        let slot = self
            .slot_clock
            .present_slot()
            .map_err(|_| Error::SlotClockError)?
            .ok_or(Error::SlotUnknowable)?;

        if !self.is_processed_slot(slot) {
            self.last_processed_slot = Some(slot);

            let shard = match self.duties.attestation_shard(slot) {
                Ok(Some(result)) => result,
                Ok(None) => return Ok(PollOutcome::AttestationNotRequired(slot)),
                Err(DutiesReaderError::UnknownEpoch) => {
                    return Ok(PollOutcome::ProposerDutiesUnknown(slot));
                }
                Err(DutiesReaderError::UnknownValidator) => {
                    return Ok(PollOutcome::ValidatorIsUnknown(slot));
                }
                Err(DutiesReaderError::EpochLengthIsZero) => return Err(Error::EpochLengthIsZero),
                Err(DutiesReaderError::Poisoned) => return Err(Error::EpochMapPoisoned),
            };

            self.propose_attestation(slot, shard)
        } else {
            Ok(PollOutcome::SlotAlreadyProcessed(slot))
        }
    }

    fn propose_attestation(&mut self, slot: Slot, shard: u64) -> Result<PollOutcome, Error> {
        let attestation_data = match self.beacon_node.propose_attestation_data(slot, shard)? {
            Some(attestation_data) => attestation_data,
            None => return Ok(PollOutcome::BeaconNodeUnableToProposeAttestation(slot)),
        };

        if !self.safe_to_propose(&attestation_data) {
            return Ok(PollOutcome::SlashableAttestationNotProposed(slot));
        }

        let signature = match self.sign_attestation_data(&attestation_data) {
            Some(signature) => signature,
            None => return Ok(PollOutcome::SignerRejection(slot)),
        };

        let validator_index = match self.duties.validator_index() {
            Some(validator_index) => validator_index,
            None => return Ok(PollOutcome::ValidatorIsUnknown(slot)),
        };

        let free_attestation = FreeAttestation {
            data: attestation_data,
            signature,
            validator_index,
        };

        self.beacon_node
            .publish_attestation_data(free_attestation)?;
        Ok(PollOutcome::AttestationProposed(slot))
    }

    fn is_processed_slot(&self, slot: Slot) -> bool {
        match self.last_processed_slot {
            Some(processed_slot) if slot <= processed_slot => true,
            _ => false,
        }
    }

    /// Consumes a block, returning that block signed by the validators private key.
    ///
    /// Important: this function will not check to ensure the block is not slashable. This must be
    /// done upstream.
    fn sign_attestation_data(&mut self, attestation_data: &AttestationData) -> Option<Signature> {
        self.store_propose(attestation_data);

        self.signer
            .sign_attestation_message(&attestation_data.signable_message(PHASE_0_CUSTODY_BIT)[..])
    }

    /// Returns `true` if signing some attestation_data is safe (non-slashable).
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn safe_to_propose(&self, _attestation_data: &AttestationData) -> bool {
        // TODO: ensure the proposer doesn't propose slashable blocks.
        // https://github.com/sigp/lighthouse/issues/160
        true
    }

    /// Record that a block was proposed so that slashable votes may not be made in the future.
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn store_propose(&mut self, _block: &AttestationData) {
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
        ChainSpec, Keypair,
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

        let mut duties = EpochMap::new(spec.epoch_length);
        let attest_slot = Slot::new(100);
        let attest_epoch = attest_slot / spec.epoch_length;
        let attest_shard = 12;
        duties.insert_attestation_shard(attest_slot, attest_shard);
        duties.set_validator_index(Some(2));
        let duties = Arc::new(duties);

        let mut attester = Attester::new(
            duties.clone(),
            slot_clock.clone(),
            beacon_node.clone(),
            signer.clone(),
        );

        // Configure responses from the BeaconNode.
        beacon_node.set_next_propose_result(Ok(Some(AttestationData::random_for_test(&mut rng))));
        beacon_node.set_next_publish_result(Ok(PublishOutcome::ValidAttestation));

        // One slot before attestation slot...
        slot_clock.set_slot(attest_slot.as_u64() - 1);
        assert_eq!(
            attester.poll(),
            Ok(PollOutcome::AttestationNotRequired(attest_slot - 1))
        );

        // On the attest slot...
        slot_clock.set_slot(attest_slot.as_u64());
        assert_eq!(
            attester.poll(),
            Ok(PollOutcome::AttestationProposed(attest_slot))
        );

        // Trying the same attest slot again...
        slot_clock.set_slot(attest_slot.as_u64());
        assert_eq!(
            attester.poll(),
            Ok(PollOutcome::SlotAlreadyProcessed(attest_slot))
        );

        // One slot after the attest slot...
        slot_clock.set_slot(attest_slot.as_u64() + 1);
        assert_eq!(
            attester.poll(),
            Ok(PollOutcome::AttestationNotRequired(attest_slot + 1))
        );

        // In an epoch without known duties...
        let slot = (attest_epoch + 1) * spec.epoch_length;
        slot_clock.set_slot(slot.into());
        assert_eq!(
            attester.poll(),
            Ok(PollOutcome::ProposerDutiesUnknown(slot))
        );
    }
}

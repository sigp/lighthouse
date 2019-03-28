pub mod test_utils;
mod traits;

use ssz::TreeHash;
use std::sync::Arc;
use types::{
    AggregateSignature, Attestation, AttestationData, AttestationDataAndCustodyBit,
    AttestationDuty, Bitfield, Signature, Slot,
};

pub use self::traits::{
    BeaconNode, BeaconNodeError, DutiesReader, DutiesReaderError, PublishOutcome, Signer,
};

const PHASE_0_CUSTODY_BIT: bool = false;
const DOMAIN_ATTESTATION: u64 = 1;

#[derive(Debug, PartialEq)]
pub enum PollOutcome {
    AttestationProduced(Slot),
    AttestationNotRequired(Slot),
    SlashableAttestationNotProduced(Slot),
    BeaconNodeUnableToProduceAttestation(Slot),
    ProducerDutiesUnknown(Slot),
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
pub struct Attester<U: BeaconNode, W: Signer> {
    pub last_processed_slot: Option<Slot>,
    beacon_node: Arc<U>,
    signer: Arc<W>,
}

impl<U: BeaconNode, W: Signer> Attester<U, W> {
    /// Returns a new instance where `last_processed_slot == 0`.
    pub fn new(beacon_node: Arc<U>, signer: Arc<W>) -> Self {
        Self {
            last_processed_slot: None,
            beacon_node,
            signer,
        }
    }
}

impl<B: BeaconNode, W: Signer> Attester<B, W> {
    fn produce_attestation(
        &mut self,
        attestation_duty: AttestationDuty,
    ) -> Result<PollOutcome, Error> {
        let attestation_data = match self
            .beacon_node
            .produce_attestation_data(attestation_duty.slot, attestation_duty.shard)?
        {
            Some(attestation_data) => attestation_data,
            None => {
                return Ok(PollOutcome::BeaconNodeUnableToProduceAttestation(
                    attestation_duty.slot,
                ))
            }
        };

        dbg!(&attestation_data);

        if !self.safe_to_produce(&attestation_data) {
            return Ok(PollOutcome::SlashableAttestationNotProduced(
                attestation_duty.slot,
            ));
        }

        let signature = match self.sign_attestation_data(&attestation_data) {
            Some(signature) => signature,
            None => return Ok(PollOutcome::SignerRejection(attestation_duty.slot)),
        };
        let mut agg_sig = AggregateSignature::new();
        agg_sig.add(&signature);

        let attestation = Attestation {
            aggregation_bitfield: Bitfield::new(),
            data: attestation_data,
            custody_bitfield: Bitfield::from_elem(8, PHASE_0_CUSTODY_BIT),
            aggregate_signature: agg_sig,
        };

        self.beacon_node.publish_attestation(attestation)?;
        Ok(PollOutcome::AttestationProduced(attestation_duty.slot))
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
        self.store_produce(attestation_data);

        let message = AttestationDataAndCustodyBit {
            data: attestation_data.clone(),
            custody_bit: PHASE_0_CUSTODY_BIT,
        }
        .hash_tree_root();

        self.signer
            .sign_attestation_message(&message[..], DOMAIN_ATTESTATION)
    }

    /// Returns `true` if signing some attestation_data is safe (non-slashable).
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn safe_to_produce(&self, _attestation_data: &AttestationData) -> bool {
        // TODO: ensure the producer doesn't produce slashable blocks.
        // https://github.com/sigp/lighthouse/issues/160
        true
    }

    /// Record that a block was produced so that slashable votes may not be made in the future.
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn store_produce(&mut self, _block: &AttestationData) {
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
        let beacon_node = Arc::new(SimulatedBeaconNode::default());
        let signer = Arc::new(LocalSigner::new(Keypair::random()));

        let attest_slot = Slot::new(100);
        let attest_epoch = attest_slot / spec.slots_per_epoch;
        let attest_shard = 12;

        let mut attester = Attester::new(beacon_node.clone(), signer.clone());

        // Configure responses from the BeaconNode.
        beacon_node.set_next_produce_result(Ok(Some(AttestationData::random_for_test(&mut rng))));
        beacon_node.set_next_publish_result(Ok(PublishOutcome::ValidAttestation));

        /*
         * All these tests are broken because we no longer have a slot clock in the attester

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
            Ok(PollOutcome::AttestationProduced(attest_slot))
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
        let slot = (attest_epoch + 1) * spec.slots_per_epoch;
        slot_clock.set_slot(slot.into());
        assert_eq!(
            attester.poll(),
            Ok(PollOutcome::ProducerDutiesUnknown(slot))
        );
        */
    }
}

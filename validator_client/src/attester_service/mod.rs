mod grpc;
mod beacon_node_attestation;

use std::sync::Arc;
use types::{BeaconBlock, ChainSpec, Domain, Fork, Slot};

#[derive(Debug, PartialEq)]
pub enum Error {
    BeaconNodeError(BeaconNodeError),
}

/// This struct contains the logic for requesting and signing beacon attestations for a validator. The
/// validator can abstractly sign via the Signer trait object.
pub struct AttestationProducer<'a, B: BeaconNodeAttestation, S: Signer> {
    /// The current fork.
    pub fork: Fork,
    /// The current slot to produce an attestation for.
    pub slot: Slot,
    /// The current epoch.
    pub spec: Arc<ChainSpec>,
    /// The beacon node to connect to.
    pub beacon_node: Arc<B>,
    /// The signer to sign the block.
    pub signer: &'a S,
}

impl<'a, B: BeaconNodeAttestation, S: Signer> AttestationProducer<'a, B, S> {
    /// Handle outputs and results from attestation production.
    pub fn handle_produce_attestation(&mut self, log: slog::Logger) {
        match self.produce_attestation() {
            Ok(ValidatorEvent::AttestationProduced(_slot)) => {
                info!(log, "Attestation produced"; "Validator" => format!("{}", self.signer))
            }
            Err(e) => error!(log, "Attestation production error"; "Error" => format!("{:?}", e)),
            Ok(ValidatorEvent::SignerRejection(_slot)) => {
                error!(log, "Attestation production error"; "Error" => format!("Signer could not sign the attestation"))
            }
            Ok(ValidatorEvent::SlashableAttestationNotProduced(_slot)) => {
                error!(log, "Attestation production error"; "Error" => format!("Rejected the attestation as it could have been slashed"))
            }
            Ok(ValidatorEvent::BeaconNodeUnableToProduceAttestation(_slot)) => {
                error!(log, "Attestation production error"; "Error" => format!("Beacon node was unable to produce an attestation"))
            }
        }
    }

    /// Produce an attestation, sign it and send it back
    ///
    /// Assumes that an attestation is required at this slot (does not check the duties).
    ///
    /// Ensures the message is not slashable.
    ///
    /// !!! UNSAFE !!!
    ///
    /// The slash-protection code is not yet implemented. There is zero protection against
    /// slashing.
    pub fn produce_attestation(&mut self) -> Result<ValidatorEvent, Error> {
        let epoch = self.slot.epoch(self.spec.slots_per_epoch);

        if let Some(attestation) = self
            .beacon_node
            .produce_attestation_data(self.slot, self.shard)?
        {
            if self.safe_to_produce(&attestation) {
                let domain = self.spec.get_domain(epoch, Domain::Attestation, &self.fork);
                if let Some(attestation) = self.sign_attestation(attestation, domain) {
                    self.beacon_node.publish_attestation(attestation)?;
                    Ok(ValidatorEvent::AttestationProduced(self.slot))
                } else {
                    Ok(ValidatorEvent::SignerRejection(self.slot))
                }
            } else {
                Ok(ValidatorEvent::SlashableAttestationNotProduced(self.slot))
            }
        } else {
            Ok(ValidatorEvent::BeaconNodeUnableToProduceAttestation(self.slot))
        }
    }

    /// Consumes an attestation, returning the attestation signed by the validators private key.
    ///
    /// Important: this function will not check to ensure the attestation is not slashable. This must be
    /// done upstream.
    fn sign_attestation(&mut self, mut attestation: Attestation, duties: AttestationDuties, domain: u64) -> Option<AggregateSignature> {
        self.store_produce(&attestation);

        // build the aggregate signature
        let aggregate_sig = {
            let message = AttestationDataAndCustodyBit {
                                    data: attestation.clone(),
                                    custody_bit: false,
                        }.hash_tree_root();

            let sig = self.signer.sign_message(&message, domain)?;

            let mut agg_sig = AggregateSignature::new();
            agg_sig.add(&sig);
            agg_sig
            }

	    let mut aggregation_bitfield = Bitfield::with_capacity(duties.comitee_size);
	    let custody_bitfield = Bitfield::with_capacity(duties.committee_size);
	    aggregation_bitfield.set(duties.committee_index, true);

             Attestation {
                    aggregation_bitfield,
                    data,
                    custody_bitfield,
                    aggregate_signature,
		}
    }

    /// Returns `true` if signing an attestation is safe (non-slashable).
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn safe_to_produce(&self, _block: &Attestation) -> bool {
	//TODO: Implement slash protection
        true
    }

    /// Record that an attestation was produced so that slashable votes may not be made in the future.
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn store_produce(&mut self, _block: &BeaconBlock) {
        // TODO: Implement slash protection
    }
}

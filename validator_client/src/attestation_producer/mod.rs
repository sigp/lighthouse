mod beacon_node_attestation;
mod rest;

use std::sync::Arc;
use types::{ChainSpec, Domain, EthSpec, Fork};
//TODO: Move these higher up in the crate
pub use self::rest::AttestationRestClient;
use super::block_producer::{BeaconNodeError, PublishOutcome, ValidatorEvent};
use crate::signer::Signer;
pub use beacon_node_attestation::BeaconNodeAttestation;
use core::marker::PhantomData;
use futures::future::Future;
use slog::{error, info, warn};
use tree_hash::TreeHash;
use types::{
    AggregateSignature, Attestation, AttestationDataAndCustodyBit, AttestationDuty, BitList,
};

//TODO: Group these errors at a crate level
#[derive(Debug, PartialEq)]
pub enum Error {
    BeaconNodeError(BeaconNodeError),
    AttestationError(String),
}

impl From<BeaconNodeError> for Error {
    fn from(e: BeaconNodeError) -> Error {
        Error::BeaconNodeError(e)
    }
}

/// This struct contains the logic for requesting and signing beacon attestations for a validator. The
/// validator can abstractly sign via the Signer trait object.
pub struct AttestationProducer<'a, B: BeaconNodeAttestation, S: Signer, E: EthSpec> {
    /// The current fork.
    pub fork: Fork,
    /// The attestation duty to perform.
    pub duty: AttestationDuty,
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
}

impl<'a, B: BeaconNodeAttestation, S: Signer, E: EthSpec> AttestationProducer<'a, B, S, E> {
    /// Handle outputs and results from attestation production.
    pub fn handle_produce_attestation(&mut self, log: slog::Logger) {
        match self.produce_attestation() {
            ValidatorEvent::AttestationProduced(slot) => info!(
                log,
                "Attestation produced";
                "validator" => format!("{}", self.signer),
                "slot" => slot,
            ),
            ValidatorEvent::SignerRejection(_slot) => {
                error!(log, "Attestation production error"; "Error" => "Signer could not sign the attestation".to_string())
            }
            ValidatorEvent::AttestationNotProduced(_slot) => {
                error!(log, "Attestation production error"; "Error" => "Rejected the attestation as it could have been slashed".to_string())
            }
            ValidatorEvent::PublishAttestationFailed => {
                error!(log, "Attestation production error"; "Error" => "Beacon node was unable to publish an attestation".to_string())
            }
            ValidatorEvent::InvalidAttestation => {
                error!(log, "Attestation production error"; "Error" => "The signed attestation was invalid".to_string())
            }
            v => {
                warn!(log, "Unknown result for attestation production"; "Error" => format!("{:?}",v))
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
    pub fn produce_attestation(&mut self) -> ValidatorEvent {
        let epoch = self.duty.slot.epoch(self.slots_per_epoch);

        let publish_future = self
            .beacon_node
            .produce_attestation_data(self.duty.slot, self.duty.shard)
            .map_err(|e| ValidatorEvent::BeaconNodeUnableToProduceBlock(self.duty.slot))
            .and_then(|attestation| {
                if !self.safe_to_produce(&attestation) {
                    return futures::future::err(ValidatorEvent::AttestationNotProduced(
                        self.duty.slot,
                    ));
                }
                futures::future::ok(attestation)
            })
            .and_then(|attestation| {
                let domain = self.spec.get_domain(epoch, Domain::Attestation, &self.fork);
                match self.sign_attestation(attestation, self.duty, domain) {
                    Some(attestation) => futures::future::ok(attestation),
                    None => futures::future::err(ValidatorEvent::SignerRejection(self.duty.slot)),
                }
            })
            .and_then(|attestation| {
                self.beacon_node
                    .publish_attestation(attestation)
                    .map_err(|e| ValidatorEvent::PublishAttestationFailed)
            })
            .and_then(|outcome| match outcome {
                PublishOutcome::Valid => {
                    futures::future::ok(ValidatorEvent::AttestationProduced(self.duty.slot))
                }
                PublishOutcome::Invalid(_string) => {
                    futures::future::err(ValidatorEvent::InvalidAttestation)
                }
                PublishOutcome::Rejected(_string) => {
                    futures::future::err(ValidatorEvent::InvalidAttestation)
                }
            })
            .map_err(|e| futures::future::ok::<_, ValidatorEvent>(e))
            .wait()
            .expect("Cannot be an error, since we already converted those to ok.");
        publish_future
    }

    /// Consumes an attestation, returning the attestation signed by the validators private key.
    ///
    /// Important: this function will not check to ensure the attestation is not slashable. This must be
    /// done upstream.
    fn sign_attestation(
        &mut self,
        attestation: Attestation<E>,
        duties: AttestationDuty,
        domain: u64,
    ) -> Option<Attestation<E>> {
        self.store_produce(&attestation);

        // build the aggregate signature
        let aggregate_signature = {
            let message = AttestationDataAndCustodyBit {
                data: attestation.data.clone(),
                custody_bit: false,
            }
            .tree_hash_root();

            let sig = self.signer.sign_message(&message, domain)?;

            let mut agg_sig = AggregateSignature::new();
            agg_sig.add(&sig);
            agg_sig
        };

        let mut aggregation_bits = BitList::with_capacity(duties.committee_len).ok()?;
        let custody_bits = BitList::with_capacity(duties.committee_len).ok()?;
        aggregation_bits.set(duties.committee_index, true).ok()?;

        Some(Attestation {
            aggregation_bits,
            data: attestation.data,
            custody_bits,
            signature: aggregate_signature,
        })
    }

    /// Returns `true` if signing an attestation is safe (non-slashable).
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn safe_to_produce(&self, _attestation: &Attestation<E>) -> bool {
        //TODO: Implement slash protection
        true
    }

    /// Record that an attestation was produced so that slashable votes may not be made in the future.
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn store_produce(&mut self, _attestation: &Attestation<E>) {
        // TODO: Implement slash protection
    }
}

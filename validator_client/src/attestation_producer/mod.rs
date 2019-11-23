mod beacon_node_attestation;
mod grpc;

use std::sync::Arc;
use types::{ChainSpec, Domain, EthSpec, Fork};
//TODO: Move these higher up in the crate
use super::block_producer::{BeaconNodeError, PublishOutcome, ValidatorEvent};
use crate::signer::Signer;
use beacon_node_attestation::BeaconNodeAttestation;
use core::marker::PhantomData;
use slog::{error, info, warn};
use tree_hash::TreeHash;
use types::{AggregateSignature, Attestation, AttestationData, AttestationDuty, BitList};

use parking_lot::Mutex;
use slashing_protection::attester_slashings::SignedAttestation;
use slashing_protection::slashing_protection::{HistoryInfo, SlashingProtection};

//TODO: Group these errors at a crate level
#[derive(Debug, PartialEq)]
pub enum Error {
    BeaconNodeError(BeaconNodeError),
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
    ///
    pub history_info: Arc<Mutex<HistoryInfo<SignedAttestation>>>,
    /// Mere vessel for E.
    pub _phantom: PhantomData<E>,
}

impl<'a, B: BeaconNodeAttestation, S: Signer, E: EthSpec> AttestationProducer<'a, B, S, E> {
    /// Handle outputs and results from attestation production.
    pub fn handle_produce_attestation(&mut self, log: slog::Logger) {
        match self.produce_attestation() {
            Ok(ValidatorEvent::AttestationProduced(slot)) => info!(
                log,
                "Attestation produced";
                "validator" => format!("{}", self.signer),
                "slot" => slot,
            ),
            Err(e) => error!(log, "Attestation production error"; "Error" => format!("{:?}", e)),
            Ok(ValidatorEvent::SignerRejection(_slot)) => {
                error!(log, "Attestation production error"; "Error" => "Signer could not sign the attestation".to_string())
            }
            Ok(ValidatorEvent::IndexedAttestationNotProduced(_slot)) => {
                error!(log, "Attestation production error"; "Error" => "Rejected the attestation as it could have been slashed".to_string())
            }
            Ok(ValidatorEvent::PublishAttestationFailed) => {
                error!(log, "Attestation production error"; "Error" => "Beacon node was unable to publish an attestation".to_string())
            }
            Ok(ValidatorEvent::InvalidAttestation) => {
                error!(log, "Attestation production error"; "Error" => "The signed attestation was invalid".to_string())
            }
            Ok(v) => {
                warn!(log, "Unknown result for attestation production"; "Error" => format!("{:?}",v))
            }
        }
    }

    /// Produce an attestation, sign it and send it back
    ///
    /// Assumes that an attestation is required at this slot (does not check the duties).
    ///
    /// Ensures the message is not slashable.
    pub fn produce_attestation(&mut self) -> Result<ValidatorEvent, Error> {
        let epoch = self.duty.slot.epoch(self.slots_per_epoch);

        let attestation = self
            .beacon_node
            .produce_attestation_data(self.duty.slot, self.duty.index)?;
        if self.safe_to_produce(&attestation) {
            let domain = self
                .spec
                .get_domain(epoch, Domain::BeaconAttester, &self.fork);
            if let Some(attestation) = self.sign_attestation(attestation, self.duty, domain) {
                match self.beacon_node.publish_attestation(attestation) {
                    Ok(PublishOutcome::InvalidAttestation(_string)) => {
                        Ok(ValidatorEvent::InvalidAttestation)
                    }
                    Ok(PublishOutcome::Valid) => {
                        Ok(ValidatorEvent::AttestationProduced(self.duty.slot))
                    }
                    Err(_) | Ok(_) => Ok(ValidatorEvent::PublishAttestationFailed),
                }
            } else {
                Ok(ValidatorEvent::SignerRejection(self.duty.slot))
            }
        } else {
            Ok(ValidatorEvent::IndexedAttestationNotProduced(
                self.duty.slot,
            ))
        }
    }

    /// Consumes an attestation, returning the attestation signed by the validators private key.
    ///
    /// Important: this function will not check to ensure the attestation is not slashable. This must be
    /// done upstream.
    fn sign_attestation(
        &mut self,
        attestation: AttestationData,
        duties: AttestationDuty,
        domain: u64,
    ) -> Option<Attestation<E>> {
        // build the aggregate signature
        let aggregate_signature = {
            let message = attestation.tree_hash_root();

            let sig = self.signer.sign_message(&message, domain)?;

            let mut agg_sig = AggregateSignature::new();
            agg_sig.add(&sig);
            agg_sig
        };

        let mut aggregation_bits = BitList::with_capacity(duties.committee_len).ok()?;
        aggregation_bits.set(duties.committee_position, true).ok()?;

        Some(Attestation {
            aggregation_bits,
            data: attestation,
            signature: aggregate_signature,
        })
    }

    /// Returns `true` if signing an attestation is safe (non-slashable).
    fn safe_to_produce(&self, attestation: &AttestationData) -> bool {
        let mut history = self.history_info.lock();
        history.update_if_valid(attestation).is_ok()
    }
}

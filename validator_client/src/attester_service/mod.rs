mod grpc;
/*
use attester::{Attester, BeaconNode, DutiesReader, PollOutcome as AttesterPollOutcome, Signer};
use slog::{error, info, warn, Logger};
use slot_clock::SlotClock;
use std::time::Duration;

pub use self::attestation_grpc_client::AttestationGrpcClient;

pub struct AttesterService<U: BeaconNode, W: Signer> {
    pub attester: Attester<U, W>,
    pub poll_interval_millis: u64,
    pub log: Logger,
}


impl<U: BeaconNode, W: Signer> AttesterService<U, W> {
    /// Run a loop which polls the Attester each `poll_interval_millis` millseconds.
    ///
    /// Logs the results of the polls.
    pub fn run(&mut self) {
        loop {
            /* We don't do the polling any more...
            match self.attester.poll() {
                Err(error) => {
                    error!(self.log, "Attester poll error"; "error" => format!("{:?}", error))
                }
                Ok(AttesterPollOutcome::AttestationProduced(slot)) => {
                    info!(self.log, "Produced Attestation"; "slot" => slot)
                }
                Ok(AttesterPollOutcome::SlashableAttestationNotProduced(slot)) => {
                    warn!(self.log, "Slashable attestation was not produced"; "slot" => slot)
                }
                Ok(AttesterPollOutcome::AttestationNotRequired(slot)) => {
                    info!(self.log, "Attestation not required"; "slot" => slot)
                }
                Ok(AttesterPollOutcome::ProducerDutiesUnknown(slot)) => {
                    error!(self.log, "Attestation duties unknown"; "slot" => slot)
                }
                Ok(AttesterPollOutcome::SlotAlreadyProcessed(slot)) => {
                    warn!(self.log, "Attempted to re-process slot"; "slot" => slot)
                }
                Ok(AttesterPollOutcome::BeaconNodeUnableToProduceAttestation(slot)) => {
                    error!(self.log, "Beacon node unable to produce attestation"; "slot" => slot)
                }
                Ok(AttesterPollOutcome::SignerRejection(slot)) => {
                    error!(self.log, "The cryptographic signer refused to sign the attestation"; "slot" => slot)
                }
                Ok(AttesterPollOutcome::ValidatorIsUnknown(slot)) => {
                    error!(self.log, "The Beacon Node does not recognise the validator"; "slot" => slot)
                }
            };
            */
println!("Legacy polling still happening...");
std::thread::sleep(Duration::from_millis(self.poll_interval_millis));
}
}
}
*/

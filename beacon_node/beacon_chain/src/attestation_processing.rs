use super::{BeaconChain, ClientDB, SlotClock};
pub use crate::attestation_aggregator::{Error as AggregatorError, ProcessOutcome};
use types::FreeAttestation;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The free attestation was not processed succesfully.
    AggregatorError(AggregatorError),
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    /// Validate a `FreeAttestation` and either:
    ///
    /// - Create a new `Attestation`.
    /// - Aggregate it to an existing `Attestation`.
    pub fn process_free_attestation(
        &self,
        free_attestation: FreeAttestation,
    ) -> Result<ProcessOutcome, Error> {
        self.attestation_aggregator
            .write()
            .process_free_attestation(&self.state.read(), &free_attestation, &self.spec)
            .map_err(|e| e.into())
    }
}

impl From<AggregatorError> for Error {
    fn from(e: AggregatorError) -> Error {
        Error::AggregatorError(e)
    }
}

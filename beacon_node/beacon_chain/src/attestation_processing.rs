use super::{BeaconChain, ClientDB, SlotClock};
pub use crate::attestation_aggregator::{Error as AggregatorError, ProcessOutcome};
use crate::canonical_head::Error as HeadError;
use types::FreeAttestation;

#[derive(Debug, PartialEq)]
pub enum Error {
    PresentSlotUnknown,
    AggregatorError(AggregatorError),
    HeadError(HeadError),
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
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

impl From<HeadError> for Error {
    fn from(e: HeadError) -> Error {
        Error::HeadError(e)
    }
}

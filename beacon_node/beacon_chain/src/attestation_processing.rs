use super::{BeaconChain, ClientDB, SlotClock};
pub use crate::attestation_aggregator::{ProcessError as AggregatorError, ProcessOutcome};
use crate::canonical_head::Error as HeadError;
use types::{AttestationData, Signature};

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
        attestation_data: &AttestationData,
        signature: &Signature,
        validator_index: u64,
    ) -> Result<ProcessOutcome, Error> {
        let present_slot = self
            .present_slot()
            .ok_or_else(|| Error::PresentSlotUnknown)?;
        let state = self.state(present_slot)?;

        self.attestation_aggregator
            .write()
            .expect("Aggregator unlock failed.")
            .process_free_attestation(&state, attestation_data, signature, validator_index)
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

use ssz::{Decode, Encode};
use types::{
    EthSpec, SignedExecutionPayloadEnvelope, SignedExecutionPayloadEnvelopeGloas,
    SignedExecutionPayloadEnvelopeHeze,
};

use crate::{DBColumn, Error, StoreItem};

/// This fork-agnostic implementation should be only used for writing.
///
/// It is very inefficient at reading, and decoding the desired fork-specific variant is recommended
/// instead.
impl<E: EthSpec> StoreItem for SignedExecutionPayloadEnvelope<E> {
    fn db_column() -> DBColumn {
        DBColumn::PayloadEnvelope
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // The Gloas and Heze formats are currently byte-identical, so the variant decoded
        // here is not authoritative. Readers that care about the fork variant must re-tag
        // using the fork at the envelope's slot (see `HotColdDB::get_payload_envelope`).
        if let Ok(envelope) = SignedExecutionPayloadEnvelopeGloas::from_ssz_bytes(bytes) {
            return Ok(Self::Gloas(envelope));
        }

        SignedExecutionPayloadEnvelopeHeze::from_ssz_bytes(bytes)
            .map(Self::Heze)
            .map_err(Into::into)
    }
}

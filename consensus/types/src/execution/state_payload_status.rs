use serde::{Deserialize, Serialize};

/// Payload status as it applies to a `BeaconState` post-Gloas.
///
/// A state can either be a post-state for a block (in which case we call it `Pending`) or a
/// payload envelope (`Full`). When handling states it is often necessary to know which of these
/// two variants is required.
///
/// Note that states at skipped slots could be either `Pending` or `Full`, depending on whether
/// the payload for the most-recently applied block was also applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatePayloadStatus {
    /// For states produced by `process_block` executed on a `BeaconBlock`.
    Pending,
    /// For states produced by `process_execution_payload` on a `ExecutionPayloadEnvelope`.
    Full,
}

use crate::engine_api::{Error as ApiError, PayloadStatusV1, PayloadStatusV1Status};
use crate::engines::EngineError;
use crate::Error;
use slog::{crit, warn, Logger};
use types::ExecutionBlockHash;

/// Provides a simpler, easier to parse version of `PayloadStatusV1` for upstream users.
///
/// It primarily ensures that the `latest_valid_hash` is always present when relevant.
#[derive(Debug, Clone, PartialEq)]
pub enum PayloadStatus {
    Valid,
    Invalid {
        latest_valid_hash: ExecutionBlockHash,
        validation_error: Option<String>,
    },
    Syncing,
    Accepted,
    InvalidBlockHash {
        validation_error: Option<String>,
    },
    InvalidTerminalBlock {
        validation_error: Option<String>,
    },
}

/// Processes the responses from multiple execution engines, finding the "best" status and returning
/// it (if any).
///
/// This function has the following basic goals:
///
/// - Detect a consensus failure between nodes.
/// - Find the most-synced node by preferring a definite response (valid/invalid) over a
///     syncing/accepted response or error.
///
/// # Details
///
/// - If there are conflicting valid/invalid responses, always return an error.
/// - If there are syncing/accepted responses but valid/invalid responses exist, return the
///     valid/invalid responses since they're definite.
/// - If there are multiple valid responses, return the first one processed.
/// - If there are multiple invalid responses, return the first one processed.
/// - Syncing/accepted responses are grouped, if there are multiple of them, return the first one
///     processed.
/// - If there are no responses (only errors or nothing), return an error.
pub fn process_multiple_payload_statuses(
    head_block_hash: ExecutionBlockHash,
    statuses: impl Iterator<Item = Result<PayloadStatusV1, EngineError>>,
    log: &Logger,
) -> Result<PayloadStatus, Error> {
    let mut errors = vec![];
    let mut valid_statuses = vec![];
    let mut invalid_statuses = vec![];
    let mut other_statuses = vec![];

    for status in statuses {
        match status {
            Err(e) => errors.push(e),
            Ok(response) => match &response.status {
                PayloadStatusV1Status::Valid => {
                    if response
                        .latest_valid_hash
                        .map_or(false, |h| h == head_block_hash)
                    {
                        // The response is only valid if `latest_valid_hash` is not `null` and
                        // equal to the provided `block_hash`.
                        valid_statuses.push(PayloadStatus::Valid)
                    } else {
                        errors.push(EngineError::Api {
                                id: "unknown".to_string(),
                                error: ApiError::BadResponse(
                                    format!(
                                        "new_payload: response.status = VALID but invalid latest_valid_hash. Expected({:?}) Found({:?})",
                                        head_block_hash,
                                        response.latest_valid_hash,
                                    )
                                ),
                            });
                    }
                }
                PayloadStatusV1Status::Invalid => {
                    if let Some(latest_valid_hash) = response.latest_valid_hash {
                        // The response is only valid if `latest_valid_hash` is not `null`.
                        invalid_statuses.push(PayloadStatus::Invalid {
                            latest_valid_hash,
                            validation_error: response.validation_error.clone(),
                        })
                    } else {
                        errors.push(EngineError::Api {
                            id: "unknown".to_string(),
                            error: ApiError::BadResponse(
                                "new_payload: response.status = INVALID but null latest_valid_hash"
                                    .to_string(),
                            ),
                        });
                    }
                }
                PayloadStatusV1Status::InvalidBlockHash => {
                    // In the interests of being liberal with what we accept, only raise a
                    // warning here.
                    if response.latest_valid_hash.is_some() {
                        warn!(
                            log,
                            "Malformed response from execution engine";
                            "msg" => "expected a null latest_valid_hash",
                            "status" => ?response.status
                        )
                    }

                    invalid_statuses.push(PayloadStatus::InvalidBlockHash {
                        validation_error: response.validation_error.clone(),
                    });
                }
                PayloadStatusV1Status::InvalidTerminalBlock => {
                    // In the interests of being liberal with what we accept, only raise a
                    // warning here.
                    if response.latest_valid_hash.is_some() {
                        warn!(
                            log,
                            "Malformed response from execution engine";
                            "msg" => "expected a null latest_valid_hash",
                            "status" => ?response.status
                        )
                    }

                    invalid_statuses.push(PayloadStatus::InvalidTerminalBlock {
                        validation_error: response.validation_error.clone(),
                    });
                }
                PayloadStatusV1Status::Syncing => {
                    // In the interests of being liberal with what we accept, only raise a
                    // warning here.
                    if response.latest_valid_hash.is_some() {
                        warn!(
                            log,
                            "Malformed response from execution engine";
                            "msg" => "expected a null latest_valid_hash",
                            "status" => ?response.status
                        )
                    }

                    other_statuses.push(PayloadStatus::Syncing)
                }
                PayloadStatusV1Status::Accepted => {
                    // In the interests of being liberal with what we accept, only raise a
                    // warning here.
                    if response.latest_valid_hash.is_some() {
                        warn!(
                            log,
                            "Malformed response from execution engine";
                            "msg" => "expected a null latest_valid_hash",
                            "status" => ?response.status
                        )
                    }

                    other_statuses.push(PayloadStatus::Accepted)
                }
            },
        }
    }

    if !valid_statuses.is_empty() && !invalid_statuses.is_empty() {
        crit!(
            log,
            "Consensus failure between execution nodes";
            "invalid_statuses" => ?invalid_statuses,
            "valid_statuses" => ?valid_statuses,
        );

        // Choose to exit and ignore the valid response. This preferences correctness over
        // liveness.
        return Err(Error::ConsensusFailure);
    }

    // Log any errors to assist with troubleshooting.
    for error in &errors {
        warn!(
            log,
            "Error whilst processing payload status";
            "error" => ?error,
        );
    }

    valid_statuses
        .first()
        .or_else(|| invalid_statuses.first())
        .or_else(|| other_statuses.first())
        .cloned()
        .map(Result::Ok)
        .unwrap_or_else(|| Err(Error::EngineErrors(errors)))
}

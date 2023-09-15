use crate::engine_api::{Error as ApiError, PayloadStatusV1, PayloadStatusV1Status};
use crate::engines::EngineError;
use slog::{warn, Logger};
use types::ExecutionBlockHash;

/// Provides a simpler, easier to parse version of `PayloadStatusV1` for upstream users.
///
/// It primarily ensures that the `latest_valid_hash` is always present when relevant.
#[derive(Debug, Clone, PartialEq)]
pub enum PayloadStatus {
    Valid,
    Invalid {
        /// The EE will provide a `None` LVH when it is unable to determine the
        /// latest valid ancestor.
        latest_valid_hash: Option<ExecutionBlockHash>,
        validation_error: Option<String>,
    },
    Syncing,
    Accepted,
    InvalidBlockHash {
        validation_error: Option<String>,
    },
}

/// Processes the response from the execution engine.
pub fn process_payload_status(
    head_block_hash: ExecutionBlockHash,
    status: Result<PayloadStatusV1, EngineError>,
    log: &Logger,
) -> Result<PayloadStatus, EngineError> {
    match status {
        Err(error) => {
            warn!(
            log,
            "Error whilst processing payload status";
            "error" => ?error,
            );
            Err(error)
        }
        Ok(response) => match &response.status {
            PayloadStatusV1Status::Valid => {
                if response
                    .latest_valid_hash
                    .map_or(false, |h| h == head_block_hash)
                {
                    // The response is only valid if `latest_valid_hash` is not `null` and
                    // equal to the provided `block_hash`.
                    Ok(PayloadStatus::Valid)
                } else {
                    let error = format!(
                        "new_payload: response.status = VALID but invalid latest_valid_hash. Expected({:?}) Found({:?})",
                        head_block_hash,
                        response.latest_valid_hash
                    );
                    Err(EngineError::Api {
                        error: ApiError::BadResponse(error),
                    })
                }
            }
            PayloadStatusV1Status::Invalid => Ok(PayloadStatus::Invalid {
                latest_valid_hash: response.latest_valid_hash,
                validation_error: response.validation_error,
            }),
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

                Ok(PayloadStatus::InvalidBlockHash {
                    validation_error: response.validation_error.clone(),
                })
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

                Ok(PayloadStatus::Syncing)
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

                Ok(PayloadStatus::Accepted)
            }
        },
    }
}

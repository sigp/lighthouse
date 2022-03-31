use crate::engine_api::{Error as ApiError, PayloadStatusV1, PayloadStatusV1Status};
use slog::{warn, Logger};
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

impl PayloadStatus {
    pub fn new(
        head_block_hash: ExecutionBlockHash,
        response: PayloadStatusV1,
        log: &Logger,
    ) -> Result<Self, ApiError> {
        match &response.status {
            PayloadStatusV1Status::Valid => {
                if response
                    .latest_valid_hash
                    .map_or(false, |h| h == head_block_hash)
                {
                    // The response is only valid if `latest_valid_hash` is not `null` and
                    // equal to the provided `block_hash`.
                    Ok(PayloadStatus::Valid)
                } else {
                    let message = format!(
                        "new_payload: response.status = VALID but invalid latest_valid_hash. Expected({:?}) Found({:?})",
                        head_block_hash,
                        response.latest_valid_hash,
                    );
                    Err(ApiError::BadResponse(message))
                }
            }
            PayloadStatusV1Status::Invalid => {
                if let Some(latest_valid_hash) = response.latest_valid_hash {
                    // The response is only valid if `latest_valid_hash` is not `null`.
                    Ok(PayloadStatus::Invalid {
                        latest_valid_hash,
                        validation_error: response.validation_error.clone(),
                    })
                } else {
                    let message =
                        "new_payload: response.status = INVALID but null latest_valid_hash"
                            .to_string();
                    Err(ApiError::BadResponse(message))
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

                Ok(PayloadStatus::InvalidBlockHash {
                    validation_error: response.validation_error.clone(),
                })
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

                Ok(PayloadStatus::InvalidTerminalBlock {
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
        }
    }
}

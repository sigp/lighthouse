//! Provides tools for checking if a node is ready for the Verge upgrade and following merge
//! transition.

use crate::{BeaconChain, BeaconChainTypes};
use execution_layer::http::{ENGINE_GET_PAYLOAD_V4, ENGINE_NEW_PAYLOAD_V4};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use types::*;

/// The time before the Verge fork when we will start issuing warnings about preparation.
use super::merge_readiness::SECONDS_IN_A_WEEK;
pub const VERGE_READINESS_PREPARATION_SECONDS: u64 = SECONDS_IN_A_WEEK * 2;
pub const ENGINE_CAPABILITIES_REFRESH_INTERVAL: u64 = 300;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum VergeReadiness {
    /// The execution engine is verge-enabled (as far as we can tell)
    Ready,
    /// We are connected to an execution engine which doesn't support the V4 engine api methods
    V4MethodsNotSupported { error: String },
    /// The transition configuration with the EL failed, there might be a problem with
    /// connectivity, authentication or a difference in configuration.
    ExchangeCapabilitiesFailed { error: String },
    /// The user has not configured an execution endpoint
    NoExecutionEndpoint,
}

impl fmt::Display for VergeReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VergeReadiness::Ready => {
                write!(f, "This node appears ready for Verge.")
            }
            VergeReadiness::ExchangeCapabilitiesFailed { error } => write!(
                f,
                "Could not exchange capabilities with the \
                    execution endpoint: {}",
                error
            ),
            VergeReadiness::NoExecutionEndpoint => write!(
                f,
                "The --execution-endpoint flag is not specified, this is a \
                    requirement post-merge"
            ),
            VergeReadiness::V4MethodsNotSupported { error } => write!(
                f,
                "Execution endpoint does not support Verge methods: {}",
                error
            ),
        }
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Returns `true` if verge epoch is set and Verge fork has occurred or will
    /// occur within `VERGE_READINESS_PREPARATION_SECONDS`
    pub fn is_time_to_prepare_for_verge(&self, current_slot: Slot) -> bool {
        if let Some(verge_epoch) = self.spec.verge_fork_epoch {
            let verge_slot = verge_epoch.start_slot(T::EthSpec::slots_per_epoch());
            let verge_readiness_preparation_slots =
                VERGE_READINESS_PREPARATION_SECONDS / self.spec.seconds_per_slot;
            // Return `true` if Verge has happened or is within the preparation time.
            current_slot + verge_readiness_preparation_slots > verge_slot
        } else {
            // The Verge fork epoch has not been defined yet, no need to prepare.
            false
        }
    }

    /// Attempts to connect to the EL and confirm that it is ready for verge.
    pub async fn check_verge_readiness(&self) -> VergeReadiness {
        if let Some(el) = self.execution_layer.as_ref() {
            match el
                .get_engine_capabilities(Some(Duration::from_secs(
                    ENGINE_CAPABILITIES_REFRESH_INTERVAL,
                )))
                .await
            {
                Err(e) => {
                    // The EL was either unreachable or responded with an error
                    VergeReadiness::ExchangeCapabilitiesFailed {
                        error: format!("{:?}", e),
                    }
                }
                Ok(capabilities) => {
                    let mut missing_methods = String::from("Required Methods Unsupported:");
                    let mut all_good = true;
                    if !capabilities.get_payload_v2 {
                        missing_methods.push(' ');
                        missing_methods.push_str(ENGINE_GET_PAYLOAD_V4);
                        all_good = false;
                    }
                    //if !capabilities.forkchoice_updated_v2 {
                    //    missing_methods.push(' ');
                    //    missing_methods.push_str(ENGINE_FORKCHOICE_UPDATED_V2);
                    //    all_good = false;
                    //}
                    if !capabilities.new_payload_v2 {
                        missing_methods.push(' ');
                        missing_methods.push_str(ENGINE_NEW_PAYLOAD_V4);
                        all_good = false;
                    }

                    if all_good {
                        VergeReadiness::Ready
                    } else {
                        VergeReadiness::V4MethodsNotSupported {
                            error: missing_methods,
                        }
                    }
                }
            }
        } else {
            VergeReadiness::NoExecutionEndpoint
        }
    }
}

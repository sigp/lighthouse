//! Provides tools for checking if a node is ready for the Fulu upgrade.

use crate::{BeaconChain, BeaconChainTypes};
use execution_layer::http::{ENGINE_GET_PAYLOAD_V5, ENGINE_NEW_PAYLOAD_V5};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use types::*;

/// The time before the Fulu fork when we will start issuing warnings about preparation.
use super::bellatrix_readiness::SECONDS_IN_A_WEEK;
pub const FULU_READINESS_PREPARATION_SECONDS: u64 = SECONDS_IN_A_WEEK * 2;
pub const ENGINE_CAPABILITIES_REFRESH_INTERVAL: u64 = 300;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum FuluReadiness {
    /// The execution engine is fulu-enabled (as far as we can tell)
    Ready,
    /// We are connected to an execution engine which doesn't support the V5 engine api methods
    V5MethodsNotSupported { error: String },
    /// The transition configuration with the EL failed, there might be a problem with
    /// connectivity, authentication or a difference in configuration.
    ExchangeCapabilitiesFailed { error: String },
    /// The user has not configured an execution endpoint
    NoExecutionEndpoint,
}

impl fmt::Display for FuluReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuluReadiness::Ready => {
                write!(f, "This node appears ready for Fulu.")
            }
            FuluReadiness::ExchangeCapabilitiesFailed { error } => write!(
                f,
                "Could not exchange capabilities with the \
                    execution endpoint: {}",
                error
            ),
            FuluReadiness::NoExecutionEndpoint => write!(
                f,
                "The --execution-endpoint flag is not specified, this is a \
                    requirement post-merge"
            ),
            FuluReadiness::V5MethodsNotSupported { error } => write!(
                f,
                "Execution endpoint does not support Fulu methods: {}",
                error
            ),
        }
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Returns `true` if fulu epoch is set and Fulu fork has occurred or will
    /// occur within `FULU_READINESS_PREPARATION_SECONDS`
    pub fn is_time_to_prepare_for_fulu(&self, current_slot: Slot) -> bool {
        if let Some(fulu_epoch) = self.spec.fulu_fork_epoch {
            let fulu_slot = fulu_epoch.start_slot(T::EthSpec::slots_per_epoch());
            let fulu_readiness_preparation_slots =
                FULU_READINESS_PREPARATION_SECONDS / self.spec.seconds_per_slot;
            // Return `true` if Fulu has happened or is within the preparation time.
            current_slot + fulu_readiness_preparation_slots > fulu_slot
        } else {
            // The Fulu fork epoch has not been defined yet, no need to prepare.
            false
        }
    }

    /// Attempts to connect to the EL and confirm that it is ready for fulu.
    pub async fn check_fulu_readiness(&self) -> FuluReadiness {
        if let Some(el) = self.execution_layer.as_ref() {
            match el
                .get_engine_capabilities(Some(Duration::from_secs(
                    ENGINE_CAPABILITIES_REFRESH_INTERVAL,
                )))
                .await
            {
                Err(e) => {
                    // The EL was either unreachable or responded with an error
                    FuluReadiness::ExchangeCapabilitiesFailed {
                        error: format!("{:?}", e),
                    }
                }
                Ok(capabilities) => {
                    let mut missing_methods = String::from("Required Methods Unsupported:");
                    let mut all_good = true;
                    if !capabilities.get_payload_v5 {
                        missing_methods.push(' ');
                        missing_methods.push_str(ENGINE_GET_PAYLOAD_V5);
                        all_good = false;
                    }
                    if !capabilities.new_payload_v5 {
                        missing_methods.push(' ');
                        missing_methods.push_str(ENGINE_NEW_PAYLOAD_V5);
                        all_good = false;
                    }

                    if all_good {
                        FuluReadiness::Ready
                    } else {
                        FuluReadiness::V5MethodsNotSupported {
                            error: missing_methods,
                        }
                    }
                }
            }
        } else {
            FuluReadiness::NoExecutionEndpoint
        }
    }
}

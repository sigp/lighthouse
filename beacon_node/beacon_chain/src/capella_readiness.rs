//! Provides tools for checking if a node is ready for the Capella upgrade and following merge
//! transition.

use crate::{BeaconChain, BeaconChainTypes};
use execution_layer::http::{
    ENGINE_FORKCHOICE_UPDATED_V2, ENGINE_GET_PAYLOAD_V2, ENGINE_NEW_PAYLOAD_V2,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use types::*;

/// The time before the Capella fork when we will start issuing warnings about preparation.
use super::merge_readiness::SECONDS_IN_A_WEEK;
pub const CAPELLA_READINESS_PREPARATION_SECONDS: u64 = SECONDS_IN_A_WEEK * 2;
pub const ENGINE_CAPABILITIES_REFRESH_INTERVAL: u64 = 300;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum CapellaReadiness {
    /// The execution engine is capella-enabled (as far as we can tell)
    Ready,
    /// We are connected to an execution engine which doesn't support the V2 engine api methods
    V2MethodsNotSupported { error: String },
    /// The transition configuration with the EL failed, there might be a problem with
    /// connectivity, authentication or a difference in configuration.
    ExchangeCapabilitiesFailed { error: String },
    /// The user has not configured an execution endpoint
    NoExecutionEndpoint,
}

impl fmt::Display for CapellaReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapellaReadiness::Ready => {
                write!(f, "This node appears ready for Capella.")
            }
            CapellaReadiness::ExchangeCapabilitiesFailed { error } => write!(
                f,
                "Could not exchange capabilities with the \
                    execution endpoint: {}",
                error
            ),
            CapellaReadiness::NoExecutionEndpoint => write!(
                f,
                "The --execution-endpoint flag is not specified, this is a \
                    requirement post-merge"
            ),
            CapellaReadiness::V2MethodsNotSupported { error } => write!(
                f,
                "Execution endpoint does not support Capella methods: {}",
                error
            ),
        }
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Returns `true` if capella epoch is set and Capella fork has occurred or will
    /// occur within `CAPELLA_READINESS_PREPARATION_SECONDS`
    pub fn is_time_to_prepare_for_capella(&self, current_slot: Slot) -> bool {
        if let Some(capella_epoch) = self.spec.capella_fork_epoch {
            let capella_slot = capella_epoch.start_slot(T::EthSpec::slots_per_epoch());
            let capella_readiness_preparation_slots =
                CAPELLA_READINESS_PREPARATION_SECONDS / self.spec.seconds_per_slot;
            // Return `true` if Capella has happened or is within the preparation time.
            current_slot + capella_readiness_preparation_slots > capella_slot
        } else {
            // The Capella fork epoch has not been defined yet, no need to prepare.
            false
        }
    }

    /// Attempts to connect to the EL and confirm that it is ready for capella.
    pub async fn check_capella_readiness(&self) -> CapellaReadiness {
        if let Some(el) = self.execution_layer.as_ref() {
            match el
                .get_engine_capabilities(Some(Duration::from_secs(
                    ENGINE_CAPABILITIES_REFRESH_INTERVAL,
                )))
                .await
            {
                Err(e) => {
                    // The EL was either unreachable or responded with an error
                    CapellaReadiness::ExchangeCapabilitiesFailed {
                        error: format!("{:?}", e),
                    }
                }
                Ok(capabilities) => {
                    let mut missing_methods = String::from("Required Methods Unsupported:");
                    let mut all_good = true;
                    if !capabilities.get_payload_v2 {
                        missing_methods.push(' ');
                        missing_methods.push_str(ENGINE_GET_PAYLOAD_V2);
                        all_good = false;
                    }
                    if !capabilities.forkchoice_updated_v2 {
                        missing_methods.push(' ');
                        missing_methods.push_str(ENGINE_FORKCHOICE_UPDATED_V2);
                        all_good = false;
                    }
                    if !capabilities.new_payload_v2 {
                        missing_methods.push(' ');
                        missing_methods.push_str(ENGINE_NEW_PAYLOAD_V2);
                        all_good = false;
                    }

                    if all_good {
                        CapellaReadiness::Ready
                    } else {
                        CapellaReadiness::V2MethodsNotSupported {
                            error: missing_methods,
                        }
                    }
                }
            }
        } else {
            CapellaReadiness::NoExecutionEndpoint
        }
    }
}

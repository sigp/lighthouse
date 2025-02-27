//! Provides tools for checking if a node is ready for the Deneb upgrade.

use crate::{BeaconChain, BeaconChainTypes};
use execution_layer::http::{
    ENGINE_FORKCHOICE_UPDATED_V3, ENGINE_GET_PAYLOAD_V3, ENGINE_NEW_PAYLOAD_V3,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use types::*;

/// The time before the Deneb fork when we will start issuing warnings about preparation.
use super::bellatrix_readiness::SECONDS_IN_A_WEEK;
pub const DENEB_READINESS_PREPARATION_SECONDS: u64 = SECONDS_IN_A_WEEK * 2;
pub const ENGINE_CAPABILITIES_REFRESH_INTERVAL: u64 = 300;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum DenebReadiness {
    /// The execution engine is deneb-enabled (as far as we can tell)
    Ready,
    /// We are connected to an execution engine which doesn't support the V3 engine api methods
    V3MethodsNotSupported { error: String },
    /// The transition configuration with the EL failed, there might be a problem with
    /// connectivity, authentication or a difference in configuration.
    ExchangeCapabilitiesFailed { error: String },
    /// The user has not configured an execution endpoint
    NoExecutionEndpoint,
}

impl fmt::Display for DenebReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenebReadiness::Ready => {
                write!(f, "This node appears ready for Deneb.")
            }
            DenebReadiness::ExchangeCapabilitiesFailed { error } => write!(
                f,
                "Could not exchange capabilities with the \
                    execution endpoint: {}",
                error
            ),
            DenebReadiness::NoExecutionEndpoint => write!(
                f,
                "The --execution-endpoint flag is not specified, this is a \
                    requirement post-merge"
            ),
            DenebReadiness::V3MethodsNotSupported { error } => write!(
                f,
                "Execution endpoint does not support Deneb methods: {}",
                error
            ),
        }
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Returns `true` if deneb epoch is set and Deneb fork has occurred or will
    /// occur within `DENEB_READINESS_PREPARATION_SECONDS`
    pub fn is_time_to_prepare_for_deneb(&self, current_slot: Slot) -> bool {
        if let Some(deneb_epoch) = self.spec.deneb_fork_epoch {
            let deneb_slot = deneb_epoch.start_slot(T::EthSpec::slots_per_epoch());
            let deneb_readiness_preparation_slots =
                DENEB_READINESS_PREPARATION_SECONDS / self.spec.seconds_per_slot;
            // Return `true` if Deneb has happened or is within the preparation time.
            current_slot + deneb_readiness_preparation_slots > deneb_slot
        } else {
            // The Deneb fork epoch has not been defined yet, no need to prepare.
            false
        }
    }

    /// Attempts to connect to the EL and confirm that it is ready for capella.
    pub async fn check_deneb_readiness(&self) -> DenebReadiness {
        if let Some(el) = self.execution_layer.as_ref() {
            match el
                .get_engine_capabilities(Some(Duration::from_secs(
                    ENGINE_CAPABILITIES_REFRESH_INTERVAL,
                )))
                .await
            {
                Err(e) => {
                    // The EL was either unreachable or responded with an error
                    DenebReadiness::ExchangeCapabilitiesFailed {
                        error: format!("{:?}", e),
                    }
                }
                Ok(capabilities) => {
                    let mut missing_methods = String::from("Required Methods Unsupported:");
                    let mut all_good = true;
                    if !capabilities.get_payload_v3 {
                        missing_methods.push(' ');
                        missing_methods.push_str(ENGINE_GET_PAYLOAD_V3);
                        all_good = false;
                    }
                    if !capabilities.forkchoice_updated_v3 {
                        missing_methods.push(' ');
                        missing_methods.push_str(ENGINE_FORKCHOICE_UPDATED_V3);
                        all_good = false;
                    }
                    if !capabilities.new_payload_v3 {
                        missing_methods.push(' ');
                        missing_methods.push_str(ENGINE_NEW_PAYLOAD_V3);
                        all_good = false;
                    }

                    if all_good {
                        DenebReadiness::Ready
                    } else {
                        DenebReadiness::V3MethodsNotSupported {
                            error: missing_methods,
                        }
                    }
                }
            }
        } else {
            DenebReadiness::NoExecutionEndpoint
        }
    }
}

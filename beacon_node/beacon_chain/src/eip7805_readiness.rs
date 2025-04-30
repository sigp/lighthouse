//! Provides tools for checking if a node is ready for the Electra upgrade and following merge
//! transition.

use crate::{BeaconChain, BeaconChainTypes};
use execution_layer::http::{
    ENGINE_GET_INCLUSION_LIST_V1, ENGINE_GET_PAYLOAD_V4, ENGINE_NEW_PAYLOAD_V4,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use types::*;

/// The time before the eip7805 fork when we will start issuing warnings about preparation.
use super::bellatrix_readiness::SECONDS_IN_A_WEEK;
pub const EIP7805_READINESS_PREPARATION_SECONDS: u64 = SECONDS_IN_A_WEEK * 2;
pub const ENGINE_CAPABILITIES_REFRESH_INTERVAL: u64 = 300;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum Eip7805Readiness {
    /// The execution engine is eip7805-enabled (as far as we can tell)
    Ready,
    /// We are connected to an execution engine which doesn't support the V4 engine api methods
    V4MethodsNotSupported { error: String },
    /// The transition configuration with the EL failed, there might be a problem with
    /// connectivity, authentication or a difference in configuration.
    ExchangeCapabilitiesFailed { error: String },
    /// The user has not configured an execution endpoint
    NoExecutionEndpoint,
}

impl fmt::Display for Eip7805Readiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Eip7805Readiness::Ready => {
                write!(f, "This node appears ready for Eip7805.")
            }
            Eip7805Readiness::ExchangeCapabilitiesFailed { error } => write!(
                f,
                "Could not exchange capabilities with the \
                    execution endpoint: {}",
                error
            ),
            Eip7805Readiness::NoExecutionEndpoint => write!(
                f,
                "The --execution-endpoint flag is not specified, this is a \
                    requirement post-merge"
            ),
            Eip7805Readiness::V4MethodsNotSupported { error } => write!(
                f,
                "Execution endpoint does not support eip7805 methods: {}",
                error
            ),
        }
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Returns `true` if eip7805 epoch is set and Eip7805 fork has occurred or will
    /// occur within `EIP7805_READINESS_PREPARATION_SECONDS`
    pub fn is_time_to_prepare_for_eip7805(&self, current_slot: Slot) -> bool {
        if let Some(eip7805_epoch) = self.spec.eip7805_fork_epoch {
            let eip7805_slot = eip7805_epoch.start_slot(T::EthSpec::slots_per_epoch());
            let eip7805_readiness_preparation_slots =
                EIP7805_READINESS_PREPARATION_SECONDS / self.spec.seconds_per_slot;
            // Return `true` if eip7805 has happened or is within the preparation time.
            current_slot + eip7805_readiness_preparation_slots > eip7805_slot
        } else {
            // The Electra fork epoch has not been defined yet, no need to prepare.
            false
        }
    }

    /// Attempts to connect to the EL and confirm that it is ready for eip7805.
    pub async fn check_eip7805_readiness(&self) -> Eip7805Readiness {
        if let Some(el) = self.execution_layer.as_ref() {
            match el
                .get_engine_capabilities(Some(Duration::from_secs(
                    ENGINE_CAPABILITIES_REFRESH_INTERVAL,
                )))
                .await
            {
                Err(e) => {
                    // The EL was either unreachable or responded with an error
                    Eip7805Readiness::ExchangeCapabilitiesFailed {
                        error: format!("{:?}", e),
                    }
                }
                Ok(capabilities) => {
                    let mut missing_methods = String::from("Required Methods Unsupported:");
                    let mut all_good = true;
                    if !capabilities.get_payload_v4 {
                        missing_methods.push(' ');
                        missing_methods.push_str(ENGINE_GET_PAYLOAD_V4);
                        all_good = false;
                    }
                    if !capabilities.new_payload_v4 {
                        missing_methods.push(' ');
                        missing_methods.push_str(ENGINE_NEW_PAYLOAD_V4);
                        all_good = false;
                    }
                    if !capabilities.get_inclusion_list_v1 {
                        missing_methods.push(' ');
                        missing_methods.push_str(ENGINE_GET_INCLUSION_LIST_V1);
                        all_good = false;
                    }

                    if all_good {
                        Eip7805Readiness::Ready
                    } else {
                        Eip7805Readiness::V4MethodsNotSupported {
                            error: missing_methods,
                        }
                    }
                }
            }
        } else {
            Eip7805Readiness::NoExecutionEndpoint
        }
    }
}

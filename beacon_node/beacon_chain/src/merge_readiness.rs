//! Provides tools for checking if a node is ready for the Bellatrix upgrade and following merge
//! transition.

use crate::{BeaconChain, BeaconChainTypes};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;
use std::fmt::Write;
use types::*;

/// The time before the Bellatrix fork when we will start issuing warnings about preparation.
const SECONDS_IN_A_WEEK: u64 = 604800;
pub const MERGE_READINESS_PREPARATION_SECONDS: u64 = SECONDS_IN_A_WEEK * 2;

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct MergeConfig {
    #[serde(serialize_with = "serialize_uint256")]
    pub terminal_total_difficulty: Option<Uint256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_block_hash: Option<ExecutionBlockHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_block_hash_epoch: Option<Epoch>,
}

impl fmt::Display for MergeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.terminal_block_hash.is_none()
            && self.terminal_block_hash_epoch.is_none()
            && self.terminal_total_difficulty.is_none()
        {
            return write!(
                f,
                "Merge terminal difficulty parameters not configured, check your config"
            );
        }
        let mut display_string = String::new();
        if let Some(terminal_total_difficulty) = self.terminal_total_difficulty {
            write!(
                display_string,
                "terminal_total_difficulty: {},",
                terminal_total_difficulty
            )?;
        }
        if let Some(terminal_block_hash) = self.terminal_block_hash {
            write!(
                display_string,
                "terminal_block_hash: {},",
                terminal_block_hash
            )?;
        }
        if let Some(terminal_block_hash_epoch) = self.terminal_block_hash_epoch {
            write!(
                display_string,
                "terminal_block_hash_epoch: {},",
                terminal_block_hash_epoch
            )?;
        }
        write!(f, "{}", display_string.trim_end_matches(','))?;
        Ok(())
    }
}
impl MergeConfig {
    /// Instantiate `self` from the values in a `ChainSpec`.
    pub fn from_chainspec(spec: &ChainSpec) -> Self {
        let mut params = MergeConfig::default();
        if spec.terminal_total_difficulty != Uint256::max_value() {
            params.terminal_total_difficulty = Some(spec.terminal_total_difficulty);
        }
        if spec.terminal_block_hash != ExecutionBlockHash::zero() {
            params.terminal_block_hash = Some(spec.terminal_block_hash);
        }
        if spec.terminal_block_hash_activation_epoch != Epoch::max_value() {
            params.terminal_block_hash_epoch = Some(spec.terminal_block_hash_activation_epoch);
        }
        params
    }
}

/// Indicates if a node is ready for the Bellatrix upgrade and subsequent merge transition.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum MergeReadiness {
    /// The node is ready, as far as we can tell.
    Ready {
        config: MergeConfig,
        #[serde(serialize_with = "serialize_uint256")]
        current_difficulty: Option<Uint256>,
    },
    /// The transition configuration with the EL failed, there might be a problem with
    /// connectivity, authentication or a difference in configuration.
    ExchangeTransitionConfigurationFailed { error: String },
    /// The EL can be reached and has the correct configuration, however it's not yet synced.
    NotSynced,
    /// The user has not configured this node to use an execution endpoint.
    NoExecutionEndpoint,
}

impl fmt::Display for MergeReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MergeReadiness::Ready {
                config: params,
                current_difficulty,
            } => {
                write!(
                    f,
                    "This node appears ready for the merge. \
                        Params: {}, current_difficulty: {:?}",
                    params, current_difficulty
                )
            }
            MergeReadiness::ExchangeTransitionConfigurationFailed { error } => write!(
                f,
                "Could not confirm the transition configuration with the \
                    execution endpoint: {:?}",
                error
            ),
            MergeReadiness::NotSynced => write!(
                f,
                "The execution endpoint is connected and configured, \
                    however it is not yet synced"
            ),
            MergeReadiness::NoExecutionEndpoint => write!(
                f,
                "The --execution-endpoint flag is not specified, this is a \
                    requirement for the merge"
            ),
        }
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Returns `true` if user has an EL configured, or if the Bellatrix fork has occurred or will
    /// occur within `MERGE_READINESS_PREPARATION_SECONDS`.
    pub fn is_time_to_prepare_for_bellatrix(&self, current_slot: Slot) -> bool {
        if let Some(bellatrix_epoch) = self.spec.bellatrix_fork_epoch {
            let bellatrix_slot = bellatrix_epoch.start_slot(T::EthSpec::slots_per_epoch());
            let merge_readiness_preparation_slots =
                MERGE_READINESS_PREPARATION_SECONDS / self.spec.seconds_per_slot;

            if self.execution_layer.is_some() {
                // The user has already configured an execution layer, start checking for readiness
                // right away.
                true
            } else {
                // Return `true` if Bellatrix has happened or is within the preparation time.
                current_slot + merge_readiness_preparation_slots > bellatrix_slot
            }
        } else {
            // The Bellatrix fork epoch has not been defined yet, no need to prepare.
            false
        }
    }

    /// Attempts to connect to the EL and confirm that it is ready for the merge.
    pub async fn check_merge_readiness(&self) -> MergeReadiness {
        if let Some(el) = self.execution_layer.as_ref() {
            if let Err(e) = el.exchange_transition_configuration(&self.spec).await {
                // The EL was either unreachable, responded with an error or has a different
                // configuration.
                return MergeReadiness::ExchangeTransitionConfigurationFailed {
                    error: format!("{:?}", e),
                };
            }

            if !el.is_synced().await {
                // The EL is not synced.
                return MergeReadiness::NotSynced;
            }
            let params = MergeConfig::from_chainspec(&self.spec);
            let current_difficulty = el.get_current_difficulty().await.ok();
            MergeReadiness::Ready {
                config: params,
                current_difficulty,
            }
        } else {
            // There is no EL configured.
            MergeReadiness::NoExecutionEndpoint
        }
    }
}

/// Utility function to serialize a Uint256 as a decimal string.
fn serialize_uint256<S>(val: &Option<Uint256>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match val {
        Some(v) => v.to_string().serialize(s),
        None => s.serialize_none(),
    }
}

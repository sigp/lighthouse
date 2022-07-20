use crate::{BeaconChain, BeaconChainTypes};
use execution_layer::Error as EngineError;
use std::fmt;
use std::fmt::Write;
use types::*;

/// The time before the Bellatrix fork when we will start issuing warnings about preparation.
///
/// Currently set to two weeks.
const MERGE_READINESS_PREPARATION_SECONDS: u64 = 1_209_600 * 2;
const MERGE_READINESS_PREPARATION_HELP_TEXT: &str = "four weeks";

#[derive(Default, Debug)]
pub struct MergeConfig {
    pub terminal_total_difficulty: Option<Uint256>,
    pub terminal_block_hash: Option<ExecutionBlockHash>,
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

pub enum MergeReadiness {
    Ready {
        config: MergeConfig,
        current_difficulty: Result<Uint256, String>,
    },
    BellatrixNotSpecified,
    BellatrixIsDistant,
    ExchangeTransitionConfigurationFailed(EngineError),
    NotSynced,
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
            MergeReadiness::BellatrixNotSpecified => {
                write!(f, "The Bellatrix upgrade epoch has not yet been specified")
            }
            MergeReadiness::BellatrixIsDistant => write!(
                f,
                "The Bellatrix upgrade epoch will occur in {} or more",
                MERGE_READINESS_PREPARATION_HELP_TEXT
            ),
            MergeReadiness::ExchangeTransitionConfigurationFailed(e) => write!(
                f,
                "Could not confirm the transition configuration with the \
                    execution endpoint: {:?}",
                e
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
    pub fn is_time_to_prepare_for_bellatrix(&self, current_slot: Slot) -> bool {
        if let Some(bellatrix_epoch) = self.spec.bellatrix_fork_epoch {
            let bellatrix_slot = bellatrix_epoch.start_slot(T::EthSpec::slots_per_epoch());
            let merge_readiness_preparation_slots =
                MERGE_READINESS_PREPARATION_SECONDS / self.spec.seconds_per_slot;

            if current_slot + merge_readiness_preparation_slots > bellatrix_slot {
                // Bellatrix is either nearby or has already happened, time to prepare!
                true
            } else {
                // The Bellatrix fork epoch is far enough in the future that we don't need to
                // prepare yet.
                false
            }
        } else {
            // The Bellatrix fork epoch has not been defined yet, no need to prepare.
            false
        }
    }

    pub async fn check_merge_readiness(&self, current_slot: Slot) -> MergeReadiness {
        let bellatrix_epoch = if let Some(epoch) = self.spec.bellatrix_fork_epoch {
            epoch
        } else {
            // There is no Bellatrix fork specified, no need to check for an EL yet.
            return MergeReadiness::BellatrixNotSpecified;
        };

        let bellatrix_slot = bellatrix_epoch.start_slot(T::EthSpec::slots_per_epoch());
        let merge_readiness_preparation_slots =
            MERGE_READINESS_PREPARATION_SECONDS / self.spec.seconds_per_slot;
        if current_slot + merge_readiness_preparation_slots < bellatrix_slot {
            // Bellatrix is far in the future, no need to check for an EL.
            return MergeReadiness::BellatrixIsDistant;
        }

        if let Some(el) = self.execution_layer.as_ref() {
            if let Err(e) = el.exchange_transition_configuration(&self.spec).await {
                // The EL was either unreachable, responded with an error or has a different
                // configuration.
                return MergeReadiness::ExchangeTransitionConfigurationFailed(e);
            }

            if !el.is_synced_for_notifier().await {
                // The EL is not synced.
                return MergeReadiness::NotSynced;
            }
            let params = MergeConfig::from_chainspec(&self.spec);
            let current_difficulty = el
                .get_current_difficulty()
                .await
                .map_err(|_| "Failed to get current difficulty from execution node".to_string());
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

use crate::{BeaconChain, BeaconChainTypes};
use execution_layer::Error as EngineError;
use std::fmt;
use types::{ChainSpec, Epoch, ExecutionBlockHash, Uint256};

pub struct MergeParams {
    terminal_total_difficulty: Uint256,
    terminal_block_hash: ExecutionBlockHash,
    terminal_block_hash_epoch: Epoch,
}

impl fmt::Display for MergeParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.terminal_block_hash == ExecutionBlockHash::zero()
            && self.terminal_block_hash_epoch == Epoch::max_value()
            && self.terminal_total_difficulty == Uint256::max_value()
        {
            return write!(
                f,
                "Merge terminal difficulty parameters not configured, check your config"
            );
        }
        if self.terminal_total_difficulty != Uint256::max_value() {
            write!(
                f,
                "terminal_total_difficulty {}",
                self.terminal_total_difficulty
            )?;
        }
        if self.terminal_block_hash != ExecutionBlockHash::zero() {
            write!(f, "terminal_block_hash {}", self.terminal_block_hash)?;
        }
        if self.terminal_block_hash_epoch != Epoch::max_value() {
            write!(
                f,
                "terminal_block_hash_epoch {}",
                self.terminal_block_hash_epoch
            )?;
        }
        Ok(())
    }
}
impl MergeParams {
    pub fn from_chainspec(spec: &ChainSpec) -> Self {
        Self {
            terminal_total_difficulty: spec.terminal_total_difficulty,
            terminal_block_hash: spec.terminal_block_hash,
            terminal_block_hash_epoch: spec.terminal_block_hash_activation_epoch,
        }
    }
}

pub enum MergeReadiness {
    Ready {
        params: MergeParams,
        current_difficulty: Uint256,
    },
    BellatrixNotSpecified,
    ExchangeTransitionConfigurationFailed(EngineError),
    NotSynced,
    NoExecutionEndpoint,
}

impl fmt::Display for MergeReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MergeReadiness::Ready {
                params,
                current_difficulty,
            } => {
                write!(
                    f,
                    "This node appears ready for the merge. \
                        Params: {}, current_difficulty: {}",
                    params, current_difficulty
                )
            }
            MergeReadiness::BellatrixNotSpecified => {
                write!(f, "The Bellatrix upgrade epoch has not yet been specified")
            }
            MergeReadiness::ExchangeTransitionConfigurationFailed(e) => write!(
                f,
                "Could not confirm the transition configuration with the \
                    execution endpoint: {:?}",
                e
            ),
            MergeReadiness::NotSynced => write!(
                f,
                "The execution endpoint is connected and has the right config, \
                    however it is not yet synced. The node must be synced in \
                    order to be ready for the merge."
            ),
            MergeReadiness::NoExecutionEndpoint => write!(
                f,
                "The execution endpoint is connected and has the right config, \
                    however it is not yet synced."
            ),
        }
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub async fn check_merge_readiness(&self) -> MergeReadiness {
        if self.spec.bellatrix_fork_epoch.is_none() {
            // There is no Bellatrix fork specified, no need to check for an EL yet.
            return MergeReadiness::BellatrixNotSpecified;
        };

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
            let params = MergeParams::from_chainspec(&self.spec);
            let current_difficulty = el.get_current_difficulty().await.unwrap();
            MergeReadiness::Ready {
                params,
                current_difficulty,
            }
        } else {
            // There is no EL configured.
            MergeReadiness::NoExecutionEndpoint
        }
    }
}

use crate::{BeaconChain, BeaconChainError as Error, BeaconChainTypes};
use execution_layer::Error as EngineError;
use std::fmt;

pub enum MergeReadiness {
    Ready,
    BellatrixNotSpecified,
    ExchangeTransitionConfigurationFailed(EngineError),
    NotSynced,
    NoExecutionEndpoint,
}

impl fmt::Display for MergeReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MergeReadiness::Ready => write!(f, "This node appears ready for the merge"),
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
    pub async fn check_merge_readiness(&self) -> Result<MergeReadiness, Error> {
        if self.spec.bellatrix_fork_epoch.is_none() {
            // There is no Bellatrix fork specified, no need to check for an EL yet.
            return Ok(MergeReadiness::BellatrixNotSpecified);
        };

        if let Some(el) = self.execution_layer.as_ref() {
            if let Err(e) = el.exchange_transition_configuration(&self.spec).await {
                // The EL was either unreachable, responded with an error or has a different
                // configuration.
                return Ok(MergeReadiness::ExchangeTransitionConfigurationFailed(e));
            }

            if !el.is_synced().await {
                // The EL is not synced.
                return Ok(MergeReadiness::NotSynced);
            }
        } else {
            // There is no EL configured.
            return Ok(MergeReadiness::NoExecutionEndpoint);
        }

        Ok(MergeReadiness::Ready)
    }
}

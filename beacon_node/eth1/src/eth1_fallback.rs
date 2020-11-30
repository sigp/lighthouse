use crate::{
    http::{get_chain_id, get_network_id, Eth1Id},
    service::{SingleEndpointError, STANDARD_TIMEOUT_MILLIS},
};
use fallback::{check_preconditions, Fallback, FallbackError, ServerState};
use slog::{warn, Logger};
use std::fmt::Debug;
use std::future::Future;
use tokio::time::Duration;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum EndpointError {
    NotReachable,
    WrongNetworkId,
    WrongChainId,
    FarBehind,
}

pub struct Eth1Fallback {
    pub fallback: Fallback<(String, ServerState<EndpointError>)>,
    config_network_id: Eth1Id,
    config_chain_id: Eth1Id,
    log: Logger,
}

impl Eth1Fallback {
    pub fn new(
        fallback: Fallback<(String, ServerState<EndpointError>)>,
        config_network_id: Eth1Id,
        config_chain_id: Eth1Id,
        log: Logger,
    ) -> Self {
        Self {
            fallback,
            config_network_id,
            config_chain_id,
            log,
        }
    }

    pub fn format_err<E: Debug>(&self, error: &FallbackError<E>) -> String {
        self.fallback.map_format_error(|(s, _)| s, &error)
    }

    pub async fn first_success<'a, F, O, R>(
        &'a self,
        func: F,
    ) -> Result<O, FallbackError<SingleEndpointError>>
    where
        F: Fn(&'a String) -> R,
        R: Future<Output = Result<O, SingleEndpointError>>,
    {
        let func = &func;
        self.fallback
            .first_success(|(endpoint, state)| async move {
                check_preconditions(state, |mut g| async move {
                    let result = self.check(endpoint).await;
                    *g = Some(result);
                    Self::report_result(endpoint, result)
                })
                .await?;
                let result = Self::report_result(endpoint, func(endpoint).await);
                if let Err(e) = &result {
                    if let SingleEndpointError::EndpointError(ee) = e {
                        *state.write().await = Some(Err(*ee));
                    }
                }
                result
            })
            .await
    }

    async fn check(&self, server: &str) -> Result<(), EndpointError> {
        let endpoint: &str = &server;
        let error_connecting = |_| {
            warn!(
                self.log,
                "Error connecting to eth1 node. Trying fallback ...";
                "endpoint" => endpoint,
            );
            EndpointError::NotReachable
        };
        let network_id = get_network_id(endpoint, Duration::from_millis(STANDARD_TIMEOUT_MILLIS))
            .await
            .map_err(error_connecting)?;
        if network_id != self.config_network_id {
            warn!(
                self.log,
                "Invalid eth1 network id. Please switch to correct network id. Trying \
                 fallback ...";
                "endpoint" => endpoint,
                "expected" => format!("{:?}", self.config_network_id),
                "received" => format!("{:?}", network_id),
            );
            return Err(EndpointError::WrongNetworkId);
        }
        let chain_id = get_chain_id(endpoint, Duration::from_millis(STANDARD_TIMEOUT_MILLIS))
            .await
            .map_err(error_connecting)?;
        // Eth1 nodes return chain_id = 0 if the node is not synced
        // Handle the special case
        if chain_id == Eth1Id::Custom(0) {
            warn!(
                self.log,
                "Remote eth1 node is not synced";
                "endpoint" => endpoint,
            );
            return Err(EndpointError::FarBehind);
        }
        if chain_id != self.config_chain_id {
            warn!(
                self.log,
                "Invalid eth1 chain id. Please switch to correct chain id. Trying \
                 fallback ...";
                "endpoint" => endpoint,
                "expected" => format!("{:?}", self.config_chain_id),
                "received" => format!("{:?}", chain_id),
            );
            Err(EndpointError::WrongChainId)
        } else {
            Ok(())
        }
    }

    fn report_result<T, E>(endpoint: &str, result: Result<T, E>) -> Result<T, E> {
        crate::metrics::inc_counter_vec(&crate::metrics::ENDPOINT_REQUESTS, &[endpoint]);
        if result.is_err() {
            crate::metrics::inc_counter_vec(&crate::metrics::ENDPOINT_ERRORS, &[endpoint]);
        }
        result
    }
}

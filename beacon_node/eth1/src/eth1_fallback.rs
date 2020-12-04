use crate::{
    http::{get_chain_id, get_network_id, Eth1Id},
    service::{SingleEndpointError, STANDARD_TIMEOUT_MILLIS},
};
use fallback::{check_preconditions, Fallback, FallbackError, ServerState};
use slog::{warn, Logger};
use std::fmt::Debug;
use std::future::Future;
use tokio::time::Duration;

/// Error state for an eth1 endpoint
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum EndpointError {
    NotReachable,
    WrongNetworkId,
    WrongChainId,
    FarBehind,
}

/// Stores a set of eth1 endpoints fallbacks and context data needed to determine endpoint states.
/// Before a beacon node is used the first time it gets checked if it is online, has the correct
/// network id and the correct chain id. Furthermore, it remembers for each fallback if a
/// `FarBehind` error occurred.
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

    /// Format the given fallback error according to the endpoints list.
    pub fn format_err<E: Debug>(&self, error: &FallbackError<E>) -> String {
        self.fallback.map_format_error(|(s, _)| s, &error)
    }

    /// Wrapper function for `Fallback::first_success` that checks and remembers endpoint states +
    /// increase metric counts for each used endpoint.
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

    /// Check and return the current server state. Checks if the endpoint is online + has the
    /// correct network id + has the correct chain id.
    async fn check(&self, server: &str) -> Result<(), EndpointError> {
        let endpoint: &str = &server;
        let error_connecting = |e| {
            warn!(
                self.log,
                "Error connecting to eth1 node. Trying fallback ...";
                "endpoint" => endpoint,
                "error" => e,
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
                "expected" => ?self.config_network_id,
                "received" => ?network_id,
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
            Err(EndpointError::FarBehind)
        } else if chain_id != self.config_chain_id {
            warn!(
                self.log,
                "Invalid eth1 chain id. Please switch to correct chain id. Trying \
                 fallback ...";
                "endpoint" => endpoint,
                "expected" => ?self.config_chain_id,
                "received" => ?chain_id,
            );
            Err(EndpointError::WrongChainId)
        } else {
            Ok(())
        }
    }

    /// Increase metrics counts for an endpoint request.
    fn report_result<T, E>(endpoint: &str, result: Result<T, E>) -> Result<T, E> {
        crate::metrics::inc_counter_vec(&crate::metrics::ENDPOINT_REQUESTS, &[endpoint]);
        if result.is_err() {
            crate::metrics::inc_counter_vec(&crate::metrics::ENDPOINT_ERRORS, &[endpoint]);
        }
        result
    }
}

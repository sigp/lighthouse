use crate::http_metrics::metrics::{inc_counter_vec, ENDPOINT_ERRORS, ENDPOINT_REQUESTS};
use crate::is_synced::is_synced;
use crate::BeaconNodeConnectionError;
use eth2::{BeaconNodeHttpClient, Error};
use fallback::{check_preconditions, Fallback, FallbackError, ServerState};
use slog::{info, trace, warn, Logger};
use slot_clock::SlotClock;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use tokio::sync::RwLockWriteGuard;
use tokio::time::Duration;
use types::{ChainSpec, EthSpec};

/// Error object returned on fallback calls.
#[derive(Debug)]
pub enum BeaconNodeError<E> {
    /// A precondition is not satisfied for this node
    ConnectionError(BeaconNodeConnectionError),
    /// An error occurred during executing the function on the endpoint
    ApiError(E),
}

impl From<Error> for BeaconNodeError<Error> {
    fn from(e: Error) -> Self {
        Self::ApiError(e)
    }
}

impl From<()> for BeaconNodeError<()> {
    fn from(_: ()) -> Self {
        Self::ApiError(())
    }
}

impl From<String> for BeaconNodeError<String> {
    fn from(e: String) -> Self {
        Self::ApiError(e)
    }
}

impl From<&str> for BeaconNodeError<String> {
    fn from(s: &str) -> Self {
        Self::ApiError(s.to_string())
    }
}

impl<E> From<BeaconNodeConnectionError> for BeaconNodeError<E> {
    fn from(e: BeaconNodeConnectionError) -> Self {
        Self::ConnectionError(e)
    }
}

impl Into<String> for BeaconNodeConnectionError {
    fn into(self) -> String {
        format!("{:?}", self)
    }
}

/// Data used to check if a beacon node uses the same specs as the validator client.
#[derive(Clone)]
pub struct BeaconNodeContext<E: EthSpec> {
    chain_spec: ChainSpec,
    phantom: PhantomData<E>,
    log: Logger,
}

impl<E: EthSpec> BeaconNodeContext<E> {
    pub fn new(chain_spec: ChainSpec, log: Logger) -> Self {
        Self {
            chain_spec,
            phantom: PhantomData,
            log,
        }
    }

    /// Checks if a beacon node is online and uses the same specs as the validator client
    async fn check(
        &self,
        beacon_node: &BeaconNodeHttpClient,
    ) -> Result<(), BeaconNodeConnectionError> {
        let result = beacon_node
            .get_node_version()
            .await
            .map_err(|e| format!("{:?}", e))
            .map(|body| body.data.version);

        match result {
            Ok(version) => {
                info!(
                    self.log,
                    "Connected to beacon node";
                    "endpoint" => %beacon_node,
                    "version" => version,
                );
            }
            Err(e) => {
                warn!(
                    self.log,
                    "Unable to connect to beacon node";
                    "endpoint" => %beacon_node,
                    "error" => e,
                );
                return Err(BeaconNodeConnectionError::Offline);
            }
        }

        let yaml_config = beacon_node
            .get_config_spec()
            .await
            .map_err(|e| {
                warn!(
                    self.log,
                    "Unable to read spec from beacon node";
                    "endpoint" => %beacon_node,
                    "error" => ?e,
                );
                BeaconNodeConnectionError::Offline
            })?
            .data;

        let beacon_node_spec = yaml_config
            .apply_to_chain_spec::<E>(&E::default_spec())
            .ok_or_else(|| {
                warn!(
                    self.log,
                    "The minimal/mainnet spec type of the beacon node does not match the validator \
                    client. See the --network command.";
                    "endpoint" => %beacon_node,
                );
                BeaconNodeConnectionError::WrongConfig
            })?;

        if self.chain_spec != beacon_node_spec {
            warn!(
                self.log,
                "The beacon node is using a different Eth2 specification to this validator client. \
                See the --network command.";
                "endpoint" => %beacon_node,
            );
            return Err(BeaconNodeConnectionError::WrongConfig);
        }

        Ok(())
    }

    /// Log a warning if the given result is an error. Convenience function to use during result
    /// processing.
    fn log_error<O, Err: Debug>(
        &self,
        node: &BeaconNodeHttpClient,
        result: Result<O, Err>,
    ) -> Result<O, Err> {
        if let Err(e) = &result {
            warn!(
                self.log,
                "An error occurred on a beacon node request";
                "error" => ?e,
                "endpoint" => %node,
            );
        }
        result
    }
}

/// Holds possibly multiple beacon nodes structured as fallbacks. Before a beacon node is used the
/// first time it gets checked if it uses the same spec as the validator client.
#[derive(Clone)]
pub struct BeaconNodeFallback<E: EthSpec> {
    pub fallback: Fallback<(BeaconNodeHttpClient, ServerState<BeaconNodeConnectionError>)>,
    context: BeaconNodeContext<E>,
}

impl<E: EthSpec> BeaconNodeFallback<E> {
    pub fn new(
        fallback: Fallback<(BeaconNodeHttpClient, ServerState<BeaconNodeConnectionError>)>,
        context: BeaconNodeContext<E>,
    ) -> Self {
        Self { fallback, context }
    }

    /// Wrapper function for `Fallback::first_success` that checks if a beacon node is online (but
    /// does not remember the online state) + checks if the the node uses the correct spec (gets
    /// remembered) + increase metric counts for each used beacon node.
    pub async fn first_success<'a, F, O, R, Err>(
        &'a self,
        func: F,
    ) -> Result<O, FallbackError<BeaconNodeError<Err>>>
    where
        Err: Debug,
        F: Fn(&'a BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<O, BeaconNodeError<Err>>>,
    {
        let func = &func;
        self.fallback
            .first_success(|(node, state)| async move {
                check_preconditions(state, |g| async move {
                    let result = self.context.check(node).await;
                    save_result(g, &result);
                    report_result(node, result)
                })
                .await?;
                trace!(self.context.log, "Send request"; "endpoint" => %node);
                report_result(node, self.context.log_error(node, func(node).await))
            })
            .await
    }

    /// Wrapper function for `Fallback::first_success_concurrent_retry` that checks if a beacon node
    /// is online (but does not remember the online state) + checks if the the node uses the correct
    /// spec (gets remembered) + increase metric counts for each used beacon node.
    pub async fn first_success_concurrent_retry<'a, F, G, O, R, Err: Debug>(
        &'a self,
        func: F,
        should_retry: G,
        retry_delay: Duration,
    ) -> Result<O, FallbackError<(usize, BeaconNodeError<Err>)>>
    where
        F: Fn(&'a BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<O, BeaconNodeError<Err>>>,
        G: Fn(&Result<O, BeaconNodeError<Err>>) -> bool,
    {
        let func = &func;
        self.fallback
            .first_success_concurrent_retry(
                |(node, state)| async move {
                    check_preconditions(state, |g| async move {
                        let result = self.context.check(node).await;
                        save_result(g, &result);
                        report_result(node, result)
                    })
                    .await?;
                    report_result(node, self.context.log_error(node, func(node).await))
                },
                should_retry,
                retry_delay,
            )
            .await
    }
}

fn report_result<T, E>(endpoint: &BeaconNodeHttpClient, result: Result<T, E>) -> Result<T, E> {
    inc_counter_vec(&ENDPOINT_REQUESTS, &[endpoint.as_ref()]);
    if result.is_err() {
        inc_counter_vec(&ENDPOINT_ERRORS, &[endpoint.as_ref()]);
    }
    result
}

fn save_result(
    mut g: RwLockWriteGuard<Option<Result<(), BeaconNodeConnectionError>>>,
    result: &Result<(), BeaconNodeConnectionError>,
) {
    if !matches!(result, Err(BeaconNodeConnectionError::Offline)) {
        *g = Some(*result);
    }
}

/// Holds possibly multiple beacon nodes structured as fallbacks. Before a beacon node is used the
/// first time it gets checked if it uses the same spec as the validator client and if it is fully
/// synced.
#[derive(Clone)]
pub struct BeaconNodeFallbackWithSyncChecks<T, E: EthSpec> {
    pub fallback: Fallback<(
        BeaconNodeHttpClient,
        ServerState<BeaconNodeConnectionError>,
        ServerState<()>,
    )>,
    context: BeaconNodeContext<E>,
    slot_clock: T,
    pub allow_unsynced: bool,
}

impl<T, E> BeaconNodeFallbackWithSyncChecks<T, E>
where
    T: SlotClock + 'static,
    E: EthSpec,
{
    pub fn from(
        beacon_node_fallback: &BeaconNodeFallback<E>,
        slot_clock: T,
        allow_unsynced: bool,
    ) -> Self {
        Self {
            fallback: Fallback::new(
                beacon_node_fallback
                    .fallback
                    .iter_servers()
                    .map(|(n, s)| (n.clone(), s.clone(), Default::default()))
                    .collect(),
            ),
            context: beacon_node_fallback.context.clone(),
            slot_clock,
            allow_unsynced,
        }
    }

    /// Forgets all the sync states so that they get rechecked the next time a beacon node is used.
    pub async fn reset_sync_states(&self) {
        for (_, _, s) in self.fallback.iter_servers() {
            *s.write().await = None;
        }
    }

    /// Format the given fallback error according to the beacon node list.
    pub fn format_err<Err: Debug>(&self, error: &FallbackError<Err>) -> String {
        self.fallback.map_format_error(|(n, _, _)| n, &error)
    }

    /// Wrapper function for `Fallback::first_success` that checks if a beacon node is online (but
    /// does not remember the online state) + checks if the the node uses the correct spec (gets
    /// remembered) + checks if the node is fully synced (gets remembered) + increase metric counts
    /// for each used beacon node. If `self.allow_unsynced` is true and all beacon nodes are
    /// offline, have wrong specs, or are unsynced it retries ignoring the sync state.
    pub async fn first_success<'a, F, O, R, Err>(
        &'a self,
        func: F,
    ) -> Result<O, FallbackError<BeaconNodeError<Err>>>
    where
        Err: Debug,
        F: Fn(&'a BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<O, BeaconNodeError<Err>>>,
    {
        let func = &func;
        let result = self
            .fallback
            .first_success(|(node, s1, s2)| async move {
                check_preconditions(s1, |g| async move {
                    let result = self.context.check(node).await;
                    save_result(g, &result);
                    report_result(node, result)
                })
                .await?;
                check_preconditions(s2, |mut g| async move {
                    let result = self.check_sync(node).await;
                    *g = Some(result);
                    report_result(node, result)
                })
                .await
                .map_err(|()| BeaconNodeConnectionError::OutOfSync)?;
                trace!(self.context.log, "Send request after sync check"; "endpoint" => %node);
                report_result(node, self.context.log_error(node, func(node).await))
            })
            .await;
        if let Err(FallbackError::AllErrored(v)) = &result {
            if self.allow_unsynced
                && v.iter()
                    .all(|e| matches!(e, BeaconNodeError::ConnectionError(_)))
            {
                // all nodes are not available or out of sync => retry by checking only
                // out of sync
                return self
                    .fallback
                    .first_success(|(node, s1, _)| async move {
                        match *s1.read().await {
                            None => Err(BeaconNodeError::ConnectionError(
                                BeaconNodeConnectionError::Offline,
                            )), // node is offline
                            Some(Err(e)) => Err(BeaconNodeError::ConnectionError(e)),
                            Some(Ok(())) => {
                                // this means the peer was offline or out of sync, we can't distinguish
                                // that => retry without checking sync state
                                report_result(node, self.context.log_error(node, func(node).await))
                            }
                        }
                    })
                    .await;
            }
        }
        result
    }

    /// Checks if the beacon node is synced.
    async fn check_sync(&self, beacon_node: &BeaconNodeHttpClient) -> Result<(), ()> {
        if is_synced(beacon_node, &self.slot_clock, Some(&self.context.log)).await {
            Ok(())
        } else {
            Err(())
        }
    }
}

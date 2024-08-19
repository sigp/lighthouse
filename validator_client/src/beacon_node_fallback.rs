//! Allows for a list of `BeaconNodeHttpClient` to appear as a single entity which will exhibits
//! "fallback" behaviour; it will try a request on all of the nodes until one or none of them
//! succeed.

use crate::check_synced::check_synced;
use crate::http_metrics::metrics::{inc_counter_vec, ENDPOINT_ERRORS, ENDPOINT_REQUESTS};
use environment::RuntimeContext;
use eth2::BeaconNodeHttpClient;
use futures::future;
use serde::{Deserialize, Serialize};
use slog::{debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::fmt;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};
use strum::{EnumString, EnumVariantNames};
use tokio::{sync::RwLock, time::sleep};
use types::{ChainSpec, Config, EthSpec};

/// Message emitted when the VC detects the BN is using a different spec.
const UPDATE_REQUIRED_LOG_HINT: &str = "this VC or the remote BN may need updating";

/// The number of seconds *prior* to slot start that we will try and update the state of fallback
/// nodes.
///
/// Ideally this should be somewhere between 2/3rds through the slot and the end of it. If we set it
/// too early, we risk switching nodes between the time of publishing an attestation and publishing
/// an aggregate; this may result in a missed aggregation. If we set this time too late, we risk not
/// having the correct nodes up and running prior to the start of the slot.
const SLOT_LOOKAHEAD: Duration = Duration::from_secs(2);

/// Indicates a measurement of latency between the VC and a BN.
pub struct LatencyMeasurement {
    /// An identifier for the beacon node (e.g. the URL).
    pub beacon_node_id: String,
    /// The round-trip latency, if the BN responded successfully.
    pub latency: Option<Duration>,
}

/// Starts a service that will routinely try and update the status of the provided `beacon_nodes`.
///
/// See `SLOT_LOOKAHEAD` for information about when this should run.
pub fn start_fallback_updater_service<T: SlotClock + 'static, E: EthSpec>(
    context: RuntimeContext<E>,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
) -> Result<(), &'static str> {
    let executor = context.executor;
    if beacon_nodes.slot_clock.is_none() {
        return Err("Cannot start fallback updater without slot clock");
    }

    let future = async move {
        loop {
            beacon_nodes.update_all_candidates().await;

            let sleep_time = beacon_nodes
                .slot_clock
                .as_ref()
                .and_then(|slot_clock| {
                    let slot = slot_clock.now()?;
                    let till_next_slot = slot_clock.duration_to_slot(slot + 1)?;

                    till_next_slot.checked_sub(SLOT_LOOKAHEAD)
                })
                .unwrap_or_else(|| Duration::from_secs(1));

            sleep(sleep_time).await
        }
    };

    executor.spawn(future, "fallback");

    Ok(())
}

/// Indicates if a beacon node must be synced before some action is performed on it.
#[derive(PartialEq, Clone, Copy)]
pub enum RequireSynced {
    Yes,
    No,
}

/// Indicates if a beacon node should be set to `Offline` if a request fails.
#[derive(PartialEq, Clone, Copy)]
pub enum OfflineOnFailure {
    Yes,
    No,
}

impl PartialEq<bool> for RequireSynced {
    fn eq(&self, other: &bool) -> bool {
        if *other {
            *self == RequireSynced::Yes
        } else {
            *self == RequireSynced::No
        }
    }
}

#[derive(Debug)]
pub enum Error<T> {
    /// The node was unavailable and we didn't attempt to contact it.
    Unavailable(CandidateError),
    /// We attempted to contact the node but it failed.
    RequestFailed(T),
}

impl<T> Error<T> {
    pub fn request_failure(&self) -> Option<&T> {
        match self {
            Error::RequestFailed(e) => Some(e),
            _ => None,
        }
    }
}

/// The list of errors encountered whilst attempting to perform a query.
pub struct Errors<T>(pub Vec<(String, Error<T>)>);

impl<T: Debug> fmt::Display for Errors<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.0.is_empty() {
            write!(f, "Some endpoints failed, num_failed: {}", self.0.len())?;
        }
        for (i, (id, error)) in self.0.iter().enumerate() {
            let comma = if i + 1 < self.0.len() { "," } else { "" };

            write!(f, " {} => {:?}{}", id, error, comma)?;
        }
        Ok(())
    }
}

impl<T> Errors<T> {
    pub fn num_errors(&self) -> usize {
        self.0.len()
    }
}

/// Reasons why a candidate might not be ready.
#[derive(Debug, Clone, Copy)]
pub enum CandidateError {
    Uninitialized,
    Offline,
    Incompatible,
    NotSynced,
}

/// Represents a `BeaconNodeHttpClient` inside a `BeaconNodeFallback` that may or may not be used
/// for a query.
pub struct CandidateBeaconNode<E> {
    beacon_node: BeaconNodeHttpClient,
    status: RwLock<Result<(), CandidateError>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> CandidateBeaconNode<E> {
    /// Instantiate a new node.
    pub fn new(beacon_node: BeaconNodeHttpClient) -> Self {
        Self {
            beacon_node,
            status: RwLock::new(Err(CandidateError::Uninitialized)),
            _phantom: PhantomData,
        }
    }

    /// Returns the status of `self`.
    ///
    /// If `RequiredSynced::No`, any `NotSynced` node will be ignored and mapped to `Ok(())`.
    pub async fn status(&self, synced: RequireSynced) -> Result<(), CandidateError> {
        match *self.status.read().await {
            Err(CandidateError::NotSynced) if synced == false => Ok(()),
            other => other,
        }
    }

    /// Indicate that `self` is offline.
    pub async fn set_offline(&self) {
        *self.status.write().await = Err(CandidateError::Offline)
    }

    /// Perform some queries against the node to determine if it is a good candidate, updating
    /// `self.status` and returning that result.
    pub async fn refresh_status<T: SlotClock>(
        &self,
        slot_clock: Option<&T>,
        spec: &ChainSpec,
        log: &Logger,
    ) -> Result<(), CandidateError> {
        let previous_status = self.status(RequireSynced::Yes).await;
        let was_offline = matches!(previous_status, Err(CandidateError::Offline));

        let new_status = if let Err(e) = self.is_online(was_offline, log).await {
            Err(e)
        } else if let Err(e) = self.is_compatible(spec, log).await {
            Err(e)
        } else if let Err(e) = self.is_synced(slot_clock, log).await {
            Err(e)
        } else {
            Ok(())
        };

        // In case of concurrent use, the latest value will always be used. It's possible that a
        // long time out might over-ride a recent successful response, leading to a falsely-offline
        // status. I deem this edge-case acceptable in return for the concurrency benefits of not
        // holding a write-lock whilst we check the online status of the node.
        *self.status.write().await = new_status;

        new_status
    }

    /// Checks if the node is reachable.
    async fn is_online(&self, was_offline: bool, log: &Logger) -> Result<(), CandidateError> {
        let result = self
            .beacon_node
            .get_node_version()
            .await
            .map(|body| body.data.version);

        match result {
            Ok(version) => {
                if was_offline {
                    info!(
                        log,
                        "Connected to beacon node";
                        "version" => version,
                        "endpoint" => %self.beacon_node,
                    );
                }
                Ok(())
            }
            Err(e) => {
                warn!(
                    log,
                    "Offline beacon node";
                    "error" => %e,
                    "endpoint" => %self.beacon_node,
                );
                Err(CandidateError::Offline)
            }
        }
    }

    /// Checks if the node has the correct specification.
    async fn is_compatible(&self, spec: &ChainSpec, log: &Logger) -> Result<(), CandidateError> {
        let config = self
            .beacon_node
            .get_config_spec::<Config>()
            .await
            .map_err(|e| {
                error!(
                    log,
                    "Unable to read spec from beacon node";
                    "error" => %e,
                    "endpoint" => %self.beacon_node,
                );
                CandidateError::Offline
            })?
            .data;

        let beacon_node_spec = ChainSpec::from_config::<E>(&config).ok_or_else(|| {
            error!(
                log,
                "The minimal/mainnet spec type of the beacon node does not match the validator \
                client. See the --network command.";
                "endpoint" => %self.beacon_node,
            );
            CandidateError::Incompatible
        })?;

        if beacon_node_spec.genesis_fork_version != spec.genesis_fork_version {
            error!(
                log,
                "Beacon node is configured for a different network";
                "endpoint" => %self.beacon_node,
                "bn_genesis_fork" => ?beacon_node_spec.genesis_fork_version,
                "our_genesis_fork" => ?spec.genesis_fork_version,
            );
            return Err(CandidateError::Incompatible);
        } else if beacon_node_spec.altair_fork_epoch != spec.altair_fork_epoch {
            warn!(
                log,
                "Beacon node has mismatched Altair fork epoch";
                "endpoint" => %self.beacon_node,
                "endpoint_altair_fork_epoch" => ?beacon_node_spec.altair_fork_epoch,
                "hint" => UPDATE_REQUIRED_LOG_HINT,
            );
        } else if beacon_node_spec.bellatrix_fork_epoch != spec.bellatrix_fork_epoch {
            warn!(
                log,
                "Beacon node has mismatched Bellatrix fork epoch";
                "endpoint" => %self.beacon_node,
                "endpoint_bellatrix_fork_epoch" => ?beacon_node_spec.bellatrix_fork_epoch,
                "hint" => UPDATE_REQUIRED_LOG_HINT,
            );
        } else if beacon_node_spec.capella_fork_epoch != spec.capella_fork_epoch {
            warn!(
                log,
                "Beacon node has mismatched Capella fork epoch";
                "endpoint" => %self.beacon_node,
                "endpoint_capella_fork_epoch" => ?beacon_node_spec.capella_fork_epoch,
                "hint" => UPDATE_REQUIRED_LOG_HINT,
            );
        } else if beacon_node_spec.deneb_fork_epoch != spec.deneb_fork_epoch {
            warn!(
                log,
                "Beacon node has mismatched Deneb fork epoch";
                "endpoint" => %self.beacon_node,
                "endpoint_deneb_fork_epoch" => ?beacon_node_spec.deneb_fork_epoch,
                "hint" => UPDATE_REQUIRED_LOG_HINT,
            );
        } else if beacon_node_spec.electra_fork_epoch != spec.electra_fork_epoch {
            warn!(
                log,
                "Beacon node has mismatched Electra fork epoch";
                "endpoint" => %self.beacon_node,
                "endpoint_electra_fork_epoch" => ?beacon_node_spec.electra_fork_epoch,
                "hint" => UPDATE_REQUIRED_LOG_HINT,
            );
        }

        Ok(())
    }

    /// Checks if the beacon node is synced.
    async fn is_synced<T: SlotClock>(
        &self,
        slot_clock: Option<&T>,
        log: &Logger,
    ) -> Result<(), CandidateError> {
        if let Some(slot_clock) = slot_clock {
            check_synced(&self.beacon_node, slot_clock, Some(log)).await
        } else {
            // Skip this check if we don't supply a slot clock.
            Ok(())
        }
    }
}

/// A collection of `CandidateBeaconNode` that can be used to perform requests with "fallback"
/// behaviour, where the failure of one candidate results in the next candidate receiving an
/// identical query.
pub struct BeaconNodeFallback<T, E> {
    candidates: Vec<CandidateBeaconNode<E>>,
    slot_clock: Option<T>,
    broadcast_topics: Vec<ApiTopic>,
    spec: ChainSpec,
    log: Logger,
}

impl<T: SlotClock, E: EthSpec> BeaconNodeFallback<T, E> {
    pub fn new(
        candidates: Vec<CandidateBeaconNode<E>>,
        broadcast_topics: Vec<ApiTopic>,
        spec: ChainSpec,
        log: Logger,
    ) -> Self {
        Self {
            candidates,
            slot_clock: None,
            broadcast_topics,
            spec,
            log,
        }
    }

    /// Used to update the slot clock post-instantiation.
    ///
    /// This is the result of a chicken-and-egg issue where `Self` needs a slot clock for some
    /// operations, but `Self` is required to obtain the slot clock since we need the genesis time
    /// from a beacon node.
    pub fn set_slot_clock(&mut self, slot_clock: T) {
        self.slot_clock = Some(slot_clock);
    }

    /// The count of candidates, regardless of their state.
    pub fn num_total(&self) -> usize {
        self.candidates.len()
    }

    /// The count of synced and ready candidates.
    pub async fn num_synced(&self) -> usize {
        let mut n = 0;
        for candidate in &self.candidates {
            if candidate.status(RequireSynced::Yes).await.is_ok() {
                n += 1
            }
        }
        n
    }

    /// The count of synced and ready fallbacks excluding the primary beacon node candidate.
    pub async fn num_synced_fallback(&self) -> usize {
        let mut n = 0;
        for candidate in self.candidates.iter().skip(1) {
            if candidate.status(RequireSynced::Yes).await.is_ok() {
                n += 1
            }
        }
        n
    }

    /// The count of candidates that are online and compatible, but not necessarily synced.
    pub async fn num_available(&self) -> usize {
        let mut n = 0;
        for candidate in &self.candidates {
            if candidate.status(RequireSynced::No).await.is_ok() {
                n += 1
            }
        }
        n
    }

    /// Loop through ALL candidates in `self.candidates` and update their sync status.
    ///
    /// It is possible for a node to return an unsynced status while continuing to serve
    /// low quality responses. To route around this it's best to poll all connected beacon nodes.
    /// A previous implementation of this function polled only the unavailable BNs.
    pub async fn update_all_candidates(&self) {
        let futures = self
            .candidates
            .iter()
            .map(|candidate| {
                candidate.refresh_status(self.slot_clock.as_ref(), &self.spec, &self.log)
            })
            .collect::<Vec<_>>();

        // run all updates concurrently and ignore errors
        let _ = future::join_all(futures).await;
    }

    /// Concurrently send a request to all candidates (regardless of
    /// offline/online) status and attempt to collect a rough reading on the
    /// latency between the VC and candidate.
    pub async fn measure_latency(&self) -> Vec<LatencyMeasurement> {
        let futures: Vec<_> = self
            .candidates
            .iter()
            .map(|candidate| async {
                let beacon_node_id = candidate.beacon_node.to_string();
                // The `node/version` endpoint is used since I imagine it would
                // require the least processing in the BN and therefore measure
                // the connection moreso than the BNs processing speed.
                //
                // I imagine all clients have the version string availble as a
                // pre-computed string.
                let response_instant = candidate
                    .beacon_node
                    .get_node_version()
                    .await
                    .ok()
                    .map(|_| Instant::now());
                (beacon_node_id, response_instant)
            })
            .collect();

        let request_instant = Instant::now();

        // Send the request to all BNs at the same time. This might involve some
        // queueing on the sending host, however I hope it will avoid bias
        // caused by sending requests at different times.
        future::join_all(futures)
            .await
            .into_iter()
            .map(|(beacon_node_id, response_instant)| LatencyMeasurement {
                beacon_node_id,
                latency: response_instant
                    .and_then(|response| response.checked_duration_since(request_instant)),
            })
            .collect()
    }

    /// Run `func` against each candidate in `self`, returning immediately if a result is found.
    /// Otherwise, return all the errors encountered along the way.
    ///
    /// First this function will try all nodes with a suitable status. If no candidates are suitable
    /// or all the requests fail, it will try updating the status of all unsuitable nodes and
    /// re-running `func` again.
    pub async fn first_success<'a, F, O, Err, R>(
        &'a self,
        require_synced: RequireSynced,
        offline_on_failure: OfflineOnFailure,
        func: F,
    ) -> Result<O, Errors<Err>>
    where
        F: Fn(&'a BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<O, Err>>,
        Err: Debug,
    {
        let mut errors = vec![];
        let mut to_retry = vec![];
        let mut retry_unsynced = vec![];
        let log = &self.log.clone();

        // Run `func` using a `candidate`, returning the value or capturing errors.
        //
        // We use a macro instead of a closure here since it is not trivial to move `func` into a
        // closure.
        macro_rules! try_func {
            ($candidate: ident) => {{
                inc_counter_vec(&ENDPOINT_REQUESTS, &[$candidate.beacon_node.as_ref()]);

                // There exists a race condition where `func` may be called when the candidate is
                // actually not ready. We deem this an acceptable inefficiency.
                match func(&$candidate.beacon_node).await {
                    Ok(val) => return Ok(val),
                    Err(e) => {
                        debug!(
                            log,
                            "Request to beacon node failed";
                            "node" => $candidate.beacon_node.to_string(),
                            "error" => ?e,
                        );
                        // If we have an error on this function, make the client as not-ready.
                        //
                        // There exists a race condition where the candidate may have been marked
                        // as ready between the `func` call and now. We deem this an acceptable
                        // inefficiency.
                        if matches!(offline_on_failure, OfflineOnFailure::Yes) {
                            $candidate.set_offline().await;
                        }
                        errors.push(($candidate.beacon_node.to_string(), Error::RequestFailed(e)));
                        inc_counter_vec(&ENDPOINT_ERRORS, &[$candidate.beacon_node.as_ref()]);
                    }
                }
            }};
        }

        // First pass: try `func` on all synced and ready candidates.
        //
        // This ensures that we always choose a synced node if it is available.
        for candidate in &self.candidates {
            match candidate.status(RequireSynced::Yes).await {
                Err(e @ CandidateError::NotSynced) if require_synced == false => {
                    // This client is unsynced we will try it after trying all synced clients
                    retry_unsynced.push(candidate);
                    errors.push((candidate.beacon_node.to_string(), Error::Unavailable(e)));
                }
                Err(e) => {
                    // This client was not ready on the first pass, we might try it again later.
                    to_retry.push(candidate);
                    errors.push((candidate.beacon_node.to_string(), Error::Unavailable(e)));
                }
                _ => try_func!(candidate),
            }
        }

        // Second pass: try `func` on ready unsynced candidates. This only runs if we permit
        // unsynced candidates.
        //
        // Due to async race-conditions, it is possible that we will send a request to a candidate
        // that has been set to an offline/unready status. This is acceptable.
        if require_synced == false {
            for candidate in retry_unsynced {
                try_func!(candidate);
            }
        }

        // Third pass: try again, attempting to make non-ready clients become ready.
        for candidate in to_retry {
            // If the candidate hasn't luckily transferred into the correct state in the meantime,
            // force an update of the state.
            let new_status = match candidate.status(require_synced).await {
                Ok(()) => Ok(()),
                Err(_) => {
                    candidate
                        .refresh_status(self.slot_clock.as_ref(), &self.spec, &self.log)
                        .await
                }
            };

            match new_status {
                Ok(()) => try_func!(candidate),
                Err(CandidateError::NotSynced) if require_synced == false => try_func!(candidate),
                Err(e) => {
                    errors.push((candidate.beacon_node.to_string(), Error::Unavailable(e)));
                }
            }
        }

        // There were no candidates already ready and we were unable to make any of them ready.
        Err(Errors(errors))
    }

    /// Run `func` against all candidates in `self`, collecting the result of `func` against each
    /// candidate.
    ///
    /// First this function will try all nodes with a suitable status. If no candidates are suitable
    /// it will try updating the status of all unsuitable nodes and re-running `func` again.
    ///
    /// Note: This function returns `Ok(())` if `func` returned successfully on all beacon nodes.
    /// It returns a list of errors along with the beacon node id that failed for `func`.
    /// Since this ignores the actual result of `func`, this function should only be used for beacon
    /// node calls whose results we do not care about, only that they completed successfully.
    pub async fn broadcast<'a, F, O, Err, R>(
        &'a self,
        require_synced: RequireSynced,
        offline_on_failure: OfflineOnFailure,
        func: F,
    ) -> Result<(), Errors<Err>>
    where
        F: Fn(&'a BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<O, Err>>,
    {
        let mut to_retry = vec![];
        let mut retry_unsynced = vec![];

        // Run `func` using a `candidate`, returning the value or capturing errors.
        let run_on_candidate = |candidate: &'a CandidateBeaconNode<E>| async {
            inc_counter_vec(&ENDPOINT_REQUESTS, &[candidate.beacon_node.as_ref()]);

            // There exists a race condition where `func` may be called when the candidate is
            // actually not ready. We deem this an acceptable inefficiency.
            match func(&candidate.beacon_node).await {
                Ok(val) => Ok(val),
                Err(e) => {
                    // If we have an error on this function, mark the client as not-ready.
                    //
                    // There exists a race condition where the candidate may have been marked
                    // as ready between the `func` call and now. We deem this an acceptable
                    // inefficiency.
                    if matches!(offline_on_failure, OfflineOnFailure::Yes) {
                        candidate.set_offline().await;
                    }
                    inc_counter_vec(&ENDPOINT_ERRORS, &[candidate.beacon_node.as_ref()]);
                    Err((candidate.beacon_node.to_string(), Error::RequestFailed(e)))
                }
            }
        };

        // First pass: try `func` on all synced and ready candidates.
        //
        // This ensures that we always choose a synced node if it is available.
        let mut first_batch_futures = vec![];
        for candidate in &self.candidates {
            match candidate.status(RequireSynced::Yes).await {
                Ok(_) => {
                    first_batch_futures.push(run_on_candidate(candidate));
                }
                Err(CandidateError::NotSynced) if require_synced == false => {
                    // This client is unsynced we will try it after trying all synced clients
                    retry_unsynced.push(candidate);
                }
                Err(_) => {
                    // This client was not ready on the first pass, we might try it again later.
                    to_retry.push(candidate);
                }
            }
        }
        let first_batch_results = futures::future::join_all(first_batch_futures).await;

        // Second pass: try `func` on ready unsynced candidates. This only runs if we permit
        // unsynced candidates.
        //
        // Due to async race-conditions, it is possible that we will send a request to a candidate
        // that has been set to an offline/unready status. This is acceptable.
        let second_batch_results = if require_synced == false {
            futures::future::join_all(retry_unsynced.into_iter().map(run_on_candidate)).await
        } else {
            vec![]
        };

        // Third pass: try again, attempting to make non-ready clients become ready.
        let mut third_batch_futures = vec![];
        let mut third_batch_results = vec![];
        for candidate in to_retry {
            // If the candidate hasn't luckily transferred into the correct state in the meantime,
            // force an update of the state.
            let new_status = match candidate.status(require_synced).await {
                Ok(()) => Ok(()),
                Err(_) => {
                    candidate
                        .refresh_status(self.slot_clock.as_ref(), &self.spec, &self.log)
                        .await
                }
            };

            match new_status {
                Ok(()) => third_batch_futures.push(run_on_candidate(candidate)),
                Err(CandidateError::NotSynced) if require_synced == false => {
                    third_batch_futures.push(run_on_candidate(candidate))
                }
                Err(e) => third_batch_results.push(Err((
                    candidate.beacon_node.to_string(),
                    Error::Unavailable(e),
                ))),
            }
        }
        third_batch_results.extend(futures::future::join_all(third_batch_futures).await);

        let mut results = first_batch_results;
        results.extend(second_batch_results);
        results.extend(third_batch_results);

        let errors: Vec<_> = results.into_iter().filter_map(|res| res.err()).collect();

        if !errors.is_empty() {
            Err(Errors(errors))
        } else {
            Ok(())
        }
    }

    /// Call `func` on first beacon node that returns success or on all beacon nodes
    /// depending on the `topic` and configuration.
    pub async fn request<'a, F, Err, R>(
        &'a self,
        require_synced: RequireSynced,
        offline_on_failure: OfflineOnFailure,
        topic: ApiTopic,
        func: F,
    ) -> Result<(), Errors<Err>>
    where
        F: Fn(&'a BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<(), Err>>,
        Err: Debug,
    {
        if self.broadcast_topics.contains(&topic) {
            self.broadcast(require_synced, offline_on_failure, func)
                .await
        } else {
            self.first_success(require_synced, offline_on_failure, func)
                .await?;
            Ok(())
        }
    }
}

/// Serves as a cue for `BeaconNodeFallback` to tell which requests need to be broadcasted.
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize, EnumString, EnumVariantNames)]
#[strum(serialize_all = "kebab-case")]
pub enum ApiTopic {
    Attestations,
    Blocks,
    Subscriptions,
    SyncCommittee,
}

impl ApiTopic {
    pub fn all() -> Vec<ApiTopic> {
        use ApiTopic::*;
        vec![Attestations, Blocks, Subscriptions, SyncCommittee]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    use strum::VariantNames;

    #[test]
    fn api_topic_all() {
        let all = ApiTopic::all();
        assert_eq!(all.len(), ApiTopic::VARIANTS.len());
        assert!(ApiTopic::VARIANTS
            .iter()
            .map(|topic| ApiTopic::from_str(topic).unwrap())
            .eq(all.into_iter()));
    }
}

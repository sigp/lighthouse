//! Allows for a list of `BeaconNodeHttpClient` to appear as a single entity which will exhibits
//! "fallback" behaviour; it will try a request on all of the nodes until one or none of them
//! succeed.

pub mod beacon_node_health;
use beacon_node_health::{
    check_node_health, BeaconNodeHealth, BeaconNodeSyncDistanceTiers, ExecutionEngineHealth,
    IsOptimistic, SyncDistanceTier,
};
use environment::RuntimeContext;
use eth2::BeaconNodeHttpClient;
use futures::future;
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use slog::{debug, error, warn, Logger};
use slot_clock::SlotClock;
use std::cmp::Ordering;
use std::fmt;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};
use strum::{EnumString, EnumVariantNames};
use tokio::{sync::RwLock, time::sleep};
use types::{ChainSpec, Config as ConfigSpec, EthSpec, Slot};
use validator_metrics::{inc_counter_vec, ENDPOINT_ERRORS, ENDPOINT_REQUESTS};

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

/// If the beacon node slot_clock is within 1 slot, this is deemed acceptable. Otherwise the node
/// will be marked as CandidateError::TimeDiscrepancy.
const FUTURE_SLOT_TOLERANCE: Slot = Slot::new(1);

// Configuration for the Beacon Node fallback.
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub sync_tolerances: BeaconNodeSyncDistanceTiers,
}

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

#[derive(Debug)]
pub enum Error<T> {
    /// We attempted to contact the node but it failed.
    RequestFailed(T),
}

impl<T> Error<T> {
    pub fn request_failure(&self) -> Option<&T> {
        match self {
            Error::RequestFailed(e) => Some(e),
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
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
pub enum CandidateError {
    PreGenesis,
    Uninitialized,
    Offline,
    Incompatible,
    TimeDiscrepancy,
}

impl std::fmt::Display for CandidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CandidateError::PreGenesis => write!(f, "PreGenesis"),
            CandidateError::Uninitialized => write!(f, "Uninitialized"),
            CandidateError::Offline => write!(f, "Offline"),
            CandidateError::Incompatible => write!(f, "Incompatible"),
            CandidateError::TimeDiscrepancy => write!(f, "TimeDiscrepancy"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CandidateInfo {
    pub index: usize,
    pub endpoint: String,
    pub health: Result<BeaconNodeHealth, CandidateError>,
}

impl Serialize for CandidateInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CandidateInfo", 2)?;

        state.serialize_field("index", &self.index)?;
        state.serialize_field("endpoint", &self.endpoint)?;

        // Serialize either the health or the error field based on the Result
        match &self.health {
            Ok(health) => {
                state.serialize_field("health", health)?;
            }
            Err(e) => {
                state.serialize_field("error", &e.to_string())?;
            }
        }

        state.end()
    }
}

/// Represents a `BeaconNodeHttpClient` inside a `BeaconNodeFallback` that may or may not be used
/// for a query.
#[derive(Clone, Debug)]
pub struct CandidateBeaconNode<E> {
    pub index: usize,
    pub beacon_node: BeaconNodeHttpClient,
    pub health: Arc<RwLock<Result<BeaconNodeHealth, CandidateError>>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> PartialEq for CandidateBeaconNode<E> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && self.beacon_node == other.beacon_node
    }
}

impl<E: EthSpec> Eq for CandidateBeaconNode<E> {}

impl<E: EthSpec> CandidateBeaconNode<E> {
    /// Instantiate a new node.
    pub fn new(beacon_node: BeaconNodeHttpClient, index: usize) -> Self {
        Self {
            index,
            beacon_node,
            health: Arc::new(RwLock::new(Err(CandidateError::Uninitialized))),
            _phantom: PhantomData,
        }
    }

    /// Returns the health of `self`.
    pub async fn health(&self) -> Result<BeaconNodeHealth, CandidateError> {
        *self.health.read().await
    }

    pub async fn refresh_health<T: SlotClock>(
        &self,
        distance_tiers: &BeaconNodeSyncDistanceTiers,
        slot_clock: Option<&T>,
        spec: &ChainSpec,
        log: &Logger,
    ) -> Result<(), CandidateError> {
        if let Err(e) = self.is_compatible(spec, log).await {
            *self.health.write().await = Err(e);
            return Err(e);
        }

        if let Some(slot_clock) = slot_clock {
            match check_node_health(&self.beacon_node, log).await {
                Ok((head, is_optimistic, el_offline)) => {
                    let Some(slot_clock_head) = slot_clock.now() else {
                        let e = match slot_clock.is_prior_to_genesis() {
                            Some(true) => CandidateError::PreGenesis,
                            _ => CandidateError::Uninitialized,
                        };
                        *self.health.write().await = Err(e);
                        return Err(e);
                    };

                    if head > slot_clock_head + FUTURE_SLOT_TOLERANCE {
                        let e = CandidateError::TimeDiscrepancy;
                        *self.health.write().await = Err(e);
                        return Err(e);
                    }
                    let sync_distance = slot_clock_head.saturating_sub(head);

                    // Currently ExecutionEngineHealth is solely determined by online status.
                    let execution_status = if el_offline {
                        ExecutionEngineHealth::Unhealthy
                    } else {
                        ExecutionEngineHealth::Healthy
                    };

                    let optimistic_status = if is_optimistic {
                        IsOptimistic::Yes
                    } else {
                        IsOptimistic::No
                    };

                    let new_health = BeaconNodeHealth::from_status(
                        self.index,
                        sync_distance,
                        head,
                        optimistic_status,
                        execution_status,
                        distance_tiers,
                    );

                    *self.health.write().await = Ok(new_health);
                    Ok(())
                }
                Err(e) => {
                    // Set the health as `Err` which is sorted last in the list.
                    *self.health.write().await = Err(e);
                    Err(e)
                }
            }
        } else {
            // Slot clock will only be `None` at startup.
            let e = CandidateError::Uninitialized;
            *self.health.write().await = Err(e);
            Err(e)
        }
    }

    /// Checks if the node has the correct specification.
    async fn is_compatible(&self, spec: &ChainSpec, log: &Logger) -> Result<(), CandidateError> {
        let config = self
            .beacon_node
            .get_config_spec::<ConfigSpec>()
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
}

/// A collection of `CandidateBeaconNode` that can be used to perform requests with "fallback"
/// behaviour, where the failure of one candidate results in the next candidate receiving an
/// identical query.
#[derive(Clone, Debug)]
pub struct BeaconNodeFallback<T, E> {
    pub candidates: Arc<RwLock<Vec<CandidateBeaconNode<E>>>>,
    distance_tiers: BeaconNodeSyncDistanceTiers,
    slot_clock: Option<T>,
    broadcast_topics: Vec<ApiTopic>,
    spec: Arc<ChainSpec>,
    log: Logger,
}

impl<T: SlotClock, E: EthSpec> BeaconNodeFallback<T, E> {
    pub fn new(
        candidates: Vec<CandidateBeaconNode<E>>,
        config: Config,
        broadcast_topics: Vec<ApiTopic>,
        spec: Arc<ChainSpec>,
        log: Logger,
    ) -> Self {
        let distance_tiers = config.sync_tolerances;
        Self {
            candidates: Arc::new(RwLock::new(candidates)),
            distance_tiers,
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
    pub async fn num_total(&self) -> usize {
        self.candidates.read().await.len()
    }

    /// The count of candidates that are online and compatible, but not necessarily synced.
    pub async fn num_available(&self) -> usize {
        let mut n = 0;
        for candidate in self.candidates.read().await.iter() {
            match candidate.health().await {
                Ok(_) | Err(CandidateError::Uninitialized) => n += 1,
                Err(_) => continue,
            }
        }
        n
    }

    // Returns all data required by the VC notifier.
    pub async fn get_notifier_info(&self) -> (Vec<CandidateInfo>, usize, usize) {
        let candidates = self.candidates.read().await;

        let mut candidate_info = Vec::with_capacity(candidates.len());
        let mut num_available = 0;
        let mut num_synced = 0;

        for candidate in candidates.iter() {
            let health = candidate.health().await;

            match health {
                Ok(health) => {
                    if self
                        .distance_tiers
                        .compute_distance_tier(health.health_tier.sync_distance)
                        == SyncDistanceTier::Synced
                    {
                        num_synced += 1;
                    }
                    num_available += 1;
                }
                Err(CandidateError::Uninitialized) => num_available += 1,
                Err(_) => (),
            }

            candidate_info.push(CandidateInfo {
                index: candidate.index,
                endpoint: candidate.beacon_node.to_string(),
                health,
            });
        }

        (candidate_info, num_available, num_synced)
    }

    /// Loop through ALL candidates in `self.candidates` and update their sync status.
    ///
    /// It is possible for a node to return an unsynced status while continuing to serve
    /// low quality responses. To route around this it's best to poll all connected beacon nodes.
    /// A previous implementation of this function polled only the unavailable BNs.
    pub async fn update_all_candidates(&self) {
        // Clone the vec, so we release the read lock immediately.
        // `candidate.health` is behind an Arc<RwLock>, so this would still allow us to mutate the values.
        let candidates = self.candidates.read().await.clone();
        let mut futures = Vec::with_capacity(candidates.len());
        let mut nodes = Vec::with_capacity(candidates.len());

        for candidate in candidates.iter() {
            futures.push(candidate.refresh_health(
                &self.distance_tiers,
                self.slot_clock.as_ref(),
                &self.spec,
                &self.log,
            ));
            nodes.push(candidate.beacon_node.to_string());
        }

        // Run all updates concurrently.
        let future_results = future::join_all(futures).await;
        let results = future_results.iter().zip(nodes);

        for (result, node) in results {
            if let Err(e) = result {
                if *e != CandidateError::PreGenesis {
                    warn!(
                        self.log,
                        "A connected beacon node errored during routine health check";
                        "error" => ?e,
                        "endpoint" => node,
                    );
                }
            }
        }

        drop(candidates);

        let mut candidates = self.candidates.write().await;
        sort_nodes_by_health(&mut candidates).await;
    }

    /// Concurrently send a request to all candidates (regardless of
    /// offline/online) status and attempt to collect a rough reading on the
    /// latency between the VC and candidate.
    pub async fn measure_latency(&self) -> Vec<LatencyMeasurement> {
        let candidates = self.candidates.read().await;
        let futures: Vec<_> = candidates
            .clone()
            .into_iter()
            .map(|candidate| async move {
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
        drop(candidates);

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
    pub async fn first_success<F, O, Err, R>(&self, func: F) -> Result<O, Errors<Err>>
    where
        F: Fn(BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<O, Err>>,
        Err: Debug,
    {
        let mut errors = vec![];

        // First pass: try `func` on all candidates. Candidate order has already been set in
        // `update_all_candidates`. This ensures the most suitable node is always tried first.
        let candidates = self.candidates.read().await;
        let mut futures = vec![];

        // Run `func` using a `candidate`, returning the value or capturing errors.
        for candidate in candidates.iter() {
            futures.push(Self::run_on_candidate(
                candidate.beacon_node.clone(),
                &func,
                &self.log,
            ));
        }
        drop(candidates);

        for future in futures {
            match future.await {
                Ok(val) => return Ok(val),
                Err(e) => errors.push(e),
            }
        }

        // Second pass. No candidates returned successfully. Try again with the same order.
        // This will duplicate errors.
        let candidates = self.candidates.read().await;
        let mut futures = vec![];

        // Run `func` using a `candidate`, returning the value or capturing errors.
        for candidate in candidates.iter() {
            futures.push(Self::run_on_candidate(
                candidate.beacon_node.clone(),
                &func,
                &self.log,
            ));
        }
        drop(candidates);

        for future in futures {
            match future.await {
                Ok(val) => return Ok(val),
                Err(e) => errors.push(e),
            }
        }

        // No candidates returned successfully.
        Err(Errors(errors))
    }

    /// Run the future `func` on `candidate` while reporting metrics.
    async fn run_on_candidate<F, R, Err, O>(
        candidate: BeaconNodeHttpClient,
        func: F,
        log: &Logger,
    ) -> Result<O, (String, Error<Err>)>
    where
        F: Fn(BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<O, Err>>,
        Err: Debug,
    {
        inc_counter_vec(&ENDPOINT_REQUESTS, &[candidate.as_ref()]);

        // There exists a race condition where `func` may be called when the candidate is
        // actually not ready. We deem this an acceptable inefficiency.
        match func(candidate.clone()).await {
            Ok(val) => Ok(val),
            Err(e) => {
                debug!(
                    log,
                    "Request to beacon node failed";
                    "node" => %candidate,
                    "error" => ?e,
                );
                inc_counter_vec(&ENDPOINT_ERRORS, &[candidate.as_ref()]);
                Err((candidate.to_string(), Error::RequestFailed(e)))
            }
        }
    }

    /// Run `func` against all candidates in `self`, collecting the result of `func` against each
    /// candidate.
    ///
    /// Note: This function returns `Ok(())` if `func` returned successfully on all beacon nodes.
    /// It returns a list of errors along with the beacon node id that failed for `func`.
    /// Since this ignores the actual result of `func`, this function should only be used for beacon
    /// node calls whose results we do not care about, only that they completed successfully.
    pub async fn broadcast<F, O, Err, R>(&self, func: F) -> Result<(), Errors<Err>>
    where
        F: Fn(BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<O, Err>>,
        Err: Debug,
    {
        // Run `func` on all candidates.
        let candidates = self.candidates.read().await;
        let mut futures = vec![];

        // Run `func` using a `candidate`, returning the value or capturing errors.
        for candidate in candidates.iter() {
            futures.push(Self::run_on_candidate(
                candidate.beacon_node.clone(),
                &func,
                &self.log,
            ));
        }
        drop(candidates);

        let results = future::join_all(futures).await;

        let errors: Vec<_> = results.into_iter().filter_map(|res| res.err()).collect();

        if !errors.is_empty() {
            Err(Errors(errors))
        } else {
            Ok(())
        }
    }

    /// Call `func` on first beacon node that returns success or on all beacon nodes
    /// depending on the `topic` and configuration.
    pub async fn request<F, Err, R>(&self, topic: ApiTopic, func: F) -> Result<(), Errors<Err>>
    where
        F: Fn(BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<(), Err>>,
        Err: Debug,
    {
        if self.broadcast_topics.contains(&topic) {
            self.broadcast(func).await
        } else {
            self.first_success(func).await?;
            Ok(())
        }
    }
}

/// Helper functions to allow sorting candidate nodes by health.
async fn sort_nodes_by_health<E: EthSpec>(nodes: &mut Vec<CandidateBeaconNode<E>>) {
    // Fetch all health values.
    let health_results: Vec<Result<BeaconNodeHealth, CandidateError>> =
        future::join_all(nodes.iter().map(|node| node.health())).await;

    // Pair health results with their indices.
    let mut indices_with_health: Vec<(usize, Result<BeaconNodeHealth, CandidateError>)> =
        health_results.into_iter().enumerate().collect();

    // Sort indices based on their health.
    indices_with_health.sort_by(|a, b| match (&a.1, &b.1) {
        (Ok(health_a), Ok(health_b)) => health_a.cmp(health_b),
        (Err(_), Ok(_)) => Ordering::Greater,
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Err(_)) => Ordering::Equal,
    });

    // Reorder candidates based on the sorted indices.
    let sorted_nodes: Vec<CandidateBeaconNode<E>> = indices_with_health
        .into_iter()
        .map(|(index, _)| nodes[index].clone())
        .collect();
    *nodes = sorted_nodes;
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
mod tests {
    use super::*;
    use crate::beacon_node_health::BeaconNodeHealthTier;
    use eth2::SensitiveUrl;
    use eth2::Timeouts;
    use std::str::FromStr;
    use strum::VariantNames;
    use types::{MainnetEthSpec, Slot};

    type E = MainnetEthSpec;

    #[test]
    fn api_topic_all() {
        let all = ApiTopic::all();
        assert_eq!(all.len(), ApiTopic::VARIANTS.len());
        assert!(ApiTopic::VARIANTS
            .iter()
            .map(|topic| ApiTopic::from_str(topic).unwrap())
            .eq(all.into_iter()));
    }

    #[tokio::test]
    async fn check_candidate_order() {
        // These fields is irrelvant for sorting. They are set to arbitrary values.
        let head = Slot::new(99);
        let optimistic_status = IsOptimistic::No;
        let execution_status = ExecutionEngineHealth::Healthy;

        fn new_candidate(index: usize) -> CandidateBeaconNode<E> {
            let beacon_node = BeaconNodeHttpClient::new(
                SensitiveUrl::parse(&format!("http://example_{index}.com")).unwrap(),
                Timeouts::set_all(Duration::from_secs(index as u64)),
            );
            CandidateBeaconNode::new(beacon_node, index)
        }

        let candidate_1 = new_candidate(1);
        let expected_candidate_1 = new_candidate(1);
        let candidate_2 = new_candidate(2);
        let expected_candidate_2 = new_candidate(2);
        let candidate_3 = new_candidate(3);
        let expected_candidate_3 = new_candidate(3);
        let candidate_4 = new_candidate(4);
        let expected_candidate_4 = new_candidate(4);
        let candidate_5 = new_candidate(5);
        let expected_candidate_5 = new_candidate(5);
        let candidate_6 = new_candidate(6);
        let expected_candidate_6 = new_candidate(6);

        let synced = SyncDistanceTier::Synced;
        let small = SyncDistanceTier::Small;

        // Despite `health_1` having a larger sync distance, it is inside the `synced` range which
        // does not tie-break on sync distance and so will tie-break on `user_index` instead.
        let health_1 = BeaconNodeHealth {
            user_index: 1,
            head,
            optimistic_status,
            execution_status,
            health_tier: BeaconNodeHealthTier::new(1, Slot::new(2), synced),
        };
        let health_2 = BeaconNodeHealth {
            user_index: 2,
            head,
            optimistic_status,
            execution_status,
            health_tier: BeaconNodeHealthTier::new(2, Slot::new(1), synced),
        };

        // `health_3` and `health_4` have the same health tier and sync distance so should
        // tie-break on `user_index`.
        let health_3 = BeaconNodeHealth {
            user_index: 3,
            head,
            optimistic_status,
            execution_status,
            health_tier: BeaconNodeHealthTier::new(3, Slot::new(9), small),
        };
        let health_4 = BeaconNodeHealth {
            user_index: 4,
            head,
            optimistic_status,
            execution_status,
            health_tier: BeaconNodeHealthTier::new(3, Slot::new(9), small),
        };

        // `health_5` has a smaller sync distance and is outside the `synced` range so should be
        // sorted first. Note the values of `user_index`.
        let health_5 = BeaconNodeHealth {
            user_index: 6,
            head,
            optimistic_status,
            execution_status,
            health_tier: BeaconNodeHealthTier::new(4, Slot::new(9), small),
        };
        let health_6 = BeaconNodeHealth {
            user_index: 5,
            head,
            optimistic_status,
            execution_status,
            health_tier: BeaconNodeHealthTier::new(4, Slot::new(10), small),
        };

        *candidate_1.health.write().await = Ok(health_1);
        *candidate_2.health.write().await = Ok(health_2);
        *candidate_3.health.write().await = Ok(health_3);
        *candidate_4.health.write().await = Ok(health_4);
        *candidate_5.health.write().await = Ok(health_5);
        *candidate_6.health.write().await = Ok(health_6);

        let mut candidates = vec![
            candidate_3,
            candidate_6,
            candidate_5,
            candidate_1,
            candidate_4,
            candidate_2,
        ];
        let expected_candidates = vec![
            expected_candidate_1,
            expected_candidate_2,
            expected_candidate_3,
            expected_candidate_4,
            expected_candidate_5,
            expected_candidate_6,
        ];

        sort_nodes_by_health(&mut candidates).await;

        assert_eq!(candidates, expected_candidates);
    }
}

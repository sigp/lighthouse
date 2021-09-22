//! Allows for a list of `BeaconNodeHttpClient` to appear as a single entity which will exhibits
//! "fallback" behaviour; it will try a request on all of the nodes until one or none of them
//! succeed.

use crate::check_synced::check_synced;
use crate::http_metrics::metrics::{inc_counter_vec, ENDPOINT_ERRORS, ENDPOINT_REQUESTS};
use bls::Hash256;
use environment::RuntimeContext;
use eth2::types::{EventKind, EventTopic};
use eth2::BeaconNodeHttpClient;
use futures::future;
use futures_util::pin_mut;
use futures_util::stream::StreamExt;
use slog::{debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::fmt;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use tokio::{sync::broadcast, sync::RwLock, time::sleep};
use types::{ChainSpec, EthSpec};

/// The number of seconds *prior* to slot start that we will try and update the state of fallback
/// nodes.
///
/// Ideally this should be somewhere between 2/3rds through the slot and the end of it. If we set it
/// too early, we risk switching nodes between the time of publishing an attestation and publishing
/// an aggregate; this may result in a missed aggregation. If we set this time too late, we risk not
/// having the correct nodes up and running prior to the start of the slot.
const SLOT_LOOKAHEAD: Duration = Duration::from_secs(1);

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
            beacon_nodes.update_unready_candidates().await;

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

pub fn start_event_stream_tasks<T: SlotClock + 'static, E: EthSpec>(
    context: RuntimeContext<E>,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
) -> Result<(), &'static str> {
    let executor = context.executor;
    if beacon_nodes.slot_clock.is_none() {
        return Err("Cannot start event manager service without slot clock");
    }

    for candidate_index in 0..beacon_nodes.candidates.len() {
        let beacon_nodes = beacon_nodes.clone();
        let future = |beacon_nodes: Arc<BeaconNodeFallback<T, E>>| async move {
            'outer: loop {
                let beacon_nodes = beacon_nodes.clone();
                let candidate = match beacon_nodes.candidates.get(candidate_index) {
                    Some(candidate) => candidate,
                    None => {
                        warn!(
                            beacon_nodes.log,
                            "Invalid fallback candidate index, this candidate will not be retried"
                        );
                        break 'outer;
                    }
                };

                if candidate.status(RequireSynced::Yes).await.is_ok() {
                    info!(
                        beacon_nodes.log,
                        "Opening events stream connection with beacon node {}", candidate_index
                    );
                    if let Ok(stream) = candidate
                        .beacon_node
                        .get_events::<E>(&[EventTopic::Head])
                        .await
                    {
                        pin_mut!(stream);
                        'inner: while let Some(event) = stream.next().await {
                            match event {
                                Ok(EventKind::Head(head)) => {
                                    let current_slot = if let Some(slot) = beacon_nodes
                                        .slot_clock
                                        .as_ref()
                                        .and_then(|clock| clock.now())
                                    {
                                        slot
                                    } else {
                                        continue 'inner;
                                    };

                                    let primary = *beacon_nodes.primary_candidate.read().await;
                                    if let Some(primary_index) = primary {
                                        if primary_index == candidate_index
                                            && current_slot == head.slot
                                        {
                                            if let Err(e) = beacon_nodes.tx.send(head.block) {
                                                warn!(beacon_nodes.log, "Unable to send head event to attestation and sync committee services"; "error" => ?e);
                                                continue 'inner;
                                            }
                                        }
                                    }
                                }
                                Ok(event) => {
                                    warn!(beacon_nodes.log, "Invalid event received from beacon node"; "event"=>?event, "candidate_index"=> candidate_index)
                                }
                                Err(e) => {
                                    warn!(beacon_nodes.log, "Error received in event stream from beacon node"; "e"=>?e,  "candidate_index"=> candidate_index)
                                }
                            }
                        }
                        info!(
                            beacon_nodes.log,
                            "End of event stream connection with beacon node {}", candidate_index
                        );
                    }
                }

                // Retry at the start of the next slot
                let sleep_time = beacon_nodes
                    .slot_clock
                    .as_ref()
                    .and_then(|slot_clock| {
                        let slot = slot_clock.now()?;
                        slot_clock.duration_to_slot(slot + 1)
                    })
                    .unwrap_or_else(|| Duration::from_secs(1));
                sleep(sleep_time).await
            }
        };
        executor.spawn(future(beacon_nodes), "event_stream_manager_{}");
    }

    Ok(())
}

/// Indicates if a beacon node must be synced before some action is performed on it.
#[derive(PartialEq, Clone, Copy)]
pub enum RequireSynced {
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
pub enum Error<E> {
    /// The node was unavailable and we didn't attempt to contact it.
    Unavailable(CandidateError),
    /// We attempted to contact the node but it failed.
    RequestFailed(E),
}

impl<E> Error<E> {
    pub fn request_failure(&self) -> Option<&E> {
        match self {
            Error::RequestFailed(e) => Some(e),
            _ => None,
        }
    }
}

/// The list of errors encountered whilst attempting to perform a query.
pub struct AllErrored<E>(pub Vec<(String, Error<E>)>);

impl<E: Debug> fmt::Display for AllErrored<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "All endpoints failed")?;
        for (i, (id, error)) in self.0.iter().enumerate() {
            let comma = if i + 1 < self.0.len() { "," } else { "" };

            write!(f, " {} => {:?}{}", id, error, comma)?;
        }
        Ok(())
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
    id: usize,
    beacon_node: BeaconNodeHttpClient,
    status: RwLock<Result<(), CandidateError>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> CandidateBeaconNode<E> {
    /// Instantiate a new node.
    pub fn new(id: usize, beacon_node: BeaconNodeHttpClient) -> Self {
        Self {
            id,
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
        let mut status = self.status.write().await;

        if let Err(e) = self.is_online(log).await {
            info!(log, "not online"; "e" => ?e );
            *status = Err(e);
        } else if let Err(e) = self.is_compatible(spec, log).await {
            info!(log, "not compatible"; "e" => ?e );
            *status = Err(e);
        } else if let Err(e) = self.is_synced(slot_clock, log).await {
            info!(log, "not synced"; "e" => ?e );
            *status = Err(e);
        } else {
            *status = Ok(())
        }

        *status
    }

    /// Checks if the node is reachable.
    async fn is_online(&self, log: &Logger) -> Result<(), CandidateError> {
        let result = self
            .beacon_node
            .get_node_version()
            .await
            .map(|body| body.data.version);

        match result {
            Ok(version) => {
                info!(
                    log,
                    "Connected to beacon node";
                    "version" => version,
                    "endpoint" => %self.beacon_node,
                );
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
        let config_and_preset = self
            .beacon_node
            .get_config_spec()
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

        let beacon_node_spec =
            ChainSpec::from_config::<E>(&config_and_preset.config).ok_or_else(|| {
                error!(
                    log,
                    "The minimal/mainnet spec type of the beacon node does not match the validator \
                    client. See the --network command.";
                    "endpoint" => %self.beacon_node,
                );
                CandidateError::Incompatible
            })?;

        if !config_and_preset.extra_fields.is_empty() {
            debug!(
                log,
                "Beacon spec includes unknown fields";
                "endpoint" => %self.beacon_node,
                "fields" => ?config_and_preset.extra_fields,
            );
        }

        if *spec == beacon_node_spec {
            Ok(())
        } else {
            error!(
                log,
                "The beacon node is using a different Eth2 specification to this validator client. \
                See the --network command.";
                "endpoint" => %self.beacon_node,
            );
            Err(CandidateError::Incompatible)
        }
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
pub struct BeaconNodeFallback<T, E: EthSpec> {
    candidates: Vec<CandidateBeaconNode<E>>,
    primary_candidate: RwLock<Option<usize>>,
    tx: broadcast::Sender<Hash256>,
    slot_clock: Option<T>,
    spec: ChainSpec,
    log: Logger,
}

impl<T: SlotClock, E: EthSpec> BeaconNodeFallback<T, E> {
    pub fn new(candidates: Vec<CandidateBeaconNode<E>>, spec: ChainSpec, log: Logger) -> Self {
        let (tx, _) = broadcast::channel(10);
        Self {
            candidates,
            primary_candidate: RwLock::new(None),
            tx,
            slot_clock: None,
            spec,
            log,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Hash256> {
        self.tx.subscribe()
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

    /// Loop through any `self.candidates` that we don't think are online, compatible or synced and
    /// poll them to see if their status has changed.
    ///
    /// We do not poll nodes that are synced to avoid sending additional requests when everything is
    /// going smoothly.
    pub async fn update_unready_candidates(&self) {
        let initial_primary_candidate = *self.primary_candidate.read().await;

        let mut futures = Vec::new();
        for candidate in &self.candidates {
            // There is a potential race condition between having the read lock and the write
            // lock. The worst case of this race is running `try_become_ready` twice, which is
            // acceptable.
            //
            // Note: `RequireSynced` is always set to false here. This forces us to recheck the sync
            // status of nodes that were previously not-synced.
            if candidate.status(RequireSynced::Yes).await.is_err() {
                // There exists a race-condition that could result in `refresh_status` being called
                // when the status does not require refreshing anymore. This deemed is an
                // acceptable inefficiency.
                futures.push(candidate.refresh_status(
                    self.slot_clock.as_ref(),
                    &self.spec,
                    &self.log,
                ));
            }
        }

        //run all updates concurrently and ignore results
        let _ = future::join_all(futures).await;

        // Update the `primary_candidate` if it has changed
        for candidate in &self.candidates {
            let should_update = initial_primary_candidate.map_or(true, |initial_candidate_id| {
                initial_candidate_id != candidate.id
            });
            if candidate.status(RequireSynced::Yes).await.is_ok() && should_update {
                *self.primary_candidate.write().await = Some(candidate.id);
                break;
            }
        }
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
        func: F,
    ) -> Result<O, AllErrored<Err>>
    where
        F: Fn(&'a BeaconNodeHttpClient) -> R,
        R: Future<Output = Result<O, Err>>,
    {
        let mut errors = vec![];
        let mut to_retry = vec![];
        let mut retry_unsynced = vec![];

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
                        // If we have an error on this function, make the client as not-ready.
                        //
                        // There exists a race condition where the candidate may have been marked
                        // as ready between the `func` call and now. We deem this an acceptable
                        // inefficiency.
                        $candidate.set_offline().await;
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
        Err(AllErrored(errors))
    }
}

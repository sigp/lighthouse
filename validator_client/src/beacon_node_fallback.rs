use crate::check_synced::check_synced;
use crate::http_metrics::metrics::{inc_counter_vec, ENDPOINT_ERRORS, ENDPOINT_REQUESTS};
use environment::RuntimeContext;
use eth2::BeaconNodeHttpClient;
use slog::{error, info, Logger};
use slot_clock::SlotClock;
use std::fmt;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use tokio::{sync::RwLock, time::sleep};
use types::{ChainSpec, EthSpec};

const SLOT_LOOKAHEAD: Duration = Duration::from_secs(1);

pub fn start_fallback_updater_service<T: SlotClock + 'static, E: EthSpec>(
    context: RuntimeContext<E>,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
) -> Result<(), &'static str> {
    let executor = context.executor.clone();
    if beacon_nodes.slot_clock.is_none() {
        return Err("Cannot start fallback updater without slot clock");
    }

    let future = async move {
        loop {
            // We don't care about the outcome of this function.
            let _ = beacon_nodes.update_unready_candidates().await;

            let sleep_time = beacon_nodes
                .slot_clock
                .as_ref()
                .and_then(|slot_clock| {
                    let slot = slot_clock.now()?;
                    let till_next_slot = slot_clock.duration_to_slot(slot + 1)?;

                    till_next_slot.checked_sub(SLOT_LOOKAHEAD)
                })
                .unwrap_or(Duration::from_secs(1));

            sleep(sleep_time).await
        }
    };

    executor.spawn(future, "fallback");

    Ok(())
}

#[derive(PartialEq, Clone, Copy)]
pub enum RequireSynced {
    Yes,
    No,
}

pub struct AllErrored<E>(pub Vec<(String, E)>);

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

#[derive(Debug, Clone, Copy)]
pub enum CandidateError {
    Uninitialized,
    Offline,
    Incompatible,
    NotSynced,
}

pub struct CandidateBeaconNode<E> {
    beacon_node: BeaconNodeHttpClient,
    status: RwLock<Result<(), CandidateError>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> CandidateBeaconNode<E> {
    pub fn new(beacon_node: BeaconNodeHttpClient) -> Self {
        Self {
            beacon_node,
            status: RwLock::new(Err(CandidateError::Uninitialized)),
            _phantom: PhantomData,
        }
    }

    pub async fn is_ready(&self, synced: RequireSynced) -> bool {
        match *self.status.read().await {
            Ok(()) => true,
            Err(CandidateError::NotSynced) if synced == RequireSynced::No => true,
            _ => false,
        }
    }

    pub async fn set_offline(&self) {
        *self.status.write().await = Err(CandidateError::Offline)
    }

    pub async fn refresh_status<T: SlotClock>(
        &self,
        slot_clock: Option<&T>,
        spec: &ChainSpec,
        log: &Logger,
    ) -> Result<(), CandidateError> {
        let mut status = self.status.write().await;

        if let Err(e) = self.is_online(log).await {
            *status = Err(e);
        } else if let Err(e) = self.is_compatible(spec, log).await {
            *status = Err(e);
        } else if let Err(e) = self.is_synced(slot_clock, log).await {
            *status = Err(e);
        } else {
            *status = Ok(())
        }

        *status
    }

    async fn is_online(&self, log: &Logger) -> Result<(), CandidateError> {
        let result = self
            .beacon_node
            .get_node_version()
            .await
            .map_err(|e| format!("{:?}", e))
            .map(|body| body.data.version);

        match result {
            Ok(version) => {
                info!(
                    log,
                    "Connected to beacon node";
                    "endpoint" => %self.beacon_node,
                    "version" => version,
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    log,
                    "Unable to connect to beacon node";
                    "endpoint" => %self.beacon_node,
                    "error" => e,
                );
                Err(CandidateError::Offline)
            }
        }
    }

    async fn is_compatible(&self, spec: &ChainSpec, log: &Logger) -> Result<(), CandidateError> {
        let yaml_config = self
            .beacon_node
            .get_config_spec()
            .await
            .map_err(|e| {
                error!(
                    log,
                    "Unable to read spec from beacon node";
                    "endpoint" => %self.beacon_node,
                    "error" => ?e,
                );
                CandidateError::Offline
            })?
            .data;

        let beacon_node_spec = yaml_config
            .apply_to_chain_spec::<E>(&E::default_spec())
            .ok_or_else(|| {
                error!(
                    log,
                    "The minimal/mainnet spec type of the beacon node does not match the validator \
                    client. See the --network command.";
                    "endpoint" => %self.beacon_node,
                );
                CandidateError::Incompatible
            })?;

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
            match check_synced(&self.beacon_node, slot_clock, Some(log)).await {
                Ok(_) => Ok(()),
                Err(_) => Err(CandidateError::NotSynced),
            }
        } else {
            // Skip this check if we don't supply a slot clock.
            Ok(())
        }
    }
}

/// Holds possibly multiple beacon nodes structured as fallbacks. Before a beacon node is used the
/// first time it gets checked if it uses the same spec as the validator client.
pub struct BeaconNodeFallback<T, E> {
    candidates: Vec<CandidateBeaconNode<E>>,
    slot_clock: Option<T>,
    spec: ChainSpec,
    log: Logger,
}

impl<T: SlotClock, E: EthSpec> BeaconNodeFallback<T, E> {
    pub fn new(candidates: Vec<CandidateBeaconNode<E>>, spec: ChainSpec, log: Logger) -> Self {
        Self {
            candidates,
            slot_clock: None,
            spec,
            log,
        }
    }

    pub fn set_slot_clock(&mut self, slot_clock: T) {
        self.slot_clock = Some(slot_clock);
    }

    pub async fn num_total(&self) -> usize {
        self.candidates.len()
    }

    pub async fn num_synced(&self) -> usize {
        let mut n = 0;
        for candidate in &self.candidates {
            if candidate.is_ready(RequireSynced::Yes).await {
                n += 1
            }
        }
        n
    }

    pub async fn num_available(&self) -> usize {
        let mut n = 0;
        for candidate in &self.candidates {
            if candidate.is_ready(RequireSynced::No).await {
                n += 1
            }
        }
        n
    }

    pub async fn update_unready_candidates(&self) {
        for candidate in &self.candidates {
            // There is a potential race condition between having the read lock and the write
            // lock. The worst case of this race is running `try_become_ready` twice, which is
            // acceptable.
            //
            // Note: `is_ready` is always set to false here. This forces us to recheck the sync
            // status of nodes that were previously not-synced.
            if !candidate.is_ready(RequireSynced::Yes).await {
                // There exists a race-condition that could result in `refresh_status` being called
                // when the status does not require refreshing anymore. This deemed is an
                // acceptable inefficiency.
                let _ = candidate
                    .refresh_status(self.slot_clock.as_ref(), &self.spec, &self.log)
                    .await;
            }
        }
    }

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

        // First pass: try `func` on all ready candidates.
        for candidate in &self.candidates {
            if candidate.is_ready(require_synced).await {
                inc_counter_vec(&ENDPOINT_REQUESTS, &[candidate.beacon_node.as_ref()]);

                // There exists a race condition where `func` may be called when the candidate is
                // actually not ready. We deem this an acceptable inefficiency.
                match func(&candidate.beacon_node).await {
                    Ok(val) => return Ok(val),
                    Err(e) => {
                        // If we have an error on this function, make the client as not-ready.
                        //
                        // There exists a race condition where the candidate may have been marked
                        // as ready between the `func` call and now. We deem this an acceptable
                        // inefficiency.
                        candidate.set_offline().await;
                        errors.push((candidate.beacon_node.to_string(), e));
                        inc_counter_vec(&ENDPOINT_ERRORS, &[candidate.beacon_node.as_ref()]);
                    }
                }
            } else {
                // This client was not ready on the first pass, we might try it again later.
                to_retry.push(candidate);
            }
        }

        // Second pass: try again, attempting to make non-ready clients become ready.
        for candidate in to_retry {
            let became_ready = {
                candidate.is_ready(require_synced).await
                    || candidate
                        .refresh_status(self.slot_clock.as_ref(), &self.spec, &self.log)
                        .await
                        .is_ok()
            };

            if became_ready {
                inc_counter_vec(&ENDPOINT_REQUESTS, &[candidate.beacon_node.as_ref()]);

                // There exists a race condition where `func` may be called when the candidate is
                // actually not ready. We deem this an acceptable inefficiency.
                match func(&candidate.beacon_node).await {
                    Ok(val) => return Ok(val),
                    Err(e) => {
                        // If we have an error on this function, make the client as not-ready.
                        //
                        // There exists a race condition where the candidate may have been marked
                        // as ready between the `func` call and now. We deem this an acceptable
                        // inefficiency.
                        candidate.set_offline().await;
                        errors.push((candidate.beacon_node.to_string(), e));
                        inc_counter_vec(&ENDPOINT_ERRORS, &[candidate.beacon_node.as_ref()]);
                    }
                }
            }
        }

        // There were no candidates already ready and we were unable to make any of them ready.
        Err(AllErrored(errors))
    }
}

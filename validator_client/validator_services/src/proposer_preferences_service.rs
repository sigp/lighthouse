use crate::duties_service::DutiesService;
use beacon_node_fallback::BeaconNodeFallback;
use bls::PublicKeyBytes;
use eth2::types::ProposerData;
use futures::stream::FuturesUnordered;
use futures::{Future, Stream, StreamExt};
use parking_lot::Mutex;
use slot_clock::SlotClock;
use std::collections::HashSet;
use std::fmt::Debug;
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{Instrument, debug, error, info, info_span, warn};
use types::{
    ChainSpec, Epoch, EthSpec, ForkName, Hash256, ProposerPreferences, SignedProposerPreferences,
};
use validator_store::ValidatorStore;

/// Maximum number of concurrent preference publications per signing task. Must be greater than
/// one so a slow publication does not delay later ready signatures, while bounding the number
/// of simultaneous requests sent to the BN.
const MAX_CONCURRENT_PROPOSER_PREFERENCES_PUBLISHES: usize = 4;

pub struct Inner<S, T> {
    duties_service: Arc<DutiesService<S, T>>,
    validator_store: Arc<S>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    executor: TaskExecutor,
    chain_spec: Arc<ChainSpec>,
    /// `(epoch, dependent_root)` pairs with an in-flight or successfully published signing
    /// task. A task that fails to publish removes its entry so a later poll retries it.
    scheduled_preferences: Mutex<HashSet<(Epoch, Hash256)>>,
}

pub struct ProposerPreferencesService<S, T> {
    inner: Arc<Inner<S, T>>,
}

impl<S, T> Clone for ProposerPreferencesService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, T> Deref for ProposerPreferencesService<S, T> {
    type Target = Inner<S, T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<S: ValidatorStore + 'static, T: SlotClock + 'static> ProposerPreferencesService<S, T> {
    pub fn new(
        duties_service: Arc<DutiesService<S, T>>,
        validator_store: Arc<S>,
        slot_clock: T,
        beacon_nodes: Arc<BeaconNodeFallback<T>>,
        executor: TaskExecutor,
        chain_spec: Arc<ChainSpec>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                duties_service,
                validator_store,
                slot_clock,
                beacon_nodes,
                executor,
                chain_spec,
                scheduled_preferences: Mutex::new(HashSet::new()),
            }),
        }
    }

    pub fn start_update_service(self) -> Result<(), String> {
        let slot_duration = self.chain_spec.get_slot_duration();
        info!("Proposer preferences service started");

        let executor = self.executor.clone();

        let interval_fut = async move {
            loop {
                let Some(current_slot) = self.slot_clock.now() else {
                    error!("Failed to read slot clock");
                    sleep(slot_duration).await;
                    continue;
                };

                let current_epoch = current_slot.epoch(S::E::slots_per_epoch());

                self.poll_and_schedule_preferences(current_epoch);

                let duration_to_next_slot = self
                    .slot_clock
                    .duration_to_next_slot()
                    .unwrap_or(slot_duration);
                sleep(duration_to_next_slot).await;
            }
        };

        executor.spawn(interval_fut, "proposer_preferences_service");
        Ok(())
    }

    /// Schedule signing and publication of proposer preferences for the current and next epochs.
    ///
    /// At most one signing task per `(epoch, dependent_root)` runs at a time.
    fn poll_and_schedule_preferences(&self, current_epoch: Epoch) {
        for (epoch, fork_name) in [
            (
                current_epoch,
                self.chain_spec.fork_name_at_epoch(current_epoch),
            ),
            (
                current_epoch + 1,
                self.chain_spec.fork_name_at_epoch(current_epoch + 1),
            ),
        ] {
            if !fork_name.gloas_enabled() {
                continue;
            }

            let (dependent_root, duties) = {
                let proposers = self.duties_service.proposers.read();
                match proposers.get(&epoch) {
                    Some((root, duties)) => (*root, duties.clone()),
                    None => continue,
                }
            };

            if self
                .scheduled_preferences
                .lock()
                .contains(&(epoch, dependent_root))
            {
                continue;
            }

            if let Some(task) =
                self.proposer_preferences_task(epoch, fork_name, dependent_root, duties)
            {
                self.scheduled_preferences
                    .lock()
                    .insert((epoch, dependent_root));
                self.executor
                    .spawn(task, "sign_and_publish_proposer_preferences");
            }
        }

        self.scheduled_preferences
            .lock()
            .retain(|(epoch, _)| *epoch >= current_epoch);
    }

    /// Build a task that signs each duty's preferences concurrently and publishes signatures
    /// as they become ready, so one slow signer cannot delay the others. Returns `None` when
    /// there is nothing to sign. The task removes its `scheduled_preferences` entry if
    /// publication fails, so a later poll retries it.
    fn proposer_preferences_task(
        &self,
        epoch: Epoch,
        fork_name: ForkName,
        dependent_root: Hash256,
        duties: Vec<ProposerData>,
    ) -> Option<impl Future<Output = ()> + Send + 'static + use<S, T>> {
        let preferences_to_sign: Vec<_> = {
            let mut result = vec![];
            for duty in duties {
                let Some(proposal_data) = self.validator_store.proposal_data(&duty.pubkey) else {
                    warn!(
                        validator = ?duty.pubkey,
                        "Missing proposal data for proposer preferences"
                    );
                    continue;
                };
                let Some(fee_recipient) = proposal_data.fee_recipient else {
                    warn!(
                        validator = ?duty.pubkey,
                        "Missing fee recipient for proposer preferences"
                    );
                    continue;
                };
                result.push((
                    duty.pubkey,
                    ProposerPreferences {
                        dependent_root,
                        proposal_slot: duty.slot,
                        validator_index: duty.validator_index,
                        fee_recipient,
                        target_gas_limit: proposal_data.gas_limit,
                    },
                ));
            }
            result
        };

        // Returning None leaves the pair unscheduled so the next slot's poll can retry.
        if preferences_to_sign.is_empty() {
            return None;
        }

        let count = preferences_to_sign.len();
        debug!(
            %epoch,
            ?dependent_root,
            count,
            "Scheduling proposer preferences signing"
        );

        let service = self.clone();
        let task = async move {
            let validator_store = service.validator_store.clone();
            let signing_futures = preferences_to_sign
                .into_iter()
                .map(move |(pubkey, preferences)| {
                    let validator_store = validator_store.clone();
                    async move {
                        let result = validator_store
                            .sign_proposer_preferences(pubkey, preferences)
                            .await;
                        (pubkey, result)
                    }
                })
                .collect::<FuturesUnordered<_>>();

            let publish_results =
                sign_and_publish_proposer_preferences(signing_futures, count, |signed| {
                    publish_proposer_preferences_batch(
                        service.beacon_nodes.clone(),
                        epoch,
                        fork_name,
                        signed,
                    )
                })
                .await;

            // Retry on a later poll if any chunk failed to publish or nothing was published.
            if publish_results.is_empty() || publish_results.iter().any(Result::is_err) {
                service
                    .scheduled_preferences
                    .lock()
                    .remove(&(epoch, dependent_root));
            }
        }
        .instrument(info_span!(
            "sign_and_publish_proposer_preferences",
            %epoch,
            ?dependent_root
        ));

        Some(task)
    }
}

/// Publish signatures in ready chunks as signing futures complete, so a slow signer does not
/// block signatures that are ready. Signing failures are logged and dropped. Returns one
/// result per attempted chunk publication. `max_batch_size` must be non-zero.
async fn sign_and_publish_proposer_preferences<St, E, P, PFut>(
    signing_results: St,
    max_batch_size: usize,
    mut publish_batch: P,
) -> Vec<Result<(), String>>
where
    St: Stream<Item = (PublicKeyBytes, Result<SignedProposerPreferences, E>)>,
    E: Debug,
    P: FnMut(Vec<SignedProposerPreferences>) -> PFut,
    PFut: Future<Output = Result<(), String>>,
{
    signing_results
        .filter_map(|(pubkey, result)| async move {
            match result {
                Ok(signed) => Some(signed),
                Err(e) => {
                    error!(
                        error = ?e,
                        validator = ?pubkey,
                        "Failed to sign proposer preferences"
                    );
                    None
                }
            }
        })
        .ready_chunks(max_batch_size)
        .map(|signed| {
            let publish = publish_batch(signed);
            async move {
                let result = publish.await;
                if let Err(e) = &result {
                    error!(error = %e, "Failed to publish proposer preferences");
                }
                result
            }
        })
        .buffer_unordered(MAX_CONCURRENT_PROPOSER_PREFERENCES_PUBLISHES)
        .collect()
        .await
}

async fn publish_proposer_preferences_batch<T: SlotClock + 'static>(
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    epoch: Epoch,
    fork_name: ForkName,
    signed: Vec<SignedProposerPreferences>,
) -> Result<(), String> {
    let count = signed.len();
    let signed = Arc::new(signed);
    let result = beacon_nodes
        .first_success(|beacon_node| {
            let signed = signed.clone();
            async move {
                beacon_node
                    .post_validator_proposer_preferences_ssz(&signed, fork_name)
                    .await
                    .map_err(|e| format!("Failed to publish proposer preferences (SSZ): {e:?}"))
            }
        })
        .await;

    let result = match result {
        Ok(()) => Ok(()),
        Err(ssz_err) => {
            debug!(error = %ssz_err, "SSZ publish failed, falling back to JSON");
            beacon_nodes
                .first_success(|beacon_node| {
                    let signed = signed.clone();
                    async move {
                        beacon_node
                            .post_validator_proposer_preferences(&signed, fork_name)
                            .await
                            .map_err(|e| {
                                format!("Failed to publish proposer preferences (JSON): {e:?}")
                            })
                    }
                })
                .await
        }
    };

    if result.is_ok() {
        info!(
            %epoch,
            %count,
            "Successfully published proposer preferences"
        );
    }
    result.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use futures::future::{BoxFuture, Ready, pending, ready};
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::time::timeout;

    type SigningResult = (
        PublicKeyBytes,
        Result<SignedProposerPreferences, &'static str>,
    );

    fn signed_preferences(validator_index: u64) -> SignedProposerPreferences {
        let mut preferences = SignedProposerPreferences::empty();
        preferences.message.validator_index = validator_index;
        preferences
    }

    fn ok_signer(validator_index: u64) -> BoxFuture<'static, SigningResult> {
        ready((
            PublicKeyBytes::empty(),
            Ok(signed_preferences(validator_index)),
        ))
        .boxed()
    }

    fn failed_signer() -> BoxFuture<'static, SigningResult> {
        ready((PublicKeyBytes::empty(), Err("signing failed"))).boxed()
    }

    fn validator_indices(signed: Vec<SignedProposerPreferences>) -> Vec<u64> {
        signed
            .into_iter()
            .map(|preferences| preferences.message.validator_index)
            .collect()
    }

    fn record_publish(
        published: &Arc<Mutex<Vec<Vec<u64>>>>,
    ) -> impl FnMut(Vec<SignedProposerPreferences>) -> Ready<Result<(), String>> {
        let published = published.clone();
        move |signed| {
            published.lock().unwrap().push(validator_indices(signed));
            ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn slow_signer_does_not_block_ready_siblings() {
        let published = Arc::new(Mutex::new(Vec::new()));
        let signing_futures: FuturesUnordered<BoxFuture<'static, SigningResult>> =
            [pending().boxed(), failed_signer(), ok_signer(2)]
                .into_iter()
                .collect();

        let drain =
            sign_and_publish_proposer_preferences(signing_futures, 3, record_publish(&published));

        // The pending signer keeps the drain alive, but the ready signature must still publish.
        assert!(timeout(Duration::from_millis(50), drain).await.is_err());
        assert_eq!(*published.lock().unwrap(), vec![vec![2]]);
    }

    #[tokio::test]
    async fn all_ready_signers_publish_as_single_batch() {
        let published = Arc::new(Mutex::new(Vec::new()));
        let signing_futures: FuturesUnordered<BoxFuture<'static, SigningResult>> =
            (0..5).map(ok_signer).collect();

        let publish_results =
            sign_and_publish_proposer_preferences(signing_futures, 5, record_publish(&published))
                .await;

        assert_eq!(publish_results, vec![Ok(())]);
        let published = published.lock().unwrap();
        assert_eq!(published.len(), 1);
        let mut indices = published[0].clone();
        indices.sort_unstable();
        assert_eq!(indices, vec![0, 1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn reports_failed_or_missing_publications() {
        // A failed publish surfaces in the results, so the service can retry on a later poll.
        let signing_futures: FuturesUnordered<BoxFuture<'static, SigningResult>> =
            [ok_signer(1)].into_iter().collect();
        let publish_results = sign_and_publish_proposer_preferences(signing_futures, 1, |_| {
            ready(Err("beacon nodes unavailable".to_string()))
        })
        .await;
        assert_eq!(
            publish_results,
            vec![Err("beacon nodes unavailable".to_string())]
        );

        // Nothing published (every signer failed) yields no results.
        let published = Arc::new(Mutex::new(Vec::new()));
        let signing_futures: FuturesUnordered<BoxFuture<'static, SigningResult>> =
            [failed_signer()].into_iter().collect();
        let publish_results =
            sign_and_publish_proposer_preferences(signing_futures, 1, record_publish(&published))
                .await;
        assert!(publish_results.is_empty());
        assert!(published.lock().unwrap().is_empty());
    }

    #[derive(Default)]
    struct PublishTracker {
        in_flight: usize,
        max_in_flight: usize,
        completed: Vec<u64>,
    }

    #[tokio::test(start_paused = true)]
    async fn slow_publication_does_not_block_later_chunks() {
        let tracker = Arc::new(Mutex::new(PublishTracker::default()));

        // Staggered completions make `ready_chunks` yield multiple chunks.
        let signing_futures: FuturesUnordered<BoxFuture<'static, SigningResult>> = (0..6)
            .map(|validator_index| {
                async move {
                    sleep(Duration::from_millis(10 * (validator_index + 1))).await;
                    (
                        PublicKeyBytes::empty(),
                        Ok(signed_preferences(validator_index)),
                    )
                }
                .boxed()
            })
            .collect();

        let publish_batch = {
            let tracker = tracker.clone();
            move |signed: Vec<SignedProposerPreferences>| {
                let tracker = tracker.clone();
                let indices = validator_indices(signed);
                async move {
                    {
                        let mut tracker = tracker.lock().unwrap();
                        tracker.in_flight += 1;
                        tracker.max_in_flight = tracker.max_in_flight.max(tracker.in_flight);
                    }
                    // Validator 0's publication never resolves.
                    if indices.contains(&0) {
                        pending::<()>().await;
                    }
                    sleep(Duration::from_millis(100)).await;
                    let mut tracker = tracker.lock().unwrap();
                    tracker.in_flight -= 1;
                    tracker.completed.extend(indices);
                    Ok(())
                }
                .boxed()
            }
        };

        let drain = sign_and_publish_proposer_preferences(signing_futures, 6, publish_batch);

        // The stuck publication keeps the drain alive, but later chunks must still publish.
        assert!(timeout(Duration::from_secs(60), drain).await.is_err());

        let tracker = tracker.lock().unwrap();
        let mut completed = tracker.completed.clone();
        completed.sort_unstable();
        assert_eq!(completed, vec![1, 2, 3, 4, 5]);
        assert_eq!(
            tracker.max_in_flight,
            MAX_CONCURRENT_PROPOSER_PREFERENCES_PUBLISHES
        );
    }
}

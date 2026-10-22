use crate::duties_service::DutiesService;
use crate::request_auth_cache::RequestAuthCache;
use beacon_node_fallback::BeaconNodeFallback;
use bls::PublicKeyBytes;
use builder_store::BuilderStore;
use builder_types::{BuilderEntry, BuilderUrl, RequestAuthData};
use eth2::Error as BeaconNodeError;
use eth2::types::{
    BuilderPreferenceEntry, IndexedErrorMessage, MAX_SUBMITTED_BUILDER_PREFERENCES,
    SubmittedBuilderPreferences,
};
use reqwest::{Response, StatusCode};
use slot_clock::SlotClock;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, info};
use types::{ChainSpec, EthSpec, ForkName, Slot};
use validator_metrics::{ENDPOINT_ERRORS, ENDPOINT_REQUESTS, inc_counter_vec};
use validator_store::ValidatorStore;

/// Identifies a builder preference within one proposal slot.
#[derive(PartialEq, Eq, Hash)]
struct InnerPreferencesKey {
    pubkey: PublicKeyBytes,
    url: BuilderUrl,
    auth_data: RequestAuthData,
}

/// Tracks the last execution payment cap published for each slot, proposer, URL and auth data.
///
/// A changed cap replaces the previous value, so restoring an earlier configuration publishes it
/// again. The signature is determined by the proposer, auth data and slot, so it adds no identity.
#[derive(Default)]
struct PublishedBuilderPreferencesCache {
    cache: BTreeMap<Slot, HashMap<InnerPreferencesKey, u64>>,
}

impl PublishedBuilderPreferencesCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(
        &self,
        slot: Slot,
        pubkey: PublicKeyBytes,
        builder_entry: &BuilderEntry,
    ) -> bool {
        self.cache.get(&slot).is_some_and(|entries| {
            entries.get(&InnerPreferencesKey {
                pubkey,
                url: builder_entry.url.clone(),
                auth_data: builder_entry.auth.message.data.clone(),
            }) == Some(&builder_entry.max_execution_payment)
        })
    }

    pub fn forget(&mut self, entry: &BuilderPreferenceEntry) {
        if let Some(entries) = self.cache.get_mut(&entry.auth.message.slot) {
            entries.remove(&InnerPreferencesKey {
                pubkey: entry.proposer_pubkey,
                url: entry.url.clone(),
                auth_data: entry.auth.message.data.clone(),
            });
        }
    }

    pub fn mark_sent(
        &mut self,
        pubkey: PublicKeyBytes,
        builder_preferences_entry: BuilderPreferenceEntry,
    ) {
        let slot = builder_preferences_entry.auth.message.slot;
        let inner_key = InnerPreferencesKey {
            pubkey,
            url: builder_preferences_entry.url,
            auth_data: builder_preferences_entry.auth.message.data,
        };
        self.cache
            .entry(slot)
            .or_default()
            .insert(inner_key, builder_preferences_entry.max_execution_payment);
    }

    pub fn prune(&mut self, current_slot: Slot) {
        self.cache = self.cache.split_off(&current_slot);
    }
}

// Minimizes `Arc` usage
struct Inner<S, T> {
    duties_service: Arc<DutiesService<S, T>>,
    validator_store: Arc<S>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    configured_builders: BuilderStore,
    request_auth_cache: RequestAuthCache,
    executor: TaskExecutor,
    chain_spec: Arc<ChainSpec>,
}

pub struct BuilderPreferencesService<S, T> {
    inner: Arc<Inner<S, T>>,
}

// Generic clone implementation is too dumb to do this
impl<S, T> Clone for BuilderPreferencesService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S: ValidatorStore + 'static, T: SlotClock + 'static> BuilderPreferencesService<S, T> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        duties_service: Arc<DutiesService<S, T>>,
        validator_store: Arc<S>,
        slot_clock: T,
        beacon_nodes: Arc<BeaconNodeFallback<T>>,
        configured_builders: BuilderStore,
        request_auth_cache: RequestAuthCache,
        executor: TaskExecutor,
        chain_spec: Arc<ChainSpec>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                duties_service,
                validator_store,
                slot_clock,
                beacon_nodes,
                configured_builders,
                request_auth_cache,
                executor,
                chain_spec,
            }),
        }
    }

    pub fn start_update_service(self) -> Result<(), String> {
        let slot_duration = self.inner.chain_spec.get_slot_duration();
        info!("Builder preferences service started");

        let executor = self.inner.executor.clone();

        let interval_fut = async move {
            let mut published_preferences = PublishedBuilderPreferencesCache::new();

            loop {
                let Some(current_slot) = self.inner.slot_clock.now() else {
                    error!("Failed to read slot clock");
                    sleep(slot_duration).await;
                    continue;
                };

                self.poll_and_publish_preferences(current_slot, &mut published_preferences)
                    .await;

                published_preferences.prune(current_slot);
                self.inner.request_auth_cache.prune(current_slot);

                let duration_to_next_slot = self
                    .inner
                    .slot_clock
                    .duration_to_next_slot()
                    .unwrap_or(slot_duration);
                sleep(duration_to_next_slot).await;
            }
        };

        executor.spawn(interval_fut, "builder_preferences_service");
        Ok(())
    }

    /// Publish builder preferences for `current_epoch` and `current_epoch + 1`.
    /// Skips a builder preference when its execution payment cap has not changed.
    async fn poll_and_publish_preferences(
        &self,
        current_slot: Slot,
        published_preferences: &mut PublishedBuilderPreferencesCache,
    ) {
        let current_epoch = current_slot.epoch(S::E::slots_per_epoch());
        // Entries are grouped by the fork of the epoch their proposal slot falls in, and each
        // group is submitted under that fork's `Eth-Consensus-Version`: the header names the fork
        // the preferences belong to (beacon-APIs #630), and builders decode the forwarded
        // submission by it (builder-specs #165), so lookahead entries gathered in the epoch
        // before a fork go out under the new fork, not the one active at submission time —
        // matching the proposer-preferences service's per-epoch publishing. Outside a
        // fork-boundary epoch both epochs share a fork, so this is still one flat request.
        let mut pending_groups: Vec<(ForkName, Vec<BuilderPreferenceEntry>)> = Vec::new();

        for (epoch, fork_name) in [
            (
                current_epoch,
                self.inner.chain_spec.fork_name_at_epoch(current_epoch),
            ),
            (
                current_epoch + 1,
                self.inner.chain_spec.fork_name_at_epoch(current_epoch + 1),
            ),
        ] {
            if !fork_name.gloas_enabled() {
                continue;
            }

            let proposers = match self.inner.duties_service.proposers.read().get(&epoch) {
                Some((_, proposers)) => proposers.clone(),
                None => continue,
            };

            let mut epoch_entries: Vec<BuilderPreferenceEntry> = Vec::new();
            for proposer_data in &proposers {
                let slot = proposer_data.slot;
                // A duty whose slot has passed is dead. The caches prune below `current_slot`
                // every poll, so without this guard each elapsed duty would be re-signed and
                // re-submitted (and rejected by builders) every remaining slot of its epoch —
                // and its failing chunk would keep every cohabiting entry unmarked.
                if slot < current_slot {
                    continue;
                }
                let pubkey = proposer_data.pubkey;

                // Resolve and sign the whole builder config for this proposer/slot. Auths are
                // cached, so builders already published for this slot cost only a cache hit.
                // Per-builder sign failures are logged and omitted inside `builder_config`, so a
                // fully-failed set just yields an empty `builders` list (nothing to publish).
                let config = self
                    .inner
                    .configured_builders
                    .builder_config(&pubkey, |auth_data| {
                        self.inner.request_auth_cache.get_or_sign(
                            slot,
                            pubkey,
                            auth_data,
                            |request_auth_v1| {
                                self.inner
                                    .validator_store
                                    .sign_request_auth_v1(pubkey, request_auth_v1)
                            },
                        )
                    })
                    .await;

                // A `BuilderPreferenceEntry` is a `BuilderEntry` narrowed to what a builder may see:
                // its private `min_bid`/`builder_boost_factor`/`builder_pubkeys` are dropped.
                for entry in config.builders.iter() {
                    if published_preferences.contains(slot, pubkey, entry) {
                        // already published, skip
                        continue;
                    }
                    epoch_entries.push(BuilderPreferenceEntry::from_builder_entry(
                        pubkey,
                        entry.clone(),
                    ));
                }
            }

            if epoch_entries.is_empty() {
                continue;
            }
            match pending_groups.last_mut() {
                Some((fork, entries)) if *fork == fork_name => entries.extend(epoch_entries),
                _ => pending_groups.push((fork_name, epoch_entries)),
            }
        }

        if pending_groups.is_empty() {
            return;
        }

        // One submission carries at most `MAX_SUBMITTED_BUILDER_PREFERENCES` entries (beacon-APIs
        // #630), so submit in bounded chunks. Each chunk is best-effort: a failed chunk is logged
        // and does not stop the rest.
        for (fork_name, pending_entries) in pending_groups {
            for chunk in pending_entries.chunks(MAX_SUBMITTED_BUILDER_PREFERENCES) {
                self.publish_chunk(
                    current_slot,
                    fork_name,
                    chunk.to_vec(),
                    published_preferences,
                )
                .await;
            }
        }
    }

    async fn publish_chunk(
        &self,
        poll_slot: Slot,
        fork_name: ForkName,
        mut pending_entries: Vec<BuilderPreferenceEntry>,
        published_preferences: &mut PublishedBuilderPreferencesCache,
    ) {
        let candidates = self.inner.beacon_nodes.candidates.read().await.clone();

        for candidate in candidates {
            let beacon_node = candidate.beacon_node;
            let mut use_json = false;
            let result = loop {
                let current_slot = self.inner.slot_clock.now().unwrap_or(poll_slot);
                pending_entries.retain(|entry| entry.auth.message.slot >= current_slot);
                if pending_entries.is_empty() {
                    return;
                }
                let Ok(entries) = SubmittedBuilderPreferences::new(pending_entries.clone()) else {
                    // Unreachable: the caller bounds each chunk, and retries only remove entries.
                    return;
                };

                // A failed request can still reach a builder. Forget the previous cap before sending
                // its replacement, so a later configuration change cannot suppress a needed update.
                for entry in entries.iter() {
                    published_preferences.forget(entry);
                }

                inc_counter_vec(&ENDPOINT_REQUESTS, &[beacon_node.server().redacted()]);
                let result = if use_json {
                    debug!(
                        endpoint = %beacon_node,
                        "Beacon node does not support SSZ builder preferences, falling back to JSON"
                    );
                    beacon_node
                        .post_validator_builder_preferences(&entries, fork_name)
                        .await
                } else {
                    beacon_node
                        .post_validator_builder_preferences_ssz(&entries, fork_name)
                        .await
                };
                if result
                    .as_ref()
                    .map_or(true, |response| !response.status().is_success())
                {
                    inc_counter_vec(&ENDPOINT_ERRORS, &[beacon_node.server().redacted()]);
                }

                if !use_json
                    && result.as_ref().is_ok_and(|response| {
                        response.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE
                    })
                {
                    use_json = true;
                } else {
                    break result;
                }
            };

            let status = result.as_ref().ok().map(Response::status);
            let result = match result {
                Ok(response) => eth2::success_or_error(response).await.map(|_| ()),
                Err(e) => Err(e),
            };

            match result {
                Ok(()) => {
                    for entry in pending_entries.drain(..) {
                        published_preferences.mark_sent(entry.proposer_pubkey, entry);
                    }
                    return;
                }
                Err(BeaconNodeError::ServerIndexedMessage(indexed_error))
                    if status == Some(StatusCode::BAD_REQUEST) =>
                {
                    let Some(failed_indices) =
                        valid_failure_indices(&indexed_error, pending_entries.len())
                    else {
                        error!(
                            endpoint = %beacon_node,
                            error = ?indexed_error,
                            "Beacon node returned invalid builder preference failure indices"
                        );
                        continue;
                    };

                    let mut failed_entries = Vec::with_capacity(failed_indices.len());
                    for (index, entry) in pending_entries.drain(..).enumerate() {
                        if failed_indices.contains(&index) {
                            failed_entries.push(entry);
                        } else {
                            published_preferences.mark_sent(entry.proposer_pubkey, entry);
                        }
                    }
                    pending_entries = failed_entries;
                }
                Err(e) => {
                    debug!(
                        endpoint = %beacon_node,
                        error = %e,
                        "Failed to publish builder preferences"
                    );
                }
            }
        }

        error!(
            remaining = pending_entries.len(),
            %fork_name,
            "Failed to publish builder preferences"
        );
    }
}

fn valid_failure_indices(
    error: &IndexedErrorMessage,
    entry_count: usize,
) -> Option<HashSet<usize>> {
    if error.failures.is_empty() {
        return None;
    }

    let mut indices = HashSet::with_capacity(error.failures.len());
    for failure in &error.failures {
        let index = usize::try_from(failure.index).ok()?;
        if index >= entry_count || !indices.insert(index) {
            return None;
        }
    }
    Some(indices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duties_service::DutiesServiceBuilder;
    use crate::request_auth_cache::RequestAuthCache;
    use builder_store::{BuilderDefinition, ValidatorBuilderConfig, ValidatorBuilderDefinition};
    use builder_types::BuilderUrl;
    use eth2::types::ProposerData;
    use std::str::FromStr;
    use types::{Epoch, ForkName};
    use validator_test_rig::validator_client_harness::{S, ValidatorClientHarness};

    const INDEXED_FAILURE_AT_INDEX_ONE: &str = r#"{
        "code": 1001,
        "message": "one entry failed",
        "failures": [{"index": 1, "message": "failed"}]
    }"#;
    const INDEXED_FAILURE_OUT_OF_BOUNDS: &str = r#"{
        "code": 400,
        "message": "invalid failure index",
        "failures": [{"index": 2, "message": "failed"}]
    }"#;
    const ERROR_BODY_500: &str = r#"{"code":500,"message":"server error"}"#;
    const ERROR_BODY_415: &str = r#"{"code":415,"message":"unsupported media type"}"#;

    #[test]
    fn empty_failure_indices_are_invalid() {
        let error = IndexedErrorMessage {
            code: StatusCode::BAD_REQUEST.as_u16(),
            message: "no failure indices".to_string(),
            failures: vec![],
        };

        assert!(valid_failure_indices(&error, 1).is_none());
    }

    struct TestHarness {
        harness: ValidatorClientHarness,
        service: BuilderPreferencesService<S, slot_clock::ManualSlotClock>,
    }

    impl TestHarness {
        async fn new(num_validators: usize, gloas_fork_epoch: Epoch) -> Self {
            let harness = ValidatorClientHarness::new(num_validators).await;
            let mut spec = (*harness.spec).clone();
            spec.gloas_fork_epoch = Some(gloas_fork_epoch);
            let spec = Arc::new(spec);

            let duties_service = Arc::new(
                DutiesServiceBuilder::new()
                    .validator_store(harness.validator_store.clone())
                    .slot_clock(harness.slot_clock.clone())
                    .beacon_nodes(harness.beacon_nodes.clone())
                    .executor(harness.test_runtime.task_executor.clone())
                    .spec(spec.clone())
                    .build()
                    .unwrap(),
            );
            let configured_builders =
                BuilderStore::open_or_create(harness._validator_dir.path()).unwrap();
            configured_builders
                .insert(BuilderDefinition {
                    enabled: true,
                    url: BuilderUrl::from_str("http://builder.example.com").unwrap(),
                    auth_data: None,
                    builder_pubkeys: vec![],
                    max_execution_payment: 1,
                    min_bid: None,
                    builder_boost_factor: None,
                })
                .unwrap();
            let service = BuilderPreferencesService::new(
                duties_service,
                harness.validator_store.clone(),
                harness.slot_clock.clone(),
                harness.beacon_nodes.clone(),
                configured_builders,
                RequestAuthCache::default(),
                harness.test_runtime.task_executor.clone(),
                spec,
            );

            Self { harness, service }
        }

        fn set_slot(&self, slot: Slot) {
            self.harness.slot_clock.set_slot(slot.as_u64());
        }

        fn insert_duties(&self, epoch: Epoch, duties: Vec<(usize, Slot)>) {
            let proposers = duties
                .into_iter()
                .map(|(validator_index, slot)| ProposerData {
                    pubkey: self.harness.pubkeys[validator_index],
                    validator_index: validator_index as u64,
                    slot,
                })
                .collect();
            self.service
                .inner
                .duties_service
                .proposers
                .write()
                .insert(epoch, (Default::default(), proposers));
        }

        fn received_slots(&self, beacon_node: usize) -> Vec<Vec<Slot>> {
            let received = match beacon_node {
                1 => &self.harness.mock_beacon_node_1.builder_preferences,
                2 => &self.harness.mock_beacon_node_2.builder_preferences,
                _ => panic!("unknown beacon node"),
            };
            received
                .lock()
                .unwrap()
                .iter()
                .map(|entries| {
                    entries
                        .iter()
                        .map(|entry| entry.auth.message.slot)
                        .collect()
                })
                .collect()
        }
    }

    #[tokio::test]
    async fn lookahead_entries_submit_under_their_epochs_fork() {
        let slots_per_epoch = <S as ValidatorStore>::E::slots_per_epoch();
        let gloas_epoch = Epoch::new(1);
        let current_slot = Slot::new(slots_per_epoch - 1);
        let first_gloas_slot = gloas_epoch.start_slot(slots_per_epoch);
        let mut test_harness = TestHarness::new(2, gloas_epoch).await;
        test_harness.set_slot(current_slot);
        test_harness.insert_duties(Epoch::new(0), vec![(0, current_slot)]);
        test_harness.insert_duties(gloas_epoch, vec![(1, first_gloas_slot)]);

        let mock = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas, 200, "");
        let other_fork = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_any_fork();
        let mut published = PublishedBuilderPreferencesCache::new();
        test_harness
            .service
            .poll_and_publish_preferences(current_slot, &mut published)
            .await;

        mock.expect(1).assert();
        other_fork.expect(0).assert();
        assert_eq!(test_harness.received_slots(1), vec![vec![first_gloas_slot]]);
    }

    #[tokio::test]
    async fn past_duties_are_skipped() {
        let current_slot = Slot::new(2);
        let mut test_harness = TestHarness::new(3, Epoch::new(0)).await;
        test_harness.set_slot(current_slot);
        test_harness.insert_duties(
            Epoch::new(0),
            vec![(0, Slot::new(1)), (1, current_slot), (2, Slot::new(3))],
        );

        let mock = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas, 200, "");
        let mut published = PublishedBuilderPreferencesCache::new();
        test_harness
            .service
            .poll_and_publish_preferences(current_slot, &mut published)
            .await;

        mock.expect(1).assert();
        assert_eq!(
            test_harness.received_slots(1),
            vec![vec![current_slot, Slot::new(3)]]
        );
    }

    #[tokio::test]
    async fn indexed_partial_failure_retries_only_failed_entries() {
        let current_slot = Slot::new(0);
        let mut test_harness = TestHarness::new(2, Epoch::new(0)).await;
        test_harness.insert_duties(Epoch::new(0), vec![(0, Slot::new(1)), (1, Slot::new(2))]);

        let first = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_ssz(
                ForkName::Gloas,
                400,
                INDEXED_FAILURE_AT_INDEX_ONE,
            );
        let second = test_harness
            .harness
            .mock_beacon_node_2
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas, 200, "");
        let mut published = PublishedBuilderPreferencesCache::new();
        test_harness
            .service
            .poll_and_publish_preferences(current_slot, &mut published)
            .await;
        test_harness
            .service
            .poll_and_publish_preferences(current_slot, &mut published)
            .await;

        first.expect(1).assert();
        second.expect(1).assert();
        assert_eq!(test_harness.received_slots(2), vec![vec![Slot::new(2)]]);
    }

    #[tokio::test]
    async fn invalid_partial_failure_retries_the_complete_batch() {
        for (status, body) in [
            (400, INDEXED_FAILURE_OUT_OF_BOUNDS),
            (500, INDEXED_FAILURE_AT_INDEX_ONE),
        ] {
            let current_slot = Slot::new(0);
            let mut test_harness = TestHarness::new(2, Epoch::new(0)).await;
            test_harness.insert_duties(Epoch::new(0), vec![(0, Slot::new(1)), (1, Slot::new(2))]);

            let first = test_harness
                .harness
                .mock_beacon_node_1
                .mock_post_validator_builder_preferences_ssz(ForkName::Gloas, status, body);
            let second = test_harness
                .harness
                .mock_beacon_node_2
                .mock_post_validator_builder_preferences_ssz(ForkName::Gloas, 200, "");
            let mut published = PublishedBuilderPreferencesCache::new();
            test_harness
                .service
                .poll_and_publish_preferences(current_slot, &mut published)
                .await;

            first.expect(1).assert();
            second.expect(1).assert();
            assert_eq!(
                test_harness.received_slots(2),
                vec![vec![Slot::new(1), Slot::new(2)]]
            );
        }
    }

    #[tokio::test]
    async fn each_beacon_node_is_tried_once_per_poll() {
        let current_slot = Slot::new(0);
        let mut test_harness = TestHarness::new(1, Epoch::new(0)).await;
        test_harness.insert_duties(Epoch::new(0), vec![(0, Slot::new(1))]);

        let first = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas, 500, ERROR_BODY_415);
        let json = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_json(ForkName::Gloas, 200, "");
        let second = test_harness
            .harness
            .mock_beacon_node_2
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas, 500, ERROR_BODY_500);
        let mut published = PublishedBuilderPreferencesCache::new();
        test_harness
            .service
            .poll_and_publish_preferences(current_slot, &mut published)
            .await;

        first.expect(1).assert();
        second.expect(1).assert();
        json.expect(0).assert();
    }

    #[tokio::test]
    async fn unsupported_ssz_fallback_drops_entries_that_passed() {
        let current_slot = Slot::new(0);
        let mut test_harness = TestHarness::new(2, Epoch::new(0)).await;
        test_harness.insert_duties(Epoch::new(0), vec![(0, current_slot), (1, Slot::new(1))]);

        let slot_clock = test_harness.harness.slot_clock.clone();
        let ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_ssz_with_hook(
                ForkName::Gloas,
                415,
                ERROR_BODY_500,
                move || slot_clock.advance_slot(),
            );
        let json = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_json(ForkName::Gloas, 200, "");
        let second_node = test_harness
            .harness
            .mock_beacon_node_2
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas, 500, ERROR_BODY_500);
        let mut published = PublishedBuilderPreferencesCache::new();
        test_harness
            .service
            .poll_and_publish_preferences(current_slot, &mut published)
            .await;

        ssz.expect(1).assert();
        json.expect(1).assert();
        second_node.expect(0).assert();
        assert_eq!(
            test_harness.received_slots(1),
            vec![vec![current_slot, Slot::new(1)], vec![Slot::new(1)]]
        );
    }

    #[tokio::test]
    async fn builder_config_updates_apply_to_upcoming_duties() {
        let mut test_harness = TestHarness::new(1, Epoch::new(0)).await;
        test_harness.set_slot(Slot::new(2));
        test_harness.insert_duties(Epoch::new(0), vec![(0, Slot::new(0)), (0, Slot::new(3))]);
        let service = &test_harness.service;
        let configured_builders = &service.inner.configured_builders;
        let mock = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas, 200, "");

        let mut published = PublishedBuilderPreferencesCache::new();
        // Poll from slot 2: the slot-0 duty has elapsed, the slot-3 duty has not.
        service
            .poll_and_publish_preferences(Slot::new(2), &mut published)
            .await;

        let validator_config = ValidatorBuilderConfig {
            builders: Some(vec![ValidatorBuilderDefinition {
                url: "http://builder.example.com".parse().unwrap(),
                auth_data: None,
                builder_pubkeys: vec![],
                max_execution_payment: Some(20),
                min_bid: None,
                builder_boost_factor: None,
            }]),
            ..Default::default()
        };
        configured_builders
            .set_validator_config(&test_harness.harness.pubkeys[0], validator_config.clone())
            .unwrap();
        service
            .poll_and_publish_preferences(Slot::new(2), &mut published)
            .await;

        configured_builders
            .delete_validator_config(&test_harness.harness.pubkeys[0])
            .unwrap();
        service
            .poll_and_publish_preferences(Slot::new(2), &mut published)
            .await;
        // An unchanged configuration must not trigger another submission.
        service
            .poll_and_publish_preferences(Slot::new(2), &mut published)
            .await;

        let mock = mock.expect(3);
        mock.assert();
        mock.remove();

        // A failed update must stay retryable and must not suppress a later restore.
        let failed_mock = mock.with_status(500).with_body("").expect(2).create();
        configured_builders
            .set_validator_config(&test_harness.harness.pubkeys[0], validator_config)
            .unwrap();
        for _ in 0..2 {
            service
                .poll_and_publish_preferences(Slot::new(2), &mut published)
                .await;
        }
        failed_mock.assert();
        failed_mock.remove();

        let restored_mock = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas, 200, "");
        configured_builders
            .delete_validator_config(&test_harness.harness.pubkeys[0])
            .unwrap();
        service
            .poll_and_publish_preferences(Slot::new(2), &mut published)
            .await;
        restored_mock.assert();
        let received = test_harness
            .harness
            .mock_beacon_node_1
            .builder_preferences
            .lock()
            .unwrap();
        assert_eq!(received.len(), 4);
        assert_eq!(
            received
                .iter()
                .map(|entries| entries[0].max_execution_payment)
                .collect::<Vec<_>>(),
            vec![1, 20, 1, 1]
        );
        for entries in received.iter() {
            assert_eq!(
                entries.len(),
                1,
                "only the upcoming duty should be submitted"
            );
            assert_eq!(entries[0].auth.message.slot, Slot::new(3));
            assert_eq!(entries[0].proposer_pubkey, test_harness.harness.pubkeys[0]);
        }
    }
}

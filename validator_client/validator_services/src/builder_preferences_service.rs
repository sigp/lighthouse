use crate::duties_service::DutiesService;
use crate::request_auth_cache::RequestAuthCache;
use beacon_node_fallback::BeaconNodeFallback;
use bls::PublicKeyBytes;
use builder_store::BuilderStore;
use builder_types::{BuilderEntry, BuilderUrl, RequestAuthData};
use eth2::types::{
    BuilderPreferenceEntry, IndexedErrorMessage, MAX_SUBMITTED_BUILDER_PREFERENCES,
    SubmittedBuilderPreferences,
};
use eth2::{BeaconNodeHttpClient, Error as BeaconNodeError};
use reqwest::StatusCode;
use slot_clock::SlotClock;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, info};
use types::{ChainSpec, EthSpec, ForkName, Slot};
use validator_metrics::{ENDPOINT_ERRORS, ENDPOINT_REQUESTS, inc_counter_vec};
use validator_store::ValidatorStore;

/// The non-slot part of a published entry's identity: the proposer pubkey plus the decomposed
/// `BuilderPreferenceEntry` with its `slot` factored out to the enclosing map's key.
/// - `pubkey`: the proposer the entry was submitted for
/// - `url`: `entry.url`
/// - `auth_data`: `entry.auth.message.data`
/// - `max_execution_payment`: `entry.max_execution_payment`
///
/// See [`PublishedBuilderPreferencesCache`] for how `entry.auth` decomposes into `auth_data` here
/// and `slot` at the map level, and why the `auth` signature is dropped.
#[derive(PartialEq, Eq, Hash)]
struct InnerPreferencesKey {
    pubkey: PublicKeyBytes,
    url: BuilderUrl,
    auth_data: RequestAuthData,
    max_execution_payment: u64,
}

/// De-duplicates the `BuilderPreferenceEntry`s we've already published, so we don't re-send one.
///
/// The identity of a published entry is `(proposer_pubkey, decompose(entry))`. That decomposition is
/// split across the two levels of this map:
/// - `entry.auth.message.slot` becomes the outer `BTreeMap<Slot, _>` key;
/// - the rest — `proposer_pubkey`, `entry.url`, `entry.auth.message.data`, and
///   `entry.max_execution_payment` — forms the [`InnerPreferencesKey`] held in the per-slot set.
///
/// So `entry.auth` decomposes into its `slot` (the map key) and its `data`/`auth_data` (in the inner
/// key); the `auth` signature is dropped, as it is a deterministic function of the proposer, the
/// `auth_data`, and the slot and so adds no identity.
///
/// Operators may change their builder config at any time. Because this identity captures every entry
/// field that reaches a builder, any edit yields a new key that won't match a previously-sent entry,
/// so the updated preference is published again.
#[derive(Default)]
struct PublishedBuilderPreferencesCache {
    cache: BTreeMap<Slot, HashSet<InnerPreferencesKey>>,
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
        self.cache.get(&slot).is_some_and(|set| {
            set.contains(&InnerPreferencesKey {
                pubkey,
                url: builder_entry.url.clone(),
                auth_data: builder_entry.auth.message.data.clone(),
                max_execution_payment: builder_entry.max_execution_payment,
            })
        })
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
            max_execution_payment: builder_preferences_entry.max_execution_payment,
        };
        self.cache.entry(slot).or_default().insert(inner_key);
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
    /// Will only publish a given `(proposer, builder, max_execution_payment)` preference once.
    async fn poll_and_publish_preferences(
        &self,
        current_slot: Slot,
        published_preferences: &mut PublishedBuilderPreferencesCache,
    ) {
        let current_epoch = current_slot.epoch(S::E::slots_per_epoch());
        let mut pending_entries_by_fork = BTreeMap::<ForkName, Vec<BuilderPreferenceEntry>>::new();

        for epoch in [current_epoch, current_epoch + 1] {
            let proposers = match self.inner.duties_service.proposers.read().get(&epoch) {
                Some((_, proposers)) => proposers.clone(),
                None => continue,
            };

            for proposer_data in &proposers {
                let slot = proposer_data.slot;
                let pubkey = proposer_data.pubkey;
                if slot < current_slot {
                    continue;
                }
                let proposal_fork = self.inner.chain_spec.fork_name_at_slot::<S::E>(slot);
                if !proposal_fork.gloas_enabled() {
                    continue;
                }

                // Resolve and sign the whole builder config for this proposer/slot. Auths are
                // cached, so builders already published for this slot cost only a cache hit.
                // Per-builder sign failures are logged and omitted inside `builder_config`, so a
                // fully-failed set just yields an empty `builders` list (nothing to publish).
                let config = self
                    .inner
                    .configured_builders
                    .builder_config(|auth_data| {
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
                    pending_entries_by_fork
                        .entry(proposal_fork)
                        .or_default()
                        .push(BuilderPreferenceEntry::from_builder_entry(
                            pubkey,
                            entry.clone(),
                        ));
                }
            }
        }

        // One submission carries at most `MAX_SUBMITTED_BUILDER_PREFERENCES` entries (beacon-APIs
        // #630), so submit in bounded chunks. Each chunk is best-effort: a failed chunk is logged
        // and does not stop the rest.
        for (fork_name, pending_entries) in pending_entries_by_fork {
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
            let current_slot = self.inner.slot_clock.now().unwrap_or(poll_slot);
            pending_entries.retain(|entry| entry.auth.message.slot >= current_slot);
            if pending_entries.is_empty() {
                return;
            }

            let Ok(entries) = SubmittedBuilderPreferences::new(pending_entries.clone()) else {
                // Unreachable: the caller bounds each chunk by the list limit, and retries only
                // remove entries.
                return;
            };
            let beacon_node = candidate.beacon_node;
            let mut result =
                Self::post_builder_preferences_ssz(&beacon_node, &entries, fork_name).await;

            if result.as_ref().err().and_then(BeaconNodeError::status)
                == Some(StatusCode::UNSUPPORTED_MEDIA_TYPE)
            {
                let current_slot = self.inner.slot_clock.now().unwrap_or(poll_slot);
                pending_entries.retain(|entry| entry.auth.message.slot >= current_slot);
                if pending_entries.is_empty() {
                    return;
                }
                let Ok(entries) = SubmittedBuilderPreferences::new(pending_entries.clone()) else {
                    // Unreachable: retries only remove entries from the bounded chunk.
                    return;
                };
                debug!(
                    endpoint = %beacon_node,
                    "Beacon node does not support SSZ builder preferences, falling back to JSON"
                );
                result =
                    Self::post_builder_preferences_json(&beacon_node, &entries, fork_name).await;
            }

            match result {
                Ok(()) => {
                    for entry in pending_entries.drain(..) {
                        published_preferences.mark_sent(entry.proposer_pubkey, entry);
                    }
                    return;
                }
                Err(BeaconNodeError::ServerIndexedMessage(indexed_error)) => {
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
                    if pending_entries.is_empty() {
                        return;
                    }
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

        if !pending_entries.is_empty() {
            error!(
                remaining = pending_entries.len(),
                %fork_name,
                "Failed to publish builder preferences"
            );
        }
    }

    async fn post_builder_preferences_ssz(
        beacon_node: &BeaconNodeHttpClient,
        entries: &SubmittedBuilderPreferences,
        fork_name: ForkName,
    ) -> Result<(), BeaconNodeError> {
        inc_counter_vec(&ENDPOINT_REQUESTS, &[beacon_node.server().redacted()]);
        let result = beacon_node
            .post_validator_builder_preferences_ssz(entries, fork_name)
            .await;
        if result.is_err() {
            inc_counter_vec(&ENDPOINT_ERRORS, &[beacon_node.server().redacted()]);
        }
        result
    }

    async fn post_builder_preferences_json(
        beacon_node: &BeaconNodeHttpClient,
        entries: &SubmittedBuilderPreferences,
        fork_name: ForkName,
    ) -> Result<(), BeaconNodeError> {
        inc_counter_vec(&ENDPOINT_REQUESTS, &[beacon_node.server().redacted()]);
        let result = beacon_node
            .post_validator_builder_preferences(entries, fork_name)
            .await;
        if result.is_err() {
            inc_counter_vec(&ENDPOINT_ERRORS, &[beacon_node.server().redacted()]);
        }
        result
    }
}

fn valid_failure_indices(
    error: &IndexedErrorMessage,
    entry_count: usize,
) -> Option<HashSet<usize>> {
    if error.code != StatusCode::BAD_REQUEST.as_u16() || error.failures.is_empty() {
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
    use builder_store::BuilderDefinition;
    use builder_types::BuilderUrl;
    use eth2::types::ProposerData;
    use std::str::FromStr;
    use types::{Epoch, ForkName};
    use validator_test_rig::validator_client_harness::{S, ValidatorClientHarness};

    const INDEXED_FAILURE_AT_INDEX_ONE: &str = r#"{
        "code": 400,
        "message": "one entry failed",
        "failures": [{"index": 1, "message": "failed"}]
    }"#;
    const INDEXED_FAILURE_OUT_OF_BOUNDS: &str = r#"{
        "code": 400,
        "message": "invalid failure index",
        "failures": [{"index": 2, "message": "failed"}]
    }"#;
    const SERVER_ERROR: &str = r#"{"code":500,"message":"server error"}"#;
    const UNSUPPORTED_MEDIA_TYPE: &str = r#"{"code":415,"message":"unsupported media type"}"#;

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
                1 => &self.harness.mock_beacon_node_1.received_builder_preferences,
                2 => &self.harness.mock_beacon_node_2.received_builder_preferences,
                _ => panic!("unknown beacon node"),
            };
            received
                .lock()
                .unwrap()
                .iter()
                .map(|(_, entries)| {
                    entries
                        .iter()
                        .map(|entry| entry.auth.message.slot)
                        .collect()
                })
                .collect()
        }
    }

    #[tokio::test]
    async fn future_gloas_preferences_use_their_proposal_fork() {
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
        let mut published = PublishedBuilderPreferencesCache::new();
        test_harness
            .service
            .poll_and_publish_preferences(current_slot, &mut published)
            .await;

        mock.expect(1).assert();
        assert_eq!(test_harness.received_slots(1), vec![vec![first_gloas_slot]]);
    }

    #[tokio::test]
    async fn passed_proposal_slots_are_not_submitted() {
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
    async fn invalid_failure_index_retries_the_complete_batch() {
        let current_slot = Slot::new(0);
        let mut test_harness = TestHarness::new(2, Epoch::new(0)).await;
        test_harness.insert_duties(Epoch::new(0), vec![(0, Slot::new(1)), (1, Slot::new(2))]);

        let first = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_ssz(
                ForkName::Gloas,
                400,
                INDEXED_FAILURE_OUT_OF_BOUNDS,
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

        first.expect(1).assert();
        second.expect(1).assert();
        assert_eq!(
            test_harness.received_slots(2),
            vec![vec![Slot::new(1), Slot::new(2)]]
        );
    }

    #[tokio::test]
    async fn each_beacon_node_is_tried_once_per_poll() {
        let current_slot = Slot::new(0);
        let mut test_harness = TestHarness::new(1, Epoch::new(0)).await;
        test_harness.insert_duties(Epoch::new(0), vec![(0, Slot::new(1))]);

        let first = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas, 500, SERVER_ERROR);
        let second = test_harness
            .harness
            .mock_beacon_node_2
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas, 500, SERVER_ERROR);
        let mut published = PublishedBuilderPreferencesCache::new();
        test_harness
            .service
            .poll_and_publish_preferences(current_slot, &mut published)
            .await;

        first.expect(1).assert();
        second.expect(1).assert();
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
                UNSUPPORTED_MEDIA_TYPE,
                move || slot_clock.advance_slot(),
            );
        let json = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_json(ForkName::Gloas, 200, "");
        let second_node = test_harness
            .harness
            .mock_beacon_node_2
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas, 500, SERVER_ERROR);
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
}

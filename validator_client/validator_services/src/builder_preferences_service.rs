use crate::duties_service::DutiesService;
use crate::request_auth_cache::RequestAuthCache;
use beacon_node_fallback::BeaconNodeFallback;
use bls::PublicKeyBytes;
use builder_store::BuilderStore;
use builder_types::{BuilderEntry, BuilderUrl, RequestAuthData};
use eth2::types::{
    BuilderPreferenceEntry, MAX_SUBMITTED_BUILDER_PREFERENCES, SubmittedBuilderPreferences,
};
use slot_clock::SlotClock;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, info};
use types::{ChainSpec, EthSpec, ForkName, Slot};
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
        // #630), so submit in bounded chunks, each under its group's fork. Each chunk is
        // best-effort: a failed chunk is logged and does not stop the rest.
        let mut chunks: Vec<(ForkName, &[BuilderPreferenceEntry])> = Vec::new();
        for (fork_name, group) in &pending_groups {
            for chunk in group.chunks(MAX_SUBMITTED_BUILDER_PREFERENCES) {
                chunks.push((*fork_name, chunk));
            }
        }
        for (fork_name, chunk) in chunks {
            let Ok(entries) = SubmittedBuilderPreferences::new(chunk.to_vec()) else {
                // Unreachable: `chunks()` bounds each chunk by the list limit.
                continue;
            };
            let entries_ref = &entries;

            // A failed request can still reach a builder. Forget the previous cap before sending
            // its replacement, so a later configuration change cannot suppress a needed update.
            for entry in entries.iter() {
                published_preferences.forget(entry);
            }

            // Try SSZ first, falling back to JSON. `first_success` is okay here because later
            // we'll be resending the auths when we publish the beacon block.
            let ssz_result = self
                .inner
                .beacon_nodes
                .first_success(|beacon_node| async move {
                    beacon_node
                        .post_validator_builder_preferences_ssz(entries_ref, fork_name)
                        .await
                })
                .await;

            let result = match ssz_result {
                Ok(()) => Ok(()),
                Err(ssz_err) => {
                    debug!(error = %ssz_err, "SSZ builder preferences publish failed, falling back to JSON");
                    self.inner
                        .beacon_nodes
                        .first_success(|beacon_node| async move {
                            beacon_node
                                .post_validator_builder_preferences(entries_ref, fork_name)
                                .await
                        })
                        .await
                }
            };

            match result {
                Ok(()) => {
                    for entry in entries.iter().cloned() {
                        let pubkey = entry.proposer_pubkey;
                        published_preferences.mark_sent(pubkey, entry);
                    }
                }
                Err(e) => error!(error = %e, "Failed to publish builder preferences"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duties_service::DutiesServiceBuilder;
    use builder_store::{BuilderDefinition, ValidatorBuilderConfig, ValidatorBuilderDefinition};
    use eth2::types::ProposerData;
    use types::{Epoch, ForkName, Hash256};
    use validator_test_rig::validator_client_harness::{S, ValidatorClientHarness};

    /// One epoch before the Gloas fork, lookahead entries for the first Gloas epoch must go out
    /// under `Eth-Consensus-Version: gloas` — the fork their proposal slots belong to — not the
    /// fork active at submission time.
    #[tokio::test]
    async fn lookahead_entries_submit_under_their_epochs_fork() {
        let mut harness = ValidatorClientHarness::new(1).await;

        // A spec whose Gloas fork begins at epoch 1, so submission time (epoch 0) is pre-Gloas.
        let mut spec = (*harness.spec).clone();
        spec.gloas_fork_epoch = Some(Epoch::new(1));
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

        // One proposer duty in the first Gloas epoch (the lookahead epoch from now).
        let gloas_epoch = Epoch::new(1);
        duties_service.proposers.write().insert(
            gloas_epoch,
            (
                Hash256::ZERO,
                vec![ProposerData {
                    pubkey: harness.pubkeys[0],
                    validator_index: 0,
                    slot: gloas_epoch.start_slot(<S as ValidatorStore>::E::slots_per_epoch()),
                }],
            ),
        );

        // A single enabled builder.
        let configured_builders =
            BuilderStore::open_or_create(harness._validator_dir.path()).unwrap();
        configured_builders
            .insert(BuilderDefinition {
                enabled: true,
                url: "http://builder.example.com".parse().unwrap(),
                auth_data: None,
                builder_pubkeys: vec![],
                max_execution_payment: 0,
                min_bid: None,
                builder_boost_factor: None,
            })
            .unwrap();

        // Fork-matched mock first, catch-all second: a submission labeled with any other fork
        // (e.g. the pre-Gloas fork active at submission time) falls through to the catch-all.
        let mock_gloas = harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas);
        let mock_other_fork = harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_any_fork();

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

        let mut published = PublishedBuilderPreferencesCache::new();
        // Poll from a pre-Gloas slot (epoch 0).
        service
            .poll_and_publish_preferences(Slot::new(0), &mut published)
            .await;

        mock_gloas.expect(1).assert();
        mock_other_fork.expect(0).assert();
    }

    #[tokio::test]
    async fn builder_config_updates_apply_to_upcoming_duties() {
        let mut harness = ValidatorClientHarness::new(1).await;
        let spec = harness.spec.clone();

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

        // Two duties in the current epoch: one already elapsed, one upcoming.
        let epoch = Epoch::new(0);
        duties_service.proposers.write().insert(
            epoch,
            (
                Hash256::ZERO,
                vec![
                    ProposerData {
                        pubkey: harness.pubkeys[0],
                        validator_index: 0,
                        slot: Slot::new(0),
                    },
                    ProposerData {
                        pubkey: harness.pubkeys[0],
                        validator_index: 0,
                        slot: Slot::new(3),
                    },
                ],
            ),
        );

        let configured_builders =
            BuilderStore::open_or_create(harness._validator_dir.path()).unwrap();
        configured_builders
            .insert(BuilderDefinition {
                enabled: true,
                url: "http://builder.example.com".parse().unwrap(),
                auth_data: None,
                builder_pubkeys: vec![],
                max_execution_payment: 0,
                min_bid: None,
                builder_boost_factor: None,
            })
            .unwrap();

        let mock = harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas);

        let service = BuilderPreferencesService::new(
            duties_service,
            harness.validator_store.clone(),
            harness.slot_clock.clone(),
            harness.beacon_nodes.clone(),
            configured_builders.clone(),
            RequestAuthCache::default(),
            harness.test_runtime.task_executor.clone(),
            spec,
        );

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
            .set_validator_config(&harness.pubkeys[0], validator_config.clone())
            .unwrap();
        service
            .poll_and_publish_preferences(Slot::new(2), &mut published)
            .await;

        configured_builders
            .delete_validator_config(&harness.pubkeys[0])
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
        // Each poll attempts SSZ and JSON twice through `first_success`.
        let failed_mock = mock.with_status(500).with_body("").expect(8).create();
        configured_builders
            .set_validator_config(&harness.pubkeys[0], validator_config)
            .unwrap();
        for _ in 0..2 {
            service
                .poll_and_publish_preferences(Slot::new(2), &mut published)
                .await;
        }
        failed_mock.assert();
        failed_mock.remove();

        let restored_mock = harness
            .mock_beacon_node_1
            .mock_post_validator_builder_preferences_ssz(ForkName::Gloas);
        configured_builders
            .delete_validator_config(&harness.pubkeys[0])
            .unwrap();
        service
            .poll_and_publish_preferences(Slot::new(2), &mut published)
            .await;
        restored_mock.assert();
        let received = harness
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
            vec![0, 20, 0, 0]
        );
        for entries in received.iter() {
            assert_eq!(
                entries.len(),
                1,
                "only the upcoming duty should be submitted"
            );
            assert_eq!(entries[0].auth.message.slot, Slot::new(3));
            assert_eq!(entries[0].proposer_pubkey, harness.pubkeys[0]);
        }
    }
}

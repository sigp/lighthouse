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
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, info};
use types::{ChainSpec, EthSpec, Slot};
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
        // One flat request whose body spans both epochs, each entry naming its own proposer
        // (beacon-APIs #630, whose body is sized for several epochs of entries). The single
        // `Eth-Consensus-Version` is the version active now, at submission time.
        let current_fork = self.inner.chain_spec.fork_name_at_epoch(current_epoch);
        let mut pending_entries: Vec<BuilderPreferenceEntry> = Vec::new();

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

            for proposer_data in &proposers {
                let slot = proposer_data.slot;
                let pubkey = proposer_data.pubkey;

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
                    pending_entries.push(BuilderPreferenceEntry::from_builder_entry(
                        pubkey,
                        entry.clone(),
                    ));
                }
            }
        }

        if pending_entries.is_empty() {
            return;
        }

        // One submission carries at most `MAX_SUBMITTED_BUILDER_PREFERENCES` entries (beacon-APIs
        // #630), so submit in bounded chunks. Each chunk is best-effort: a failed chunk is logged
        // and does not stop the rest.
        for chunk in pending_entries.chunks(MAX_SUBMITTED_BUILDER_PREFERENCES) {
            let Ok(entries) = SubmittedBuilderPreferences::new(chunk.to_vec()) else {
                // Unreachable: `chunks()` bounds each chunk by the list limit.
                continue;
            };
            let entries_ref = &entries;

            // Try SSZ first, falling back to JSON. `first_success` is okay here because later
            // we'll be resending the auths when we publish the beacon block.
            let ssz_result = self
                .inner
                .beacon_nodes
                .first_success(|beacon_node| async move {
                    beacon_node
                        .post_validator_builder_preferences_ssz(entries_ref, current_fork)
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
                                .post_validator_builder_preferences(entries_ref, current_fork)
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

use super::{
    Config, Error, LighthouseValidatorStore,
    vrf_state::{self, Record, Source},
    xmss_cache::{CacheLoader, CachedSigner},
    xmss_cache_source::{self, RegisteredKey, Registry},
};
use bls::{Keypair, PublicKeyBytes};
use futures::{StreamExt, stream};
use genesis::pq::{POPULATED_LEAVES, VrfTree};
use parking_lot::Mutex;
use signing_method::SigningMethod;
use slot_clock::SlotClock;
use state_processing::pq;
use std::collections::HashMap;
use std::time::Duration;
use std::{
    path::PathBuf,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    sync::{Notify, OnceCell, Semaphore, oneshot},
    time::{Instant, MissedTickBehavior, interval_at},
};
use tracing::{debug, info, warn};
use types::{
    AggregateAndProof, AggregateAndProofPq, Attestation, AttestationData, AttestationProof,
    BeaconState, Domain, EthSpec, ForkName, Hash256, SignedAggregateAndProof,
    SignedAggregateAndProofPq, SignedRoot, SingleAttestation, SingleAttestationPq, Slot, VrfProof,
    XmssPublicKey, XmssSignature,
};
use validator_store::{AttestationToSign, DoppelgangerStatus, ValidatorStore};
use xmss::{LeafIndex, SUBTREE_LEAVES};

const PQ_WORKERS: usize = 8;
const PQ_KEY_LOAD_LOG_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PreparationWindow {
    slot_tree: LeafIndex,
    attestation_tree: LeafIndex,
}

impl PreparationWindow {
    fn new<E: EthSpec>(slot: Slot) -> Result<Self, Error> {
        let tree = |leaf| {
            LeafIndex::try_from(leaf)
                .map(|leaf| leaf - leaf % SUBTREE_LEAVES)
                .map_err(pq_leaf_error)
        };
        Ok(Self {
            slot_tree: tree(
                pq::slot_leaf_index(slot, pq::LEAF_OFFSET_BEACON_PROPOSER)
                    .map_err(pq_leaf_error)?,
            )?,
            attestation_tree: tree(
                pq::attestation_leaf_index(slot.epoch(E::slots_per_epoch()))
                    .map_err(pq_leaf_error)?,
            )?,
        })
    }

    fn current(self) -> [LeafIndex; 2] {
        [self.slot_tree, self.attestation_tree]
    }

    fn leaves(self) -> impl Iterator<Item = LeafIndex> {
        self.current()
            .into_iter()
            .chain(self.slot_tree.checked_add(SUBTREE_LEAVES))
            .chain(self.attestation_tree.checked_add(SUBTREE_LEAVES))
    }
}

enum KeyLoadOutcome {
    Prepared,
    Skipped,
    Failed,
}

#[derive(Default)]
struct Key {
    xmss: OnceLock<CachedSigner>,
    xmss_ready: AtomicBool,
    prepared_window: Mutex<Option<PreparationWindow>>,
    vrf: OnceCell<VrfTree>,
    registered_vrf_root: OnceLock<Hash256>,
}

impl Key {
    fn mark_xmss_ready(&self, keys_changed: &Notify) {
        if !self.xmss_ready.swap(true, Ordering::Relaxed) {
            keys_changed.notify_one();
        }
    }
}

pub(super) struct Keys {
    entries: Mutex<HashMap<PublicKeyBytes, Arc<Key>>>,
    permits: Arc<Semaphore>,
    xmss_registry: OnceLock<Registry>,
    source: Result<Option<Source>, String>,
    vrf_cache_dir: Option<PathBuf>,
    xmss_cache_dir: Option<PathBuf>,
    xmss_cache_source: Option<xmss_cache_source::Source>,
    xmss_keys_changed: Arc<Notify>,
}

impl Keys {
    pub(super) fn new(config: &Config) -> Self {
        let xmss_cache_source = config.xmss_cache_url.as_deref().and_then(|value| {
            if xmss::FAKE_CRYPTO {
                return None;
            }
            match xmss_cache_source::Source::new(value) {
                Ok(source) => Some(source),
                Err(error) => {
                    warn!(%error, "Ignoring unusable pregenerated PQ XMSS cache source");
                    None
                }
            }
        });
        Self {
            entries: Mutex::default(),
            permits: Arc::new(Semaphore::new(PQ_WORKERS)),
            xmss_registry: OnceLock::new(),
            source: config.vrf_state_url.as_deref().map(Source::new).transpose(),
            vrf_cache_dir: config.vrf_state_cache_dir.clone(),
            xmss_cache_dir: config.xmss_cache_dir.clone(),
            xmss_cache_source,
            xmss_keys_changed: Arc::default(),
        }
    }
}

impl<T: SlotClock + 'static, E: EthSpec> LighthouseValidatorStore<T, E> {
    /// Use the trusted local PQ genesis registry to authenticate distributed XMSS caches.
    pub fn set_pq_cache_registry(&self, mut state: BeaconState<E>) -> Result<(), String> {
        if self.pq_keys.xmss_cache_source.is_none() {
            return Ok(());
        }
        let expected_root = self.genesis_validators_root;
        if !matches!(state, BeaconState::Pq(_))
            || state.genesis_validators_root() != expected_root
            || state
                .update_validators_tree_hash_cache()
                .map_err(|error| format!("{error:?}"))?
                != expected_root
        {
            return Err("PQ XMSS cache requires a matching genesis validator registry".into());
        }
        let registry = Registry::new(state.validators().iter().map(|validator| RegisteredKey {
            public_key: validator.pubkey,
            vrf_root: validator.vrf_root,
        }));
        self.pq_keys
            .xmss_registry
            .set(registry)
            .map_err(|_| "PQ XMSS cache registry already initialized".into())
    }

    async fn with_local_pq_key<R: Send + 'static>(
        &self,
        pubkey: PublicKeyBytes,
        signing_method: Arc<SigningMethod>,
        work: impl FnOnce(&Key, &Keypair) -> Result<R, Error> + Send + 'static,
    ) -> Result<R, Error> {
        if !matches!(&*signing_method, SigningMethod::LocalKeystore { .. }) {
            return Err(Error::Middleware(
                "PQ supports local validator keystores only".into(),
            ));
        }
        let key = self
            .pq_keys
            .entries
            .lock()
            .entry(pubkey)
            .or_default()
            .clone();
        let permit = self
            .pq_keys
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::ExecutorError)?;
        self.task_executor
            .spawn_blocking_handle(
                move || {
                    let _permit = permit;
                    let SigningMethod::LocalKeystore { voting_keypair, .. } = &*signing_method
                    else {
                        return Err(Error::UnknownPubkey(pubkey));
                    };
                    work(&key, voting_keypair)
                },
                "pq_validator_key",
            )
            .ok_or(Error::ExecutorError)?
            .await
            .map_err(|_| Error::ExecutorError)?
    }

    async fn prepare_pq_key(
        &self,
        pubkey: PublicKeyBytes,
        signing_method: Arc<SigningMethod>,
        slot: Slot,
    ) -> Result<(), Error> {
        let cache_dir = self.pq_keys.xmss_cache_dir.clone();
        let (loader, imported) = if let (Some(source), Some(registry)) = (
            &self.pq_keys.xmss_cache_source,
            self.pq_keys.xmss_registry.get(),
        ) {
            let dir = cache_dir.clone();
            let loader = self
                .with_local_pq_key(pubkey, Arc::clone(&signing_method), move |key, bls| {
                    if key.xmss.get().is_some() {
                        return Ok(None);
                    }
                    match CacheLoader::open(&bls.sk, pubkey, dir.as_deref()) {
                        Ok(signer) => {
                            let _ = key.xmss.set(signer);
                            Ok(None)
                        }
                        Err(loader) => Ok(Some(loader)),
                    }
                })
                .await?;
            let mut imported = None;
            if let Some(loader) = &loader
                && let SigningMethod::LocalKeystore {
                    voting_keystore, ..
                } = &*signing_method
            {
                let index = vrf_state::derivation_index(voting_keystore.path().as_deref())
                    .unwrap_or_else(|error| {
                        debug!(?pubkey, %error, "Looking up PQ XMSS cache by registered identity");
                        None
                    });
                if let Some(key) = loader
                    .public_parameter()
                    .and_then(|parameter| registry.identify(parameter))
                {
                    let vrf_source = self.pq_keys.source.as_ref().ok().and_then(Option::as_ref);
                    match source.fetch(key, index, vrf_source).await {
                        Ok(record) => imported = Some(record),
                        Err(error) => warn!(
                            ?pubkey, %error,
                            "Unable to read pregenerated PQ XMSS cache, building locally"
                        ),
                    }
                } else {
                    debug!(
                        ?pubkey,
                        "Validator does not match a unique genesis PQ XMSS key"
                    );
                }
            }
            (loader, imported)
        } else {
            (None, None)
        };

        let keys_changed = Arc::clone(&self.pq_keys.xmss_keys_changed);
        self.with_local_pq_key(pubkey, signing_method, move |key, bls| {
            let signer = key.xmss.get_or_init(|| match loader {
                Some(loader) => loader.finish(pubkey, imported),
                None => CachedSigner::load(&bls.sk, pubkey, cache_dir.as_deref()),
            });
            for leaf in PreparationWindow::new::<E>(slot)?.current() {
                signer.key.prepare(leaf).map_err(pq_leaf_error)?;
            }
            signer.persist(pubkey);
            key.mark_xmss_ready(&keys_changed);
            Ok(())
        })
        .await
    }

    fn local_pq_key_ready(&self, pubkey: &PublicKeyBytes) -> bool {
        self.pq_keys
            .entries
            .lock()
            .get(pubkey)
            .is_some_and(|key| key.xmss_ready.load(Ordering::Relaxed))
    }

    pub(super) async fn load_pq_keys(&self, pubkeys: Vec<PublicKeyBytes>) {
        if pubkeys.iter().all(|pubkey| self.local_pq_key_ready(pubkey)) {
            return;
        }

        let total = pubkeys.len();
        let started = Instant::now();
        let slot = self.slot_clock.now_or_genesis().unwrap_or_default();
        info!(total, workers = PQ_WORKERS, %slot, "Preparing PQ XMSS validator keys");

        let keys = stream::iter(pubkeys)
            .map(|pubkey| async move {
                if self.local_pq_key_ready(&pubkey) {
                    return KeyLoadOutcome::Skipped;
                }
                let Ok(signing_method) = self.doppelganger_bypassed_signing_method(pubkey) else {
                    return KeyLoadOutcome::Skipped;
                };
                match self.prepare_pq_key(pubkey, signing_method, slot).await {
                    Ok(()) => KeyLoadOutcome::Prepared,
                    Err(error) => {
                        warn!(?pubkey, ?error, "Unable to prepare PQ XMSS validator key");
                        KeyLoadOutcome::Failed
                    }
                }
            })
            .buffer_unordered(PQ_WORKERS);
        futures::pin_mut!(keys);
        let mut progress =
            interval_at(started + PQ_KEY_LOAD_LOG_INTERVAL, PQ_KEY_LOAD_LOG_INTERVAL);
        progress.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let (mut prepared, mut skipped, mut failed) = (0_usize, 0_usize, 0_usize);
        loop {
            tokio::select! {
                outcome = keys.next() => match outcome {
                    Some(KeyLoadOutcome::Prepared) => prepared += 1,
                    Some(KeyLoadOutcome::Skipped) => skipped += 1,
                    Some(KeyLoadOutcome::Failed) => failed += 1,
                    None => break,
                },
                _ = progress.tick() => info!(
                    total,
                    completed = prepared + skipped + failed,
                    prepared,
                    skipped,
                    failed,
                    elapsed_ms = started.elapsed().as_millis(),
                    "PQ XMSS validator key preparation in progress"
                ),
            }
        }
        info!(
            total,
            completed = prepared + skipped + failed,
            prepared,
            skipped,
            failed,
            elapsed_ms = started.elapsed().as_millis(),
            "Finished preparing PQ XMSS validator keys"
        );
    }

    /// A single background worker prepares rolling signing windows. It uses neither
    /// the signing semaphore nor a long-held signing cache lock.
    pub fn start_pq_xmss_preparation(self: &Arc<Self>) {
        if xmss::FAKE_CRYPTO || !self.spec.is_pq_scheduled() {
            return;
        }
        let store = Arc::clone(self);
        self.task_executor.spawn(
            async move { store.prepare_pq_xmss_windows().await },
            "pq_xmss_preparation",
        );
    }

    async fn prepare_pq_xmss_windows(&self) {
        let mut previous = None;
        let mut keys_changed = true;
        loop {
            let window = self.pq_xmss_window();
            if let Some(window) = window
                && (keys_changed || Some(window) != previous)
            {
                self.prepare_pq_xmss_window(window).await;
            }
            previous = window;

            tokio::select! {
                _ = self.pq_keys.xmss_keys_changed.notified() => keys_changed = true,
                _ = tokio::time::sleep(self.slot_clock.slot_duration()) => keys_changed = false,
            }
        }
    }

    fn pq_xmss_window(&self) -> Option<PreparationWindow> {
        let slot = self.slot_clock.now_or_genesis()?;
        if self.spec.fork_name_at_slot::<E>(slot) != ForkName::Pq {
            return None;
        }
        PreparationWindow::new::<E>(slot).ok()
    }

    async fn prepare_pq_xmss_window(&self, window: PreparationWindow) {
        let pubkeys: Vec<_> = self.voting_pubkeys(DoppelgangerStatus::ignored);
        let entries = {
            let entries = self.pq_keys.entries.lock();
            pubkeys
                .into_iter()
                .filter_map(|pubkey| Some((pubkey, Arc::clone(entries.get(&pubkey)?))))
                .collect::<Vec<_>>()
        };

        for (pubkey, key) in entries {
            if self.pq_xmss_window() != Some(window) {
                break;
            }
            if !key.xmss_ready.load(Ordering::Relaxed)
                || *key.prepared_window.lock() == Some(window)
            {
                continue;
            }

            // A tree already building can finish after shutdown, but the cancellation
            // check stops the worker before it starts the next tree.
            let (cancel, alive) = oneshot::channel::<()>();
            let Some(work) = self.task_executor.spawn_blocking_handle(
                move || -> Result<(), xmss::Error> {
                    let Some(signer) = key.xmss.get() else {
                        return Ok(());
                    };
                    let started = Instant::now();
                    for leaf in window.leaves() {
                        if cancel.is_closed()
                            || !signer
                                .key
                                .prepare_with_cancel(leaf, || cancel.is_closed())?
                        {
                            return Ok(());
                        }
                    }
                    if !cancel.is_closed() {
                        signer.persist(pubkey);
                        *key.prepared_window.lock() = Some(window);
                        debug!(
                            ?pubkey,
                            ?window,
                            elapsed_ms = started.elapsed().as_millis(),
                            "Prepared rolling PQ XMSS signing trees"
                        );
                    }
                    Ok(())
                },
                "pq_xmss_prepare_window",
            ) else {
                return;
            };

            let result = work.await;
            drop(alive);
            if let Ok(Err(error)) = result {
                warn!(?pubkey, %error, "Unable to prepare rolling PQ XMSS signing trees");
            }
        }
    }

    pub(super) fn local_pq_public_key(&self, pubkey: &PublicKeyBytes) -> Option<XmssPublicKey> {
        self.pq_keys
            .entries
            .lock()
            .get(pubkey)?
            .xmss
            .get()
            .map(|signer| signer.key.public_key())
    }

    pub(super) fn has_pq_vrf_root(&self, pubkey: &PublicKeyBytes) -> bool {
        self.pq_keys
            .entries
            .lock()
            .get(pubkey)
            .is_some_and(|key| key.registered_vrf_root.get().is_some())
    }

    pub(super) fn set_pq_vrf_root(&self, pubkey: PublicKeyBytes, root: Hash256) -> bool {
        let key = self
            .pq_keys
            .entries
            .lock()
            .entry(pubkey)
            .or_default()
            .clone();
        if let Err(root) = key.registered_vrf_root.set(root) {
            if key.registered_vrf_root.get() != Some(&root) {
                warn!(
                    ?pubkey,
                    "Beacon node returned a conflicting registered PQ VRF root"
                );
            }
            return false;
        }
        matches!(self.pq_keys.source, Ok(Some(_)))
    }

    pub(super) async fn warm_pq_vrf(&self, pubkey: PublicKeyBytes) {
        let result = async {
            let signing_method = self.doppelganger_bypassed_signing_method(pubkey)?;
            self.pq_vrf_key(pubkey, signing_method).await.map(|_| ())
        }
        .await;
        if let Err(error) = result {
            warn!(?pubkey, ?error, "Unable to prepare full PQ VRF state");
        }
    }

    async fn pq_vrf_key(
        &self,
        pubkey: PublicKeyBytes,
        signing_method: Arc<SigningMethod>,
    ) -> Result<Arc<Key>, Error> {
        let source = self
            .pq_keys
            .source
            .as_ref()
            .map_err(|error| Error::Middleware(error.clone()))?
            .as_ref()
            .ok_or_else(|| Error::Middleware("PQ proposals require --vrf-state-url".into()))?;
        let SigningMethod::LocalKeystore {
            voting_keystore, ..
        } = &*signing_method
        else {
            return Err(Error::Middleware(
                "PQ VRF requires a local voting keystore".into(),
            ));
        };
        let index = vrf_state::derivation_index(voting_keystore.path().as_deref()).unwrap_or_else(
            |error| {
                debug!(?pubkey, %error, "Looking up PQ VRF state by registered root");
                None
            },
        );
        let key = self
            .pq_keys
            .entries
            .lock()
            .entry(pubkey)
            .or_default()
            .clone();
        let root = *key.registered_vrf_root.get().ok_or_else(|| {
            Error::Middleware("registered PQ VRF root has not been resolved".into())
        })?;
        key.vrf
            .get_or_try_init(|| async {
                let cache_path = self.pq_keys.vrf_cache_dir.as_ref().map(|dir| match index {
                    Some(index) => dir.join(format!("{root:x}-{index}.vrf")),
                    None => dir.join(format!("{root:x}.vrf")),
                });
                let cached = match cache_path.as_deref() {
                    Some(path) => vrf_state::read_cache(path).await,
                    None => None,
                };
                if let Some(bytes) = cached {
                    match self
                        .validate_vrf_record(pubkey, signing_method.clone(), root, &bytes)
                        .await
                    {
                        Ok(tree) => return Ok::<VrfTree, Error>(tree),
                        Err(error) => {
                            warn!(?pubkey, ?error, "Ignoring invalid cached PQ VRF state")
                        }
                    }
                }
                let bytes = source
                    .record_for_validator(index, root)
                    .await
                    .map_err(Error::Middleware)?;
                let tree = self
                    .validate_vrf_record(pubkey, signing_method, root, &bytes)
                    .await?;
                if let Some(path) = cache_path
                    && let Err(error) = vrf_state::write_cache(&path, &bytes).await
                {
                    warn!(?pubkey, ?error, "Unable to persist PQ VRF state");
                }
                Ok(tree)
            })
            .await?;
        Ok(key)
    }

    async fn validate_vrf_record(
        &self,
        pubkey: PublicKeyBytes,
        signing_method: Arc<SigningMethod>,
        root: Hash256,
        bytes: &[u8],
    ) -> Result<VrfTree, Error> {
        let record = Record::decode(bytes, root).map_err(Error::Middleware)?;
        self.with_local_pq_key(pubkey, signing_method, move |_, bls| {
            let started = Instant::now();
            info!(?pubkey, "Computing PQ RANDAO VRF subtree");
            let tree = VrfTree::from_slot_zero_state(&bls.sk, record.root, &record.branch)
                .map_err(|error| Error::Middleware(error.into()))?;
            info!(
                ?pubkey,
                elapsed_ms = started.elapsed().as_millis(),
                "Verified full PQ RANDAO VRF state"
            );
            Ok(tree)
        })
        .await
    }

    pub(super) async fn pq_vrf_proof(
        &self,
        pubkey: PublicKeyBytes,
        slot: Slot,
    ) -> Result<VrfProof, Error> {
        if slot.as_u64() >= POPULATED_LEAVES {
            return Err(Error::Middleware(
                "slot is outside the first 2^20 leaves covered by PQ VRF state".into(),
            ));
        }
        let signing_method = self.doppelganger_checked_signing_method(pubkey)?;
        let key = self.pq_vrf_key(pubkey, signing_method.clone()).await?;
        self.with_local_pq_key(pubkey, signing_method, move |_, _| {
            key.vrf
                .get()
                .ok_or_else(|| Error::Middleware("PQ VRF state is unavailable".into()))?
                .proof(slot)
                .map_err(|error| Error::Middleware(format!("PQ RANDAO proof: {error:?}")))
        })
        .await
    }

    pub(super) async fn sign_pq(
        &self,
        pubkey: PublicKeyBytes,
        leaf: u64,
        signing_root: Hash256,
        attestation: Option<AttestationData>,
    ) -> Result<XmssSignature, Error> {
        let leaf = LeafIndex::try_from(leaf)
            .map_err(|error| Error::Middleware(format!("PQ signature leaf: {error}")))?;
        let signing_method = self.doppelganger_checked_signing_method(pubkey)?;
        let slashing_protection = self.slashing_protection.clone();
        let cache_dir = self.pq_keys.xmss_cache_dir.clone();
        let keys_changed = Arc::clone(&self.pq_keys.xmss_keys_changed);
        self.with_local_pq_key(pubkey, signing_method, move |key, bls| {
            // Commit before touching the signer. A cancellation or failure after this
            // point still reserves the leaf, and only the identical message may retry.
            slashing_protection
                .with_transaction(|txn| {
                    if let Some(data) = attestation {
                        slashing_protection.check_and_insert_attestation_signing_root(
                            &pubkey,
                            data.source.epoch,
                            data.target.epoch,
                            signing_root.into(),
                            txn,
                        )?;
                    }
                    slashing_protection.reserve_xmss_leaf(txn, &pubkey, leaf, signing_root)
                })
                .map_err(Error::Slashable)?;

            let signer = key
                .xmss
                .get_or_init(|| CachedSigner::load(&bls.sk, pubkey, cache_dir.as_deref()));
            let _timer = validator_metrics::start_timer(&validator_metrics::PQ_XMSS_SIGN_SECONDS);
            let result = signer.key.sign(&signing_root.0, leaf);
            key.mark_xmss_ready(&keys_changed);
            result.map_err(|error| Error::Middleware(format!("PQ signature: {error:?}")))
        })
        .await
    }

    pub(super) async fn sign_pq_attestations(
        &self,
        attestations: Vec<AttestationToSign>,
    ) -> Vec<SingleAttestation> {
        stream::iter(attestations)
            .map(|attestation| async move {
                let AttestationToSign {
                    attester_index,
                    pubkey,
                    committee_index,
                    data,
                } = attestation;
                let epoch = data.target.epoch;
                if self.spec.fork_name_at_epoch(epoch) != ForkName::Pq
                    || data.slot.epoch(E::slots_per_epoch()) != epoch
                    || data.index > 1
                {
                    warn!(?pubkey, ?data, "Invalid PQ attestation data");
                    return None;
                }
                let domain = self
                    .signing_context(Domain::BeaconAttester, epoch)
                    .domain_hash(&self.spec);
                let result = async {
                    let leaf = pq::attestation_leaf_index(epoch).map_err(pq_leaf_error)?;
                    self.sign_pq(pubkey, leaf, data.signing_root(domain), Some(data.clone()))
                        .await
                }
                .await;
                match result {
                    Ok(signature) => {
                        validator_metrics::inc_counter_vec(
                            &validator_metrics::SIGNED_ATTESTATIONS_TOTAL,
                            &[validator_metrics::SUCCESS],
                        );
                        Some(SingleAttestation::Pq(SingleAttestationPq {
                            committee_index,
                            attester_index,
                            data,
                            signature,
                        }))
                    }
                    Err(error) => {
                        warn!(?pubkey, ?error, "Unable to sign PQ attestation");
                        None
                    }
                }
            })
            .buffer_unordered(PQ_WORKERS)
            .filter_map(std::future::ready)
            .collect()
            .await
    }

    pub(super) async fn sign_pq_aggregate(
        &self,
        pubkey: PublicKeyBytes,
        aggregator_index: u64,
        aggregate: Attestation<E>,
        proof: AttestationProof<E>,
    ) -> Result<SignedAggregateAndProof<E>, Error> {
        let Attestation::Pq(aggregate) = aggregate else {
            return Err(Error::Middleware(
                "Expected a PQ attestation aggregate".into(),
            ));
        };
        let slot = aggregate.data.slot;
        let epoch = slot.epoch(E::slots_per_epoch());
        if self.spec.fork_name_at_epoch(epoch) != ForkName::Pq
            || aggregate.data.target.epoch != epoch
            || aggregate.get_committee_indices().len() != 1
            || proof.is_empty()
        {
            return Err(Error::Middleware("Invalid PQ attestation aggregate".into()));
        }
        let domain = self
            .signing_context(Domain::AggregateAndProof, epoch)
            .domain_hash(&self.spec);
        let message = AggregateAndProof::Pq(AggregateAndProofPq {
            aggregator_index,
            aggregate,
            proof,
        });
        let leaf = pq::slot_leaf_index(slot, pq::LEAF_OFFSET_AGGREGATE_AND_PROOF)
            .map_err(pq_leaf_error)?;
        let signature = self
            .sign_pq(pubkey, leaf, message.signing_root(domain), None)
            .await?;
        let AggregateAndProof::Pq(message) = message else {
            return Err(Error::Middleware(
                "Expected a PQ aggregate-and-proof".into(),
            ));
        };
        validator_metrics::inc_counter_vec(
            &validator_metrics::SIGNED_AGGREGATES_TOTAL,
            &[validator_metrics::SUCCESS],
        );
        Ok(SignedAggregateAndProof::Pq(SignedAggregateAndProofPq {
            message,
            signature,
        }))
    }
}

pub(super) fn pq_leaf_error(error: impl std::fmt::Debug) -> Error {
    Error::Middleware(format!("PQ signature leaf: {error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolling_xmss_window_prepares_each_duty_range_ahead_of_its_boundary() {
        use types::MainnetEthSpec;

        let at = |slot| PreparationWindow::new::<MainnetEthSpec>(Slot::new(slot)).unwrap();
        let initial = at(0);
        assert_eq!(initial, at(4_095));
        assert_eq!(
            initial.leaves().collect::<Vec<_>>(),
            [
                initial.slot_tree,
                initial.attestation_tree,
                initial.slot_tree + SUBTREE_LEAVES,
                initial.attestation_tree + SUBTREE_LEAVES,
            ]
        );
        let next_slot_window = at(4_096);
        assert_eq!(
            next_slot_window.slot_tree,
            initial.slot_tree + SUBTREE_LEAVES
        );
        assert_eq!(next_slot_window.attestation_tree, initial.attestation_tree);
        assert!(
            initial
                .leaves()
                .any(|leaf| leaf == next_slot_window.slot_tree)
        );
        assert_eq!(next_slot_window, at(12_287));
        assert_eq!(
            at(12_288).slot_tree,
            next_slot_window.slot_tree + SUBTREE_LEAVES
        );

        let epoch_boundary = (1 << 15) * MainnetEthSpec::slots_per_epoch();
        let previous = at(epoch_boundary - 1);
        let current = at(epoch_boundary);
        assert_eq!(
            current.attestation_tree,
            previous.attestation_tree + SUBTREE_LEAVES
        );
        assert!(
            previous
                .leaves()
                .any(|leaf| leaf == current.attestation_tree)
        );
    }
}

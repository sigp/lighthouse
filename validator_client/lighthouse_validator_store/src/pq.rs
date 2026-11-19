use super::{
    Config, Error, LighthouseValidatorStore,
    vrf_state::{self, Record, Source},
};
use bls::{Keypair, PublicKeyBytes};
use futures::{StreamExt, stream};
use genesis::pq::{POPULATED_LEAVES, VrfTree, xmss_key_from_bls};
use parking_lot::Mutex;
use signing_method::SigningMethod;
use slot_clock::SlotClock;
use state_processing::pq;
use std::collections::HashMap;
use std::time::Duration;
use std::{
    path::PathBuf,
    sync::{Arc, OnceLock},
};
use tokio::{
    sync::{OnceCell, Semaphore},
    time::{Instant, MissedTickBehavior, interval_at},
};
use tracing::{info, warn};
use types::{
    AggregateAndProof, AggregateAndProofPq, Attestation, AttestationData, AttestationProof, Domain,
    EthSpec, ForkName, Hash256, SignedAggregateAndProof, SignedAggregateAndProofPq, SignedRoot,
    SingleAttestation, SingleAttestationPq, Slot, VrfProof, XmssPublicKey, XmssSignature,
};
use validator_store::AttestationToSign;
use xmss::{LeafIndex, XmssSecretKey};

const PQ_WORKERS: usize = 8;
const PQ_KEY_LOAD_LOG_INTERVAL: Duration = Duration::from_secs(5);

enum KeyLoadOutcome {
    Prepared,
    Skipped,
    Failed,
}

#[derive(Default)]
struct Key {
    xmss: OnceLock<XmssSecretKey>,
    vrf: OnceCell<VrfTree>,
    registered_vrf_root: OnceLock<Hash256>,
}

pub(super) struct Keys {
    entries: Mutex<HashMap<PublicKeyBytes, Arc<Key>>>,
    permits: Arc<Semaphore>,
    indices: Mutex<HashMap<PublicKeyBytes, Result<Option<u32>, String>>>,
    source: Result<Option<Source>, String>,
    cache_dir: Option<PathBuf>,
}

impl Keys {
    pub(super) fn new(config: &Config) -> Self {
        Self {
            entries: Mutex::default(),
            permits: Arc::new(Semaphore::new(PQ_WORKERS)),
            indices: Mutex::default(),
            source: config.vrf_state_url.as_deref().map(Source::new).transpose(),
            cache_dir: config.vrf_state_cache_dir.clone(),
        }
    }
}

impl<T: SlotClock + 'static, E: EthSpec> LighthouseValidatorStore<T, E> {
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

    pub(super) async fn load_pq_keys(&self, pubkeys: Vec<PublicKeyBytes>) {
        if matches!(self.pq_keys.source, Ok(Some(_))) {
            let validators = self.validators.read();
            let indices = pubkeys.iter().map(|&pubkey| {
                let method = validators.signing_method(&pubkey);
                let index = match method.as_deref() {
                    Some(SigningMethod::LocalKeystore {
                        voting_keystore, ..
                    }) => vrf_state::derivation_index(voting_keystore.path().as_deref()),
                    _ => Err("PQ VRF requires a local voting keystore".into()),
                };
                (pubkey, index)
            });
            *self.pq_keys.indices.lock() = checked_vrf_indices(indices);
        }
        if pubkeys
            .iter()
            .all(|pubkey| self.local_pq_public_key(pubkey).is_some())
        {
            return;
        }

        let total = pubkeys.len();
        let started = Instant::now();
        let slot = self.slot_clock.now_or_genesis().unwrap_or_default();
        info!(total, workers = PQ_WORKERS, %slot, "Preparing PQ XMSS validator keys");

        let keys = stream::iter(pubkeys)
            .map(|pubkey| async move {
                if self.local_pq_public_key(&pubkey).is_some() {
                    return KeyLoadOutcome::Skipped;
                }
                let Ok(signing_method) = self.doppelganger_bypassed_signing_method(pubkey) else {
                    return KeyLoadOutcome::Skipped;
                };
                match self
                    .with_local_pq_key(pubkey, signing_method, move |key, bls| {
                        let key = key.xmss.get_or_init(|| xmss_key_from_bls(&bls.sk));
                        for leaf in [
                            pq::attestation_leaf_index(slot.epoch(E::slots_per_epoch())),
                            pq::slot_leaf_index(slot, pq::LEAF_OFFSET_BEACON_PROPOSER),
                        ] {
                            let leaf = LeafIndex::try_from(leaf.map_err(pq_leaf_error)?)
                                .map_err(pq_leaf_error)?;
                            key.prepare(leaf).map_err(pq_leaf_error)?;
                        }
                        Ok(())
                    })
                    .await
                {
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

    pub(super) fn local_pq_public_key(&self, pubkey: &PublicKeyBytes) -> Option<XmssPublicKey> {
        self.pq_keys
            .entries
            .lock()
            .get(pubkey)?
            .xmss
            .get()
            .map(XmssSecretKey::public_key)
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
        let index = self
            .pq_keys
            .indices
            .lock()
            .get(&pubkey)
            .cloned()
            .ok_or_else(|| Error::Middleware("PQ VRF keystore index has not been resolved".into()))?
            .map_err(Error::Middleware)?;
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
                let cache_path = self.pq_keys.cache_dir.as_ref().map(|dir| match index {
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
                let bytes = match index {
                    Some(index) => source.record(index).await,
                    None => source.record_for_root(root).await,
                }
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

            let key = key.xmss.get_or_init(|| {
                let started = Instant::now();
                info!(?pubkey, "Deriving PQ XMSS validator key");
                let xmss = xmss_key_from_bls(&bls.sk);
                info!(
                    ?pubkey,
                    elapsed_ms = started.elapsed().as_millis(),
                    "Derived PQ XMSS validator key"
                );
                xmss
            });
            let _timer = validator_metrics::start_timer(&validator_metrics::PQ_XMSS_SIGN_SECONDS);
            key.sign(&signing_root.0, leaf)
                .map_err(|error| Error::Middleware(format!("PQ signature: {error:?}")))
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

fn checked_vrf_indices(
    entries: impl IntoIterator<Item = (PublicKeyBytes, Result<Option<u32>, String>)>,
) -> HashMap<PublicKeyBytes, Result<Option<u32>, String>> {
    let mut indices = HashMap::new();
    let mut owners = HashMap::new();
    for (pubkey, index) in entries {
        let index = index.and_then(|index| {
            let Some(index) = index else {
                return Ok(None);
            };
            if let Some(previous) = owners.insert(index, pubkey) {
                let error = format!("ambiguous VRF derivation index {index} in enabled keystores");
                indices.insert(previous, Err(error.clone()));
                Err(error)
            } else {
                Ok(Some(index))
            }
        });
        indices.insert(pubkey, index);
    }
    indices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vrf_rejects_all_owners_of_duplicate_derivation_index() {
        let first = PublicKeyBytes::deserialize(&[1; 48]).unwrap();
        let second = PublicKeyBytes::deserialize(&[2; 48]).unwrap();
        let third = PublicKeyBytes::deserialize(&[3; 48]).unwrap();
        let indices = checked_vrf_indices([
            (first, Ok(Some(5))),
            (second, Ok(Some(5))),
            (third, Ok(Some(8))),
        ]);
        assert!(indices[&first].is_err());
        assert!(indices[&second].is_err());
        assert_eq!(indices[&third], Ok(Some(8)));
    }
}

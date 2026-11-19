use super::{Error, LighthouseValidatorStore};
use bls::{Keypair, PublicKeyBytes};
use futures::{StreamExt, stream};
use genesis::pq::{VrfTree, xmss_key_from_bls};
use parking_lot::Mutex;
use signing_method::SigningMethod;
use slot_clock::SlotClock;
use state_processing::pq;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::{
    sync::Semaphore,
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
    vrf: OnceLock<VrfTree>,
}

pub(super) struct Keys {
    entries: Mutex<HashMap<PublicKeyBytes, Arc<Key>>>,
    permits: Arc<Semaphore>,
}

impl Default for Keys {
    fn default() -> Self {
        Self {
            entries: Mutex::default(),
            permits: Arc::new(Semaphore::new(PQ_WORKERS)),
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

    pub(super) async fn pq_vrf_proof(
        &self,
        pubkey: PublicKeyBytes,
        slot: Slot,
    ) -> Result<VrfProof, Error> {
        let signing_method = self.doppelganger_checked_signing_method(pubkey)?;
        self.with_local_pq_key(pubkey, signing_method, move |key, bls| {
            key.vrf
                .get_or_init(|| {
                    let started = Instant::now();
                    info!(?pubkey, %slot, "Computing PQ RANDAO VRF tree");
                    let tree = VrfTree::from_bls(&bls.sk);
                    info!(
                        ?pubkey,
                        %slot,
                        elapsed_ms = started.elapsed().as_millis(),
                        "Computed PQ RANDAO VRF tree"
                    );
                    tree
                })
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

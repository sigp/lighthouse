use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::{
    block_service::BlockServiceNotification, http_metrics::metrics, validator_store::ValidatorStore,
};
use environment::RuntimeContext;
use eth2::types::{AttesterData, BeaconCommitteeSubscription, ProposerData, StateId, ValidatorId};
use futures::channel::mpsc::Sender;
use futures::SinkExt;
use parking_lot::{Mutex, RwLock};
use safe_arith::ArithError;
use slog::{debug, error, warn, Logger};
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::time::{interval_at, Duration, Instant};
use types::{ChainSpec, Epoch, EthSpec, Hash256, PublicKeyBytes, SelectionProof, Slot};

#[derive(Debug)]
pub enum Error {
    UnableToReadSlotClock,
    FailedToDownloadProposers(String),
    FailedToDownloadAttesters(String),
    FailedToProduceSelectionProof,
    InvalidModulo(ArithError),
}

#[derive(Clone)]
pub struct DutyAndProof {
    pub duty: AttesterData,
    pub selection_proof: Option<SelectionProof>,
}

impl DutyAndProof {
    pub fn new<T: SlotClock + 'static, E: EthSpec>(
        duty: AttesterData,
        validator_store: &ValidatorStore<T, E>,
        spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let selection_proof = validator_store
            .produce_selection_proof(&duty.pubkey, duty.slot)
            .ok_or(Error::FailedToProduceSelectionProof)?;

        let selection_proof = selection_proof
            .is_aggregator(duty.committee_length as usize, spec)
            .map_err(Error::InvalidModulo)
            .map(|is_aggregator| {
                if is_aggregator {
                    Some(selection_proof)
                } else {
                    None
                }
            })?;

        Ok(Self {
            duty,
            selection_proof,
        })
    }
}

pub struct IndicesMap<T: SlotClock + 'static, E: EthSpec> {
    map: HashMap<PublicKeyBytes, u64>,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    log: Logger,
}

impl<T: SlotClock + 'static, E: EthSpec> IndicesMap<T, E> {
    async fn get(&mut self, pubkey: PublicKeyBytes) -> Option<u64> {
        if let Some(i) = self.map.get(&pubkey) {
            return Some(*i);
        }

        let download_result = self
            .beacon_nodes
            .first_success(RequireSynced::No, |beacon_node| async move {
                beacon_node
                    .get_beacon_states_validator_id(StateId::Head, &ValidatorId::PublicKey(pubkey))
                    .await
            })
            .await;

        match download_result {
            Ok(response) => {
                let i = response?.data.index;
                self.map.insert(pubkey, i);
                Some(i)
            }
            Err(e) => {
                error!(
                    self.log,
                    "Failed to resolve pubkey to index";
                    "error" => %e,
                    "pubkey" => %pubkey,
                );
                None
            }
        }
    }
}

type DependentRoot = Hash256;

type AttesterMap = HashMap<PublicKeyBytes, HashMap<Epoch, (DependentRoot, DutyAndProof)>>;
type ProposerMap = HashMap<Epoch, (DependentRoot, Vec<ProposerData>)>;

pub struct DutiesService<T: SlotClock + 'static, E: EthSpec> {
    attesters: RwLock<AttesterMap>,
    proposers: RwLock<ProposerMap>,
    indices: Mutex<IndicesMap<T, E>>,
    validator_store: ValidatorStore<T, E>,
    pub(crate) slot_clock: T,
    pub(crate) beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    require_synced: RequireSynced,
    context: RuntimeContext<E>,
    spec: Arc<ChainSpec>,
}

impl<T: SlotClock + 'static, E: EthSpec> DutiesService<T, E> {
    /// Returns the total number of validators known to the duties service.
    pub fn total_validator_count(&self) -> usize {
        self.validator_store.num_voting_validators()
    }

    /// Returns the total number of validators that should propose in the given epoch.
    pub fn proposer_count(&self, epoch: Epoch) -> usize {
        self.proposers
            .read()
            .get(&epoch)
            .map_or(0, |(_, proposers)| proposers.len())
    }

    /// Returns the total number of validators that should attest in the given epoch.
    pub fn attester_count(&self, epoch: Epoch) -> usize {
        self.attesters
            .read()
            .iter()
            .filter(|(_, map)| map.contains_key(&epoch))
            .count()
    }

    /// Returns the pubkeys of the validators which are assigned to propose in the given slot.
    ///
    /// It is possible that multiple validators have an identical proposal slot, however that is
    /// likely the result of heavy forking (lol) or inconsistent beacon node connections.
    pub fn block_proposers(&self, slot: Slot) -> Vec<PublicKeyBytes> {
        let epoch = slot.epoch(E::slots_per_epoch());

        self.proposers
            .read()
            .get(&epoch)
            .map(|(_, proposers)| {
                proposers
                    .iter()
                    .filter(|proposer_data| proposer_data.slot == slot)
                    .map(|proposer_data| proposer_data.pubkey)
                    .collect()
            })
            .unwrap_or_else(|| vec![])
    }

    /// Returns all `ValidatorDuty` for the given `slot`.
    pub fn attesters(&self, slot: Slot) -> Vec<DutyAndProof> {
        let epoch = slot.epoch(E::slots_per_epoch());

        self.attesters
            .read()
            .iter()
            .filter_map(|(_, map)| map.get(&epoch))
            .map(|(_, duty_and_proof)| duty_and_proof)
            .filter(|duty_and_proof| duty_and_proof.duty.slot == slot)
            .cloned()
            .collect()
    }

    /// Start the service that periodically polls the beacon node for validator duties.
    pub fn start_update_service(
        self,
        block_service_tx: Sender<BlockServiceNotification>,
        spec: Arc<ChainSpec>,
    ) -> Result<Arc<Self>, String> {
        todo!();
    }
}

async fn poll_beacon_attesters<T: SlotClock, E: EthSpec>(
    duties_service: Arc<DutiesService<T, E>>,
) -> Result<(), Error> {
    let log = duties_service.context.log();

    let slot = duties_service
        .slot_clock
        .now()
        .ok_or(Error::UnableToReadSlotClock)?;
    let epoch = slot.epoch(E::slots_per_epoch());
    let next_epoch = epoch + 1;

    let local_pubkeys: HashSet<PublicKeyBytes> = duties_service
        .validator_store
        .voting_pubkeys()
        .into_iter()
        .collect();

    // No need to proceed if there are no local validators.
    if local_pubkeys.is_empty() {
        return Ok(());
    }

    let mut local_indices = Vec::with_capacity(local_pubkeys.len());
    let mut indices_map = duties_service.indices.lock();
    for &pubkey in &local_pubkeys {
        if let Some(validator_index) = indices_map.get(pubkey).await {
            local_indices.push(validator_index)
        }
    }

    if let Err(e) =
        poll_beacon_attesters_for_epoch(&duties_service, epoch, &local_indices, &local_pubkeys)
            .await
    {
        error!(
            log,
            "Failed to download attester duties";
            "current_epoch" => epoch,
            "request_epoch" => epoch,
            "err" => ?e,
        )
    }

    let subscriptions = duties_service
        .attesters
        .read()
        .iter()
        .filter_map(|(_, map)| map.get(&epoch))
        .map(|(_, duty_and_proof)| {
            let duty = &duty_and_proof.duty;
            let is_aggregator = duty_and_proof.selection_proof.is_some();

            BeaconCommitteeSubscription {
                validator_index: duty.validator_index,
                committee_index: duty.committee_index,
                committees_at_slot: duty.committees_at_slot,
                slot: duty.slot,
                is_aggregator,
            }
        })
        .collect::<Vec<_>>();

    let subscriptions_ref = &subscriptions;
    if let Err(e) = duties_service
        .beacon_nodes
        .first_success(RequireSynced::No, |beacon_node| async move {
            beacon_node
                .post_validator_beacon_committee_subscriptions(subscriptions_ref)
                .await
        })
        .await
    {
        error!(
            log,
            "Failed to subscribe validators";
            "error" => %e
        )
    }

    if let Err(e) =
        poll_beacon_attesters_for_epoch(&duties_service, next_epoch, &local_indices, &local_pubkeys)
            .await
    {
        error!(
            log,
            "Failed to download attester duties";
            "current_epoch" => epoch,
            "request_epoch" => next_epoch,
            "err" => ?e,
        )
    }

    Ok(())
}

async fn poll_beacon_attesters_for_epoch<T: SlotClock, E: EthSpec>(
    duties_service: &DutiesService<T, E>,
    epoch: Epoch,
    local_indices: &[u64],
    local_pubkeys: &HashSet<PublicKeyBytes>,
) -> Result<(), Error> {
    let log = duties_service.context.log();

    let response = duties_service
        .beacon_nodes
        .first_success(duties_service.require_synced, |beacon_node| async move {
            beacon_node
                .post_validator_duties_attester(epoch, local_indices)
                .await
        })
        .await
        .map_err(|e| Error::FailedToDownloadAttesters(e.to_string()))?;

    let dependent_root = response.dependent_root;

    let relevant_duties = response
        .data
        .into_iter()
        .filter(|attester_duty| local_pubkeys.contains(&attester_duty.pubkey))
        .collect::<Vec<_>>();

    debug!(
        log,
        "Downloaded attester duties";
        "dependent_root" => %dependent_root,
        "num_relevant_duties" => relevant_duties.len(),
    );

    let mut already_warned = Some(());
    let mut attesters_map = duties_service.attesters.write();
    for duty in relevant_duties {
        let proposer_map = attesters_map.entry(duty.pubkey).or_default();

        if proposer_map
            .get(&epoch)
            .map_or(true, |(prior, _)| *prior != dependent_root)
        {
            let duty_and_proof =
                DutyAndProof::new(duty, &duties_service.validator_store, &duties_service.spec)?;

            if let Some((prior_dependent_root, _)) =
                proposer_map.insert(epoch, (dependent_root, duty_and_proof))
            {
                // Only warn once per update, not once per validator.
                if already_warned.take().is_some() {
                    if dependent_root != prior_dependent_root {
                        warn!(
                            log,
                            "Attester duties re-org";
                            "prior_dependent_root" => %prior_dependent_root,
                            "dependent_root" => %dependent_root,
                            "msg" => "this may happen from time to time"
                        )
                    }
                }
            }
        }
    }

    Ok(())
}

async fn poll_beacon_proposers<T: SlotClock, E: EthSpec>(
    duties_service: Arc<DutiesService<T, E>>,
    mut block_service_tx: Sender<BlockServiceNotification>,
) -> Result<(), Error> {
    let log = duties_service.context.log();

    let slot = duties_service
        .slot_clock
        .now()
        .ok_or(Error::UnableToReadSlotClock)?;
    let epoch = slot.epoch(E::slots_per_epoch());

    let local_pubkeys: HashSet<PublicKeyBytes> = duties_service
        .validator_store
        .voting_pubkeys()
        .into_iter()
        .collect();

    // No need to poll if there are no local validators.
    if local_pubkeys.is_empty() {
        return Ok(());
    }

    let download_result = duties_service
        .beacon_nodes
        .first_success(duties_service.require_synced, |beacon_node| async move {
            beacon_node.get_validator_duties_proposer(epoch).await
        })
        .await;

    match download_result {
        Ok(response) => {
            let dependent_root = response.dependent_root;

            let relevant_duties = response
                .data
                .into_iter()
                .filter(|proposer_duty| local_pubkeys.contains(&proposer_duty.pubkey))
                .collect::<Vec<_>>();

            debug!(
                log,
                "Downloaded proposer duties";
                "dependent_root" => %dependent_root,
                "num_relevant_duties" => relevant_duties.len(),
            );

            if let Some((prior_dependent_root, _)) = duties_service
                .proposers
                .write()
                .insert(epoch, (dependent_root, relevant_duties))
            {
                if dependent_root != prior_dependent_root {
                    warn!(
                        log,
                        "Proposer duties re-org";
                        "prior_dependent_root" => %prior_dependent_root,
                        "dependent_root" => %dependent_root,
                        "msg" => "this may happen from time to time"
                    )
                }
            }
        }
        // Don't return early here, we still want to try and produce blocks using the cached values.
        Err(e) => error!(
            log,
            "Failed to download proposer duties";
            "err" => %e,
        ),
    }

    // Notify the block service to produce a block.
    if let Err(e) = block_service_tx
        .send(BlockServiceNotification {
            slot,
            block_proposers: duties_service.block_proposers(slot),
        })
        .await
    {
        error!(
            log,
            "Failed to notify block service";
            "error" => format!("{:?}", e)
        );
    };

    Ok(())
}

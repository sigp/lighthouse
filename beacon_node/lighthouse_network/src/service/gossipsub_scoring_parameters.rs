use crate::TopicHash;
use crate::types::{GossipEncoding, GossipKind, GossipTopic};
use libp2p::gossipsub::{
    IdentTopic as Topic, PeerScoreParams, PeerScoreThresholds, TopicScoreParams,
};
use std::cmp::max;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::time::Duration;
use types::{
    ChainSpec, DataColumnSubnetId, EthSpec, ForkContext, ForkName, Slot, SubnetId, SyncSubnetId,
    consts::altair::{SYNC_COMMITTEE_SUBNET_COUNT, TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE},
};

const MAX_IN_MESH_SCORE: f64 = 10.0;
const MAX_FIRST_MESSAGE_DELIVERIES_SCORE: f64 = 40.0;
const BEACON_BLOCK_WEIGHT: f64 = 0.5;
const BEACON_AGGREGATE_PROOF_WEIGHT: f64 = 0.5;
const VOLUNTARY_EXIT_WEIGHT: f64 = 0.05;
const PROPOSER_SLASHING_WEIGHT: f64 = 0.05;
const ATTESTER_SLASHING_WEIGHT: f64 = 0.05;
const SYNC_COMMITTEE_SUBNETS_TOTAL_WEIGHT: f64 = 0.4;
const SYNC_CONTRIBUTION_WEIGHT: f64 = 0.2;
const BLS_TO_EXECUTION_CHANGE_WEIGHT: f64 = 0.05;
const LIGHT_CLIENT_FINALITY_UPDATE_WEIGHT: f64 = 0.05;
const LIGHT_CLIENT_OPTIMISTIC_UPDATE_WEIGHT: f64 = 0.05;
const DATA_COLUMN_SIDECAR_SUBNETS_TOTAL_WEIGHT: f64 = 1.0;
const EXECUTION_PAYLOAD_WEIGHT: f64 = 0.5;
const EXECUTION_PAYLOAD_BID_WEIGHT: f64 = 0.25;
const PAYLOAD_ATTESTATION_WEIGHT: f64 = 0.5;
const PROPOSER_PREFERENCES_WEIGHT: f64 = 0.05;
const EXECUTION_PROOF_WEIGHT: f64 = 0.05;

/// The time window (seconds) that we expect messages to be forwarded to us in the mesh.
const MESH_MESSAGE_DELIVERIES_WINDOW: u64 = 2;

// Const as this is used in the peer manager to prevent gossip from disconnecting peers.
pub const GREYLIST_THRESHOLD: f64 = -16000.0;

/// Builds the peer score thresholds.
pub fn lighthouse_gossip_thresholds() -> PeerScoreThresholds {
    PeerScoreThresholds {
        gossip_threshold: -4000.0,
        publish_threshold: -8000.0,
        graylist_threshold: GREYLIST_THRESHOLD,
        accept_px_threshold: 100.0,
        opportunistic_graft_threshold: 5.0,
    }
}

pub struct PeerScoreSettings<E: EthSpec> {
    slot: Duration,
    epoch: Duration,

    beacon_attestation_subnet_weight: f64,
    max_positive_score: f64,

    decay_interval: Duration,
    decay_to_zero: f64,

    mesh_n: usize,
    max_committees_per_slot: usize,
    target_committee_size: usize,
    target_aggregators_per_committee: usize,
    attestation_subnet_count: u64,
    data_column_subnet_count: u64,
    phantom: PhantomData<E>,
}

impl<E: EthSpec> PeerScoreSettings<E> {
    pub fn new(chain_spec: &ChainSpec, mesh_n: usize) -> PeerScoreSettings<E> {
        let slot = chain_spec.get_slot_duration();
        let beacon_attestation_subnet_weight = 1.0 / chain_spec.attestation_subnet_count as f64;
        let max_positive_score = (MAX_IN_MESH_SCORE + MAX_FIRST_MESSAGE_DELIVERIES_SCORE)
            * (BEACON_BLOCK_WEIGHT
                + BEACON_AGGREGATE_PROOF_WEIGHT
                + beacon_attestation_subnet_weight * chain_spec.attestation_subnet_count as f64
                + VOLUNTARY_EXIT_WEIGHT
                + PROPOSER_SLASHING_WEIGHT
                + ATTESTER_SLASHING_WEIGHT
                + SYNC_COMMITTEE_SUBNETS_TOTAL_WEIGHT
                + SYNC_CONTRIBUTION_WEIGHT
                + BLS_TO_EXECUTION_CHANGE_WEIGHT
                + LIGHT_CLIENT_FINALITY_UPDATE_WEIGHT
                + LIGHT_CLIENT_OPTIMISTIC_UPDATE_WEIGHT
                + DATA_COLUMN_SIDECAR_SUBNETS_TOTAL_WEIGHT
                + EXECUTION_PAYLOAD_WEIGHT
                + EXECUTION_PAYLOAD_BID_WEIGHT
                + PAYLOAD_ATTESTATION_WEIGHT
                + PROPOSER_PREFERENCES_WEIGHT
                + EXECUTION_PROOF_WEIGHT);

        PeerScoreSettings {
            slot,
            epoch: slot * E::slots_per_epoch() as u32,
            beacon_attestation_subnet_weight,
            max_positive_score,
            decay_interval: max(Duration::from_secs(1), slot),
            decay_to_zero: 0.01,
            mesh_n,
            max_committees_per_slot: chain_spec.max_committees_per_slot,
            target_committee_size: chain_spec.target_committee_size,
            target_aggregators_per_committee: chain_spec.target_aggregators_per_committee as usize,
            attestation_subnet_count: chain_spec.attestation_subnet_count,
            data_column_subnet_count: chain_spec.data_column_sidecar_subnet_count,
            phantom: PhantomData,
        }
    }

    pub fn get_peer_score_params(
        &self,
        active_validators: usize,
        thresholds: &PeerScoreThresholds,
        fork_context: &ForkContext,
        spec: &ChainSpec,
        current_slot: Slot,
    ) -> Result<PeerScoreParams, String> {
        let mut params = PeerScoreParams {
            decay_interval: self.decay_interval,
            decay_to_zero: self.decay_to_zero,
            retain_score: self.epoch * 100,
            app_specific_weight: 1.0,
            ip_colocation_factor_threshold: 8.0, // Allow up to 8 nodes per IP
            behaviour_penalty_threshold: 6.0,
            behaviour_penalty_decay: self.score_parameter_decay(self.epoch * 10),
            slow_peer_decay: 0.1,
            slow_peer_weight: -10.0,
            slow_peer_threshold: 0.0,
            ..Default::default()
        };

        let target_value = Self::decay_convergence(
            params.behaviour_penalty_decay,
            10.0 / E::slots_per_epoch() as f64,
        ) - params.behaviour_penalty_threshold;
        params.behaviour_penalty_weight = thresholds.gossip_threshold / target_value.powi(2);

        params.topic_score_cap = self.max_positive_score * 0.5;
        params.ip_colocation_factor_weight = -params.topic_score_cap;

        params.topics = HashMap::new();

        let (beacon_block_params, beacon_aggregate_proof_params, beacon_attestation_subnet_params) =
            self.get_dynamic_topic_params(active_validators, current_slot)?;

        // Register topic params for current and future fork digests
        let current_digest_epoch = fork_context.current_fork_epoch();
        for digest_epoch in spec.all_digest_epochs() {
            if digest_epoch < current_digest_epoch {
                continue;
            }
            self.insert_topic_params_for_digest(
                &mut params,
                fork_context.context_bytes(digest_epoch),
                spec.fork_name_at_epoch(digest_epoch),
                &beacon_block_params,
                &beacon_aggregate_proof_params,
                &beacon_attestation_subnet_params,
            );
        }

        Ok(params)
    }

    /// Inserts the topic params for all topics that exist at `fork_name`.
    #[allow(clippy::too_many_arguments)]
    fn insert_topic_params_for_digest(
        &self,
        params: &mut PeerScoreParams,
        fork_digest: [u8; 4],
        fork_name: ForkName,
        beacon_block_params: &TopicScoreParams,
        beacon_aggregate_proof_params: &TopicScoreParams,
        beacon_attestation_subnet_params: &TopicScoreParams,
    ) {
        let get_hash = |kind: GossipKind| -> TopicHash {
            let topic: Topic =
                GossipTopic::new(kind, GossipEncoding::default(), fork_digest).into();
            topic.hash()
        };

        //first all fixed topics
        params.topics.insert(
            get_hash(GossipKind::VoluntaryExit),
            Self::get_topic_params(
                self,
                VOLUNTARY_EXIT_WEIGHT,
                4.0 / E::slots_per_epoch() as f64,
                self.epoch * 100,
                None,
            ),
        );
        params.topics.insert(
            get_hash(GossipKind::AttesterSlashing),
            Self::get_topic_params(
                self,
                ATTESTER_SLASHING_WEIGHT,
                1.0 / 5.0 / E::slots_per_epoch() as f64,
                self.epoch * 100,
                None,
            ),
        );
        params.topics.insert(
            get_hash(GossipKind::ProposerSlashing),
            Self::get_topic_params(
                self,
                PROPOSER_SLASHING_WEIGHT,
                1.0 / 5.0 / E::slots_per_epoch() as f64,
                self.epoch * 100,
                None,
            ),
        );

        //dynamic topics
        params.topics.insert(
            get_hash(GossipKind::BeaconBlock),
            beacon_block_params.clone(),
        );

        params.topics.insert(
            get_hash(GossipKind::BeaconAggregateAndProof),
            beacon_aggregate_proof_params.clone(),
        );

        for i in 0..self.attestation_subnet_count {
            params.topics.insert(
                get_hash(GossipKind::Attestation(SubnetId::new(i))),
                beacon_attestation_subnet_params.clone(),
            );
        }

        // Post-phase0 topics get first-message-delivery rewards and invalid-message penalties
        // only. Mesh delivery penalties stay disabled until we have data to tune the thresholds,
        // which matches what other clients run in production.
        if fork_name.altair_enabled() {
            params.topics.insert(
                get_hash(GossipKind::SignedContributionAndProof),
                Self::get_topic_params(
                    self,
                    SYNC_CONTRIBUTION_WEIGHT,
                    (SYNC_COMMITTEE_SUBNET_COUNT * TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE) as f64,
                    self.epoch,
                    None,
                ),
            );

            let sync_subnet_params = Self::get_topic_params(
                self,
                SYNC_COMMITTEE_SUBNETS_TOTAL_WEIGHT / SYNC_COMMITTEE_SUBNET_COUNT as f64,
                E::sync_committee_size() as f64 / SYNC_COMMITTEE_SUBNET_COUNT as f64,
                self.epoch,
                None,
            );
            for i in 0..SYNC_COMMITTEE_SUBNET_COUNT {
                params.topics.insert(
                    get_hash(GossipKind::SyncCommitteeMessage(SyncSubnetId::new(i))),
                    sync_subnet_params.clone(),
                );
            }

            params.topics.insert(
                get_hash(GossipKind::LightClientFinalityUpdate),
                Self::get_topic_params(
                    self,
                    LIGHT_CLIENT_FINALITY_UPDATE_WEIGHT,
                    4.0 / E::slots_per_epoch() as f64,
                    self.epoch * 100,
                    None,
                ),
            );
            params.topics.insert(
                get_hash(GossipKind::LightClientOptimisticUpdate),
                Self::get_topic_params(
                    self,
                    LIGHT_CLIENT_OPTIMISTIC_UPDATE_WEIGHT,
                    4.0 / E::slots_per_epoch() as f64,
                    self.epoch * 100,
                    None,
                ),
            );
        }

        if fork_name.capella_enabled() {
            params.topics.insert(
                get_hash(GossipKind::BlsToExecutionChange),
                Self::get_topic_params(
                    self,
                    BLS_TO_EXECUTION_CHANGE_WEIGHT,
                    4.0 / E::slots_per_epoch() as f64,
                    self.epoch * 100,
                    None,
                ),
            );
        }

        if fork_name.fulu_enabled() {
            // Each subnet carries at most one column sidecar per slot, and none when the block
            // has no blobs.
            let column_subnet_params = Self::get_topic_params(
                self,
                DATA_COLUMN_SIDECAR_SUBNETS_TOTAL_WEIGHT / self.data_column_subnet_count as f64,
                1.0,
                self.epoch * 20,
                None,
            );
            for i in 0..self.data_column_subnet_count {
                params.topics.insert(
                    get_hash(GossipKind::DataColumnSidecar(DataColumnSubnetId::new(i))),
                    column_subnet_params.clone(),
                );
            }
        }

        if fork_name.gloas_enabled() {
            params.topics.insert(
                get_hash(GossipKind::ExecutionPayload),
                Self::get_topic_params(self, EXECUTION_PAYLOAD_WEIGHT, 1.0, self.epoch * 20, None),
            );
            params.topics.insert(
                get_hash(GossipKind::ExecutionPayloadBid),
                Self::get_topic_params(self, EXECUTION_PAYLOAD_BID_WEIGHT, 2.0, self.epoch, None),
            );
            params.topics.insert(
                get_hash(GossipKind::PayloadAttestation),
                Self::get_topic_params(
                    self,
                    PAYLOAD_ATTESTATION_WEIGHT,
                    E::ptc_size() as f64,
                    self.epoch,
                    None,
                ),
            );
            params.topics.insert(
                get_hash(GossipKind::ProposerPreferences),
                Self::get_topic_params(self, PROPOSER_PREFERENCES_WEIGHT, 1.0, self.epoch, None),
            );
            params.topics.insert(
                get_hash(GossipKind::ExecutionProof),
                Self::get_topic_params(self, EXECUTION_PROOF_WEIGHT, 1.0, self.epoch, None),
            );
        }
    }

    pub fn get_dynamic_topic_params(
        &self,
        active_validators: usize,
        current_slot: Slot,
    ) -> Result<(TopicScoreParams, TopicScoreParams, TopicScoreParams), String> {
        let (aggregators_per_slot, committees_per_slot) =
            self.expected_aggregator_count_per_slot(active_validators)?;
        let multiple_bursts_per_subnet_per_epoch =
            committees_per_slot as u64 >= 2 * self.attestation_subnet_count / E::slots_per_epoch();

        let beacon_block_params = Self::get_topic_params(
            self,
            BEACON_BLOCK_WEIGHT,
            1.0,
            self.epoch * 20,
            Some((E::slots_per_epoch() * 5, 3.0, self.epoch, current_slot)),
        );

        let beacon_aggregate_proof_params = Self::get_topic_params(
            self,
            BEACON_AGGREGATE_PROOF_WEIGHT,
            aggregators_per_slot,
            self.epoch,
            Some((E::slots_per_epoch() * 2, 4.0, self.epoch, current_slot)),
        );
        let beacon_attestation_subnet_params = Self::get_topic_params(
            self,
            self.beacon_attestation_subnet_weight,
            active_validators as f64
                / self.attestation_subnet_count as f64
                / E::slots_per_epoch() as f64,
            self.epoch
                * (if multiple_bursts_per_subnet_per_epoch {
                    1
                } else {
                    4
                }),
            Some((
                E::slots_per_epoch()
                    * (if multiple_bursts_per_subnet_per_epoch {
                        4
                    } else {
                        16
                    }),
                16.0,
                if multiple_bursts_per_subnet_per_epoch {
                    self.slot * (E::slots_per_epoch() as u32 / 2 + 1)
                } else {
                    self.epoch * 3
                },
                current_slot,
            )),
        );

        Ok((
            beacon_block_params,
            beacon_aggregate_proof_params,
            beacon_attestation_subnet_params,
        ))
    }

    pub fn attestation_subnet_count(&self) -> u64 {
        self.attestation_subnet_count
    }

    fn score_parameter_decay_with_base(
        decay_time: Duration,
        decay_interval: Duration,
        decay_to_zero: f64,
    ) -> f64 {
        let ticks = decay_time.as_secs_f64() / decay_interval.as_secs_f64();
        decay_to_zero.powf(1.0 / ticks)
    }

    fn decay_convergence(decay: f64, rate: f64) -> f64 {
        rate / (1.0 - decay)
    }

    fn threshold(decay: f64, rate: f64) -> f64 {
        Self::decay_convergence(decay, rate) * decay
    }

    fn expected_aggregator_count_per_slot(
        &self,
        active_validators: usize,
    ) -> Result<(f64, usize), String> {
        let committees_per_slot = E::get_committee_count_per_slot_with(
            active_validators,
            self.max_committees_per_slot,
            self.target_committee_size,
        )
        .map_err(|e| format!("Could not get committee count from spec: {:?}", e))?;

        let committees = committees_per_slot * E::slots_per_epoch() as usize;

        let smaller_committee_size = active_validators / committees;
        let num_larger_committees = active_validators - smaller_committee_size * committees;

        let modulo_smaller = max(
            1,
            smaller_committee_size / self.target_aggregators_per_committee,
        );
        let modulo_larger = max(
            1,
            (smaller_committee_size + 1) / self.target_aggregators_per_committee,
        );

        Ok((
            (((committees - num_larger_committees) * smaller_committee_size) as f64
                / modulo_smaller as f64
                + (num_larger_committees * (smaller_committee_size + 1)) as f64
                    / modulo_larger as f64)
                / E::slots_per_epoch() as f64,
            committees_per_slot,
        ))
    }

    fn score_parameter_decay(&self, decay_time: Duration) -> f64 {
        Self::score_parameter_decay_with_base(decay_time, self.decay_interval, self.decay_to_zero)
    }

    fn get_topic_params(
        &self,
        topic_weight: f64,
        expected_message_rate: f64,
        first_message_decay_time: Duration,
        // decay slots (decay time in slots), cap factor, activation window, current slot
        mesh_message_info: Option<(u64, f64, Duration, Slot)>,
    ) -> TopicScoreParams {
        let mut t_params = TopicScoreParams::default();

        t_params.topic_weight = topic_weight;

        t_params.time_in_mesh_quantum = self.slot;
        t_params.time_in_mesh_cap = 3600.0 / t_params.time_in_mesh_quantum.as_secs_f64();
        t_params.time_in_mesh_weight = 10.0 / t_params.time_in_mesh_cap;

        t_params.first_message_deliveries_decay =
            self.score_parameter_decay(first_message_decay_time);
        t_params.first_message_deliveries_cap = Self::decay_convergence(
            t_params.first_message_deliveries_decay,
            2.0 * expected_message_rate / self.mesh_n as f64,
        );
        t_params.first_message_deliveries_weight = 40.0 / t_params.first_message_deliveries_cap;

        if let Some((decay_slots, cap_factor, activation_window, current_slot)) = mesh_message_info
        {
            let decay_time = self.slot * decay_slots as u32;
            t_params.mesh_message_deliveries_decay = self.score_parameter_decay(decay_time);
            t_params.mesh_message_deliveries_threshold = Self::threshold(
                t_params.mesh_message_deliveries_decay,
                expected_message_rate / 50.0,
            );
            t_params.mesh_message_deliveries_cap =
                if cap_factor * t_params.mesh_message_deliveries_threshold < 2.0 {
                    2.0
                } else {
                    cap_factor * t_params.mesh_message_deliveries_threshold
                };
            t_params.mesh_message_deliveries_activation = activation_window;
            t_params.mesh_message_deliveries_window =
                Duration::from_secs(MESH_MESSAGE_DELIVERIES_WINDOW);
            t_params.mesh_failure_penalty_decay = t_params.mesh_message_deliveries_decay;
            t_params.mesh_message_deliveries_weight = -t_params.topic_weight;
            t_params.mesh_failure_penalty_weight = t_params.mesh_message_deliveries_weight;
            if decay_slots >= current_slot.as_u64() {
                t_params.mesh_message_deliveries_threshold = 0.0;
                t_params.mesh_message_deliveries_weight = 0.0;
            }
        } else {
            t_params.mesh_message_deliveries_weight = 0.0;
            t_params.mesh_message_deliveries_threshold = 0.0;
            t_params.mesh_message_deliveries_decay = 0.0;
            t_params.mesh_message_deliveries_cap = 0.0;
            t_params.mesh_message_deliveries_window = Duration::from_secs(0);
            t_params.mesh_message_deliveries_activation = Duration::from_secs(0);
            t_params.mesh_failure_penalty_decay = 0.0;
            t_params.mesh_failure_penalty_weight = 0.0;
        }

        t_params.invalid_message_deliveries_weight =
            -self.max_positive_score / t_params.topic_weight;
        t_params.invalid_message_deliveries_decay = self.score_parameter_decay(self.epoch * 50);

        t_params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::all_topics_at_fork;
    use types::{Hash256, MainnetEthSpec};

    type E = MainnetEthSpec;

    /// Every gossip topic at every fork must have score params registered, otherwise gossipsub
    /// applies no scoring at all on that topic.
    #[test]
    fn all_topics_have_score_params_at_every_fork() {
        for fork_name in ForkName::list_all() {
            let spec = fork_name.make_genesis_spec(E::default_spec());
            let fork_context = ForkContext::new::<E>(Slot::new(0), Hash256::ZERO, &spec);
            let settings = PeerScoreSettings::<E>::new(&spec, 8);
            let params = settings
                .get_peer_score_params(
                    E::minimum_validator_count(),
                    &lighthouse_gossip_thresholds(),
                    &fork_context,
                    &spec,
                    Slot::new(0),
                )
                .unwrap();

            let fork_digest = fork_context.current_fork_digest();
            for kind in all_topics_at_fork::<E>(fork_name, &spec) {
                let topic: Topic =
                    GossipTopic::new(kind.clone(), GossipEncoding::default(), fork_digest).into();
                assert!(
                    params.topics.contains_key(&topic.hash()),
                    "missing score params for topic {kind} at fork {fork_name}"
                );
            }
        }
    }
}

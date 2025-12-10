use std::{collections::HashMap, sync::Arc};

use beacon_node_fallback::BeaconNodeFallback;
use safe_arith::SafeArith;
use slot_clock::SlotClock;
use tracing::{Instrument, info_span};
use types::{AttestationData, Checkpoint, Epoch, Slot};

#[derive(Debug, Clone)]
pub enum AttestationDataStrategy {
    Fallback,
    ByIndex(usize),
    Consensus((usize, Option<(Checkpoint, usize)>)),
    HighestScore,
    IgnoreEpoch(Epoch),
}

// New trait for aggregation strategies that need parallel queries
trait ResultAggregator {
    /// Process a single response and decide whether to continue or stop
    fn process_result(&mut self, attestation_data: &AttestationData, index: usize) -> bool; // Returns true if we should stop and return

    /// Get the final result after aggregation
    fn get_result(&self) -> Option<(AttestationData, usize)>;
}

// Consensus aggregator
struct ConsensusAggregator {
    results: HashMap<Checkpoint, Vec<usize>>,
    threshold: usize,
    target_checkpoint_and_index: Option<(Checkpoint, usize)>,
    consensus_result: Option<(AttestationData, usize)>,
}

impl ConsensusAggregator {
    fn new(threshold: usize, target_checkpoint_and_index: Option<(Checkpoint, usize)>) -> Self {
        Self {
            results: HashMap::new(),
            threshold,
            target_checkpoint_and_index,
            consensus_result: None,
        }
    }
}

impl ResultAggregator for ConsensusAggregator {
    fn process_result(&mut self, attestation_data: &AttestationData, index: usize) -> bool {
        if let Some((target_checkpoint, preferred_index)) = self.target_checkpoint_and_index {
            // If we have a preferred index set, return attestation data from it
            // TODO(attestation-consensus) this is a small optimization to immediately return data
            // from the preferred index. We shouldn't need to check the target checkpoint, but maybe
            // its just safer to do so?
            if preferred_index == index {
                self.consensus_result = Some((attestation_data.clone(), index));
                return true;
            }
            // return if fetched data matches the target checkpoint
            if attestation_data.target == target_checkpoint {
                self.consensus_result = Some((attestation_data.clone(), index));
                return true;
            }
        }
        self.results
            .entry(attestation_data.target)
            .or_insert_with(Vec::new)
            .push(index);

        if self
            .results
            .get(&attestation_data.target)
            .is_some_and(|servers| servers.len() >= self.threshold)
        {
            // Consensus has been reached
            self.consensus_result = Some((attestation_data.clone(), index));
            return true;
        }

        false
    }

    fn get_result(&self) -> Option<(AttestationData, usize)> {
        self.consensus_result.clone()
    }
}

// Score aggregator
struct ScoreAggregator {
    results: HashMap<usize, (u64, AttestationData)>,
    // TODO im pretty sure the head slot is just the requested slot
    // double check the attestation service before deleting this TODO.
    head_slot: Slot,
    responses_needed: usize,
    responses_received: usize,
}

impl ScoreAggregator {
    fn new(head_slot: Slot, responses_needed: usize) -> Self {
        Self {
            results: HashMap::new(),
            head_slot,
            responses_needed,
            responses_received: 0,
        }
    }

    fn calculate_score(&self, attestation_data: &AttestationData) -> u64 {
        let checkpoint_value = attestation_data.source.epoch + attestation_data.target.epoch;
        let slot_value = 1 + attestation_data.slot.as_u64() - self.head_slot.as_u64();
        // TODO unwrap
        checkpoint_value.as_u64() + 1.safe_div(slot_value).unwrap()
    }
}

impl ResultAggregator for ScoreAggregator {
    fn process_result(&mut self, attestation_data: &AttestationData, index: usize) -> bool {
        let score = self.calculate_score(attestation_data);
        self.results
            .insert(index, (score, attestation_data.clone()));
        self.responses_received += 1;

        // Stop when we've received enough responses
        self.responses_received >= self.responses_needed
    }

    fn get_result(&self) -> Option<(AttestationData, usize)> {
        self.results
            .iter()
            .max_by_key(|(_, (score, _))| score)
            .map(|(idx, (_, data))| (data.clone(), *idx))
    }
}

/// The AttestationDataService is responsible for downloading and caching attestation data at a given slot.
/// It also helps prevent us from re-downloading identical attestation data.
pub struct AttestationDataService<T> {
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
}

impl<T: SlotClock> AttestationDataService<T> {
    pub fn new(beacon_nodes: Arc<BeaconNodeFallback<T>>) -> Self {
        Self { beacon_nodes }
    }

    async fn data_by_index(
        &self,
        request_slot: &Slot,
        candidate_beacon_node: Option<usize>,
    ) -> Result<(AttestationData, usize), String> {
        self.beacon_nodes
            .first_success_from_index(candidate_beacon_node, |beacon_node| async move {
                let _timer = validator_metrics::start_timer_vec(
                    &validator_metrics::ATTESTATION_SERVICE_TIMES,
                    &[validator_metrics::ATTESTATIONS_HTTP_GET],
                );
                beacon_node
                    .get_validator_attestation_data(*request_slot, 0)
                    .await
                    .map_err(|e| format!("Failed to produce attestation data: {:?}", e))
                    .map(|result| result.data)
            })
            .instrument(info_span!("fetch_attestation_data"))
            .await
            .map_err(|e| e.to_string())
    }

    async fn data_with_aggregation(
        &self,
        request_slot: &Slot,
        mut aggregator: impl ResultAggregator,
    ) -> Result<(AttestationData, usize), String> {
        self.beacon_nodes
            .first_n_responses(
                |beacon_node| async move {
                    let _timer = validator_metrics::start_timer_vec(
                        &validator_metrics::ATTESTATION_SERVICE_TIMES,
                        &[validator_metrics::ATTESTATIONS_HTTP_GET],
                    );
                    beacon_node
                        .get_validator_attestation_data(*request_slot, 0)
                        .await
                        .map_err(|e| format!("Failed to produce attestation data: {:?}", e))
                        .map(|result| result.data)
                },
                |(attestation_data, index)| aggregator.process_result(attestation_data, *index),
            )
            .instrument(info_span!("fetch_attestation_data"))
            .await
            .map_err(|e| e.to_string())?;

        aggregator
            .get_result()
            .ok_or_else(|| "No valid attestation data found".to_string())
    }

    pub async fn download_data(
        &self,
        request_slot: &Slot,
        strategy: &AttestationDataStrategy,
    ) -> Result<(AttestationData, usize), String> {
        match strategy {
            AttestationDataStrategy::Fallback => self.data_by_index(request_slot, None).await,
            AttestationDataStrategy::ByIndex(index) => {
                self.data_by_index(request_slot, Some(*index)).await
            }
            AttestationDataStrategy::Consensus((threshold, checkpoint_and_index)) => {
                let consensus_aggregator =
                    ConsensusAggregator::new(*threshold, checkpoint_and_index.clone());
                self.data_with_aggregation(request_slot, consensus_aggregator)
                    .await
            }
            AttestationDataStrategy::IgnoreEpoch(epoch) => Err(format!(
                "Disabled attestation production for epoch {:?}",
                epoch
            )),
            AttestationDataStrategy::HighestScore => {
                let aggregator =
                    ScoreAggregator::new(*request_slot, self.beacon_nodes.num_total().await);
                self.data_with_aggregation(request_slot, aggregator).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use beacon_node_fallback::{BeaconNodeFallback, CandidateBeaconNode, Config as FallbackConfig};
    use eth2::{SensitiveUrl, Timeouts};
    use slot_clock::{SlotClock, TestingSlotClock};
    use types::{
        AttestationData, Checkpoint, Epoch, EthSpec, FixedBytesExtended, Hash256, MainnetEthSpec,
        MinimalEthSpec, Slot,
    };

    use crate::attestation_data_service::{AttestationDataService, AttestationDataStrategy};

    fn create_attestation_data(
        slot: Slot,
        source_epoch: Epoch,
        target_epoch: Epoch,
    ) -> AttestationData {
        AttestationData {
            slot,
            index: 0,
            beacon_block_root: Hash256::ZERO,
            source: Checkpoint {
                epoch: source_epoch,
                root: Hash256::ZERO,
            },
            target: Checkpoint {
                epoch: target_epoch,
                root: Hash256::from_low_u64_be(target_epoch.as_u64()),
            },
        }
    }

    // Helper to create a beacon node with mocked attestation endpoint
    async fn create_mocked_beacon_node(
        index: usize,
        slot: Slot,
        attestation_data: AttestationData,
    ) -> (mockito::ServerGuard, CandidateBeaconNode) {
        use eth2::types::GenericResponse;
        use mockito::{Matcher, Server};
        use regex::Regex;

        let mut server = Server::new_async().await;
        let data = GenericResponse::from(attestation_data);

        let path_pattern = Regex::new(&format!(
            r"^/eth/v1/validator/attestation_data\?slot={}&committee_index=0$",
            slot.as_u64()
        ))
        .unwrap();

        server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .with_status(200)
            .with_body(serde_json::to_string(&data).unwrap())
            .create();

        let url = SensitiveUrl::parse(&server.url()).unwrap();
        let client = eth2::BeaconNodeHttpClient::new_with_index(
            url,
            Timeouts::set_all(Duration::from_secs(1)),
            index,
        );
        let candidate = CandidateBeaconNode::new(client);

        (server, candidate)
    }

    async fn create_offline_beacon_node(
        index: usize,
    ) -> (mockito::ServerGuard, CandidateBeaconNode) {
        use mockito::{Matcher, Server};
        use regex::Regex;

        let mut server = Server::new_async().await;
        let path_pattern = Regex::new(r"^/eth/v1/validator/attestation_data").unwrap();

        server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .with_status(500)
            .create();

        let url = SensitiveUrl::parse(&server.url()).unwrap();
        let client = eth2::BeaconNodeHttpClient::new_with_index(
            url,
            Timeouts::set_all(Duration::from_secs(1)),
            index,
        );
        let candidate = CandidateBeaconNode::new(client);

        (server, candidate)
    }

    #[tokio::test]
    async fn test_download_attestation_data() {
        let spec = Arc::new(MinimalEthSpec::default_spec());
        let slot = Slot::new(10);
        let attestation_data = create_attestation_data(slot, Epoch::new(0), Epoch::new(1));

        let (_server, beacon_node) =
            create_mocked_beacon_node(0, slot, attestation_data.clone()).await;

        let mut fallback =
            BeaconNodeFallback::new(vec![beacon_node], FallbackConfig::default(), vec![], spec);

        fallback.set_slot_clock(TestingSlotClock::new(
            Slot::new(1),
            Duration::from_secs(0),
            Duration::from_secs(12),
        ));

        let service = AttestationDataService::<TestingSlotClock>::new(Arc::new(fallback));
        let result = service
            .download_data(&slot, &AttestationDataStrategy::Fallback)
            .await;

        // Verify download is successful
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (attestation_data.clone(), 0));
    }

    #[tokio::test]
    async fn test_download_attestation_data_all_nodes_offline() {
        let spec = Arc::new(MainnetEthSpec::default_spec());
        let slot = Slot::new(10);

        // Create two offline nodes
        let (_server1, beacon_node_1) = create_offline_beacon_node(0).await;
        let (_server2, beacon_node_2) = create_offline_beacon_node(1).await;

        let mut fallback = BeaconNodeFallback::new(
            vec![beacon_node_1, beacon_node_2],
            FallbackConfig::default(),
            vec![],
            spec,
        );

        fallback.set_slot_clock(TestingSlotClock::new(
            Slot::new(1),
            Duration::from_secs(0),
            Duration::from_secs(12),
        ));

        let service = AttestationDataService::<TestingSlotClock>::new(Arc::new(fallback));
        let result = service
            .download_data(&slot, &AttestationDataStrategy::Fallback)
            .await;

        // Verify all nodes offline
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Failed to produce attestation data")
        );
    }

    #[tokio::test]
    async fn test_download_attestation_data_node_fallback() {
        let spec = Arc::new(MainnetEthSpec::default_spec());
        let slot = Slot::new(10);
        let attestation_data = create_attestation_data(slot, Epoch::new(0), Epoch::new(1));

        // Create one offline node and one working node
        let (_server1, beacon_node_1) = create_offline_beacon_node(0).await;
        let (_server2, beacon_node_2) =
            create_mocked_beacon_node(1, slot, attestation_data.clone()).await;
        let (_server2, beacon_node_3) =
            create_mocked_beacon_node(2, slot, attestation_data.clone()).await;

        let mut fallback = BeaconNodeFallback::new(
            vec![beacon_node_1, beacon_node_2, beacon_node_3],
            FallbackConfig::default(),
            vec![],
            spec,
        );

        fallback.set_slot_clock(TestingSlotClock::new(
            Slot::new(1),
            Duration::from_secs(0),
            Duration::from_secs(12),
        ));

        let service = AttestationDataService::<TestingSlotClock>::new(Arc::new(fallback));
        let result = service
            .download_data(&slot, &AttestationDataStrategy::Fallback)
            .await;

        // Verify download is successful and we fell back to the next node
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (attestation_data.clone(), 1));
    }
}

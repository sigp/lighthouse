use std::sync::Arc;

use beacon_node_fallback::BeaconNodeFallback;
use slot_clock::SlotClock;
use tracing::{Instrument, info_span};
use types::{AttestationData, Slot};

/// The AttestationDataService is responsible for downloading and caching attestation data at a given slot.
/// It also helps prevent us from re-downloading identical attestation data.
pub struct AttestationDataService<T> {
    attestation_data: Option<(Slot, AttestationData, usize)>,
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
}

impl<T: SlotClock> AttestationDataService<T> {
    pub fn new(beacon_nodes: Arc<BeaconNodeFallback<T>>) -> Self {
        Self {
            attestation_data: None,
            beacon_nodes,
        }
    }

    /// Get previously downloaded attestation data.
    pub fn get_cached_attestation_data(
        &self,
        requested_slot: &Slot,
    ) -> Option<(AttestationData, usize)> {
        if let Some((cached_slot, attestation_data, node_index)) = &self.attestation_data
            && cached_slot == requested_slot
        {
            return Some((attestation_data.clone(), *node_index));
        }
        None
    }

    pub async fn download_data(
        &mut self,
        request_slot: &Slot,
        candidate_beacon_node: Option<usize>,
    ) -> Result<(AttestationData, usize), String> {
        // If we've already downloaded attestation data for `request_slot`, there's no need to re-download the data.
        if let Some((attestation_data, node_index)) = self.get_cached_attestation_data(request_slot)
        {
            return Ok((attestation_data, node_index));
        }

        let (attestation_data, node_index) = self
            .beacon_nodes
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
            .map_err(|e| e.to_string())?;

        self.attestation_data = Some((*request_slot, attestation_data.clone(), node_index));

        Ok((attestation_data, node_index))
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

    use crate::attestation_data_service::AttestationDataService;

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

    fn create_test_beacon_node_fallback() -> BeaconNodeFallback<TestingSlotClock> {
        let spec = Arc::new(MainnetEthSpec::default_spec());
        let url = SensitiveUrl::parse("http://localhost:5052").unwrap();
        let client =
            eth2::BeaconNodeHttpClient::new(url, Timeouts::set_all(Duration::from_secs(1)));
        let candidate = CandidateBeaconNode::new(client);

        let mut fallback =
            BeaconNodeFallback::new(vec![candidate], FallbackConfig::default(), vec![], spec);

        fallback.set_slot_clock(TestingSlotClock::new(
            Slot::new(1),
            Duration::from_secs(0),
            Duration::from_secs(12),
        ));

        fallback
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

    #[test]
    fn test_new_service() {
        let beacon_node_fallback = create_test_beacon_node_fallback();
        let service =
            AttestationDataService::<TestingSlotClock>::new(Arc::new(beacon_node_fallback));

        assert!(service.attestation_data.is_none());
        assert!(service.get_cached_attestation_data(&Slot::new(1)).is_none());
    }

    #[test]
    fn test_get_cached_attestation_data_returns_cached() {
        let beacon_node_fallback = create_test_beacon_node_fallback();
        let mut service =
            AttestationDataService::<TestingSlotClock>::new(Arc::new(beacon_node_fallback));

        let slot = Slot::new(10);
        let beacon_node_index = 0;
        let attestation_data = create_attestation_data(slot, Epoch::new(0), Epoch::new(1));
        service.attestation_data = Some((slot, attestation_data.clone(), beacon_node_index));

        let cached = service.get_cached_attestation_data(&slot);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), (attestation_data, beacon_node_index));
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

        let mut service = AttestationDataService::<TestingSlotClock>::new(Arc::new(fallback));
        let result = service.download_data(&slot, None).await;

        // Verify download is successful
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (attestation_data.clone(), 0));

        // Verify data is cached after successful download
        assert_eq!(
            service.get_cached_attestation_data(&slot),
            Some((attestation_data, 0))
        );
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

        let mut service = AttestationDataService::<TestingSlotClock>::new(Arc::new(fallback));
        let result = service.download_data(&slot, None).await;

        // Verify all nodes offline
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Failed to produce attestation data")
        );

        // Verify no data was cached since all nodes failed
        assert_eq!(service.get_cached_attestation_data(&slot), None);
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

        let mut service = AttestationDataService::<TestingSlotClock>::new(Arc::new(fallback));
        let result = service.download_data(&slot, None).await;

        // Verify download is successful and we fell back to the next node
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (attestation_data.clone(), 1));

        // Verify data is cached after successful download
        assert_eq!(
            service.get_cached_attestation_data(&slot),
            Some((attestation_data, 1))
        );
    }
}

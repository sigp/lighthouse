use std::marker::PhantomData;
use std::str::FromStr;
use std::time::Duration;

use mockito::{Matcher, Mock, Server, ServerGuard};
use regex::Regex;
use slog::{info, Logger};

use eth2::types::{FullBlockContents, ProduceBlockV3Metadata};
use eth2::{
    BeaconNodeHttpClient, CONSENSUS_BLOCK_VALUE_HEADER, CONSENSUS_VERSION_HEADER,
    EXECUTION_PAYLOAD_BLINDED_HEADER, EXECUTION_PAYLOAD_VALUE_HEADER,
};
use logging::test_logger;
use sensitive_url::SensitiveUrl;
use types::{
    BeaconBlock, BlobsList, EthSpec, ForkName, ForkVersionedResponse, KzgProofs, Slot, Uint256,
};

pub struct MockBeaconNode<E: EthSpec> {
    server: ServerGuard,
    pub beacon_api_client: BeaconNodeHttpClient,
    log: Logger,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> MockBeaconNode<E> {
    pub async fn new() -> Self {
        // mock server logging
        let _ = env_logger::try_init();
        let server = Server::new_async().await;
        let slot_duration = Duration::from_secs(12);
        let timeouts = crate::get_optimised_bn_timeouts(slot_duration);
        let beacon_api_client =
            BeaconNodeHttpClient::new(SensitiveUrl::from_str(&server.url()).unwrap(), timeouts);
        let log = test_logger();
        Self {
            server,
            beacon_api_client,
            log,
            _phantom: PhantomData,
        }
    }

    /// Resets all mocks
    #[allow(dead_code)]
    pub fn reset_mocks(&mut self) {
        self.server.reset();
    }

    /// Mocks the `get_validator_blocks_v3` response with an optional delay.
    pub fn mock_get_validator_blocks_v3(
        &mut self,
        fork: ForkName,
        block: BeaconBlock<E>,
        delay_seconds: Option<Duration>,
    ) -> &mut Self {
        let path_pattern = Regex::new(r"^/eth/v3/validator/blocks/(\d+).*$").unwrap();
        let log = self.log.clone();

        self.server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_header(CONSENSUS_VERSION_HEADER, &fork.to_string())
            .with_header(EXECUTION_PAYLOAD_BLINDED_HEADER, "false")
            .with_header(EXECUTION_PAYLOAD_VALUE_HEADER, "1000")
            .with_header(CONSENSUS_BLOCK_VALUE_HEADER, "1000")
            .with_body_from_request(move |request| {
                let path_pattern = path_pattern.clone();
                let captures = path_pattern.captures(request.path()).unwrap();
                let slot = Slot::from_str(&captures[1]).unwrap();
                info!(
                    log,
                    "Received validator get block request for slot {:?}", slot
                );

                if let Some(delay) = delay_seconds {
                    std::thread::sleep(delay);
                }

                let metadata = ProduceBlockV3Metadata {
                    consensus_version: fork,
                    execution_payload_blinded: false,
                    execution_payload_value: Uint256::from(1),
                    consensus_block_value: Uint256::from(1),
                };
                let data = FullBlockContents::<E>::new(
                    block.clone(),
                    Some((KzgProofs::<E>::empty(), BlobsList::<E>::empty())),
                );
                let response = ForkVersionedResponse {
                    version: Some(fork),
                    metadata,
                    data,
                };
                serde_json::to_string(&response).unwrap().into_bytes()
            })
            .create();

        self
    }

    pub fn mock_post_beacon_blinded_blocks_v1(&mut self, delay: Duration) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v1/beacon/blinded_blocks$").unwrap();
        let log = self.log.clone();
        let url = self.server.url();

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", "application/json")
            .with_status(200)
            .with_body_from_request(move |_request| {
                info!(
                    log,
                    "{}",
                    format!(
                        "Received published block request on server {} with delay {} s",
                        url,
                        delay.as_secs(),
                    )
                );

                std::thread::sleep(delay);
                vec![]
            })
            .create()
    }
}

use eth2::types::{GenericResponse, SyncingData};
use eth2::{BeaconNodeHttpClient, StatusCode, Timeouts};
use logging::test_logger;
use mockito::{Matcher, Mock, Server, ServerGuard};
use regex::Regex;
use sensitive_url::SensitiveUrl;
use slog::{info, Logger};
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use types::{ChainSpec, ConfigAndPreset, EthSpec, SignedBlindedBeaconBlock};

pub struct MockBeaconNode<E: EthSpec> {
    server: ServerGuard,
    pub beacon_api_client: BeaconNodeHttpClient,
    log: Logger,
    _phantom: PhantomData<E>,
    pub received_blocks: Arc<Mutex<Vec<SignedBlindedBeaconBlock<E>>>>,
}

impl<E: EthSpec> MockBeaconNode<E> {
    pub async fn new() -> Self {
        // mock server logging
        let server = Server::new_async().await;
        let beacon_api_client = BeaconNodeHttpClient::new(
            SensitiveUrl::from_str(&server.url()).unwrap(),
            Timeouts::set_all(Duration::from_secs(1)),
        );
        let log = test_logger();
        Self {
            server,
            beacon_api_client,
            log,
            _phantom: PhantomData,
            received_blocks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Resets all mocks
    #[allow(dead_code)]
    pub fn reset_mocks(&mut self) {
        self.server.reset();
    }

    pub fn mock_config_spec(&mut self, spec: &ChainSpec) {
        let path_pattern = Regex::new(r"^/eth/v1/config/spec$").unwrap();
        let config_and_preset = ConfigAndPreset::from_chain_spec::<E>(spec, None);
        let data = GenericResponse::from(config_and_preset);
        self.server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .with_status(200)
            .with_body(serde_json::to_string(&data).unwrap())
            .create();
    }

    pub fn mock_get_node_syncing(&mut self, response: SyncingData) {
        let path_pattern = Regex::new(r"^/eth/v1/node/syncing$").unwrap();

        let data = GenericResponse::from(response);

        self.server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .with_status(200)
            .with_body(serde_json::to_string(&data).unwrap())
            .create();
    }

    /// Mocks the `post_beacon_blinded_blocks_v2_ssz` response with an optional `delay`.
    pub fn mock_post_beacon_blinded_blocks_v2_ssz(&mut self, delay: Duration) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v2/beacon/blinded_blocks$").unwrap();
        let log = self.log.clone();
        let url = self.server.url();

        let received_blocks = Arc::clone(&self.received_blocks);

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", "application/octet-stream")
            .with_status(200)
            .with_body_from_request(move |request| {
                info!(
                    log,
                    "{}",
                    format!(
                        "Received published block request on server {} with delay {} s",
                        url,
                        delay.as_secs(),
                    )
                );

                let body = request.body().expect("Failed to get request body");
                let block: SignedBlindedBeaconBlock<E> =
                    SignedBlindedBeaconBlock::any_from_ssz_bytes(body)
                        .expect("Failed to deserialize body as SignedBlindedBeaconBlock");

                received_blocks.lock().unwrap().push(block);

                std::thread::sleep(delay);
                vec![]
            })
            .create()
    }

    pub fn mock_offline_node(&mut self) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v1/node/version$").unwrap();

        self.server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .with_status(StatusCode::INTERNAL_SERVER_ERROR.as_u16() as usize)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"Internal Server Error"}"#)
            .create()
    }

    pub fn mock_online_node(&mut self) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v1/node/version$").unwrap();

        self.server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "data": {
                    "version": "lighthouse-mock"
                }
            }"#,
            )
            .create()
    }
}

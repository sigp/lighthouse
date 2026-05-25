use eth2::types::{GenericResponse, SyncingData};
use eth2::{BeaconNodeHttpClient, Timeouts};
use mockito::{Matcher, Mock, Server, ServerGuard};
use regex::Regex;
use reqwest::StatusCode;
use sensitive_url::SensitiveUrl;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::info;
use types::{
    ChainSpec, ConfigAndPreset, EthSpec, ForkName, PayloadAttestationData,
    PayloadAttestationMessage, SignedBlindedBeaconBlock, Slot,
};

pub struct MockBeaconNode<E: EthSpec> {
    server: ServerGuard,
    pub beacon_api_client: BeaconNodeHttpClient,
    _phantom: PhantomData<E>,
    pub received_blocks: Arc<Mutex<Vec<SignedBlindedBeaconBlock<E>>>>,
}

impl<E: EthSpec> fmt::Debug for MockBeaconNode<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let server_url = self.server.url();
        let received = self.received_blocks.lock().unwrap();
        f.debug_struct("MockBeaconNode")
            .field("server", &server_url)
            .field("beacon_api_client", &"<client omitted>")
            .field("received_blocks", &received)
            .finish()
    }
}

impl<E: EthSpec> MockBeaconNode<E> {
    pub async fn new() -> Self {
        // mock server logging
        let server = Server::new_async().await;
        let beacon_api_client = BeaconNodeHttpClient::new(
            SensitiveUrl::from_str(&server.url()).unwrap(),
            Timeouts::set_all(Duration::from_secs(1)),
        );
        Self {
            server,
            beacon_api_client,
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
        let config_and_preset = ConfigAndPreset::from_chain_spec::<E>(spec);
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
        let url = self.server.url();

        let received_blocks = Arc::clone(&self.received_blocks);

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", "application/octet-stream")
            .with_status(200)
            .with_body_from_request(move |request| {
                info!(
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

    pub fn mock_get_validator_payload_attestation_data(
        &mut self,
        data: &PayloadAttestationData,
        fork_name: ForkName,
        slot: Slot,
    ) -> Mock {
        let path_pattern = Regex::new(&format!(
            r"^/eth/v1/validator/payload_attestation_data/{}$",
            slot.as_u64()
        ))
        .unwrap();

        let body = serde_json::json!({
        "version": fork_name.to_string(),
        "data": data,
        });

        self.server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    pub fn mock_post_beacon_pool_payload_attestations(
        &mut self,
        received: Arc<Mutex<Vec<Vec<PayloadAttestationMessage>>>>,
    ) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v1/beacon/pool/payload_attestations$").unwrap();

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", Matcher::Regex("application/json".into()))
            .with_status(200)
            .with_body_from_request(move |request| {
                let body = request.body().expect("Failed to get request body");
                let messages: Vec<PayloadAttestationMessage> = serde_json::from_slice(body)
                    .expect("Failed to deserialize payload attestations");
                received.lock().unwrap().push(messages);
                vec![]
            })
            .create()
    }

    /// Mocks `POST /eth/v1/beacon/pool/payload_attestations` (SSZ) with an optional `delay`.                                                                         
    pub fn mock_post_beacon_pool_payload_attestations_ssz(
        &mut self,
        received: Arc<Mutex<Vec<Vec<u8>>>>,
        delay: Duration,
    ) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v1/beacon/pool/payload_attestations$").unwrap();
        let url = self.server.url();

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", "application/octet-stream")
            .with_status(200)
            .with_body_from_request(move |request| {
                info!(
                    "Received payload attestation SSZ on server {} with delay {} ms",
                    url,
                    delay.as_millis(),
                );
                let body = request.body().expect("Failed to get request body");
                received.lock().unwrap().push(body.to_vec());
                std::thread::sleep(delay);
                vec![]
            })
            .create()
    }
}

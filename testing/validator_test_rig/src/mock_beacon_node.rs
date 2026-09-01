use eth2::types::{GenericResponse, PublishBlockRequest, SyncingData};
use eth2::{BLOB_DATA_INCLUDED_HEADER, BeaconNodeHttpClient, CONSENSUS_VERSION_HEADER, Timeouts};
use mockito::{Matcher, Mock, Server, ServerGuard};
use regex::Regex;
use reqwest::StatusCode;
use sensitive_url::SensitiveUrl;
use ssz::{Decode, Encode};
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::info;
use types::{
    BeaconBlock, ChainSpec, ConfigAndPreset, EthSpec, ExecutionPayloadEnvelope, ForkName, Hash256,
    PayloadAttestationData, PayloadAttestationMessage, SignedBlindedBeaconBlock,
    SignedExecutionPayloadEnvelope, Slot,
};

pub struct MockBeaconNode<E: EthSpec> {
    server: ServerGuard,
    pub beacon_api_client: BeaconNodeHttpClient,
    _phantom: PhantomData<E>,
    pub received_blinded_blocks: Arc<Mutex<Vec<SignedBlindedBeaconBlock<E>>>>,
    pub received_full_blocks: Arc<Mutex<Vec<PublishBlockRequest<E>>>>,
    pub execution_payload_envelope: Arc<Mutex<Vec<SignedExecutionPayloadEnvelope<E>>>>,
    pub payload_attestation_message: Arc<Mutex<Vec<PayloadAttestationMessage>>>,
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
            received_blinded_blocks: Arc::new(Mutex::new(Vec::new())),
            received_full_blocks: Arc::new(Mutex::new(Vec::new())),
            execution_payload_envelope: Arc::new(Mutex::new(Vec::new())),
            payload_attestation_message: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Resets all mocks
    #[allow(dead_code)]
    pub fn reset_mocks(&mut self) {
        self.server.reset();
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

    pub fn mock_get_config_spec(&mut self, spec: &ChainSpec) {
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

    /// Mocks `GET /eth/v4/validator/blocks/{slot}`
    pub fn mock_get_validator_blocks_v4(
        &mut self,
        block: &BeaconBlock<E>,
        fork_name: ForkName,
        slot: Slot,
    ) -> Mock {
        let path_pattern =
            Regex::new(&format!(r"^/eth/v4/validator/blocks/{}", slot.as_u64())).unwrap();

        let body = serde_json::json!({
            "version": fork_name.to_string(),
            "consensus_block_value": "0",
            "execution_payload_value": "0",
            "execution_payload_included": false,
            "data": block,
        });

        self.server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .match_query(Matcher::UrlEncoded(
                "include_payload".into(),
                "false".into(),
            ))
            .match_header("accept", "application/json")
            .with_status(200)
            .with_header("Eth-Consensus-Version", &fork_name.to_string())
            .with_header("Eth-Consensus-Block-Value", "0")
            .with_header("Eth-Execution-Payload-Value", "0")
            .with_header("Eth-Execution-Payload-Included", "false")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    /// Mocks `GET /eth/v4/validator/blocks/{slot}` (SSZ)
    pub fn mock_get_validator_blocks_v4_ssz(
        &mut self,
        block: &BeaconBlock<E>,
        fork_name: ForkName,
        slot: Slot,
    ) -> Mock {
        let path_pattern =
            Regex::new(&format!(r"^/eth/v4/validator/blocks/{}", slot.as_u64())).unwrap();

        let ssz_bytes = block.as_ssz_bytes();

        self.server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .match_query(Matcher::UrlEncoded(
                "include_payload".into(),
                "false".into(),
            ))
            .match_header("accept", "application/octet-stream")
            .with_status(200)
            // These headers are required for v4 get validator block endpoint: https://github.com/ethereum/beacon-APIs/pull/580
            .with_header("Eth-Consensus-Version", &fork_name.to_string())
            .with_header("Eth-Consensus-Block-Value", "0")
            .with_header("Eth-Execution-Payload-Value", "0")
            .with_header("Eth-Execution-Payload-Included", "false")
            .with_body(ssz_bytes)
            .create()
    }

    /// Mocks `GET /eth/v4/validator/blocks/{slot}` (SSZ) returning error
    pub fn mock_get_validator_blocks_v4_ssz_error(&mut self, slot: Slot) -> Mock {
        let path_pattern =
            Regex::new(&format!(r"^/eth/v4/validator/blocks/{}", slot.as_u64())).unwrap();

        self.server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .match_query(Matcher::UrlEncoded(
                "include_payload".into(),
                "false".into(),
            ))
            .match_header("accept", "application/octet-stream")
            .with_status(500)
            .with_body(r#"{"message":"Internal server error"}"#)
            .create()
    }

    /// Mocks `GET /eth/v1/validator/payload_attestations_data/{slot}`
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

    /// Mocks `GET /eth/v1/validator/payload_attestation_data/{slot}` returning error
    pub fn mock_get_validator_payload_attestation_data_error(&mut self, slot: Slot) -> Mock {
        let path_pattern = Regex::new(&format!(
            r"^/eth/v1/validator/payload_attestation_data/{}$",
            slot.as_u64()
        ))
        .unwrap();

        self.server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"Internal server error"}"#)
            .create()
    }

    /// Mocks `GET /eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}` (SSZ)
    pub fn mock_get_validator_execution_payload_envelope_ssz(
        &mut self,
        envelope: &ExecutionPayloadEnvelope<E>,
        slot: Slot,
        beacon_block_root: Hash256,
    ) -> Mock {
        let path_pattern = Regex::new(&format!(
            r"^/eth/v1/validator/execution_payload_envelopes/{}/{}$",
            slot.as_u64(),
            beacon_block_root,
        ))
        .unwrap();

        let ssz_bytes = envelope.as_ssz_bytes();

        self.server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .match_header("accept", "application/octet-stream")
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_body(ssz_bytes)
            .create()
    }

    /// Mocks `GET /eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}` returning error.
    pub fn mock_get_validator_execution_payload_envelope_ssz_error(
        &mut self,
        slot: Slot,
        beacon_block_root: Hash256,
    ) -> Mock {
        let path_pattern = Regex::new(&format!(
            r"^/eth/v1/validator/execution_payload_envelopes/{}/{}$",
            slot.as_u64(),
            beacon_block_root,
        ))
        .unwrap();

        self.server
            .mock("GET", Matcher::Regex(path_pattern.to_string()))
            .match_header("accept", "application/octet-stream")
            .with_status(500)
            .with_body(r#"{"message":"Internal server error"}"#)
            .create()
    }

    /// Mocks the `post_beacon_blinded_blocks_v2_ssz` response with an optional `delay`.
    pub fn mock_post_beacon_blinded_blocks_v2_ssz(&mut self, delay: Duration) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v2/beacon/blinded_blocks$").unwrap();
        let url = self.server.url();

        let received_blinded_blocks = Arc::clone(&self.received_blinded_blocks);

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

                received_blinded_blocks.lock().unwrap().push(block);

                std::thread::sleep(delay);
                vec![]
            })
            .create()
    }

    /// Mocks `POST /eth/v2/beacon/blocks` (SSZ)
    pub fn mock_post_beacon_blocks_v2_ssz(&mut self, fork_name: ForkName) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v2/beacon/blocks$").unwrap();

        let received_full_blocks = Arc::clone(&self.received_full_blocks);

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", "application/octet-stream")
            .with_status(200)
            .with_body_from_request(move |request| {
                let body = request.body().expect("Failed to get request body");
                let block = PublishBlockRequest::<E>::from_ssz_bytes(body, fork_name)
                    .expect("Failed to deserialize PublishBlockRequest from SSZ");
                received_full_blocks.lock().unwrap().push(block);
                vec![]
            })
            .create()
    }

    /// Mocks `POST /eth/v1/beacon/pool/payload_attestations`
    pub fn mock_post_beacon_pool_payload_attestations(&mut self) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v1/beacon/pool/payload_attestations$").unwrap();
        let payload_attestation_message = Arc::clone(&self.payload_attestation_message);

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", "application/json")
            .with_status(200)
            .with_body_from_request(move |request| {
                let body = request.body().expect("Failed to get request body");
                let message: Vec<PayloadAttestationMessage> = serde_json::from_slice(body)
                    .expect("Failed to deserialize payload attestations");
                payload_attestation_message.lock().unwrap().extend(message);
                vec![]
            })
            .create()
    }

    /// Mocks `POST /eth/v1/beacon/pool/payload_attestations` (SSZ) with an optional `delay`.
    pub fn mock_post_beacon_pool_payload_attestations_ssz(&mut self, delay: Duration) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v1/beacon/pool/payload_attestations$").unwrap();
        let url = self.server.url();

        let payload_attestation_message = Arc::clone(&self.payload_attestation_message);

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", "application/octet-stream")
            .with_status(200)
            .with_body_from_request(move |request| {
                info!(
                    "Received payload attestation SSZ on server {} with delay {} ms",
                    url,
                    delay.as_secs(),
                );
                let body = request.body().expect("Failed to get request body");

                let chunk_size = <PayloadAttestationMessage as Decode>::ssz_fixed_len();
                let messages: Vec<PayloadAttestationMessage> = body
                    .chunks(chunk_size)
                    .map(|chunk| {
                        PayloadAttestationMessage::from_ssz_bytes(chunk)
                            .expect("Failed to deserialize PayloadAttestationMessage from SSZ")
                    })
                    .collect();

                payload_attestation_message.lock().unwrap().extend(messages);
                std::thread::sleep(delay);
                vec![]
            })
            .create()
    }

    /// Mocks `POST /eth/v1/beacon/pool/payload_attestations` (SSZ) returning error
    pub fn mock_post_beacon_pool_payload_attestations_ssz_error(&mut self) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v1/beacon/pool/payload_attestations$").unwrap();

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", "application/octet-stream")
            .with_status(500)
            .with_body(r#"{"message":"Internal server error"}"#)
            .create()
    }

    /// Mocks `POST /eth/v1/beacon/execution_payload_envelopes` (SSZ) to receive signed envelopes.
    pub fn mock_post_beacon_execution_payload_envelope_ssz(&mut self) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v1/beacon/execution_payload_envelopes$").unwrap();

        let execution_payload_envelope = Arc::clone(&self.execution_payload_envelope);

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", "application/octet-stream")
            .match_header(CONSENSUS_VERSION_HEADER, "gloas")
            .match_header(BLOB_DATA_INCLUDED_HEADER, "false")
            .with_status(200)
            .with_body_from_request(move |request| {
                let body = request.body().expect("Failed to get request body");
                let envelope = SignedExecutionPayloadEnvelope::<E>::from_ssz_bytes(body)
                    .expect("Failed to deserialize SignedExecutionPayloadEnvelope from SSZ");
                execution_payload_envelope.lock().unwrap().push(envelope);
                vec![]
            })
            .create()
    }

    /// Mocks `POST /eth/v1/beacon/execution_payload_envelopes` (SSZ) returning error.
    pub fn mock_post_beacon_execution_payload_envelope_ssz_error(&mut self) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v1/beacon/execution_payload_envelopes$").unwrap();

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", "application/octet-stream")
            .match_header(CONSENSUS_VERSION_HEADER, "gloas")
            .match_header(BLOB_DATA_INCLUDED_HEADER, "false")
            .with_status(500)
            .with_body(r#"{"message":"Internal server error"}"#)
            .create()
    }

    /// Mocks `POST /eth/v1/validator/proposer_preferences`
    pub fn mock_post_validator_proposer_preferences_json(&mut self) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v1/validator/proposer_preferences$").unwrap();

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", "application/json")
            .with_status(200)
            .create()
    }

    /// Mocks `POST /eth/v1/validator/proposer_preferences` (SSZ)
    pub fn mock_post_validator_proposer_preferences_ssz(&mut self) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v1/validator/proposer_preferences$").unwrap();

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", "application/octet-stream")
            .with_status(200)
            .create()
    }

    /// Mocks `POST /eth/v1/validator/proposer_preferences` (SSZ) returning error
    pub fn mock_post_validator_proposer_preferences_ssz_error(&mut self) -> Mock {
        let path_pattern = Regex::new(r"^/eth/v1/validator/proposer_preferences$").unwrap();

        self.server
            .mock("POST", Matcher::Regex(path_pattern.to_string()))
            .match_header("content-type", "application/octet-stream")
            .with_status(500)
            .with_body(r#"{"message":"Internal server error"}"#)
            .create()
    }
}

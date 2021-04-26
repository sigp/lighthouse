use crate::*;
use remote_signer_client::api_response::SignatureApiResponse;
use remote_signer_consumer::{Error, RemoteSignerHttpConsumer, RemoteSignerObject};
use reqwest::ClientBuilder;
use sensitive_url::SensitiveUrl;
use serde::Serialize;
use tokio::runtime::Builder;
use tokio::time::Duration;
use types::{AttestationData, BeaconBlock, Epoch, EthSpec, Fork, Hash256};

pub fn set_up_test_consumer(test_signer_address: &str) -> RemoteSignerHttpConsumer {
    set_up_test_consumer_with_timeout(test_signer_address, 12)
}

pub fn set_up_test_consumer_with_timeout(
    test_signer_address: &str,
    timeout: u64,
) -> RemoteSignerHttpConsumer {
    let url = SensitiveUrl::parse(test_signer_address).unwrap();
    let reqwest_client = ClientBuilder::new()
        .timeout(Duration::from_secs(timeout))
        .build()
        .unwrap();

    RemoteSignerHttpConsumer::from_components(url, reqwest_client)
}

pub fn do_sign_request<E: EthSpec, T: RemoteSignerObject>(
    test_client: &RemoteSignerHttpConsumer,
    test_input: RemoteSignerTestData<E, T>,
) -> Result<String, Error> {
    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();

    runtime.block_on(test_client.sign(
        &test_input.public_key,
        test_input.bls_domain,
        test_input.data,
        test_input.fork,
        test_input.genesis_validators_root,
    ))
}

#[derive(Serialize)]
pub struct BlockRequestBody<E: EthSpec> {
    bls_domain: String,
    data: BeaconBlock<E>,
    fork: Fork,
    genesis_validators_root: Hash256,
}

pub fn get_test_block_body(seed: u64) -> String {
    let block: BeaconBlock<E> = get_block(seed);
    let epoch = block.epoch();

    let fork = Fork {
        previous_version: [1; 4],
        current_version: [2; 4],
        epoch,
    };

    let genesis_validators_root = Hash256::from_low_u64_be(seed);

    let block_request_body = BlockRequestBody {
        bls_domain: "beacon_proposer".to_string(),
        data: block,
        fork,
        genesis_validators_root,
    };

    serde_json::to_string(&block_request_body).unwrap()
}

#[derive(Serialize)]
pub struct AttestationRequestBody {
    bls_domain: String,
    data: AttestationData,
    fork: Fork,
    genesis_validators_root: Hash256,
}

pub fn get_test_attestation_body(seed: u64) -> String {
    let attestation = get_attestation::<E>(seed);
    let epoch = attestation.target.epoch;

    let fork = Fork {
        previous_version: [1; 4],
        current_version: [2; 4],
        epoch,
    };

    let genesis_validators_root = Hash256::from_low_u64_be(seed);

    let attestation_request_body = AttestationRequestBody {
        bls_domain: "beacon_attester".to_string(),
        data: attestation,
        fork,
        genesis_validators_root,
    };

    serde_json::to_string(&attestation_request_body).unwrap()
}

#[derive(Serialize)]
pub struct RandaoRequestBody {
    bls_domain: String,
    data: Epoch,
    fork: Fork,
    genesis_validators_root: Hash256,
}

pub fn get_test_randao_body(seed: u64) -> String {
    let epoch = Epoch::new(seed);

    let fork = Fork {
        previous_version: [1; 4],
        current_version: [2; 4],
        epoch,
    };

    let genesis_validators_root = Hash256::from_low_u64_be(seed);

    let randao_request_body = RandaoRequestBody {
        bls_domain: "randao".to_string(),
        data: epoch,
        fork,
        genesis_validators_root,
    };

    serde_json::to_string(&randao_request_body).unwrap()
}

pub fn assert_sign_ok(resp: ApiTestResponse, expected_signature: &str) {
    assert_eq!(resp.status, 200);
    assert_eq!(
        serde_json::from_value::<SignatureApiResponse>(resp.json)
            .unwrap()
            .signature,
        expected_signature
    );
}

pub fn assert_sign_error(resp: ApiTestResponse, http_status: u16, error_msg: &str) {
    assert_eq!(resp.status, http_status);
    assert_eq!(resp.json["error"].as_str().unwrap(), error_msg);
}

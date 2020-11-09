mod constants;
mod objects;

use clap::{App, Arg, ArgMatches};
use client::api_response::SignatureApiResponse;
use client::Client;
pub use constants::*;
use environment::{Environment, EnvironmentBuilder};
pub use objects::*;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::fs::{create_dir, File};
use std::io::Write;
use std::net::IpAddr::{V4, V6};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempdir::TempDir;
use types::{AttestationData, BeaconBlock, Epoch, EthSpec, Fork, Hash256, MainnetEthSpec};

pub type E = MainnetEthSpec;

pub struct ApiTestSigner<E: EthSpec> {
    pub address: String,
    environment: Environment<E>,
}

pub struct ApiTestResponse {
    pub status: u16,
    pub json: Value,
}

impl ApiTestSigner<MainnetEthSpec> {
    pub fn new(arg_vec: Vec<&str>) -> Self {
        let matches = set_matches(arg_vec);
        let mut environment = get_environment(false);
        let runtime_context = environment.core_context();

        let client = environment
            .runtime()
            .block_on(Client::new(runtime_context, &matches))
            .map_err(|e| format!("Failed to init Rest API: {}", e))
            .unwrap();

        let address = get_address(&client);

        Self {
            address,
            environment,
        }
    }

    pub fn shutdown(mut self) {
        self.environment.fire_signal()
    }
}

pub fn set_matches(arg_vec: Vec<&str>) -> ArgMatches<'static> {
    let matches = App::new("BLS_Remote_Signer")
        .arg(
            Arg::with_name("storage-raw-dir")
                .long("storage-raw-dir")
                .value_name("DIR"),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .default_value("9000")
                .takes_value(true),
        );

    matches.get_matches_from(arg_vec)
}

pub fn get_environment(is_log_active: bool) -> Environment<E> {
    let environment_builder = EnvironmentBuilder::mainnet();

    let builder = if is_log_active {
        environment_builder.async_logger("info", None).unwrap()
    } else {
        environment_builder.null_logger().unwrap()
    };

    builder
        .multi_threaded_tokio_runtime()
        .unwrap()
        .build()
        .unwrap()
}

pub fn set_up_api_test_signer_raw_dir() -> (ApiTestSigner<E>, TempDir) {
    let tmp_dir = TempDir::new("bls-remote-signer-test").unwrap();
    let arg_vec = vec![
        "this_test",
        "--port",
        "0",
        "--storage-raw-dir",
        tmp_dir.path().to_str().unwrap(),
    ];
    let test_signer = ApiTestSigner::new(arg_vec);

    (test_signer, tmp_dir)
}

pub fn set_up_api_test_signer_to_sign_message() -> (ApiTestSigner<E>, TempDir) {
    let (test_signer, tmp_dir) = set_up_api_test_signer_raw_dir();
    add_sub_dirs(&tmp_dir);
    add_key_files(&tmp_dir);
    add_non_key_files(&tmp_dir);
    add_mismatched_key_file(&tmp_dir);
    add_invalid_secret_key_file(&tmp_dir);

    (test_signer, tmp_dir)
}

pub fn get_address(client: &Client) -> String {
    let listening_address = client.get_listening_address();
    let ip = match listening_address.ip() {
        V4(ip) => ip.to_string(),
        V6(ip) => ip.to_string(),
    };

    format!("http://{}:{}", ip, listening_address.port())
}

pub fn set_permissions(path: &Path, perm_octal: u32) {
    let metadata = fs::metadata(path).unwrap();
    let mut permissions = metadata.permissions();
    permissions.set_mode(perm_octal);
    fs::set_permissions(path, permissions).unwrap();
}

pub fn add_key_files(tmp_dir: &TempDir) {
    let pairs = vec![
        (PUBLIC_KEY_1, SECRET_KEY_1),
        (PUBLIC_KEY_2, SECRET_KEY_2),
        (PUBLIC_KEY_3, SECRET_KEY_3),
    ];

    add_files(tmp_dir, pairs);
}

pub fn add_mismatched_key_file(tmp_dir: &TempDir) {
    let pairs = vec![(MISMATCHED_PUBLIC_KEY, SECRET_KEY_1)];

    add_files(tmp_dir, pairs);
}

pub fn add_invalid_secret_key_file(tmp_dir: &TempDir) {
    let pairs = vec![(PUBLIC_KEY_FOR_INVALID_SECRET_KEY, INVALID_SECRET_KEY)];

    add_files(tmp_dir, pairs);
}

pub fn add_non_key_files(tmp_dir: &TempDir) {
    let pairs = vec![
        (SILLY_FILE_NAME_1, SILLY_CONTENT_1),
        (SILLY_FILE_NAME_2, SILLY_CONTENT_2),
        (SILLY_FILE_NAME_3, SILLY_CONTENT_3),
    ];

    add_files(tmp_dir, pairs);
}

fn add_files(tmp_dir: &TempDir, pairs: Vec<(&str, &str)>) {
    for pair in pairs {
        let file_path = tmp_dir.path().join(pair.0);
        let mut tmp_file = File::create(file_path).unwrap();
        writeln!(tmp_file, "{}", pair.1).unwrap();
    }
}

pub fn add_sub_dirs(tmp_dir: &TempDir) {
    let random_sub_dir_path = tmp_dir.path().join("random_sub_dir_name");
    create_dir(random_sub_dir_path).unwrap();

    let another_sub_dir_path = tmp_dir.path().join(SUB_DIR_NAME);
    create_dir(another_sub_dir_path).unwrap();
}

pub fn http_get(url: &str) -> ApiTestResponse {
    let response = reqwest::blocking::get(url).unwrap();

    ApiTestResponse {
        status: response.status().as_u16(),
        json: serde_json::from_str(&response.text().unwrap()).unwrap(),
    }
}

pub fn http_post(url: &str, hashmap: HashMap<&str, &str>) -> ApiTestResponse {
    let response = reqwest::blocking::Client::new()
        .post(url)
        .json(&hashmap)
        .send()
        .unwrap();

    ApiTestResponse {
        status: response.status().as_u16(),
        json: serde_json::from_str(&response.text().unwrap()).unwrap(),
    }
}

pub fn http_post_custom_body(url: &str, body: &str) -> ApiTestResponse {
    let response = reqwest::blocking::Client::new()
        .post(url)
        .body(body.to_string())
        .send()
        .unwrap();

    ApiTestResponse {
        status: response.status().as_u16(),
        json: serde_json::from_str(&response.text().unwrap()).unwrap(),
    }
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

use crate::*;
use clap::{App, Arg, ArgMatches};
use environment::{Environment, EnvironmentBuilder};
pub use local_signer_test_data::*;
use remote_signer_client::Client;
use serde_json::Value;
use std::collections::HashMap;
use tempdir::TempDir;
use types::EthSpec;

pub struct ApiTestSigner<E: EthSpec> {
    pub address: String,
    environment: Environment<E>,
}

pub struct ApiTestResponse {
    pub status: u16,
    pub json: Value,
}

impl ApiTestSigner<E> {
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

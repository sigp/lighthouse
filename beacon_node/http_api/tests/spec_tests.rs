use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use eth2::{BeaconNodeHttpClient, Timeouts};
use http_api::test_utils::{ApiServer, create_api_server};
use oas3;
use sensitive_url::SensitiveUrl;
use serde_yaml;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::Duration;
use types::MainnetEthSpec;

type E = MainnetEthSpec;

#[derive(Debug, Clone)]
struct RequiredFields {
    // A higher-level generic required fields in the response, including: "version", "execution_optimistic", "finalized" and "data"
    generic_required_fields: Vec<String>,
    // Specific required fields for the data in the generic_required_fields
    specific_required_fields: Vec<String>,
}

async fn new() -> (
    Arc<BeaconChainHarness<EphemeralHarnessType<E>>>,
    BeaconNodeHttpClient,
) {
    let harness = Arc::new(
        BeaconChainHarness::builder(MainnetEthSpec)
            .default_spec()
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .build(),
    );

    let ApiServer {
        server,
        listening_socket,
        ..
    } = create_api_server(harness.chain.clone(), &harness.runtime).await;

    harness.runtime.task_executor.spawn(server, "api_server");

    let client = BeaconNodeHttpClient::new(
        SensitiveUrl::parse(&format!("http://127.0.0.1:{}", listening_socket.port())).unwrap(),
        Timeouts::set_all(Duration::from_secs(12)),
    );

    (harness, client)
}

// Extracts the expected fields from beacon-APIs repository
async fn extract_all_endpoints() -> HashMap<String, RequiredFields> {
    // Obtain the main Beacon APIs yaml file
    // This will parse the main yaml file as a String
    let yaml = reqwest::get(
        "https://raw.githubusercontent.com/ethereum/beacon-APIs/refs/heads/master/beacon-node-oapi.yaml")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    // Use the function from oas3 crate to parse the main yaml file
    let spec = oas3::from_yaml(yaml).unwrap();

    let mut endpoint_fields = HashMap::new();

    // spec.paths is Option<IndexMap<String, PathItem>>, so we use if let here
    // spec.paths looks like this (for 1 endpoint):
    /* Some({"/eth/v1/beacon/blinded_blocks/{block_id}": PathItem { reference: Some("./apis/beacon/blocks/blinded_block.yaml"), summary: None, description: None, get: None, put: None,
    post: None, delete: None, options: None, head: None, patch: None, trace: None, servers: [], parameters: [], extensions: {} } */
    // so: path is a String, e.g.,: "/eth/v1/beacon/blinded_blocks/{block_id}"
    // path_item itself is a Struct, and the reference field in PathItem contains the yaml file of the endpoint, which is what we want
    if let Some(paths) = &spec.paths {
        for (path, path_item) in paths {
            println!("Processing endpoint: {}", path);

            if let Some(reference_path) = &path_item.reference {
                println!(" Found reference: {}", reference_path);

                // because the path starts with "./", we want to trim this off
                let trimmed_path: &str = reference_path.trim_start_matches("./");
                println!("trimmed_path is: {:?}", trimmed_path);
                let url = format!(
                    "https://raw.githubusercontent.com/ethereum/beacon-APIs/refs/heads/master/{}",
                    trimmed_path
                );

                println!("url is: {:?}", url);

                // Fetch the endpoint-specific YAML
                let endpoint_yaml = reqwest::get(&url).await.unwrap().text().await.unwrap();

                let yaml_value: serde_yaml::Value = serde_yaml::from_str(&endpoint_yaml).unwrap();

                // Navigate to the "schema" level of the yaml file
                let schema = yaml_value
                    .get("get")
                    .and_then(|v| v.get("responses"))
                    .and_then(|v| v.get("200"))
                    .and_then(|v| v.get("content"))
                    .and_then(|v| v.get("application/json"))
                    .and_then(|v| v.get("schema"));

                // Extract the generic_required_fields
                let generic_required_fields = schema
                    .and_then(|s| s.get("required"))
                    .and_then(|v| v.as_sequence())
                    .map(|seq| {
                        seq.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_else(Vec::new);

                // Extract the specific_required_fields
                let specific_required_fields = schema
                    .and_then(|s| s.get("properties"))
                    .and_then(|v| v.get("data"))
                    .and_then(|v| v.get("required"))
                    .and_then(|v| v.as_sequence())
                    .map(|seq| {
                        seq.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_else(Vec::new);

                println!("  Generic fields are: {:?}", generic_required_fields);
                println!("  Specific fields are: {:?}", specific_required_fields);

                endpoint_fields.insert(
                    path.to_string(),
                    RequiredFields {
                        generic_required_fields,
                        specific_required_fields,
                    },
                );
            }
        }
    }
    endpoint_fields
}

#[tokio::test]
async fn test_genesis_endpoint_conforms_to_spec() {
    let (_harness, client) = new().await;

    let all_endpoints = extract_all_endpoints().await;

    // Get the expected fields for the genesis endpoint
    // TODO: all_endpoints contains all beacon APIs endpoints, so we want to extend this to calling all endpoints (raw HTTP calls)
    let expected_fields = all_endpoints.get("/eth/v1/beacon/genesis").unwrap();

    // Get the actual response
    let response = client.get_beacon_genesis().await.unwrap();

    // Convert the entire response to JSON to check response-level fields
    let response_json = serde_json::to_value(&response)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();

    // Check response-level required fields
    for field in &expected_fields.generic_required_fields {
        assert!(
            response_json.contains_key(field),
            "Response missing expected field '{}'",
            field,
        );
    }

    let data_json = serde_json::to_value(&response.data)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();

    for field in &expected_fields.specific_required_fields {
        assert!(
            data_json.contains_key(field),
            "Response data missing expected field '{}'",
            field,
        );
    }
}

use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use eth2::{BeaconNodeHttpClient, Timeouts};
use http_api::test_utils::{ApiServer, create_api_server};
use sensitive_url::SensitiveUrl;
use serde_yaml;
use std::sync::Arc;
use tokio::time::Duration;
use types::MainnetEthSpec;

type E = MainnetEthSpec;

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
async fn extract_expected_fields(path: &str) -> Option<Vec<String>> {
    let url = format!(
        "https://raw.githubusercontent.com/ethereum/beacon-APIs/master/apis/{}",
        path
    );

    let text = reqwest::get(&url).await.unwrap().text().await.unwrap();
    let yaml = serde_yaml::from_str::<serde_yaml::Value>(&text).unwrap();

    // Travels down each level of the yaml file
    // Example: for beacon/genesis.yaml: https://raw.githubusercontent.com/ethereum/beacon-APIs/master/apis/beacon/genesis.yaml
    // Returns the required fields, e.g., vec![genesis_time, genesis_validators_root, genesis_fork_version]
    yaml.get("get")?
        .get("responses")?
        .get("200")?
        .get("content")?
        .get("application/json")?
        .get("schema")?
        .get("properties")?
        .get("data")?
        .get("required")?
        .as_sequence()
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
}

#[tokio::test]
async fn test_genesis_endpoint_conforms_to_spec() {
    let (_harness, client) = new().await;

    let expected_fields = extract_expected_fields("beacon/genesis.yaml")
        .await
        .unwrap();

    let response = client.get_beacon_genesis().await.unwrap().data;
    let result = serde_json::to_value(&response)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    println!("data_json is: {:?}", response);
    println!("data_object is: {:?}", result);

    for field in &expected_fields {
        assert!(
            result.contains_key(field),
            "Response missing an expected field '{}'",
            field,
        );
    }
}

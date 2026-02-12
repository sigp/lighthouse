use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use eth2::{BeaconNodeHttpClient, Timeouts};
use http_api::test_utils::{ApiServer, create_api_server};
use lighthouse_network::PeerId;
use oas3;
use oas3::spec::ObjectOrReference;
use oas3::spec::Schema;
use sensitive_url::SensitiveUrl;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::Duration;
use types::{Epoch, EthSpec, MainnetEthSpec};

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
    u16,
    PeerId,
) {
    // Create a spec with Fulu fork starting from epoch 0
    // because some endpoints like sync committee require Altair fork, so we start with Fulu straight away
    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(Epoch::new(0));
    spec.bellatrix_fork_epoch = Some(Epoch::new(0));
    spec.capella_fork_epoch = Some(Epoch::new(0));
    spec.deneb_fork_epoch = Some(Epoch::new(0));
    spec.electra_fork_epoch = Some(Epoch::new(0));
    spec.fulu_fork_epoch = Some(Epoch::new(0));

    let harness = Arc::new(
        BeaconChainHarness::builder(MainnetEthSpec)
            .spec(spec.into())
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .build(),
    );

    // Output external_peer_id so that we can replace in the replace_parameter function later
    // A correct peer_id is required to make a valid request for endpoint: /eth/v1/node/peers/{peer_id}
    let ApiServer {
        server,
        listening_socket,
        external_peer_id,
        ..
    } = create_api_server(harness.chain.clone(), &harness.runtime).await;

    harness.runtime.task_executor.spawn(server, "api_server");

    let port = listening_socket.port();

    let client = BeaconNodeHttpClient::new(
        SensitiveUrl::parse(&format!("http://127.0.0.1:{}", port)).unwrap(),
        Timeouts::set_all(Duration::from_secs(12)),
    );

    (harness, client, port, external_peer_id)
}

// Extracts the expected fields from beacon-APIs repository
async fn extract_all_endpoints() -> HashMap<String, RequiredFields> {
    // Obtain the whole Beacon APIs yaml file
    // This will parse the yaml file as a String
    let yaml = reqwest::get(
        "https://github.com/ethereum/beacon-APIs/releases/download/v4.0.0/beacon-node-oapi.yaml",
    )
    .await
    .unwrap()
    .text()
    .await
    .unwrap();
    // Use the function from oas3 crate to parse the main yaml file
    let spec = oas3::from_yaml(yaml).unwrap();

    let mut fields_by_endpoint = HashMap::new();

    // spec.paths is Option<IndexMap<String, PathItem>>, so we use if let here
    // spec.paths looks like this (for 1 endpoint):
    // "/eth/v1/beacon/states/{state_id}/fork": PathItem { reference: None, summary: None, description: None, get: Some(Operation {...
    // so: endpoint is a String, e.g.,: "/eth/v1/beacon/states/{state_id}/fork"
    // path_item itself is a Struct
    if let Some(paths) = &spec.paths {
        for (endpoint, path_item) in paths {
            println!("Processing endpoint: {}", endpoint);
            // path_item.get is of type: Option<Operation>
            // This will process all GET endpoints and ignore others (e.g., POST)
            let get = match &path_item.get {
                Some(get) => get.clone(),
                None => {
                    println!(
                        "{} is not a GET endpoint, continue with the next endpoint",
                        endpoint
                    );
                    continue;
                }
            };
            // responses if of type: Option<BTreeMap<String, ObjectOrReference<Response>>>
            let responses = get.responses.unwrap();
            // From the responses BTreeMap
            // where the String is like "200", "400" and the value is the corresponding Object<Response> type
            // with .get("200"), we get to the ObjectOrReference<Response>
            // So response is of type Response (a struct)
            let response = match responses.get("200").unwrap() {
                ObjectOrReference::Object(object) => object,
                ObjectOrReference::Ref { .. } => panic!("Should be an Object"),
            };
            // response.content is of type: BTreeMap<String, MediaType>
            // where the key (with type String) is "application/json" (or "application/octet-stream") and the value of type: MediaType
            /* Mediatype is a Struct:
            pub struct MediaType {
                pub schema: Option<ObjectOrReference<ObjectSchema>>,
                pub examples: Option<MediaTypeExamples>,
                pub encoding: BTreeMap<String, Encoding>,
                pub extensions: BTreeMap<String, Value>,
            }
             */
            // media_type is of type MediaType
            let media_type = match response.content.get("application/json") {
                Some(media_type) => media_type,
                None => {
                    // eth/v1/events does not have application/json, only application/octet-stream
                    println!(
                        "No application/json content found for endpoint {}",
                        endpoint
                    );
                    continue;
                }
            };

            // media_type.schema accesses the field schema in the struct, and it is of type: Option<ObjectOrReference<ObjectSchema>>
            // After matching with Object enum, object_schema variable is of type ObjectSchema
            let object_schema = match media_type.schema.clone().unwrap() {
                ObjectOrReference::Object(schema) => schema,
                ObjectOrReference::Ref { .. } => panic!("Should be an Object"),
            };

            // required is a field in struct ObjectSchema, with type: Vec<String>
            // this is what we want to check against the spec
            let generic_required_fields = object_schema.required;

            // Temporarily skipping light_client/updates endpoint
            // because the data is under: object_schema > item > properties > data (1 level deeper)
            // while all other endpoints are under: object_schema > properties > data
            let specific_required_fields = if endpoint != "/eth/v1/beacon/light_client/updates" {
                // properties is a field in struct ObjectSchema, with type: BTreeMap<String, ObjectOrReference<ObjectSchema>>
                // where the String can be: "data", "version", "finalized" etc, i.e., the String in generic_required_fields
                // and the value is still an ObjectScheme type
                // we want to extract the string "data" and get to the specific fields defined in the spec
                // .get("data") gets to the ObjectOrReference<ObjectSchema> for String "data" for the BTreeMap object_schema.properties
                // the schema_type can be Array or Object, and it needs to be handled differently
                match object_schema.properties.get("data") {
                    Some(ObjectOrReference::Object(object_schema_data)) => {
                        if let Some(ref type_set) = object_schema_data.schema_type {
                            // Check if data is an array type
                            // example: /eth/v1/node/peers: https://github.com/ethereum/beacon-APIs/blob/d35584220e9a6c660600b83bf5814ba2d81bedf9/apis/node/peers.yaml#L24-L45
                            // we can see type: array here: https://github.com/ethereum/beacon-APIs/blob/d35584220e9a6c660600b83bf5814ba2d81bedf9/apis/node/peers.yaml#L35
                            // so data_schema is an Array, and it needs to be handled differently compared to an Object
                            // .is_array_or_nullable_array() is a method for SchemaTypeSet: https://docs.rs/oas3/latest/oas3/spec/enum.SchemaTypeSet.html
                            if type_set.is_array_or_nullable_array() {
                                // Extract required fields from array items
                                // using the peers endpoint, data_schema.items accesses the Peer type in the repo:https://github.com/ethereum/beacon-APIs/blob/d35584220e9a6c660600b83bf5814ba2d81bedf9/apis/node/peers.yaml#L37
                                // Peer is defined here: https://github.com/ethereum/beacon-APIs/blob/d35584220e9a6c660600b83bf5814ba2d81bedf9/types/p2p.yaml#L43-L59
                                match object_schema_data.items.clone().unwrap().as_ref() {
                                    // data_schema.items is of type Option<Box<Schema>>: https://docs.rs/oas3/latest/oas3/spec/struct.ObjectSchema.html
                                    // Schema can be a Boolean or Object: https://docs.rs/oas3/latest/oas3/spec/enum.Schema.html
                                    Schema::Boolean(_) => panic!("Should be an Object"),
                                    // For Schema::Object, the type is: Box<ObjectOrReference<ObjectSchema>> which brings back to ObjectSchema type
                                    Schema::Object(object_schema_data_items) => {
                                        match object_schema_data_items.as_ref() {
                                            ObjectOrReference::Object(object) => {
                                                object.required.clone()
                                            }
                                            ObjectOrReference::Ref { .. } => {
                                                panic!("Should be an Object")
                                            }
                                        }
                                    }
                                }
                            } else {
                                // If data_schema.schema_type is an object - handle AnyOf or directly extract the specific required fields
                                // example of endpoint with AnyOf under data: /eth/v1/beacon/blinded_blocks/{block_id}
                                // the data can be AnyOf these: https://github.com/ethereum/beacon-APIs/blob/master/apis/beacon/blocks/blinded_block.yaml#L35-L42
                                if !object_schema_data.any_of.is_empty() {
                                    // ObjectSchema.any_of is of type: Vec<ObjectOrReference<ObjectSchema>> (as there are a few ObjectSchema)
                                    match &object_schema_data.any_of[0] {
                                        ObjectOrReference::Object(object) => {
                                            object.required.clone()
                                        }
                                        ObjectOrReference::Ref { .. } => {
                                            panic!("Should be an Object")
                                        }
                                    }
                                } else {
                                    // If there is no AnyOf, then we can extract the specific required fields directly
                                    // for example, for "/eth/v1/beacon/states/{state_id}/fork": it leads to this: https://github.com/ethereum/beacon-APIs/blob/d35584220e9a6c660600b83bf5814ba2d81bedf9/apis/beacon/states/fork.yaml#L27
                                    // which is actually this Fork type: https://github.com/ethereum/beacon-APIs/blob/d35584220e9a6c660600b83bf5814ba2d81bedf9/types/misc.yaml#L1-L11
                                    // for this example, object_schema.properties.get("data") is of type Object<ObjectSchema>
                                    // i.e., Fork is parsed as Object<ObjectSchema> under the oas3 crate
                                    // and if object_schema_data.schema_type is Object (below), then we can get to object_schema_data.required to get to the specific required fields
                                    object_schema_data.required.clone()
                                }
                            }
                        } else {
                            // No schema_type, assume object
                            object_schema_data.required.clone()
                        }
                    }
                    Some(ObjectOrReference::Ref { .. }) => panic!("Should be an Object"),
                    None => Vec::new(),
                }
            } else {
                Vec::new()
            };

            fields_by_endpoint.insert(
                endpoint.to_string(),
                RequiredFields {
                    generic_required_fields,
                    specific_required_fields,
                },
            );
        }
    }

    fields_by_endpoint
}

// Used to replace parameters such as {block_id} with actual value so that a valid HTTP request is made
fn replace_parameter(
    param: &str,
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    peer_id: PeerId,
) -> String {
    // A correct block_root is required to make a valid request for endpoint: /eth/v1/beacon/light_client/bootstrap/{block_root}
    let block_root = harness.chain.genesis_block_root;

    param
        .replace("{block_id}", "head")
        .replace("{state_id}", "finalized")
        .replace("{slot}", "0")
        .replace("{epoch}", "0")
        .replace("{validator_id}", "0")
        .replace("{block_root}", &format!("{:?}", block_root))
        .replace("{peer_id}", &format!("{}", peer_id))
}

#[tokio::test]
async fn test_genesis_endpoint_conforms_to_spec() {
    let (harness, client, port, peer_id) = new().await;

    let fields_by_endpoint = extract_all_endpoints().await;

    // Test all endpoints in the spec
    for (endpoint, fields) in &fields_by_endpoint {
        // Call the HTTP endpoint using raw HTTP calls
        // endpoint looks like this: "/eth/v1/beacon/genesis" which is exactly what we want in the url
        let url = format!(
            "http://127.0.0.1:{}{}",
            port,
            replace_parameter(endpoint, &harness, peer_id)
        );
        println!("Testing endpoint: {}", endpoint);
        println!("URL is: {}", url);
        println!(
            "Generic fields are: {}",
            fields.generic_required_fields.join(", ")
        );
        println!(
            "Specific fields are: {}",
            fields.specific_required_fields.join(", ")
        );

        let response: serde_json::Value = client.get(url).await.unwrap();
        // println!("Response is: {:?}", response);

        let response_json = response.as_object().unwrap();
        // println!("Response JSON is: {:?}", response_json);

        // Check generic required fields
        for field in &fields.generic_required_fields {
            assert!(
                response_json.contains_key(field),
                "Response missing generic required field '{}'",
                field,
            );
        }

        // Check if data is an array or object and handle differently
        if let Some(data_array) = response_json.get("data").and_then(|v| v.as_array()) {
            for item in data_array.iter() {
                let item_json = item.as_object().unwrap();
                for field in &fields.specific_required_fields {
                    assert!(
                        item_json.contains_key(field),
                        "Response missing specific required field '{}'",
                        field,
                    );
                }
            }
        } else if let Some(data_json) = response_json.get("data").and_then(|v| v.as_object()) {
            // Data is an object - check required fields on it
            for field in &fields.specific_required_fields {
                assert!(
                    data_json.contains_key(field),
                    "Response missing specific required field '{}'",
                    field,
                );
            }
        }

        // let data_json = response_json
        //     .get("data")
        //     .and_then(|v| v.as_object())
        //     .unwrap();
        //
        // // println!("data_json is: {:?}", data_json);
        //
        // for field in &fields.specific_required_fields {
        //     assert!(
        //         data_json.contains_key(field),
        //         "Response missing specific required field '{}'",
        //         field,
        //     );
        // }

        println!("Test passed for endpoint: {}", endpoint);
    }
}

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
    RelativeSyncCommittee,
};
use bls::{Signature, SignatureBytes};
use eth2::{BeaconNodeHttpClient, Timeouts};
use http_api::test_utils::{ApiServer, create_api_server};
use lighthouse_network::PeerId;
use oas3::spec::{ObjectOrReference, ObjectSchema, Schema, SchemaType, SchemaTypeSet};
use regex::RegexBuilder;
use sensitive_url::SensitiveUrl;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::Duration;
use tree_hash::TreeHash;
use types::{Epoch, EthSpec, Hash256, MainnetEthSpec, SyncCommitteeContribution};

type E = MainnetEthSpec;

const SLOTS_PER_EPOCH: u64 = 32;
const VALIDATOR_COUNT: usize = SLOTS_PER_EPOCH as usize;
const CHAIN_LENGTH: u64 = SLOTS_PER_EPOCH * 5 - 1;

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

    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec.into())
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    // Build a chain with light client data to achieve finalization (required for light_client endpoints)
    for _ in 0..CHAIN_LENGTH {
        harness
            .extend_chain_with_light_client_data(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;

        harness.advance_slot();
    }

    let harness = Arc::new(harness);

    // Output external_peer_id as a correct peer_id is required to make a valid request for endpoint: /eth/v1/node/peers/{peer_id}
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

// Extract the full ObjectSchema for each endpoint's 200 response from the beacon-APIs spec.
// This ObjectSchema contains all the required info in an endpoint that we want to check
async fn extract_all_endpoints() -> HashMap<String, ObjectSchema> {
    // Obtain the complete Beacon APIs yaml file, this will parse the yaml file as a String
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

    let mut object_schema_by_endpoint = HashMap::new();

    // spec.paths is Option<IndexMap<String, PathItem>>
    // spec.paths looks like this (for 1 endpoint):
    // "/eth/v1/beacon/states/{state_id}/fork": PathItem { reference: None, summary: None, description: None, get: Some(Operation {...
    // So: endpoint is a String, e.g.,: "/eth/v1/beacon/states/{state_id}/fork"
    // path_item itself is a struct of type PathItem
    if let Some(paths) = &spec.paths {
        for (endpoint, path_item) in paths {
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
            // where the String can be "200", "400" etc, and the value is of type ObjectOrReference<Response>
            // with .get("200"), we get to the ObjectOrReference<Response>
            // So response is of type Response (a struct) after extracting the Object
            let response = match responses.get("200").unwrap() {
                ObjectOrReference::Object(object) => object,
                ObjectOrReference::Ref { .. } => panic!("Should be an Object"),
            };

            // response.content is of type: BTreeMap<String, MediaType>
            // where the key (with type String) is "application/json" (or "application/octet-stream") and the value is type: MediaType
            /* Mediatype is a Struct:
            pub struct MediaType {
                pub schema: Option<ObjectOrReference<ObjectSchema>>,
                pub examples: Option<MediaTypeExamples>,
                pub encoding: BTreeMap<String, Encoding>,
                pub extensions: BTreeMap<String, Value>,
            }
             */
            // media_type is of type MediaType
            let Some(media_type) = response.content.get("application/json") else {
                // eth/v1/events does not have application/json, only application/octet-stream
                // /eth/v1/node/health does not have application/json in the response: https://github.com/ethereum/beacon-APIs/blob/master/apis/node/health.yaml
                // these endpoints are ignored for now
                println!(
                    "No application/json content found for endpoint {}",
                    endpoint
                );
                continue;
            };

            // media_type.schema accesses the field schema in the struct, and it is of type: Option<ObjectOrReference<ObjectSchema>>
            // After matching with Object enum, object_schema variable is of type ObjectSchema
            let object_schema = match media_type.schema.clone().unwrap() {
                ObjectOrReference::Object(schema) => schema,
                ObjectOrReference::Ref { .. } => panic!("Should be an Object"),
            };

            object_schema_by_endpoint.insert(endpoint.to_string(), object_schema);
        }
    }
    object_schema_by_endpoint
}

// Recursively check the required field of each ObjectSchema
fn check_field(result_json: &serde_json::Value, object_schema: &ObjectSchema, endpoint: &str) {
    // if there is anyOf, we select the first index [0] of the Vec<ObjectOrReference<ObjectSchema>>
    // i.e., the first ObjectSchema, which is usually the latest fork version
    // Example of anyOf: /eth/v2/beacon/blocks/{block_id}
    // https://github.com/ethereum/beacon-APIs/blob/d8c98590a4380720252f64c1042a178f7c1d3940/apis/beacon/blocks/block.v2.yaml#L36-L43
    if !object_schema.any_of.is_empty() {
        let oor = &object_schema.any_of[0];
        let object_schema_any = return_object_schema(oor);
        check_field(result_json, object_schema_any, endpoint);
    }

    // extract the required fields from the object_schema
    if !object_schema.required.is_empty() {
        // schema.required is a Vec<String>, containing the required fields
        let required_fields = object_schema.required.clone();
        let result = result_json.as_object().unwrap();
        let result_fields = result.keys().collect::<Vec<_>>();
        println!("Required fields: {:?}", object_schema.required);
        println!("Result fields:   {:?}", result_fields);
        // check the name of each required field
        // checking this way will guarantee that all fields in required_fields in the spec are present in result
        // this implies that having more fields in result than required_fields will not fail the test
        // (e.g., extra_data in /eth/v1/debug/fork_choice appears in result but not in required_fields)
        for field in &required_fields {
            assert!(
                result.contains_key(field),
                "Endpoint {} missing required field `{}`",
                endpoint,
                field,
            );
        }

        // check the total number of required fields are the same
        // result may contain more fields in some endpoints (e.g., extra_data in /eth/v1/debug/fork_choice)
        // missing proposer_lookahead in the response for /eth/v2/debug/beacon/states/{state_id}
        if endpoint == "/eth/v2/debug/beacon/states/{state_id}"
            || endpoint == "/eth/v1/debug/fork_choice"
            || endpoint == "/eth/v1/node/identity"
        {
        } else {
            assert_eq!(
                result.len(),
                required_fields.len(),
                "Total number of fields in result is not the same as required fields for endpoint {}. \n \
                result: {:?} \n \
                required: {:?}",
                endpoint,
                result_fields,
                required_fields
            );
        }
    }

    // Recursively look into object_schema.properties as each properties may contain sub-level required fields
    // example: /eth/v1/beacon/states/{state_id}/validators/{validator_id}: https://github.com/ethereum/beacon-APIs/blob/d8c98590a4380720252f64c1042a178f7c1d3940/apis/beacon/states/validator.yaml#L24-L34
    // the first schema.required returns the top-level required fields: required: [execution_optimistic, finalized, data]
    // and we have more fields under "data", and "data" is under object_schema.properties
    // so we iterate over all name/field in object_schema.properties and for each schema.properties, we call this function again to check the field
    //
    // object_schema.properties is of type: BTreeMap<String, ObjectOrReference<ObjectSchema>>
    // Using the same example, the name in the following for loop can be: execution_optimistic, finalized, or data
    // the corresponding value in the BTreeMap is another ObjectSchema
    // if the name is "data" (which is an ObjectSchama), it is a ValidatorResponse: https://github.com/ethereum/beacon-APIs/blob/d8c98590a4380720252f64c1042a178f7c1d3940/apis/beacon/states/validator.yaml#L33-L34
    // then under object_schema.properties, the required field is: https://github.com/ethereum/beacon-APIs/blob/d8c98590a4380720252f64c1042a178f7c1d3940/types/api.yaml#L5C3-L5C48
    // these required fields will be extracted, and will be checked as well by recursively calling the check_field function
    // under "data", object_schema.properties gives the required field: ["index", "balance", "status", "validator"]
    // so each name is loop again and until it reaches "validator", where the deepest level of required is extracted: https://github.com/ethereum/beacon-APIs/blob/d8c98590a4380720252f64c1042a178f7c1d3940/types/phase0/validator.yaml#L5
    // if the name is "execution_optimistic", then schema.required is empty, when it comes to this for loop, there will be no for loop, so the recursive call stops
    for (name, object_schema_inner_ref) in &object_schema.properties {
        let object_schema_inner = return_object_schema(object_schema_inner_ref);
        // extract the corresponding result_json.get(name) so that the field is checked with the required field
        // e.g., if name is data, then result_json.get(data) will extract the data field from the result_json
        //

        let Some(result_json_inner) = result_json.get(name) else {
            println!(
                // for endpoint /eth/v1/debug/fork_choice where the field `extra_data` is not in schema.required, but appears in schema.properties
                "result_json for endpoint {} does not contain the field `{}`, continue anyway as it will be checked if it is a required field later",
                endpoint, name
            );
            continue;
        };
        // let result_json_inner = result_json.get(name).unwrap();
        // println!(
        //    "name is: {}, object_schema_inner_ref: {:?}",
        //    name, object_schema_inner_ref
        // );
        // println!("result_json_inner is: {:?}", result_json_inner);
        check_field(result_json_inner, object_schema_inner, endpoint);
    }

    // if type is Array, check each Object in the Array
    // example: https://github.com/ethereum/beacon-APIs/blob/master/apis/beacon/light_client/updates.yaml
    //

    // example: /eth/v1/beacon/headers: https://github.com/ethereum/beacon-APIs/blob/master/apis/beacon/blocks/headers.yaml
    // first level required is: required: [execution_optimistic, finalized, data]
    // second level required is: required: [root, canonical, header]
    // we still have additional fields under the "header" field, this leads to SignedBeaconBlockHeader: https://github.com/ethereum/beacon-APIs/blob/d8c98590a4380720252f64c1042a178f7c1d3940/types/phase0/block.yaml#L84-L92
    // which contains: required: [message, signature]
    if let Some(type_set) = &object_schema.schema_type
        && type_set.is_array_or_nullable_array()
    {
        // if the type is an array, then the result_json will also be an array
        let result_array = result_json.as_array().unwrap();
        // if the schema_type is array, then it will contain items in the ObjectSchema
        // example: https://github.com/ethereum/beacon-APIs/blob/d8c98590a4380720252f64c1042a178f7c1d3940/apis/beacon/light_client/updates.yaml#L30C13-L30C19
        // (other endpoints with type: Object does not have items as a field)
        let schema = object_schema.items.clone().unwrap();
        // schema is of type Box<Schema> (not ObjectSchema), where Schema is an enum: https://docs.rs/oas3/latest/oas3/spec/enum.Schema.html
        let object_schema_items = match schema.as_ref() {
            Schema::Object(oor) => return_object_schema(oor),
            _ => panic!("Should be an Object"),
        };
        for object in result_array.iter() {
            check_field(object, object_schema_items, endpoint);
        }
    }

    // Check the type
    // object_schema.schema_type can be None (e.g., when it is an array)
    if let Some(ref type_set) = object_schema.schema_type {
        // object_schema.schema_type returns type: Option<TypeSet> where TypeSet is an enum: https://docs.rs/oas3/latest/oas3/spec/enum.SchemaTypeSet.html
        // all TypeSets (under schema_type in ObjctSchema) in the beacon API spec are Single
        println!("object_schema is: {:?}", object_schema);
        println!("result_json is: {:?}", result_json);
        println!("type_set is: {:?}", type_set);
        match type_set {
            SchemaTypeSet::Single(schema_type) => {
                check_type(result_json, schema_type, object_schema, endpoint)
            }
            SchemaTypeSet::Multiple(_) => panic!("Should be Single TypeSet"),
        }
    }
}

// Check the type of each result_json
fn check_type(
    result_json: &serde_json::Value,
    schema_type: &SchemaType,
    object_schema: &ObjectSchema,
    endpoint: &str,
) {
    // if result_json is null, we skip the type check
    // this is because, e.g., in /eth/v1/debug/fork_choice, the first/parent fork_choice_node always has parent_root: null
    // but the spec has parent_root: https://github.com/ethereum/beacon-APIs/blob/d8c98590a4380720252f64c1042a178f7c1d3940/types/fork_choice.yaml#L12-L14
    // with the Root defined as type String: https://github.com/ethereum/beacon-APIs/blob/d8c98590a4380720252f64c1042a178f7c1d3940/types/primitive.yaml#L64
    // this causes the type check to fail
    if result_json.is_null() {
        return;
    }

    // List of schema_type available: https://docs.rs/oas3/latest/oas3/spec/enum.SchemaType.html
    match schema_type {
        SchemaType::Boolean => assert!(
            result_json.is_boolean(),
            "Type check failed for endpoint {}. Expected boolean, got {}.",
            endpoint,
            result_json,
        ),
        SchemaType::Integer | SchemaType::Number => assert!(
            result_json.is_number(),
            "Type check failed for endpoint {} Expected number, got {}.",
            endpoint,
            result_json,
        ),
        SchemaType::String => {
            assert!(
                result_json.is_string(),
                "Type check failed for endpoint {}. Expected string, got {}.",
                endpoint,
                result_json,
            );
            // For String type, we can further check the result_json against the regex pattern defined in the spec
            if let Some(ref pattern) = object_schema.pattern {
                //let regex = Regex::new(pattern).unwrap();
                // Using Regex::new(pattern) would error: CompiledTooBig(10485760)
                // Resize the regex limit to enable the pattern check for blob: ^0x[a-fA-F0-9]{262144}$
                let regex = RegexBuilder::new(pattern)
                    .size_limit(100000000)
                    .build()
                    .unwrap();
                let result = result_json.as_str().unwrap();
                assert!(
                    regex.is_match(result),
                    "Regex pattern check failed for endpoint {}. Regex pattern is {}, result is {}",
                    endpoint,
                    regex,
                    result
                );
            }
        }
        SchemaType::Array => assert!(
            result_json.is_array(),
            "Type check failed for endpoint {}. Expected array, got {}.",
            endpoint,
            result_json,
        ),
        SchemaType::Object => assert!(
            result_json.is_object(),
            "Type check failed for endpoint {}. Expected object, got {}.",
            endpoint,
            result_json,
        ),
        SchemaType::Null => assert!(
            result_json.is_null(),
            "Type check failed for endpoint {}. Expected null, got {}.",
            endpoint,
            result_json,
        ),
    }
}

// Used to replace parameters such as {block_id} with actual values so that a valid HTTP request is made
fn replace_parameter(
    param: &str,
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    peer_id: PeerId,
    attestation_data_root: Hash256,
) -> String {
    let head = harness.chain.head_snapshot();
    let block_root = head.beacon_block_root;

    let current_slot = harness.get_current_slot();
    let current_epoch = current_slot.epoch(E::slots_per_epoch());

    let slot = current_slot.to_string();
    let epoch = current_epoch.to_string();
    let subcommittee_index = "0";
    let committee_index = "0";
    // for endpoint /eth/v1/beacon/light_client/updates, start_period and count are required
    let start_period = "0";
    let count = "1";
    // point-at-infinity to skip randao verification
    let randao_reveal: SignatureBytes = Signature::infinity().unwrap().into();

    param
        // Need to prioritize replacing the whole endpoint before replacing a single parameter
        .replace("/eth/v1/beacon/light_client/updates", &format!("/eth/v1/beacon/light_client/updates?start_period={}&count={}", start_period, count))
        .replace("/eth/v1/validator/attestation_data", &format!("/eth/v1/validator/attestation_data?slot={}&committee_index={}", slot, committee_index))
        .replace(
            "/eth/v1/validator/sync_committee_contribution",
            &format!("/eth/v1/validator/sync_committee_contribution/?slot={}&subcommittee_index={}&beacon_block_root={}", slot, subcommittee_index, block_root))
        .replace("/eth/v2/validator/aggregate_attestation", &format!("/eth/v2/validator/aggregate_attestation?attestation_data_root={:?}&slot={}&committee_index={}", attestation_data_root, slot, committee_index))
        .replace("/eth/v3/validator/blocks/{slot}", &format!("/eth/v3/validator/blocks/{}?randao_reveal={}&skip_randao_verification=", slot, randao_reveal))
        .replace("{block_id}", "head")
        .replace("{state_id}", "finalized")
        .replace("{slot}", &slot)
        .replace("{epoch}", &epoch)
        .replace("{validator_id}", "0")
        .replace("{block_root}", &format!("{:?}", block_root))
        .replace("{peer_id}", &format!("{}", peer_id))
}

#[tokio::test]
async fn test_all_endpoints() {
    let (harness, client, port, peer_id) = new().await;

    let head = harness.chain.head_snapshot();
    let block_root = head.beacon_block_root;

    let unaggregated_attestations = harness.get_unaggregated_attestations(
        &AttestationStrategy::AllValidators,
        &head.beacon_state,
        head.beacon_state_root(),
        block_root,
        harness.chain.slot().unwrap(),
    );

    // Need to populate the attestations in the naive_aggregation_pool or the request will fail with: no matching aggregate found
    for attestations in &unaggregated_attestations {
        for (attestation, _subnet_id) in attestations {
            let _ = harness
                .chain
                .naive_aggregation_pool
                .write()
                .insert(attestation.to_ref());
        }
    }

    // For endpoint /eth/v2/validator/aggregate_attestation
    let attestation_data_root = unaggregated_attestations[0][0].0.data().tree_hash_root();

    // Similar steps for sync committee, for endpoint /eth/v1/validator/sync_committee_contribution
    let sync_contributions = harness.make_sync_contributions(
        &head.beacon_state,
        block_root,
        harness.chain.slot().unwrap(),
        RelativeSyncCommittee::Current,
    );

    for (messages, _) in sync_contributions.iter() {
        for (message, position) in messages {
            let contribution =
                SyncCommitteeContribution::from_message(message, 0, *position).unwrap();

            harness
                .chain
                .naive_sync_aggregation_pool
                .write()
                .insert(&contribution)
                .unwrap();
        }
    }

    let object_schema_by_endpoint = extract_all_endpoints().await;

    let mut checked_endpoint = 0;

    for (endpoint, object_schema) in &object_schema_by_endpoint {
        // Temporarily ignore the following endpoint
        if endpoint == "/eth/v1/beacon/states/{state_id}/proposer_lookahead" {
            continue;
        }
        // Test a single endpoint
        // endpoint != "/eth/v1/beacon/states/{state_id}/fork"
        //if endpoint != "/eth/v3/validator/blocks/{slot}" {
        //endpoint != "/eth/v1/beacon/states/{state_id}/pending_consolidations" {
        //     //endpoint != "/eth/v1/beacon/states/{state_id}/validators/{validator_id}" {
        //     // endpoint != "/eth/v1/beacon/headers" {
        // continue;
        //}

        let url = format!(
            "http://127.0.0.1:{}{}",
            port,
            replace_parameter(endpoint, &harness, peer_id, attestation_data_root)
        );
        println!("Testing endpoint: {}", endpoint);
        println!("URL is: {}", url);

        let result_json: serde_json::Value = client.get(url).await.unwrap();

        // change the result_json content to test type check or regex pattern check
        // need to modify result_json to mut
        // if endpoint == "/eth/v1/beacon/states/{state_id}/fork" {
        // manually remove one field from the response to test field check
        // result_json.as_object_mut().unwrap().remove("finalized");
        // manually change the type from Boolean to String to test type check
        // result_json["execution_optimistic"] = serde_json::Value::String("true".to_string());
        // manually change the current_version (e.g., 0x01000000) to 9 characters instead of 8 to test Regex pattern check
        // result_json["data"]["current_version"] =
        //     serde_json::Value::String("0x123456789".to_string());
        // }

        println!("Response is: {:?}", result_json);

        check_field(&result_json, object_schema, endpoint);

        println!("Test passed for endpoint: {}", endpoint);
        checked_endpoint += 1;
        println!("Checked endpoint: {}", checked_endpoint);
    }
    // let total_endpoint = object_schema_by_endpoint.len();
    // /eth/v1/beacon/states/{state_id}/proposer_lookahead hasn't been implemented yet
    // endpoints such as /eth/v1/events is not inserted in the hashmap (i.e., not included in total_endpoint)
    // assert_eq!(checked_endpoint, total_endpoint - 1);
}

// Helper function to return ObjectSchema from ObjectOrReference<ObjectSchema>
fn return_object_schema(oor: &ObjectOrReference<ObjectSchema>) -> &ObjectSchema {
    match oor {
        ObjectOrReference::Object(object_schema) => object_schema,
        ObjectOrReference::Ref { .. } => {
            panic!("Should be an Object")
        }
    }
}

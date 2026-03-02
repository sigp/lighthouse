use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::observed_operations::ObservationOutcome;
use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
    RelativeSyncCommittee,
};
use bls::FixedBytesExtended;
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
use types::{
    Address, Epoch, EthSpec, Hash256, MainnetEthSpec, PendingConsolidation, PendingDeposit,
    PendingPartialWithdrawal, Slot, SyncCommitteeContribution,
};

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
    // Allow voluntary exits without waiting
    spec.shard_committee_period = 0;

    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec.into())
        .deterministic_keypairs(VALIDATOR_COUNT)
        .deterministic_withdrawal_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .node_custody_type(NodeCustodyType::Supernode)
        .build();

    // Ensure blocks to have blob data so that /eth/v1/beacon/blob_sidecars/{block_id} contains data
    harness.execution_block_generator().set_min_blob_count(1);

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

// Extract the full ObjectSchema for each endpoint, this ObjectSchema contains all info that we need for the check
async fn extract_all_endpoints() -> HashMap<String, ObjectSchema> {
    // Obtain the complete Beacon APIs yaml file using the latest release version (not the dev versino)
    // TODO: switch to latest release before the Gloas upgrade
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
                        "{} is not a GET endpoint, ignoring this endpoint and continue to the next",
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
            // media_type is of type MediaType struct
            let Some(media_type) = response.content.get("application/json") else {
                // eth/v1/events does not have application/json, only application/octet-stream
                // /eth/v1/node/health does not have application/json in the response
                // these endpoints are ignored
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
fn check_field(
    result_json: &serde_json::Value,
    object_schema: &ObjectSchema,
    endpoint: &str,
) -> Result<(), String> {
    // if there is anyOf, we select the first index [0] of the Vec<ObjectOrReference<ObjectSchema>>
    // i.e., the first ObjectSchema, which is usually the latest fork version
    if !object_schema.any_of.is_empty() {
        let oor = &object_schema.any_of[0];
        let object_schema_any = return_object_schema(oor);
        check_field(result_json, object_schema_any, endpoint)?;
    }

    // extract the required fields from the object_schema
    if !object_schema.required.is_empty() {
        // object_schema.required is a Vec<String>, containing the required fields
        let required_fields = object_schema.required.clone();
        let result = result_json.as_object().unwrap();

        // check the name of each required field
        // checking this way will guarantee that required_fields in the spec is a subset of result
        // this implies that having more fields in result than required_fields is ok, and will not fail the test
        // (e.g., extra_data in /eth/v1/debug/fork_choice appears in result but not in required_fields)
        // (e.g., syncnets and custody_group_count in /eth/v1/node/identity are optional in the spec)
        for field in &required_fields {
            if !result.contains_key(field) {
                return Err(format!(
                    "Endpoint {} missing required field `{}`",
                    endpoint, field
                ));
            }
        }
    }

    // Recursively look into object_schema.properties as each properties may contain sub-level required fields
    // object_schema.properties will also be of type ObjectSchema, i.e, it is ObjectSchema under ObjectSchema
    // this will look into the ObjectSchema each level deeper until object_schema.properties is empty which will break the recursive call
    // example: /eth/v1/beacon/states/{state_id}/validators/{validator_id}
    // the first object_schema.required returns the top-level required fields: required: [execution_optimistic, finalized, data]
    // if the name is "data", this will go one level deeper into it to extract the required field under object_schema_inner, and this will be repeated
    // if the name is "execution_optimistic", then object_schema.required is empty, when it reaches this for loop, there will be no for loop, so the recursive call stops
    for (name, object_schema_inner_ref) in &object_schema.properties {
        let object_schema_inner = return_object_schema(object_schema_inner_ref);
        // extract the corresponding result_json.get(name) so that the field is checked with the required field
        // e.g., if name is data, then result_json.get(data) will extract the data field from the result_json
        let Some(result_json_inner) = result_json.get(name) else {
            println!(
                // for endpoint /eth/v1/debug/fork_choice where the field `extra_data` is not in object_schema.required, but appears in object_schema.properties
                "result_json for endpoint {} does not contain the field `{}`, continue anyway as it will be checked if it is a required field later",
                endpoint, name
            );
            continue;
        };
        check_field(result_json_inner, object_schema_inner, endpoint)?;
    }

    // if the type is Array, check each Object in the Array
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
            check_field(object, object_schema_items, endpoint)?;
        }
    }

    // Check the type
    // object_schema.schema_type can be None (e.g., when it is an array)
    if let Some(ref type_set) = object_schema.schema_type {
        // object_schema.schema_type returns type: Option<TypeSet> where TypeSet is an enum: https://docs.rs/oas3/latest/oas3/spec/enum.SchemaTypeSet.html
        // all TypeSets (under schema_type in ObjctSchema) in the beacon API spec are Single
        match type_set {
            SchemaTypeSet::Single(schema_type) => {
                check_type(result_json, schema_type, object_schema, endpoint)?;
            }
            SchemaTypeSet::Multiple(_) => panic!("Should be Single TypeSet"),
        }
    }

    Ok(())
}

// Check the type of each result_json
fn check_type(
    result_json: &serde_json::Value,
    schema_type: &SchemaType,
    object_schema: &ObjectSchema,
    endpoint: &str,
) -> Result<(), String> {
    // For endpoint /eth/v1/debug/fork_choice, if result_json is null, we skip the type check
    // because the first/parent fork_choice_node always has parent_root: null
    // but the spec has parent_root: https://github.com/ethereum/beacon-APIs/blob/d8c98590a4380720252f64c1042a178f7c1d3940/types/fork_choice.yaml#L12-L14
    // with the Root defined as type String: https://github.com/ethereum/beacon-APIs/blob/d8c98590a4380720252f64c1042a178f7c1d3940/types/primitive.yaml#L64
    // this causes the type check to fail
    if endpoint == "/eth/v1/debug/fork_choice" && result_json.is_null() {
        return Ok(());
    }

    // List of schema_type available: https://docs.rs/oas3/latest/oas3/spec/enum.SchemaType.html
    match schema_type {
        SchemaType::Boolean => {
            if !result_json.is_boolean() {
                return Err(format!(
                    "Type check failed for endpoint {}. Expected boolean, got {}.",
                    endpoint, result_json
                ));
            }
        }
        SchemaType::Integer | SchemaType::Number => {
            if !result_json.is_number() {
                return Err(format!(
                    "Type check failed for endpoint {}. Expected number, got {}.",
                    endpoint, result_json
                ));
            }
        }
        SchemaType::String => {
            if !result_json.is_string() {
                return Err(format!(
                    "Type check failed for endpoint {}. Expected string, got {}.",
                    endpoint, result_json
                ));
            }
            // For String type, we can further check the result_json against the regex pattern defined in the spec
            if let Some(ref pattern) = object_schema.pattern {
                // Using Regex::new(pattern) would error: CompiledTooBig(10485760)
                // Resize the regex limit to enable the pattern check for blob: ^0x[a-fA-F0-9]{262144}$
                let regex = RegexBuilder::new(pattern)
                    .size_limit(100000000)
                    .build()
                    .unwrap();
                let result = result_json.as_str().unwrap();
                if !regex.is_match(result) {
                    return Err(format!(
                        "Regex pattern check failed for endpoint {}. Regex pattern is {}, result is {}",
                        endpoint, regex, result
                    ));
                }
            }
        }
        SchemaType::Array => {
            if !result_json.is_array() {
                return Err(format!(
                    "Type check failed for endpoint {}. Expected array, got {}.",
                    endpoint, result_json
                ));
            }
        }
        SchemaType::Object => {
            if !result_json.is_object() {
                return Err(format!(
                    "Type check failed for endpoint {}. Expected object, got {}.",
                    endpoint, result_json
                ));
            }
        }
        SchemaType::Null => {
            if !result_json.is_null() {
                return Err(format!(
                    "Type check failed for endpoint {}. Expected null, got {}.",
                    endpoint, result_json
                ));
            }
        }
    }

    Ok(())
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
async fn test_all_endpoints() -> Result<(), String> {
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

    // Create BLS to execution change so that /eth/v1/beacon/pool/bls_to_execution_changes contains data
    let bls_to_execution_change = harness.make_bls_to_execution_change(0, Address::zero());
    let ObservationOutcome::New(verified_bls_change) = harness
        .chain
        .verify_bls_to_execution_change_for_gossip(bls_to_execution_change)
        .unwrap()
    else {
        panic!("bls to execution change should verify")
    };
    harness.chain.import_bls_to_execution_change(
        verified_bls_change,
        operation_pool::ReceivedPreCapella::No,
    );

    // Create voluntary exit so that /eth/v1/beacon/pool/voluntary_exits contains data
    let voluntary_exit = harness.make_voluntary_exit(0, harness.chain.epoch().unwrap());
    let ObservationOutcome::New(verified_exit) = harness
        .chain
        .verify_voluntary_exit_for_gossip(voluntary_exit)
        .unwrap()
    else {
        panic!("exit should verify")
    };
    harness.chain.import_voluntary_exit(verified_exit);

    // Create proposer slashing data so that /eth/v1/beacon/pool/proposer_slashings contains data
    let proposer_slashing = harness.make_proposer_slashing(0);
    let ObservationOutcome::New(verified_proposer_slashing) = harness
        .chain
        .verify_proposer_slashing_for_gossip(proposer_slashing)
        .unwrap()
    else {
        panic!("proposer slashing should verify")
    };
    harness
        .chain
        .import_proposer_slashing(verified_proposer_slashing);

    // Create attester slashing so that /eth/v1/beacon/pool/attester_slashings contains data
    let attester_slashing = harness.make_attester_slashing(vec![0]);
    let ObservationOutcome::New(verified_attester_slashing) = harness
        .chain
        .verify_attester_slashing_for_gossip(attester_slashing)
        .unwrap()
    else {
        panic!("attester slashing should verify")
    };
    harness
        .chain
        .import_attester_slashing(verified_attester_slashing);

    let finalized_checkpoint = harness
        .chain
        .canonical_head
        .cached_head()
        .finalized_checkpoint();
    let finalized_slot = finalized_checkpoint.epoch.start_slot(E::slots_per_epoch());
    let finalized_state_root = harness
        .chain
        .state_root_at_slot(finalized_slot)
        .unwrap()
        .unwrap();
    let mut finalized_state = harness
        .chain
        .get_state(&finalized_state_root, Some(finalized_slot), false)
        .unwrap()
        .unwrap();

    // Populate the state with deposits, consolidations, and partial_withdrawals so that these endpoints contain data
    finalized_state
        .pending_deposits_mut()
        .unwrap()
        .push(PendingDeposit {
            pubkey: harness.validator_keypairs[0].pk.compress(),
            withdrawal_credentials: Hash256::zero(),
            amount: 32_000_000_000,
            signature: Signature::infinity().unwrap().into(),
            slot: Slot::new(0),
        })
        .unwrap();

    finalized_state
        .pending_consolidations_mut()
        .unwrap()
        .push(PendingConsolidation {
            source_index: 0,
            target_index: 1,
        })
        .unwrap();

    finalized_state
        .pending_partial_withdrawals_mut()
        .unwrap()
        .push(PendingPartialWithdrawal {
            validator_index: 0,
            amount: 1_000_000_000,
            withdrawable_epoch: Epoch::new(0),
        })
        .unwrap();

    harness
        .chain
        .store
        .state_cache
        .lock()
        .update_finalized_state(
            finalized_state_root,
            finalized_checkpoint.root,
            finalized_state,
            &[],
        )
        .unwrap();

    let object_schema_by_endpoint = extract_all_endpoints().await;

    for (endpoint, object_schema) in &object_schema_by_endpoint {
        // Temporarily ignore the following endpoint
        if endpoint == "/eth/v1/beacon/states/{state_id}/proposer_lookahead" {
            continue;
        }

        let url = format!(
            "http://127.0.0.1:{}{}",
            port,
            replace_parameter(endpoint, &harness, peer_id, attestation_data_root)
        );

        let result_json: serde_json::Value = client.get(url.clone()).await.unwrap();

        check_field(&result_json, object_schema, endpoint)?;

        // Check that top-level data arrays are non-empty to ensure item schemas are validated.
        if let Some(data) = result_json.get("data")
            && let Some(data_array) = data.as_array()
            && data_array.is_empty()
        {
            return Err(format!("Empty data array for endpoint {}.", endpoint));
        }

        // NOt all endpoints have "finalized" field, so we test a single endpoint modification
        if endpoint == "/eth/v1/beacon/states/{state_id}/fork" {
            // modify to remove one field from the response to test field check
            let mut result_json_modify: serde_json::Value = client.get(url.clone()).await.unwrap();
            result_json_modify
                .as_object_mut()
                .unwrap()
                .remove("finalized");
            assert!(check_field(&result_json_modify, object_schema, endpoint).is_err());

            // modify the type from Boolean to String to test type check
            let mut result_json_modify: serde_json::Value = client.get(url.clone()).await.unwrap();
            result_json_modify["execution_optimistic"] =
                serde_json::Value::String("true".to_string());
            assert!(check_field(&result_json_modify, object_schema, endpoint).is_err());

            // manually modify the current_version (e.g., 0x01000000) to 9 characters instead of 8 to test Regex pattern check
            let mut result_json_modify: serde_json::Value = client.get(url).await.unwrap();
            result_json_modify["data"]["current_version"] =
                serde_json::Value::String("0x123456789".to_string());
            assert!(check_field(&result_json_modify, object_schema, endpoint).is_err());
        }
    }
    Ok(())
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

use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::observed_operations::ObservationOutcome;
use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
    RelativeSyncCommittee,
};
use bls::FixedBytesExtended;
use bls::{Signature, SignatureBytes};
use eth2::types::{
    BeaconCommitteeSelection, BeaconCommitteeSubscription, PublishBlockRequest,
    SyncCommitteeSelection, ValidatorId, ValidatorIndexData, ValidatorStatus,
    ValidatorsRequestBody,
};
use http_api::test_utils::{ApiServer, create_api_server};
use lighthouse_network::PeerId;
use oas3::spec::{ObjectOrReference, ObjectSchema, Operation, Schema, SchemaType, SchemaTypeSet};
use regex::RegexBuilder;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{
    Address, Epoch, EthSpec, Hash256, MainnetEthSpec, PendingConsolidation, PendingDeposit,
    PendingPartialWithdrawal, ProposerPreparationData, SignedContributionAndProof,
    SignedValidatorRegistrationData, Slot, SyncCommitteeContribution, SyncCommitteeSubscription,
    ValidatorRegistrationData,
};

type E = MainnetEthSpec;

const SLOTS_PER_EPOCH: u64 = 32;
const VALIDATOR_COUNT: usize = SLOTS_PER_EPOCH as usize;
const CHAIN_LENGTH: u64 = SLOTS_PER_EPOCH * 5 - 1;

struct ObjectSchemaByEndpoint {
    get_response: HashMap<String, ObjectSchema>,
    post_response: HashMap<String, ObjectSchema>,
    post_request: HashMap<String, ObjectSchema>,
}

struct ChainData {
    attestation_data_root: Hash256,
    block: serde_json::Value,
    blinded_block: serde_json::Value,
}

async fn new() -> (
    Arc<BeaconChainHarness<EphemeralHarnessType<E>>>,
    Client,
    u16,
    PeerId,
    network::NetworkReceivers<E>,
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

    let ApiServer {
        server,
        listening_socket,
        external_peer_id,
        network_rx,
        ..
    } = create_api_server(harness.chain.clone(), &harness.runtime).await;

    harness.runtime.task_executor.spawn(server, "api_server");

    let port = listening_socket.port();
    let client = reqwest::Client::builder().build().unwrap();

    (harness, client, port, external_peer_id, network_rx)
}

// Populate the chain with data so that some live data such as voluntary exits, pending deposits are available
async fn populate_chain_data(harness: &BeaconChainHarness<EphemeralHarnessType<E>>) -> ChainData {
    let head_snapshot = harness.chain.head_snapshot();
    let block_root = head_snapshot.beacon_block_root;

    let unaggregated_attestations = harness.get_unaggregated_attestations(
        &AttestationStrategy::AllValidators,
        &head_snapshot.beacon_state,
        head_snapshot.beacon_state_root(),
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
        &head_snapshot.beacon_state,
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

    // create blocks for POST /eth/v2/beacon/blocks and blinded_blocks endpoint
    let (next_block, _next_state) = harness
        .make_block(harness.get_current_state(), harness.get_current_slot())
        .await;
    let next_block = PublishBlockRequest::from(next_block);
    let block = serde_json::to_value(&next_block).unwrap();

    let signed_blinded_block = next_block.signed_block().clone_as_blinded();
    let blinded_block = serde_json::to_value(&signed_blinded_block).unwrap();

    ChainData {
        attestation_data_root,
        block,
        blinded_block,
    }
}

// Extract the full ObjectSchema for each endpoint, the ObjectSchema contains all info that we need for the checks
async fn extract_all_endpoints() -> ObjectSchemaByEndpoint {
    // Obtain the complete Beacon APIs yaml file using the latest release version (not the dev version)
    let yaml = reqwest::get(
        "https://github.com/ethereum/beacon-APIs/releases/latest/download/beacon-node-oapi.yaml",
    )
    .await
    .unwrap()
    .text()
    .await
    .unwrap();

    // Use the function from oas3 crate to parse the main yaml file
    let spec = oas3::from_yaml(yaml).unwrap();

    let mut get_response = HashMap::new();
    let mut post_response = HashMap::new();
    let mut post_request = HashMap::new();

    // spec.paths is Option<IndexMap<String, PathItem>>
    // spec.paths looks like this (for 1 endpoint):
    // "/eth/v1/beacon/states/{state_id}/fork": PathItem { reference: None, summary: None, description: None, get: Some(Operation {...
    // So: endpoint is a String, e.g.,: "/eth/v1/beacon/states/{state_id}/fork"
    // path_item itself is a struct of type PathItem
    if let Some(paths) = &spec.paths {
        for (endpoint, path_item) in paths {
            // path_item.get is of type: Option<Operation>
            // object_schema_from_operation is to extract the "responses" field of the Operation
            if let Some(get_operation) = &path_item.get
                && let Some(get_response_object_schema) =
                    object_schema_from_operation(get_operation, endpoint)
            {
                // This will collect all GET endpoints responses in a HashMap
                get_response.insert(endpoint.to_string(), get_response_object_schema);
            };

            // For POST endpoints, it will always have a request body, but not necessarily a response body
            // So we first collect the request_body, and then collect the response
            if let Some(post_operation) = &path_item.post {
                let request_body = post_operation.request_body.clone().unwrap();
                let request_body_object = match request_body {
                    ObjectOrReference::Object(object) => object,
                    ObjectOrReference::Ref { .. } => panic!("Should be an Object"),
                };
                let Some(media_type) = request_body_object.content.get("application/json") else {
                    println!(
                        "No application/json in request body for endpoint {} ",
                        endpoint
                    );
                    continue;
                };
                let post_request_object_schema = match media_type.schema.clone().unwrap() {
                    ObjectOrReference::Object(schema) => schema,
                    ObjectOrReference::Ref { .. } => panic!("Should be an Object"),
                };
                // Collect all POST endpoints request body
                post_request.insert(endpoint.to_string(), post_request_object_schema);

                // Some POST endpoints do have a response body
                if let Some(post_response_object_schema) =
                    object_schema_from_operation(post_operation, endpoint)
                {
                    post_response.insert(endpoint.to_string(), post_response_object_schema);
                }
            };
        }
    }

    ObjectSchemaByEndpoint {
        get_response,
        post_response,
        post_request,
    }
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

    // Some endpoints request_body has oneOf, example:
    // https://github.com/ethereum/beacon-APIs/blob/ce1451bd9575137b62fa2c94696e962e46b25f19/apis/beacon/pool/attestations.v2.yaml#L81-L87
    // we pick one of the schema to do the check
    if !object_schema.one_of.is_empty() {
        let oor = &object_schema.one_of[0];
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
        // all TypeSets (under schema_type in ObjectSchema) in the beacon API spec are Single
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
    endpoint: &str,
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    peer_id: PeerId,
    attestation_data_root: Hash256,
) -> String {
    let head_snapshot = harness.chain.head_snapshot();
    let block_root = head_snapshot.beacon_block_root;
    let current_slot = harness.get_current_slot();
    let current_epoch = current_slot.epoch(E::slots_per_epoch());
    // Endpoint /eth/v1/beacon/rewards/attestations/{epoch} needs to be queried at an earlier epoch so that the state is available
    let current_epoch_for_reward = current_slot
        .epoch(E::slots_per_epoch())
        .as_u64()
        .saturating_sub(2);

    let slot = current_slot.to_string();
    let epoch = current_epoch.to_string();
    let epoch_for_reward = current_epoch_for_reward.to_string();
    let validator_id = "0";
    let subcommittee_index = "0";
    let committee_index = "0";
    // For endpoint /eth/v1/beacon/light_client/updates, start_period and count are required
    let start_period = "0";
    let count = "1";
    // point-at-infinity to skip randao verification
    let randao_reveal: SignatureBytes = Signature::infinity().unwrap().into();

    endpoint
        // Need to prioritize replacing the whole endpoint before replacing a single parameter
        .replace("/eth/v1/beacon/light_client/updates", &format!("/eth/v1/beacon/light_client/updates?start_period={}&count={}", start_period, count))
        .replace("/eth/v1/validator/attestation_data", &format!("/eth/v1/validator/attestation_data?slot={}&committee_index={}", slot, committee_index))
        .replace(
            "/eth/v1/validator/sync_committee_contribution",
            &format!("/eth/v1/validator/sync_committee_contribution/?slot={}&subcommittee_index={}&beacon_block_root={}", slot, subcommittee_index, block_root))
        .replace("/eth/v2/validator/aggregate_attestation", &format!("/eth/v2/validator/aggregate_attestation?attestation_data_root={:?}&slot={}&committee_index={}", attestation_data_root, slot, committee_index))
        .replace("/eth/v3/validator/blocks/{slot}", &format!("/eth/v3/validator/blocks/{}?randao_reveal={}&skip_randao_verification=", slot, randao_reveal))
        .replace("/eth/v1/beacon/rewards/attestations/{epoch}", &format!("/eth/v1/beacon/rewards/attestations/{}", epoch_for_reward))
        .replace("{block_id}", "head")
        .replace("{state_id}", "finalized")
        .replace("{slot}", &slot)
        .replace("{epoch}", &epoch)
        .replace("{validator_id}", validator_id)
        .replace("{block_root}", &format!("{:?}", block_root))
        .replace("{peer_id}", &format!("{}", peer_id))
}

// Create the request body for POST endpoints
fn create_request_body(
    endpoint: &str,
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    block: serde_json::Value,
    blinded_block: serde_json::Value,
) -> Option<serde_json::Value> {
    let head_snapshot = harness.chain.head_snapshot();
    let block_root = head_snapshot.beacon_block_root;
    let state = &head_snapshot.beacon_state;
    let state_root = head_snapshot.beacon_state_root();
    let current_slot = harness.get_current_slot();
    let current_epoch = current_slot.epoch(E::slots_per_epoch());

    let validator_index = 0;
    let committee_index = 0;
    let committees_at_slot = 0;
    let sync_committee_indices = vec![0];
    let subcommittee_index = 0;
    let fee_recipient = Address::zero();

    let validator_index_data = ValidatorIndexData(vec![0]);

    let validators_request_body = ValidatorsRequestBody {
        ids: Some(vec![ValidatorId::Index(0)]),
        statuses: Some(vec![ValidatorStatus::ActiveOngoing]),
    };

    let single_attestations = harness.get_single_attestations(
        &AttestationStrategy::AllValidators,
        state,
        state_root,
        block_root,
        current_slot,
    );
    let single_attestation = &single_attestations[0][0].0;

    let sync_committee_messages = harness.make_sync_committee_messages(
        state,
        block_root,
        current_slot,
        RelativeSyncCommittee::Current,
    );
    let sync_committee_message = &sync_committee_messages[0][0].0;

    let attester_slashing = harness.make_attester_slashing(vec![validator_index]);
    let proposer_slashing = harness.make_proposer_slashing(validator_index);
    let voluntary_exit = harness.make_voluntary_exit(validator_index, current_epoch);
    let bls_to_execution_change =
        harness.make_bls_to_execution_change(validator_index, fee_recipient);

    let beacon_committee_subscription = BeaconCommitteeSubscription {
        validator_index,
        committee_index,
        committees_at_slot,
        slot: current_slot,
        is_aggregator: true,
    };

    let sync_committee_subscription = SyncCommitteeSubscription {
        validator_index,
        sync_committee_indices,
        until_epoch: current_epoch,
    };

    let proposer_preparation_data = ProposerPreparationData {
        validator_index,
        fee_recipient,
    };

    let signed_aggregate_and_proof = harness
        .make_attestations(
            &harness.get_all_validators(),
            state,
            state_root,
            block_root.into(),
            current_slot,
        )
        .into_iter()
        .find_map(|(_committee_attestation, aggregate)| aggregate)
        .unwrap();

    let contribution_and_proofs: Vec<SignedContributionAndProof<E>> = harness
        .make_sync_contributions(
            state,
            block_root,
            current_slot,
            RelativeSyncCommittee::Current,
        )
        .into_iter()
        .filter_map(|(_sync_committee_message, contribution)| contribution)
        .collect();
    let contribution_and_proof = &contribution_and_proofs[0];

    let signed_validator_registration_data = SignedValidatorRegistrationData {
        message: ValidatorRegistrationData {
            fee_recipient,
            gas_limit: 60_000_000,
            timestamp: 100,
            pubkey: harness.validator_keypairs[0].pk.compress(),
        },
        signature: Signature::infinity().unwrap(),
    };

    let beacon_committee_selection = BeaconCommitteeSelection {
        validator_index,
        slot: current_slot,
        selection_proof: Signature::infinity().unwrap(),
    };

    let sync_committee_selection = SyncCommitteeSelection {
        validator_index,
        slot: current_slot,
        subcommittee_index,
        selection_proof: Signature::infinity().unwrap(),
    };

    match endpoint {
        "/eth/v1/beacon/states/{state_id}/validator_balances"
        | "/eth/v1/beacon/states/{state_id}/validator_identities"
        | "/eth/v1/beacon/rewards/attestations/{epoch}"
        | "/eth/v1/beacon/rewards/sync_committee/{block_id}"
        | "/eth/v1/validator/duties/attester/{epoch}"
        | "/eth/v1/validator/duties/sync/{epoch}"
        | "/eth/v1/validator/liveness/{epoch}" => {
            Some(serde_json::to_value(validator_index_data).unwrap())
        }
        "/eth/v1/beacon/states/{state_id}/validators" => {
            Some(serde_json::to_value(validators_request_body).unwrap())
        }
        // The request_body type is an Array, so we need [], see:
        // https://github.com/ethereum/beacon-APIs/blob/ce1451bd9575137b62fa2c94696e962e46b25f19/apis/beacon/pool/attestations.v2.yaml#L82
        "/eth/v2/beacon/pool/attestations" => {
            Some([serde_json::to_value(single_attestation).unwrap()].into())
        }
        "/eth/v1/beacon/pool/sync_committees" => {
            Some([serde_json::to_value(sync_committee_message).unwrap()].into())
        }
        // The request_body type is not an Array, i.e., it is an Object, so no need []
        // Example: https://github.com/ethereum/beacon-APIs/blob/ce1451bd9575137b62fa2c94696e962e46b25f19/apis/beacon/pool/attester_slashings.v2.yaml#L52-L55
        "/eth/v2/beacon/pool/attester_slashings" => {
            Some(serde_json::to_value(attester_slashing).unwrap())
        }
        "/eth/v1/beacon/pool/proposer_slashings" => {
            Some(serde_json::to_value(proposer_slashing).unwrap())
        }
        "/eth/v1/beacon/pool/voluntary_exits" => {
            Some(serde_json::to_value(voluntary_exit).unwrap())
        }
        "/eth/v1/beacon/pool/bls_to_execution_changes" => {
            Some([serde_json::to_value(bls_to_execution_change).unwrap()].into())
        }
        "/eth/v2/beacon/blocks" => Some(block),
        "/eth/v2/beacon/blinded_blocks" => Some(blinded_block),
        "/eth/v1/validator/beacon_committee_subscriptions" => {
            Some([serde_json::to_value(beacon_committee_subscription).unwrap()].into())
        }
        "/eth/v1/validator/sync_committee_subscriptions" => {
            Some([serde_json::to_value(sync_committee_subscription).unwrap()].into())
        }
        "/eth/v1/validator/prepare_beacon_proposer" => {
            Some([serde_json::to_value(proposer_preparation_data).unwrap()].into())
        }
        "/eth/v2/validator/aggregate_and_proofs" => {
            Some([serde_json::to_value(signed_aggregate_and_proof).unwrap()].into())
        }
        "/eth/v1/validator/contribution_and_proofs" => {
            Some([serde_json::to_value(contribution_and_proof).unwrap()].into())
        }
        "/eth/v1/validator/register_validator" => {
            Some([serde_json::to_value(signed_validator_registration_data).unwrap()].into())
        }
        "/eth/v1/validator/beacon_committee_selections" => {
            Some([serde_json::to_value(beacon_committee_selection).unwrap()].into())
        }
        "/eth/v1/validator/sync_committee_selections" => {
            Some([serde_json::to_value(sync_committee_selection).unwrap()].into())
        }
        _ => None,
    }
}

#[tokio::test]
async fn http_api_spec_test() -> Result<(), String> {
    let (harness, client, port, peer_id, _network_receiver) = new().await;

    let ChainData {
        attestation_data_root,
        block,
        blinded_block,
    } = populate_chain_data(&harness).await;

    let object_schema_by_endpoint = extract_all_endpoints().await;

    // Test for GET endpoints response
    for (endpoint, get_response_object_schema) in &object_schema_by_endpoint.get_response {
        let url = format!(
            "http://127.0.0.1:{}{}",
            port,
            replace_parameter(endpoint, &harness, peer_id, attestation_data_root)
        );

        let get_result_json: serde_json::Value =
            client.get(&url).send().await.unwrap().json().await.unwrap();

        check_field(&get_result_json, get_response_object_schema, endpoint)?;

        // Check that top-level data arrays are non-empty to ensure item schemas are validated.
        if let Some(get_data) = get_result_json.get("data")
            && let Some(get_data_array) = get_data.as_array()
            && get_data_array.is_empty()
        {
            return Err(format!("Empty data array for endpoint {}.", endpoint));
        }

        // NOt all endpoints have "finalized" field, so we test a single endpoint modification
        if endpoint == "/eth/v1/beacon/states/{state_id}/fork" {
            // modify to remove one field from the response to test field check
            let mut result_json_modify: serde_json::Value =
                client.get(&url).send().await.unwrap().json().await.unwrap();
            result_json_modify
                .as_object_mut()
                .unwrap()
                .remove("finalized");
            assert!(
                check_field(&result_json_modify, get_response_object_schema, endpoint).is_err()
            );

            // modify the type from Boolean to String to test type check
            let mut result_json_modify: serde_json::Value =
                client.get(&url).send().await.unwrap().json().await.unwrap();
            result_json_modify["execution_optimistic"] =
                serde_json::Value::String("true".to_string());
            assert!(
                check_field(&result_json_modify, get_response_object_schema, endpoint).is_err()
            );

            // manually modify the current_version (e.g., 0x01000000) to 9 characters instead of 8 to test Regex pattern check
            let mut result_json_modify: serde_json::Value =
                client.get(&url).send().await.unwrap().json().await.unwrap();
            result_json_modify["data"]["current_version"] =
                serde_json::Value::String("0x123456789".to_string());
            assert!(
                check_field(&result_json_modify, get_response_object_schema, endpoint).is_err()
            );
        }
    }

    // Test for POST endpoints request body and response
    for (endpoint, post_request_object_schema) in &object_schema_by_endpoint.post_request {
        let request_body =
            create_request_body(endpoint, &harness, block.clone(), blinded_block.clone()).unwrap();

        // Perform checks for the request body in POST endpoints
        // The request bodies are constructed using functions and types in Lighthouse
        // If the check fails, it means the request body is not following the spec, suggesting something is not right in the functions/types
        // If the check passes, it means that the functions/types that are used to construct the request body is following the spec
        check_field(&request_body, post_request_object_schema, endpoint)?;

        let url = format!(
            "http://127.0.0.1:{}{}",
            port,
            replace_parameter(endpoint, &harness, peer_id, attestation_data_root)
        );

        // For POST endpoints with response, we can further check the response body
        // Ignore the selections endpoint as these endpoints are not implemented in the beacon node
        if object_schema_by_endpoint
            .post_response
            .contains_key(endpoint)
            && !endpoint.contains("selections")
        {
            let post_result_json = client
                .post(url)
                .json(&request_body)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();

            let post_response_object_schema = object_schema_by_endpoint
                .post_response
                .get(endpoint)
                .unwrap();
            check_field(&post_result_json, post_response_object_schema, endpoint)?;

            // Check that top-level data arrays are non-empty to ensure item schemas are validated.
            if let Some(post_data) = post_result_json.get("data")
                && let Some(post_data_array) = post_data.as_array()
                && post_data_array.is_empty()
            {
                return Err(format!("Empty data array for endpoint {}.", endpoint));
            }
        }
    }

    Ok(())
}

// Helper function to return ObjectSchema from ObjectOrReference<ObjectSchema>
fn return_object_schema(oor: &ObjectOrReference<ObjectSchema>) -> &ObjectSchema {
    match oor {
        ObjectOrReference::Object(object_schema) => object_schema,
        // All ObjectorReference should be an Object, because the yaml file has resolved/substituted all references
        // so there should be no Reference left
        ObjectOrReference::Ref { .. } => {
            panic!("Should be an Object")
        }
    }
}

// Helper function to extract object schema for responses (the response body of an endpoint) from operation
fn object_schema_from_operation(operation: &Operation, endpoint: &str) -> Option<ObjectSchema> {
    // responses if of type: Option<BTreeMap<String, ObjectOrReference<Response>>>
    let responses = operation.responses.clone().unwrap();
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
        // GET /eth/v1/events does not have application/json, only application/octet-stream
        // GET /eth/v1/node/health does not have application/json in the response
        // Some POST endpoints also do not have a response body
        println!(
            "No application/json in response.\"200\".content for endpoint {} ",
            endpoint
        );
        return None;
    };

    // media_type.schema accesses the field schema in the struct, and it is of type: Option<ObjectOrReference<ObjectSchema>>
    // After matching with Object enum, object_schema variable is of type ObjectSchema
    let object_schema = match media_type.schema.clone().unwrap() {
        ObjectOrReference::Object(schema) => schema,
        ObjectOrReference::Ref { .. } => panic!("Should be an Object"),
    };

    Some(object_schema)
}

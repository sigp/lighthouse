use httpmock::{Method, MockServer, Mock};
use std::time::{UNIX_EPOCH, SystemTime};
use tree_hash::Hash256;
use types::*;
use eth2::types::*;
use sensitive_url::SensitiveUrl;
use slot_clock::{SystemTimeSlotClock, SlotClock};
use std::collections::HashMap;
use itertools::Itertools;
use std::marker::PhantomData;

pub struct MockBeacon<'a, E: EthSpec> {
    server: &'a MockServer,
    genesis_mock: Option<Mock<'a>>,
    version_mock: Option<Mock<'a>>,
    config_mock: Option<Mock<'a>>,
    sync_mock: Option<Mock<'a>>,
    validator_mocks: HashMap<usize, Mock<'a>>,
    attester_mock: Option<Mock<'a>>,
    proposer_mock: Option<Mock<'a>>,
    slot_clock: Option<SystemTimeSlotClock>,
    validators: Option<Vec<(usize, PublicKeyBytes)>>,
    spec: &'a ChainSpec,
    _phantom: PhantomData<E>,
}

impl <'a, E: EthSpec> MockBeacon<'a, E> {
    pub fn new(server: &'a MockServer, spec: &'a ChainSpec) -> Self {
        let _ = env_logger::try_init().unwrap();
        Self {
            server,
            genesis_mock: None,
            version_mock: None,
            config_mock: None,
            sync_mock: None,
            validator_mocks: HashMap::new(),
            attester_mock: None,
            proposer_mock: None,
            slot_clock: None,
            validators: None,
            spec,
            _phantom: PhantomData,
        }
    }

    pub fn default(server: &'a MockServer, spec: &'a ChainSpec) -> Self {
        Self::new(server, spec).immediate_genesis().online().valid_config().synced()
    }

    pub fn url(&self) -> SensitiveUrl {
        SensitiveUrl::parse(self.server.url("").as_str()).unwrap()
    }

    pub fn immediate_genesis(mut self) -> Self {
        // Start a beacon node mock HTTP server.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let genesis_data = GenericResponse::from(GenesisData {
            genesis_time: now.as_secs(),
            genesis_validators_root: Hash256::zero(),
            genesis_fork_version: self.spec.genesis_fork_version,
        });
        let genesis_data_body =
            serde_json::to_string(&genesis_data).expect("should serialize genesis data");
        // Create a mock on the server.
        let genesis_mock = self.server.mock(|when, then| {
            when.method(Method::GET).path("/eth/v1/beacon/genesis");
            then.status(200)
                .header("content-type", "application/json")
                .body(genesis_data_body.as_str());
        });
        self.genesis_mock = Some(genesis_mock);
        self
    }

    pub fn valid_version(self) -> Self {
        self.online()
    }

    pub fn online(mut self) -> Self {
        let version = GenericResponse::from(VersionData {
            version: "".to_string(),
        });
        let version_body =  serde_json::to_string(&version).expect("should serialize version data");
        let version_mock = self.server.mock(|when, then| {
            when.method(Method::GET).path("/eth/v1/node/version");
            then.status(200)
                .header("content-type", "application/json")
                .body(&version_body);
        });
        self.version_mock = Some(version_mock);
        self
    }

    pub fn invalid_version(self) -> Self {
        self.offline()
    }

    pub fn offline(mut self) -> Self {
        let version_mock = self.server.mock(|when, then| {
            when.method(Method::GET).path("/eth/v1/node/version");
            then.status(200)
                .header("content-type", "application/json")
                .body("{}");
        });
        self.version_mock = Some(version_mock);
        self
    }

    pub fn slot_clock(mut self, slot_clock: SystemTimeSlotClock) -> Self {
        self.slot_clock = Some(slot_clock);
        self.synced()
    }

    pub fn validators_exist(mut self, validator_ids: &[(usize, PublicKeyBytes)]) -> Self {
        self.validators = Some(validator_ids.to_owned());
        for (index, pubkey) in validator_ids {
            self.validator_mocks.get_mut(&index).map(|mock|mock.delete());
            let val = Validator {
                pubkey: *pubkey,
                withdrawal_credentials: Hash256::zero(),
                effective_balance: self.spec.min_deposit_amount,
                slashed: false,
                activation_eligibility_epoch: Epoch::new(0),
                activation_epoch: Epoch::new(0),
                exit_epoch: Epoch::new(u64::MAX),
                withdrawable_epoch: Epoch::new(0),
            };

            let val_data = GenericResponse::from(ValidatorData {
                index: *index as u64,
                // default balance
                balance: self.spec.min_deposit_amount,
                status: ValidatorStatus::Active,
                validator: val,
            });

            let val_data_body =  serde_json::to_string(&val_data).expect("should serialize validator data");


            let val_mock = self.server.mock(|when, then| {
                when.method(Method::GET).path(format!("/eth/v1/beacon/states/head/validators/{}", pubkey));
                then.status(200)
                    .header("content-type", "application/json")
                    .body(&val_data_body);
            });
            self.validator_mocks.insert(*index, val_mock);
        }
        self.attestation_duties().proposer_duties()
    }

    pub fn valid_config(mut self) -> Self {
        let config = GenericResponse::from(ConfigAndPreset::from_chain_spec::<E>(&self.spec));
        let config_body =
            serde_json::to_string(&config).expect("should serialize genesis data");
        let config_mock = self.server.mock(|when, then| {
            when.method(Method::GET).path("/eth/v1/config/spec");
            then.status(200)
                .header("content-type", "application/json")
                .body(config_body);
        });
        self.config_mock = Some(config_mock);
        self
    }

    pub fn invalid_config(mut self) -> Self {
        let config_mock = self.server.mock(|when, then| {
            when.method(Method::GET).path("/eth/v1/config/spec");
            then.status(200)
                .header("content-type", "application/json")
                .body("{}}");
        });
        self.config_mock = Some(config_mock);
        self
    }

    pub fn synced(mut self) -> Self {
        self.sync_mock.map(|mut mock|mock.delete());
        let slot = self.slot_clock.as_ref().map_or(Slot::new(0), |clock| clock.now().expect("should read slot clock"));
        let sync_mock = self.server.mock(|when, then| {
            let sync_data = GenericResponse::from(SyncingData {
                is_syncing: false,
                head_slot: slot,
                sync_distance: Slot::new(0),
            });
            let sync_data_body =
                serde_json::to_string(&sync_data).expect("should serialize sync data");
            when.method(Method::GET).path("/eth/v1/node/syncing");
            then.status(200)
                .header("content-type", "application/json")
                .body(sync_data_body);
        });
        self.sync_mock = Some(sync_mock);
        self
    }

    pub fn not_synced(mut self) -> Self {
        self.sync_mock.map(|mut mock|mock.delete());
        let sync_data = SyncingData {
            is_syncing: true,
            head_slot: Slot::new(0),
            sync_distance: Slot::new(10),
        };
        let sync_data_body =
            serde_json::to_string(&sync_data).expect("should serialize genesis data");

        let sync_mock = self.server.mock(|when, then| {
            when.method(Method::GET).path("/eth/v1/node/syncing");
            then.status(200)
                .header("content-type", "application/json")
                .body(sync_data_body);
        });
        self.sync_mock = Some(sync_mock);
        self
    }

    pub fn attestation_duties(mut self) -> Self{
        let vals = self.validators.clone().unwrap();
        let slot_clock = self.slot_clock.clone().unwrap();
        let attester_mock = self.server.mock(|when, then| {
            when.method(Method::POST)
                .path_contains("/eth/v1/validator/duties/attester");
            let slot = slot_clock.now().unwrap();
            let duties = vals.iter().map(|(id, pubkey)| {
                AttesterData {
                    pubkey: pubkey.clone(),
                    validator_index: *id as u64,
                    validator_committee_index: *id as u64,
                    committee_index:  0,
                    committee_length: 1,
                    committees_at_slot: vals.len() as u64,
                    slot,
                }
            }).collect::<Vec<_>>();
            let duties_resp = DutiesResponse {
                data: duties,
                dependent_root: Hash256::zero(),
            };
            let duties_body = serde_json::to_string(&duties_resp).expect("should serialize duties response");
            then.status(200)
                .header("content-type", "application/json")
                .body(duties_body);
        });
        self.attester_mock = Some(attester_mock);
        self
    }

    pub fn proposer_duties(mut self) -> Self {
        let vals = self.validators.clone().unwrap();
        let slot_clock = self.slot_clock.clone().unwrap();

        let proposer_mock = self.server.mock(|when, then| {
            when.method(Method::GET)
                .path_contains("/eth/v1/validator/duties/proposer");
            let slot = slot_clock.now().unwrap();
            let duties = vals.iter().map(|(id, pubkey)| {
                ProposerData {
                    pubkey: pubkey.clone(),
                    validator_index: *id as u64,
                    slot,
                }
            }).collect::<Vec<_>>();
            let duties_resp = DutiesResponse {
                data: duties,
                dependent_root: Hash256::zero(),
            };
            let duties_body = serde_json::to_string(&duties_resp).expect("should serialize duties response");
            then.status(200)
                .header("content-type", "application/json")
                .body(&duties_body);
        });
        self.proposer_mock = Some(proposer_mock);
        self
    }

    pub fn sync_duties(&self, epoch: Epoch, validator_indices: Vec<usize>) {
        let epoch = Epoch::new(0);
        let hello_mock = self.server.mock(|when, then| {
            when.method(Method::POST)
                .path(format!("/eth/v1/validator/duties/sync/{}", epoch));
            then.status(200)
                .header("content-type", "application/json")
                .body("\"{\"data\": []}");
        });
    }

    // get attestation data
    pub fn attestation_data(&self, slot: Slot, committee_index: u64) {
        let source = Checkpoint {
            epoch: Epoch::new(0),
            root: Hash256::zero(),
        };
        let target = Checkpoint {
            epoch: Epoch::new(1),
            root: Hash256::zero(),
        };
        let att_data = AttestationData {
            slot,
            index: committee_index,
            beacon_block_root: Hash256::zero(),
            source,
            target,
        };
        let att_data_body =
            serde_json::to_string(&att_data).expect("should serialize genesis data");

        let hello_mock = self.server.mock(|when, then| {
            when.method(Method::GET)
                .path("/eth/v1/validator/attestation_data")
                .query_param("slot", format!("{}", slot).as_str())
                .query_param("committee_index", format!("{}", committee_index).as_str());
            then.status(200)
                .header("content-type", "application/json")
                .body(att_data_body);
        });
    }

    // get aggregate data
    pub fn aggregate_data(&self, slot: Slot, committee_index: u64) {
        let source = Checkpoint {
            epoch: Epoch::new(0),
            root: Hash256::zero(),
        };
        let target = Checkpoint {
            epoch: Epoch::new(1),
            root: Hash256::zero(),
        };
        let att_data = AttestationData {
            slot,
            index: committee_index,
            beacon_block_root: Hash256::zero(),
            source,
            target,
        };
        let domain = self.spec.get_domain(
            att_data.target.epoch,
            Domain::BeaconAttester,
            &self.spec.fork_at_epoch(Epoch::new(1)),
            Hash256::zero(),
        );

        let attestation_data_root = att_data.signing_root(domain);
        let attestation: Attestation<MainnetEthSpec> = Attestation {
            aggregation_bits: BitList::with_capacity(self.spec.target_committee_size).unwrap(),
            data: att_data,
            signature: AggregateSignature::empty(),
        };

        let attestation_body =
            serde_json::to_string(&attestation).expect("should serialize genesis data");

        let hello_mock = self.server.mock(|when, then| {
            when.method(Method::GET)
                .path("/eth/v1/validator/aggregate_attestation")
                .query_param(
                    "attestation_data_root",
                    format!("{}", attestation_data_root).as_str(),
                )
                .query_param("slot", format!("{}", slot).as_str());
            then.status(200)
                .header("content-type", "application/json")
                .body(attestation_body);
        });
    }

    // post attestation data

    // post aggregate
}

// Scenarios:
// 1. Normal flow
// 2. Event comes prior to 1/3 -- ensure correct node is only node queried
// 3. Event comes prior to 1/3, but node sending event is not reachable, backup has same head
// 4. Event comes prior to 1/3, but node sending event is not reachable, backup has different head
// 5. Event comes more than 1 slot prior
// 6 Event comes after 1/3
// 7. Event comes after 2/3
// 8. Event comes next slot
// 9. Multiple events

// Expected:
// 1. Only one POST to attestation endpoint
// 2. POST body must equal returned AttestationData
//      - root and slot

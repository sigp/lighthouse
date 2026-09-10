use account_utils::validator_definitions::{PasswordStorage, ValidatorDefinition};
use beacon_node_fallback::{BeaconNodeFallback, CandidateBeaconNode, Config as BeaconNodeConfig};
use bls::PublicKeyBytes;
use eth2_keystore::json_keystore::{Kdf, Scrypt};
use eth2_keystore::{DKLEN, KeystoreBuilder};
use initialized_validators::InitializedValidators;
pub use lighthouse_validator_store::{Config as ValidatorStoreConfig, LighthouseValidatorStore};
use slashing_protection::{SLASHING_PROTECTION_FILENAME, SlashingDatabase};
use slot_clock::{ManualSlotClock, SlotClock};
use std::sync::Arc;
use std::time::Duration;
use task_executor::test_utils::TestRuntime;
use tempfile::{TempDir, tempdir};
use types::{
    ChainSpec, Epoch, EthSpec, Hash256, MainnetEthSpec, Slot,
    test_utils::generate_deterministic_keypair,
};
use validator_store::ValidatorStore;

use crate::mock_beacon_node::MockBeaconNode;

pub type S = LighthouseValidatorStore<ManualSlotClock, E>;
type E = MainnetEthSpec;

pub struct ValidatorClientHarness {
    pub mock_beacon_node_1: MockBeaconNode<E>,
    pub mock_beacon_node_2: MockBeaconNode<E>,
    pub beacon_nodes: Arc<BeaconNodeFallback<ManualSlotClock>>,
    pub validator_store: Arc<S>,
    pub slot_clock: ManualSlotClock,
    pub pubkeys: Vec<PublicKeyBytes>,
    pub spec: Arc<ChainSpec>,
    pub test_runtime: TestRuntime,
    pub _validator_dir: TempDir,
}

impl ValidatorClientHarness {
    pub async fn new(num_validators: usize) -> Self {
        Self::new_with_config(num_validators, &Default::default()).await
    }

    pub async fn new_with_config(num_validators: usize, config: &ValidatorStoreConfig) -> Self {
        let mut default_spec = MainnetEthSpec::default_spec();
        default_spec.gloas_fork_epoch = Some(Epoch::new(0));
        let spec = Arc::new(default_spec);

        let test_runtime = TestRuntime::default();
        let executor = test_runtime.task_executor.clone();
        let slot_duration = spec.get_slot_duration();
        let slot_clock = ManualSlotClock::new(Slot::new(0), Duration::from_secs(0), slot_duration);

        let (validator_store, pubkeys, validator_dir) = create_validator_store(
            slot_clock.clone(),
            spec.clone(),
            executor.clone(),
            num_validators,
            config,
        )
        .await;

        let mock_beacon_node_1 = MockBeaconNode::<E>::new().await;
        let mock_beacon_node_2 = MockBeaconNode::<E>::new().await;

        let beacon_node_1 =
            CandidateBeaconNode::new(mock_beacon_node_1.beacon_api_client.clone(), 0);
        let beacon_node_2 =
            CandidateBeaconNode::new(mock_beacon_node_2.beacon_api_client.clone(), 1);

        let beacon_nodes = Arc::new(BeaconNodeFallback::new(
            vec![beacon_node_1, beacon_node_2],
            BeaconNodeConfig::default(),
            vec![],
            spec.clone(),
        ));

        Self {
            mock_beacon_node_1,
            mock_beacon_node_2,
            beacon_nodes,
            validator_store,
            slot_clock,
            pubkeys,
            spec,
            test_runtime,
            _validator_dir: validator_dir,
        }
    }
}

pub async fn create_validator_store(
    slot_clock: ManualSlotClock,
    spec: Arc<ChainSpec>,
    executor: task_executor::TaskExecutor,
    num_validators: usize,
    config: &ValidatorStoreConfig,
) -> (Arc<S>, Vec<PublicKeyBytes>, TempDir) {
    let validator_dir = tempdir().unwrap();
    let password = b"test";

    let mut validator_definitions = Vec::with_capacity(num_validators);
    let mut pubkeys = Vec::with_capacity(num_validators);

    for i in 0..num_validators {
        let keypair = generate_deterministic_keypair(i);
        let keystore = KeystoreBuilder::new(&keypair, password, "".into())
            .unwrap()
            .kdf(insecure_kdf())
            .build()
            .unwrap();
        let keystore_path = validator_dir
            .path()
            .join(format!("voting-keystore-{i}.json"));
        keystore
            .to_json_writer(std::fs::File::create(&keystore_path).unwrap())
            .unwrap();

        let validator_definition = ValidatorDefinition::new_keystore_with_password(
            keystore_path,
            PasswordStorage::ValidatorDefinitions(
                String::from_utf8(password.to_vec()).unwrap().into(),
            ),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        pubkeys.push(keypair.pk.into());
        validator_definitions.push(validator_definition);
    }

    let initialized_validators = InitializedValidators::from_definitions(
        validator_definitions.into(),
        validator_dir.path().into(),
        Default::default(),
    )
    .await
    .unwrap();

    let slashing_db_path = validator_dir.path().join(SLASHING_PROTECTION_FILENAME);
    let slashing_protection = SlashingDatabase::open_or_create(&slashing_db_path).unwrap();
    slashing_protection
        .register_validators(pubkeys.iter())
        .unwrap();

    let validator_store = Arc::new(LighthouseValidatorStore::<_, E>::new(
        initialized_validators,
        slashing_protection,
        Hash256::ZERO,
        spec,
        None,
        slot_clock,
        config,
        executor,
    ));

    for (i, pubkey) in pubkeys.iter().enumerate() {
        validator_store.set_validator_index(pubkey, i as u64);
    }

    (validator_store, pubkeys, validator_dir)
}

// Use a weak scrypt to speed up key generation process
// Copy from: lighthouse/common/validator_dir/src/insecure_keys.rs
fn insecure_kdf() -> Kdf {
    Kdf::Scrypt(Scrypt {
        dklen: DKLEN,
        // `n` is set very low, making it cheap to encrypt/decrypt keystores.
        //
        // This is very insecure, only use during testing.
        n: 2,
        p: 1,
        r: 8,
        salt: vec![1; 32].into(),
    })
}

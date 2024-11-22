use std::sync::Arc;
use std::time::Duration;

use slog::Logger;
use tempfile::TempDir;

use account_utils::validator_definitions::ValidatorDefinitions;
use environment::RuntimeContext;
use eth2_config::Eth2Config;
use logging::test_logger;
use node_test_rig::ValidatorFiles;
use slashing_protection::SlashingDatabase;
use slot_clock::SlotClock;
use slot_clock::TestingSlotClock;
use task_executor::test_utils::TestRuntime;
use types::EthSpec;
use types::{ChainSpec, Hash256, MainnetEthSpec, Slot};

use initialized_validators::{Config as InitializedValidatorConfig, InitializedValidators};
use validator_store::{Config as ValidatorStoreConfig, ValidatorStore};

type S = TestingSlotClock;
type E = MainnetEthSpec;

pub struct ValidatorTestRig {
    pub(crate) validator_store: Arc<ValidatorStore<S, E>>,
    pub(crate) runtime_context: RuntimeContext<E>,
    pub(crate) slot_clock: S,
    pub(crate) spec: Arc<ChainSpec>,
    pub(crate) logger: Logger,
}

impl ValidatorTestRig {
    pub async fn new() -> Self {
        let logger = test_logger();
        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            Duration::from_secs(12),
        );
        let spec = Arc::new(E::default_spec());
        let validator_store = ValidatorStoreConfig::default();
        let test_runtime = TestRuntime::default();
        let runtime_context = RuntimeContext {
            executor: test_runtime.task_executor.clone(),
            eth_spec_instance: MainnetEthSpec,
            eth2_config: Eth2Config::mainnet(),
            eth2_network_config: None,
            sse_logging_components: None,
        };

        let validator_files = ValidatorFiles::with_keystores(&[0]).unwrap();
        let validator_dir = validator_files.validator_dir.path();
        let secrets_dir = validator_files.secrets_dir.path();

        let mut validator_definitions =
            ValidatorDefinitions::open_or_create(validator_dir).unwrap();
        // FIXME: this is very slow
        let found = validator_definitions
            .discover_local_keystores(validator_dir, secrets_dir, &logger)
            .unwrap();
        assert_eq!(found, 1, "keystore not found");

        let validators = InitializedValidators::from_definitions(
            validator_definitions,
            validator_dir.into(),
            InitializedValidatorConfig::default(),
            logger.clone(),
        )
        .await
        .unwrap();

        let slash_db_dir = TempDir::new().unwrap();
        let slash_db_dir_path = slash_db_dir.path().join("slashing_db");
        let slashing_db = SlashingDatabase::open_or_create(slash_db_dir_path.as_path()).unwrap();
        slashing_db
            .register_validators(validators.iter_voting_pubkeys())
            .unwrap();

        let validator_store: ValidatorStore<TestingSlotClock, MainnetEthSpec> = ValidatorStore::new(
            validators,
            slashing_db,
            Hash256::random(),
            spec.clone(),
            None,
            slot_clock.clone(),
            &validator_store,
            runtime_context.executor.clone(),
            logger.clone(),
        );

        Self {
            validator_store: validator_store.into(),
            runtime_context,
            slot_clock,
            spec,
            logger,
        }
    }
}

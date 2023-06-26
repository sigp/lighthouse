#![cfg(test)]
#![cfg(not(debug_assertions))]

mod keystores;

use crate::doppelganger_service::DoppelgangerService;
use crate::{
    http_api::{ApiSecret, Config as HttpConfig, Context},
    initialized_validators::InitializedValidators,
    Config, ValidatorDefinitions, ValidatorStore,
};
use account_utils::{
    eth2_wallet::WalletBuilder, mnemonic_from_phrase, random_mnemonic, random_password,
    random_password_string, ZeroizeString,
};
use deposit_contract::decode_eth1_tx_data;
use eth2::{
    lighthouse_vc::{http_client::ValidatorClientHttpClient, types::*},
    types::ErrorMessage as ApiErrorMessage,
    Error as ApiError,
};
use eth2_keystore::KeystoreBuilder;
use logging::test_logger;
use parking_lot::RwLock;
use sensitive_url::SensitiveUrl;
use slashing_protection::{SlashingDatabase, SLASHING_PROTECTION_FILENAME};
use slot_clock::{SlotClock, TestingSlotClock};
use std::future::Future;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tempfile::{tempdir, TempDir};
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use types::graffiti::GraffitiString;

const PASSWORD_BYTES: &[u8] = &[42, 50, 37];
pub const TEST_DEFAULT_FEE_RECIPIENT: Address = Address::repeat_byte(42);

type E = MainnetEthSpec;

struct ApiTester {
    client: ValidatorClientHttpClient,
    initialized_validators: Arc<RwLock<InitializedValidators>>,
    validator_store: Arc<ValidatorStore<TestingSlotClock, E>>,
    url: SensitiveUrl,
    slot_clock: TestingSlotClock,
    _server_shutdown: oneshot::Sender<()>,
    _validator_dir: TempDir,
    _runtime_shutdown: exit_future::Signal,
}

// Builds a runtime to be used in the testing configuration.
fn build_runtime() -> Arc<Runtime> {
    Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Should be able to build a testing runtime"),
    )
}

impl ApiTester {
    pub async fn new(runtime: std::sync::Weak<Runtime>) -> Self {
        let log = test_logger();

        let validator_dir = tempdir().unwrap();
        let secrets_dir = tempdir().unwrap();

        let validator_defs = ValidatorDefinitions::open_or_create(validator_dir.path()).unwrap();

        let initialized_validators = InitializedValidators::from_definitions(
            validator_defs,
            validator_dir.path().into(),
            log.clone(),
        )
        .await
        .unwrap();

        let api_secret = ApiSecret::create_or_open(validator_dir.path()).unwrap();
        let api_pubkey = api_secret.api_token();

        let mut config = Config::default();
        config.validator_dir = validator_dir.path().into();
        config.secrets_dir = secrets_dir.path().into();
        config.fee_recipient = Some(TEST_DEFAULT_FEE_RECIPIENT);

        let spec = E::default_spec();

        let slashing_db_path = config.validator_dir.join(SLASHING_PROTECTION_FILENAME);
        let slashing_protection = SlashingDatabase::open_or_create(&slashing_db_path).unwrap();

        let genesis_time: u64 = 0;
        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(genesis_time),
            Duration::from_secs(1),
        );

        let (runtime_shutdown, exit) = exit_future::signal();
        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
        let executor = TaskExecutor::new(runtime.clone(), exit, log.clone(), shutdown_tx);

        let validator_store = Arc::new(ValidatorStore::<_, E>::new(
            initialized_validators,
            slashing_protection,
            Hash256::repeat_byte(42),
            spec.clone(),
            Some(Arc::new(DoppelgangerService::new(log.clone()))),
            slot_clock.clone(),
            &config,
            executor.clone(),
            log.clone(),
        ));

        validator_store
            .register_all_in_doppelganger_protection_if_enabled()
            .expect("Should attach doppelganger service");

        let initialized_validators = validator_store.initialized_validators();

        let context = Arc::new(Context {
            task_executor: executor,
            api_secret,
            validator_dir: Some(validator_dir.path().into()),
            validator_store: Some(validator_store.clone()),
            graffiti_file: None,
            graffiti_flag: Some(Graffiti::default()),
            spec: E::default_spec(),
            config: HttpConfig {
                enabled: true,
                listen_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                listen_port: 0,
                allow_origin: None,
            },
            sse_logging_components: None,
            log,
            slot_clock: slot_clock.clone(),
            _phantom: PhantomData,
        });
        let ctx = context.clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_shutdown = async {
            // It's not really interesting why this triggered, just that it happened.
            let _ = shutdown_rx.await;
        };
        let (listening_socket, server) = super::serve(ctx, server_shutdown).unwrap();

        tokio::spawn(async { server.await });

        let url = SensitiveUrl::parse(&format!(
            "http://{}:{}",
            listening_socket.ip(),
            listening_socket.port()
        ))
        .unwrap();

        let client = ValidatorClientHttpClient::new(url.clone(), api_pubkey).unwrap();

        Self {
            client,
            initialized_validators,
            validator_store,
            url,
            slot_clock,
            _server_shutdown: shutdown_tx,
            _validator_dir: validator_dir,
            _runtime_shutdown: runtime_shutdown,
        }
    }

    pub fn invalid_token_client(&self) -> ValidatorClientHttpClient {
        let tmp = tempdir().unwrap();
        let api_secret = ApiSecret::create_or_open(tmp.path()).unwrap();
        let invalid_pubkey = api_secret.api_token();
        ValidatorClientHttpClient::new(self.url.clone(), invalid_pubkey.clone()).unwrap()
    }

    pub async fn test_with_invalid_auth<F, A, T>(self, func: F) -> Self
    where
        F: Fn(ValidatorClientHttpClient) -> A,
        A: Future<Output = Result<T, ApiError>>,
    {
        /*
         * Test with an invalid Authorization header.
         */
        match func(self.invalid_token_client()).await {
            Err(ApiError::ServerMessage(ApiErrorMessage { code: 403, .. })) => (),
            Err(other) => panic!("expected authorized error, got {:?}", other),
            Ok(_) => panic!("expected authorized error, got Ok"),
        }

        /*
         * Test with a missing Authorization header.
         */
        let mut missing_token_client = self.client.clone();
        missing_token_client.send_authorization_header(false);
        match func(missing_token_client).await {
            Err(ApiError::ServerMessage(ApiErrorMessage {
                code: 401, message, ..
            })) if message.contains("missing Authorization header") => (),
            Err(other) => panic!("expected missing header error, got {:?}", other),
            Ok(_) => panic!("expected missing header error, got Ok"),
        }

        self
    }

    pub fn invalidate_api_token(mut self) -> Self {
        self.client = self.invalid_token_client();
        self
    }

    pub async fn test_get_lighthouse_version_invalid(self) -> Self {
        self.client.get_lighthouse_version().await.unwrap_err();
        self
    }

    pub async fn test_get_lighthouse_spec(self) -> Self {
        let result = self
            .client
            .get_lighthouse_spec::<ConfigAndPresetCapella>()
            .await
            .map(|res| ConfigAndPreset::Capella(res.data))
            .unwrap();
        let expected = ConfigAndPreset::from_chain_spec::<E>(&E::default_spec(), None);

        assert_eq!(result, expected);

        self
    }

    pub async fn test_get_lighthouse_version(self) -> Self {
        let result = self.client.get_lighthouse_version().await.unwrap().data;

        let expected = VersionData {
            version: lighthouse_version::version_with_platform(),
        };

        assert_eq!(result, expected);

        self
    }

    #[cfg(target_os = "linux")]
    pub async fn test_get_lighthouse_health(self) -> Self {
        self.client.get_lighthouse_health().await.unwrap();

        self
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn test_get_lighthouse_health(self) -> Self {
        self.client.get_lighthouse_health().await.unwrap_err();

        self
    }
    pub fn vals_total(&self) -> usize {
        self.initialized_validators.read().num_total()
    }

    pub fn vals_enabled(&self) -> usize {
        self.initialized_validators.read().num_enabled()
    }

    pub fn assert_enabled_validators_count(self, count: usize) -> Self {
        assert_eq!(self.vals_enabled(), count);
        self
    }

    pub fn assert_validators_count(self, count: usize) -> Self {
        assert_eq!(self.vals_total(), count);
        self
    }

    pub async fn create_hd_validators(self, s: HdValidatorScenario) -> Self {
        let initial_vals = self.vals_total();
        let initial_enabled_vals = self.vals_enabled();

        let validators = (0..s.count)
            .map(|i| ValidatorRequest {
                enable: !s.disabled.contains(&i),
                description: format!("boi #{}", i),
                graffiti: None,
                suggested_fee_recipient: None,
                gas_limit: None,
                builder_proposals: None,
                deposit_gwei: E::default_spec().max_effective_balance,
            })
            .collect::<Vec<_>>();

        let (response, mnemonic) = if s.specify_mnemonic {
            let mnemonic = ZeroizeString::from(random_mnemonic().phrase().to_string());
            let request = CreateValidatorsMnemonicRequest {
                mnemonic: mnemonic.clone(),
                key_derivation_path_offset: s.key_derivation_path_offset,
                validators: validators.clone(),
            };
            let response = self
                .client
                .post_lighthouse_validators_mnemonic(&request)
                .await
                .unwrap()
                .data;

            (response, mnemonic)
        } else {
            assert_eq!(
                s.key_derivation_path_offset, 0,
                "cannot use a derivation offset without specifying a mnemonic"
            );
            let response = self
                .client
                .post_lighthouse_validators(validators.clone())
                .await
                .unwrap()
                .data;
            (response.validators.clone(), response.mnemonic.clone())
        };

        assert_eq!(response.len(), s.count);
        assert_eq!(self.vals_total(), initial_vals + s.count);
        assert_eq!(
            self.vals_enabled(),
            initial_enabled_vals + s.count - s.disabled.len()
        );

        let server_vals = self.client.get_lighthouse_validators().await.unwrap().data;

        assert_eq!(server_vals.len(), self.vals_total());

        // Ensure the server lists all of these newly created validators.
        for validator in &response {
            assert!(server_vals
                .iter()
                .any(|server_val| server_val.voting_pubkey == validator.voting_pubkey));
        }

        /*
         * Verify that we can regenerate all the keys from the mnemonic.
         */

        let mnemonic = mnemonic_from_phrase(mnemonic.as_str()).unwrap();
        let mut wallet = WalletBuilder::from_mnemonic(&mnemonic, PASSWORD_BYTES, "".to_string())
            .unwrap()
            .build()
            .unwrap();

        wallet
            .set_nextaccount(s.key_derivation_path_offset)
            .unwrap();

        for i in 0..s.count {
            let keypairs = wallet
                .next_validator(PASSWORD_BYTES, PASSWORD_BYTES, PASSWORD_BYTES)
                .unwrap();
            let voting_keypair = keypairs.voting.decrypt_keypair(PASSWORD_BYTES).unwrap();

            assert_eq!(
                response[i].voting_pubkey,
                voting_keypair.pk.clone().into(),
                "the locally generated voting pk should match the server response"
            );

            let withdrawal_keypair = keypairs.withdrawal.decrypt_keypair(PASSWORD_BYTES).unwrap();

            let deposit_bytes =
                serde_utils::hex::decode(&response[i].eth1_deposit_tx_data).unwrap();

            let (deposit_data, _) =
                decode_eth1_tx_data(&deposit_bytes, E::default_spec().max_effective_balance)
                    .unwrap();

            assert_eq!(
                deposit_data.pubkey,
                voting_keypair.pk.clone().into(),
                "the locally generated voting pk should match the deposit data"
            );

            assert_eq!(
                deposit_data.withdrawal_credentials,
                Hash256::from_slice(&bls::get_withdrawal_credentials(
                    &withdrawal_keypair.pk,
                    E::default_spec().bls_withdrawal_prefix_byte
                )),
                "the locally generated withdrawal creds should match the deposit data"
            );

            assert_eq!(
                deposit_data.signature,
                deposit_data.create_signature(&voting_keypair.sk, &E::default_spec()),
                "the locally-generated deposit sig should create the same deposit sig"
            );
        }

        self
    }

    pub async fn create_keystore_validators(self, s: KeystoreValidatorScenario) -> Self {
        let initial_vals = self.vals_total();
        let initial_enabled_vals = self.vals_enabled();

        let password = random_password();
        let keypair = Keypair::random();
        let keystore = KeystoreBuilder::new(&keypair, password.as_bytes(), String::new())
            .unwrap()
            .build()
            .unwrap();

        if !s.correct_password {
            let request = KeystoreValidatorsPostRequest {
                enable: s.enabled,
                password: String::from_utf8(random_password().as_ref().to_vec())
                    .unwrap()
                    .into(),
                keystore,
                graffiti: None,
                suggested_fee_recipient: None,
                gas_limit: None,
                builder_proposals: None,
            };

            self.client
                .post_lighthouse_validators_keystore(&request)
                .await
                .unwrap_err();

            return self;
        }

        let request = KeystoreValidatorsPostRequest {
            enable: s.enabled,
            password: String::from_utf8(password.as_ref().to_vec())
                .unwrap()
                .into(),
            keystore,
            graffiti: None,
            suggested_fee_recipient: None,
            gas_limit: None,
            builder_proposals: None,
        };

        let response = self
            .client
            .post_lighthouse_validators_keystore(&request)
            .await
            .unwrap()
            .data;

        let num_enabled = s.enabled as usize;

        assert_eq!(self.vals_total(), initial_vals + 1);
        assert_eq!(self.vals_enabled(), initial_enabled_vals + num_enabled);

        let server_vals = self.client.get_lighthouse_validators().await.unwrap().data;

        assert_eq!(server_vals.len(), self.vals_total());

        assert_eq!(response.voting_pubkey, keypair.pk.into());
        assert_eq!(response.enabled, s.enabled);

        self
    }

    pub async fn create_web3signer_validators(self, s: Web3SignerValidatorScenario) -> Self {
        let initial_vals = self.vals_total();
        let initial_enabled_vals = self.vals_enabled();

        let request: Vec<_> = (0..s.count)
            .map(|i| {
                let kp = Keypair::random();
                Web3SignerValidatorRequest {
                    enable: s.enabled,
                    description: format!("{}", i),
                    graffiti: None,
                    suggested_fee_recipient: None,
                    gas_limit: None,
                    builder_proposals: None,
                    voting_public_key: kp.pk,
                    url: format!("http://signer_{}.com/", i),
                    root_certificate_path: None,
                    request_timeout_ms: None,
                    client_identity_path: None,
                    client_identity_password: None,
                }
            })
            .collect();

        self.client
            .post_lighthouse_validators_web3signer(&request)
            .await
            .unwrap();

        assert_eq!(self.vals_total(), initial_vals + s.count);
        if s.enabled {
            assert_eq!(self.vals_enabled(), initial_enabled_vals + s.count);
        } else {
            assert_eq!(self.vals_enabled(), initial_enabled_vals);
        };

        self
    }

    pub async fn test_sign_voluntary_exits(self, index: usize, maybe_epoch: Option<Epoch>) -> Self {
        let validator = &self.client.get_lighthouse_validators().await.unwrap().data[index];
        // manually setting validator index in `ValidatorStore`
        self.initialized_validators
            .write()
            .set_index(&validator.voting_pubkey, 0);

        let expected_exit_epoch = maybe_epoch.unwrap_or_else(|| self.get_current_epoch());

        let resp = self
            .client
            .post_validator_voluntary_exit(&validator.voting_pubkey, maybe_epoch)
            .await;

        assert!(resp.is_ok());
        assert_eq!(resp.unwrap().message.epoch, expected_exit_epoch);

        self
    }

    fn get_current_epoch(&self) -> Epoch {
        self.slot_clock
            .now()
            .map(|s| s.epoch(E::slots_per_epoch()))
            .unwrap()
    }

    pub async fn set_validator_enabled(self, index: usize, enabled: bool) -> Self {
        let validator = &self.client.get_lighthouse_validators().await.unwrap().data[index];

        self.client
            .patch_lighthouse_validators(&validator.voting_pubkey, Some(enabled), None, None, None)
            .await
            .unwrap();

        assert_eq!(
            self.initialized_validators
                .read()
                .is_enabled(&validator.voting_pubkey.decompress().unwrap())
                .unwrap(),
            enabled
        );

        assert!(self
            .client
            .get_lighthouse_validators()
            .await
            .unwrap()
            .data
            .into_iter()
            .find(|v| v.voting_pubkey == validator.voting_pubkey)
            .map(|v| v.enabled == enabled)
            .unwrap());

        // Check the server via an individual request.
        assert_eq!(
            self.client
                .get_lighthouse_validators_pubkey(&validator.voting_pubkey)
                .await
                .unwrap()
                .unwrap()
                .data
                .enabled,
            enabled
        );

        self
    }

    pub async fn set_gas_limit(self, index: usize, gas_limit: u64) -> Self {
        let validator = &self.client.get_lighthouse_validators().await.unwrap().data[index];

        self.client
            .patch_lighthouse_validators(
                &validator.voting_pubkey,
                None,
                Some(gas_limit),
                None,
                None,
            )
            .await
            .unwrap();

        self
    }

    pub async fn assert_gas_limit(self, index: usize, gas_limit: u64) -> Self {
        let validator = &self.client.get_lighthouse_validators().await.unwrap().data[index];

        assert_eq!(
            self.validator_store.get_gas_limit(&validator.voting_pubkey),
            gas_limit
        );

        self
    }

    pub async fn set_builder_proposals(self, index: usize, builder_proposals: bool) -> Self {
        let validator = &self.client.get_lighthouse_validators().await.unwrap().data[index];

        self.client
            .patch_lighthouse_validators(
                &validator.voting_pubkey,
                None,
                None,
                Some(builder_proposals),
                None,
            )
            .await
            .unwrap();

        self
    }

    pub async fn assert_builder_proposals(self, index: usize, builder_proposals: bool) -> Self {
        let validator = &self.client.get_lighthouse_validators().await.unwrap().data[index];

        assert_eq!(
            self.validator_store
                .get_builder_proposals(&validator.voting_pubkey),
            builder_proposals
        );

        self
    }

    pub async fn set_graffiti(self, index: usize, graffiti: &str) -> Self {
        let validator = &self.client.get_lighthouse_validators().await.unwrap().data[index];
        let graffiti_str = GraffitiString::from_str(graffiti).unwrap();
        self.client
            .patch_lighthouse_validators(
                &validator.voting_pubkey,
                None,
                None,
                None,
                Some(graffiti_str),
            )
            .await
            .unwrap();

        self
    }

    pub async fn assert_graffiti(self, index: usize, graffiti: &str) -> Self {
        let validator = &self.client.get_lighthouse_validators().await.unwrap().data[index];
        let graffiti_str = GraffitiString::from_str(graffiti).unwrap();
        assert_eq!(
            self.validator_store.graffiti(&validator.voting_pubkey),
            Some(graffiti_str.into())
        );

        self
    }
}

struct HdValidatorScenario {
    count: usize,
    specify_mnemonic: bool,
    key_derivation_path_offset: u32,
    disabled: Vec<usize>,
}

struct KeystoreValidatorScenario {
    enabled: bool,
    correct_password: bool,
}

struct Web3SignerValidatorScenario {
    count: usize,
    enabled: bool,
}

#[test]
fn invalid_pubkey() {
    let runtime = build_runtime();
    let weak_runtime = Arc::downgrade(&runtime);
    runtime.block_on(async {
        ApiTester::new(weak_runtime)
            .await
            .invalidate_api_token()
            .test_get_lighthouse_version_invalid()
            .await;
    });
}

#[test]
fn routes_with_invalid_auth() {
    let runtime = build_runtime();
    let weak_runtime = Arc::downgrade(&runtime);
    runtime.block_on(async {
        ApiTester::new(weak_runtime)
            .await
            .test_with_invalid_auth(|client| async move { client.get_lighthouse_version().await })
            .await
            .test_with_invalid_auth(|client| async move { client.get_lighthouse_health().await })
            .await
            .test_with_invalid_auth(|client| async move {
                client.get_lighthouse_spec::<types::Config>().await
            })
            .await
            .test_with_invalid_auth(
                |client| async move { client.get_lighthouse_validators().await },
            )
            .await
            .test_with_invalid_auth(|client| async move {
                client
                    .get_lighthouse_validators_pubkey(&PublicKeyBytes::empty())
                    .await
            })
            .await
            .test_with_invalid_auth(|client| async move {
                client
                    .post_lighthouse_validators(vec![ValidatorRequest {
                        enable: <_>::default(),
                        description: <_>::default(),
                        graffiti: <_>::default(),
                        suggested_fee_recipient: <_>::default(),
                        gas_limit: <_>::default(),
                        builder_proposals: <_>::default(),
                        deposit_gwei: <_>::default(),
                    }])
                    .await
            })
            .await
            .test_with_invalid_auth(|client| async move {
                client
                    .post_lighthouse_validators_mnemonic(&CreateValidatorsMnemonicRequest {
                        mnemonic: String::default().into(),
                        key_derivation_path_offset: <_>::default(),
                        validators: <_>::default(),
                    })
                    .await
            })
            .await
            .test_with_invalid_auth(|client| async move {
                let password = random_password();
                let keypair = Keypair::random();
                let keystore = KeystoreBuilder::new(&keypair, password.as_bytes(), String::new())
                    .unwrap()
                    .build()
                    .unwrap();
                client
                    .post_lighthouse_validators_keystore(&KeystoreValidatorsPostRequest {
                        password: String::default().into(),
                        enable: <_>::default(),
                        keystore,
                        graffiti: <_>::default(),
                        suggested_fee_recipient: <_>::default(),
                        gas_limit: <_>::default(),
                        builder_proposals: <_>::default(),
                    })
                    .await
            })
            .await
            .test_with_invalid_auth(|client| async move {
                client
                    .patch_lighthouse_validators(
                        &PublicKeyBytes::empty(),
                        Some(false),
                        None,
                        None,
                        None,
                    )
                    .await
            })
            .await
            .test_with_invalid_auth(|client| async move { client.get_keystores().await })
            .await
            .test_with_invalid_auth(|client| async move {
                let password = random_password_string();
                let keypair = Keypair::random();
                let keystore = KeystoreBuilder::new(&keypair, password.as_ref(), String::new())
                    .unwrap()
                    .build()
                    .map(KeystoreJsonStr)
                    .unwrap();
                client
                    .post_keystores(&ImportKeystoresRequest {
                        keystores: vec![keystore],
                        passwords: vec![password],
                        slashing_protection: None,
                    })
                    .await
            })
            .await
            .test_with_invalid_auth(|client| async move {
                let keypair = Keypair::random();
                client
                    .delete_keystores(&DeleteKeystoresRequest {
                        pubkeys: vec![keypair.pk.compress()],
                    })
                    .await
            })
            .await
    });
}

#[test]
fn simple_getters() {
    let runtime = build_runtime();
    let weak_runtime = Arc::downgrade(&runtime);
    runtime.block_on(async {
        ApiTester::new(weak_runtime)
            .await
            .test_get_lighthouse_version()
            .await
            .test_get_lighthouse_health()
            .await
            .test_get_lighthouse_spec()
            .await;
    });
}

#[test]
fn hd_validator_creation() {
    let runtime = build_runtime();
    let weak_runtime = Arc::downgrade(&runtime);
    runtime.block_on(async {
        ApiTester::new(weak_runtime)
            .await
            .assert_enabled_validators_count(0)
            .assert_validators_count(0)
            .create_hd_validators(HdValidatorScenario {
                count: 2,
                specify_mnemonic: true,
                key_derivation_path_offset: 0,
                disabled: vec![],
            })
            .await
            .assert_enabled_validators_count(2)
            .assert_validators_count(2)
            .create_hd_validators(HdValidatorScenario {
                count: 1,
                specify_mnemonic: false,
                key_derivation_path_offset: 0,
                disabled: vec![0],
            })
            .await
            .assert_enabled_validators_count(2)
            .assert_validators_count(3)
            .create_hd_validators(HdValidatorScenario {
                count: 0,
                specify_mnemonic: true,
                key_derivation_path_offset: 4,
                disabled: vec![],
            })
            .await
            .assert_enabled_validators_count(2)
            .assert_validators_count(3);
    });
}

#[test]
fn validator_exit() {
    let runtime = build_runtime();
    let weak_runtime = Arc::downgrade(&runtime);
    runtime.block_on(async {
        ApiTester::new(weak_runtime)
            .await
            .create_hd_validators(HdValidatorScenario {
                count: 2,
                specify_mnemonic: false,
                key_derivation_path_offset: 0,
                disabled: vec![],
            })
            .await
            .assert_enabled_validators_count(2)
            .assert_validators_count(2)
            .test_sign_voluntary_exits(0, None)
            .await
            .test_sign_voluntary_exits(0, Some(Epoch::new(256)))
            .await;
    });
}

#[test]
fn validator_enabling() {
    let runtime = build_runtime();
    let weak_runtime = Arc::downgrade(&runtime);
    runtime.block_on(async {
        ApiTester::new(weak_runtime)
            .await
            .create_hd_validators(HdValidatorScenario {
                count: 2,
                specify_mnemonic: false,
                key_derivation_path_offset: 0,
                disabled: vec![],
            })
            .await
            .assert_enabled_validators_count(2)
            .assert_validators_count(2)
            .set_validator_enabled(0, false)
            .await
            .assert_enabled_validators_count(1)
            .assert_validators_count(2)
            .set_validator_enabled(0, true)
            .await
            .assert_enabled_validators_count(2)
            .assert_validators_count(2);
    });
}

#[test]
fn validator_gas_limit() {
    let runtime = build_runtime();
    let weak_runtime = Arc::downgrade(&runtime);
    runtime.block_on(async {
        ApiTester::new(weak_runtime)
            .await
            .create_hd_validators(HdValidatorScenario {
                count: 2,
                specify_mnemonic: false,
                key_derivation_path_offset: 0,
                disabled: vec![],
            })
            .await
            .assert_enabled_validators_count(2)
            .assert_validators_count(2)
            .set_gas_limit(0, 500)
            .await
            .assert_gas_limit(0, 500)
            .await
            // Update gas limit while validator is disabled.
            .set_validator_enabled(0, false)
            .await
            .assert_enabled_validators_count(1)
            .assert_validators_count(2)
            .set_gas_limit(0, 1000)
            .await
            .set_validator_enabled(0, true)
            .await
            .assert_enabled_validators_count(2)
            .assert_gas_limit(0, 1000)
            .await
    });
}

#[test]
fn validator_builder_proposals() {
    let runtime = build_runtime();
    let weak_runtime = Arc::downgrade(&runtime);
    runtime.block_on(async {
        ApiTester::new(weak_runtime)
            .await
            .create_hd_validators(HdValidatorScenario {
                count: 2,
                specify_mnemonic: false,
                key_derivation_path_offset: 0,
                disabled: vec![],
            })
            .await
            .assert_enabled_validators_count(2)
            .assert_validators_count(2)
            .set_builder_proposals(0, true)
            .await
            // Test setting builder proposals while the validator is disabled
            .set_validator_enabled(0, false)
            .await
            .assert_enabled_validators_count(1)
            .assert_validators_count(2)
            .set_builder_proposals(0, false)
            .await
            .set_validator_enabled(0, true)
            .await
            .assert_enabled_validators_count(2)
            .assert_builder_proposals(0, false)
            .await
    });
}

#[test]
fn validator_graffiti() {
    let runtime = build_runtime();
    let weak_runtime = Arc::downgrade(&runtime);
    runtime.block_on(async {
        ApiTester::new(weak_runtime)
            .await
            .create_hd_validators(HdValidatorScenario {
                count: 2,
                specify_mnemonic: false,
                key_derivation_path_offset: 0,
                disabled: vec![],
            })
            .await
            .assert_enabled_validators_count(2)
            .assert_validators_count(2)
            .set_graffiti(0, "Mr F was here")
            .await
            .assert_graffiti(0, "Mr F was here")
            .await
            // Test setting graffiti while the validator is disabled
            .set_validator_enabled(0, false)
            .await
            .assert_enabled_validators_count(1)
            .assert_validators_count(2)
            .set_graffiti(0, "Mr F was here again")
            .await
            .set_validator_enabled(0, true)
            .await
            .assert_enabled_validators_count(2)
            .assert_graffiti(0, "Mr F was here again")
            .await
    });
}

#[test]
fn keystore_validator_creation() {
    let runtime = build_runtime();
    let weak_runtime = Arc::downgrade(&runtime);
    runtime.block_on(async {
        ApiTester::new(weak_runtime)
            .await
            .assert_enabled_validators_count(0)
            .assert_validators_count(0)
            .create_keystore_validators(KeystoreValidatorScenario {
                correct_password: true,
                enabled: true,
            })
            .await
            .assert_enabled_validators_count(1)
            .assert_validators_count(1)
            .create_keystore_validators(KeystoreValidatorScenario {
                correct_password: false,
                enabled: true,
            })
            .await
            .assert_enabled_validators_count(1)
            .assert_validators_count(1)
            .create_keystore_validators(KeystoreValidatorScenario {
                correct_password: true,
                enabled: false,
            })
            .await
            .assert_enabled_validators_count(1)
            .assert_validators_count(2);
    });
}

#[test]
fn web3signer_validator_creation() {
    let runtime = build_runtime();
    let weak_runtime = Arc::downgrade(&runtime);
    runtime.block_on(async {
        ApiTester::new(weak_runtime)
            .await
            .assert_enabled_validators_count(0)
            .assert_validators_count(0)
            .create_web3signer_validators(Web3SignerValidatorScenario {
                count: 1,
                enabled: true,
            })
            .await
            .assert_enabled_validators_count(1)
            .assert_validators_count(1);
    });
}

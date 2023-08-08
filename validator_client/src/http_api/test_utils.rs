use crate::doppelganger_service::DoppelgangerService;
use crate::key_cache::{KeyCache, CACHE_FILENAME};
use crate::{
    http_api::{ApiSecret, Config as HttpConfig, Context},
    initialized_validators::{InitializedValidators, OnDecryptFailure},
    Config, ValidatorDefinitions, ValidatorStore,
};
use account_utils::{
    eth2_wallet::WalletBuilder, mnemonic_from_phrase, random_mnemonic, random_password,
    ZeroizeString,
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
use std::sync::Arc;
use std::time::Duration;
use task_executor::test_utils::TestRuntime;
use tempfile::{tempdir, TempDir};
use tokio::sync::oneshot;

pub const PASSWORD_BYTES: &[u8] = &[42, 50, 37];
pub const TEST_DEFAULT_FEE_RECIPIENT: Address = Address::repeat_byte(42);

type E = MainnetEthSpec;

pub struct HdValidatorScenario {
    pub count: usize,
    pub specify_mnemonic: bool,
    pub key_derivation_path_offset: u32,
    pub disabled: Vec<usize>,
}

pub struct KeystoreValidatorScenario {
    pub enabled: bool,
    pub correct_password: bool,
}

pub struct Web3SignerValidatorScenario {
    pub count: usize,
    pub enabled: bool,
}

pub struct ApiTester {
    pub client: ValidatorClientHttpClient,
    pub initialized_validators: Arc<RwLock<InitializedValidators>>,
    pub validator_store: Arc<ValidatorStore<TestingSlotClock, E>>,
    pub url: SensitiveUrl,
    pub api_token: String,
    pub test_runtime: TestRuntime,
    pub _server_shutdown: oneshot::Sender<()>,
    pub validator_dir: TempDir,
    pub secrets_dir: TempDir,
}

impl ApiTester {
    pub async fn new() -> Self {
        Self::new_with_http_config(Self::default_http_config()).await
    }

    pub async fn new_with_http_config(http_config: HttpConfig) -> Self {
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

        let config = Config {
            validator_dir: validator_dir.path().into(),
            secrets_dir: secrets_dir.path().into(),
            fee_recipient: Some(TEST_DEFAULT_FEE_RECIPIENT),
            ..Default::default()
        };

        let spec = E::default_spec();

        let slashing_db_path = config.validator_dir.join(SLASHING_PROTECTION_FILENAME);
        let slashing_protection = SlashingDatabase::open_or_create(&slashing_db_path).unwrap();

        let slot_clock =
            TestingSlotClock::new(Slot::new(0), Duration::from_secs(0), Duration::from_secs(1));

        let test_runtime = TestRuntime::default();

        let validator_store = Arc::new(ValidatorStore::<_, E>::new(
            initialized_validators,
            slashing_protection,
            Hash256::repeat_byte(42),
            spec,
            Some(Arc::new(DoppelgangerService::new(log.clone()))),
            slot_clock.clone(),
            &config,
            test_runtime.task_executor.clone(),
            log.clone(),
        ));

        validator_store
            .register_all_in_doppelganger_protection_if_enabled()
            .expect("Should attach doppelganger service");

        let initialized_validators = validator_store.initialized_validators();

        let context = Arc::new(Context {
            task_executor: test_runtime.task_executor.clone(),
            api_secret,
            validator_dir: Some(validator_dir.path().into()),
            secrets_dir: Some(secrets_dir.path().into()),
            validator_store: Some(validator_store.clone()),
            graffiti_file: None,
            graffiti_flag: Some(Graffiti::default()),
            spec: E::default_spec(),
            config: http_config,
            log,
            sse_logging_components: None,
            slot_clock,
            _phantom: PhantomData,
        });
        let ctx = context;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_shutdown = async {
            // It's not really interesting why this triggered, just that it happened.
            let _ = shutdown_rx.await;
        };
        let (listening_socket, server) = super::serve(ctx, server_shutdown).unwrap();

        tokio::spawn(server);

        let url = SensitiveUrl::parse(&format!(
            "http://{}:{}",
            listening_socket.ip(),
            listening_socket.port()
        ))
        .unwrap();

        let client = ValidatorClientHttpClient::new(url.clone(), api_pubkey.clone()).unwrap();

        Self {
            client,
            initialized_validators,
            validator_store,
            url,
            api_token: api_pubkey,
            test_runtime,
            _server_shutdown: shutdown_tx,
            validator_dir,
            secrets_dir,
        }
    }

    pub fn default_http_config() -> HttpConfig {
        HttpConfig {
            enabled: true,
            listen_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            listen_port: 0,
            allow_origin: None,
            allow_keystore_export: true,
            store_passwords_in_secrets_dir: false,
        }
    }

    /// Checks that the key cache exists and can be decrypted with the current
    /// set of known validators.
    #[allow(clippy::await_holding_lock)] // This is a test, so it should be fine.
    pub async fn ensure_key_cache_consistency(&self) {
        assert!(
            self.validator_dir.as_ref().join(CACHE_FILENAME).exists(),
            "the key cache should exist"
        );
        let key_cache =
            KeyCache::open_or_create(self.validator_dir.as_ref()).expect("should open a key cache");

        self.initialized_validators
            .read()
            .decrypt_key_cache(key_cache, &mut <_>::default(), OnDecryptFailure::Error)
            .await
            .expect("key cache should decypt");
    }

    pub fn invalid_token_client(&self) -> ValidatorClientHttpClient {
        let tmp = tempdir().unwrap();
        let api_secret = ApiSecret::create_or_open(tmp.path()).unwrap();
        let invalid_pubkey = api_secret.api_token();
        ValidatorClientHttpClient::new(self.url.clone(), invalid_pubkey).unwrap()
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
            .get_lighthouse_spec::<ConfigAndPresetBellatrix>()
            .await
            .map(|res| ConfigAndPreset::Bellatrix(res.data))
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
            (response.validators.clone(), response.mnemonic)
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

        for item in response.iter().take(s.count) {
            let keypairs = wallet
                .next_validator(PASSWORD_BYTES, PASSWORD_BYTES, PASSWORD_BYTES)
                .unwrap();
            let voting_keypair = keypairs.voting.decrypt_keypair(PASSWORD_BYTES).unwrap();

            assert_eq!(
                item.voting_pubkey,
                voting_keypair.pk.clone().into(),
                "the locally generated voting pk should match the server response"
            );

            let withdrawal_keypair = keypairs.withdrawal.decrypt_keypair(PASSWORD_BYTES).unwrap();

            let deposit_bytes = serde_utils::hex::decode(&item.eth1_deposit_tx_data).unwrap();

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
}

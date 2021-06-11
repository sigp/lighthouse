#![cfg(test)]
#![cfg(not(debug_assertions))]

use crate::{
    http_api::{ApiSecret, Config as HttpConfig, Context},
    Config, ForkServiceBuilder, InitializedValidators, ValidatorDefinitions, ValidatorStore,
};
use account_utils::{
    eth2_wallet::WalletBuilder, mnemonic_from_phrase, random_mnemonic, random_password,
    ZeroizeString,
};
use deposit_contract::decode_eth1_tx_data;
use environment::null_logger;
use eth2::lighthouse_vc::{http_client::ValidatorClientHttpClient, types::*};
use eth2_keystore::KeystoreBuilder;
use parking_lot::RwLock;
use sensitive_url::SensitiveUrl;
use slashing_protection::{SlashingDatabase, SLASHING_PROTECTION_FILENAME};
use slot_clock::TestingSlotClock;
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

const PASSWORD_BYTES: &[u8] = &[42, 50, 37];

type E = MainnetEthSpec;

struct ApiTester {
    client: ValidatorClientHttpClient,
    initialized_validators: Arc<RwLock<InitializedValidators>>,
    url: SensitiveUrl,
    _server_shutdown: oneshot::Sender<()>,
    _validator_dir: TempDir,
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
        let log = null_logger().unwrap();

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

        let spec = E::default_spec();

        let fork_service = ForkServiceBuilder::testing_only(spec.clone(), log.clone())
            .build()
            .unwrap();

        let slashing_db_path = config.validator_dir.join(SLASHING_PROTECTION_FILENAME);
        let slashing_protection = SlashingDatabase::open_or_create(&slashing_db_path).unwrap();

        let validator_store: ValidatorStore<TestingSlotClock, E> = ValidatorStore::new(
            initialized_validators,
            slashing_protection,
            Hash256::repeat_byte(42),
            spec,
            fork_service.clone(),
            log.clone(),
        );

        let initialized_validators = validator_store.initialized_validators();

        let context: Arc<Context<TestingSlotClock, E>> = Arc::new(Context {
            runtime,
            api_secret,
            validator_dir: Some(validator_dir.path().into()),
            validator_store: Some(validator_store),
            spec: E::default_spec(),
            config: HttpConfig {
                enabled: true,
                listen_addr: Ipv4Addr::new(127, 0, 0, 1),
                listen_port: 0,
                allow_origin: None,
            },
            log,
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
            initialized_validators,
            _validator_dir: validator_dir,
            client,
            url,
            _server_shutdown: shutdown_tx,
        }
    }

    pub fn invalidate_api_token(mut self) -> Self {
        let tmp = tempdir().unwrap();
        let api_secret = ApiSecret::create_or_open(tmp.path()).unwrap();
        let invalid_pubkey = api_secret.api_token();

        self.client = ValidatorClientHttpClient::new(self.url.clone(), invalid_pubkey).unwrap();
        self
    }

    pub async fn test_get_lighthouse_version_invalid(self) -> Self {
        self.client.get_lighthouse_version().await.unwrap_err();
        self
    }

    pub async fn test_get_lighthouse_spec(self) -> Self {
        let result = self.client.get_lighthouse_spec().await.unwrap().data;

        let expected = YamlConfig::from_spec::<E>(&E::default_spec());

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

    pub async fn set_validator_enabled(self, index: usize, enabled: bool) -> Self {
        let validator = &self.client.get_lighthouse_validators().await.unwrap().data[index];

        self.client
            .patch_lighthouse_validators(&validator.voting_pubkey, enabled)
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

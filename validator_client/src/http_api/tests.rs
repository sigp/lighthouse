#![cfg(test)]

use crate::{
    http_api::{Config, Context},
    InitializedValidators, ValidatorDefinitions,
};
use account_utils::{random_mnemonic, random_password};
use environment::null_logger;
use eth2::{
    lighthouse_vc::{http_client::ValidatorClientHttpClient, types::*},
    Url,
};
use eth2_keystore::KeystoreBuilder;
use parking_lot::RwLock;
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use tokio::sync::oneshot;

type E = MainnetEthSpec;

struct ApiTester {
    client: ValidatorClientHttpClient,
    initialized_validators: Arc<RwLock<InitializedValidators>>,
    _server_shutdown: oneshot::Sender<()>,
    datadir: TempDir,
}

impl ApiTester {
    pub async fn new() -> Self {
        let log = null_logger().unwrap();

        let datadir = tempdir().unwrap();

        let validator_defs = ValidatorDefinitions::open_or_create(datadir.path()).unwrap();

        let initialized_validators = InitializedValidators::from_definitions(
            validator_defs,
            datadir.path().into(),
            false,
            log.clone(),
        )
        .await
        .unwrap();

        let initialized_validators = Arc::new(RwLock::new(initialized_validators));

        let context: Arc<Context<E>> = Arc::new(Context {
            data_dir: Some(datadir.path().into()),
            spec: E::default_spec(),
            initialized_validators: Some(initialized_validators.clone()),
            config: Config {
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

        let client = ValidatorClientHttpClient::new(
            Url::parse(&format!(
                "http://{}:{}",
                listening_socket.ip(),
                listening_socket.port()
            ))
            .unwrap(),
        );

        Self {
            initialized_validators,
            datadir,
            client,
            _server_shutdown: shutdown_tx,
        }
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

        let mnemonic = Some(random_mnemonic().phrase().to_string()).filter(|_| s.specify_mnemonic);
        let key_derivation_path_offset = 0;
        let validators = (0..s.count)
            .map(|i| HdValidator {
                enable: !s.disabled.contains(&i),
                validator_desc: format!("boi #{}", i),
                deposit_gwei: E::default_spec().max_effective_balance,
            })
            .collect::<Vec<_>>();

        let request = HdValidatorsPostRequest {
            mnemonic: mnemonic.clone(),
            key_derivation_path_offset,
            validators: validators.clone(),
        };

        let response = self
            .client
            .post_lighthouse_validators_hd(&request)
            .await
            .unwrap()
            .data;

        assert!(
            mnemonic.is_some() != response.mnemonic.is_some(),
            "should not return mnemonic if it is sent, but should return if it is not sent."
        );

        assert_eq!(response.validators.len(), s.count);
        assert_eq!(self.vals_total(), initial_vals + s.count);
        assert_eq!(
            self.vals_enabled(),
            initial_enabled_vals + s.count - s.disabled.len()
        );

        let server_vals = self.client.get_lighthouse_validators().await.unwrap().data;

        assert_eq!(server_vals.len(), self.vals_total());

        // Ensure the server lists all of these newly created validators.
        for validator in &response.validators {
            assert!(server_vals
                .iter()
                .any(|server_val| server_val.voting_pubkey == validator.voting_pubkey));
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
                password: String::from_utf8(random_password().as_ref().to_vec()).unwrap(),
                keystore,
            };

            self.client
                .post_lighthouse_validators_keystore(&request)
                .await
                .unwrap_err();

            return self;
        }

        let request = KeystoreValidatorsPostRequest {
            enable: s.enabled,
            password: String::from_utf8(password.as_ref().to_vec()).unwrap(),
            keystore,
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
    disabled: Vec<usize>,
}

struct KeystoreValidatorScenario {
    enabled: bool,
    correct_password: bool,
}

#[tokio::test(core_threads = 2)]
async fn simple_getters() {
    ApiTester::new()
        .await
        .test_get_lighthouse_version()
        .await
        .test_get_lighthouse_health()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn hd_validator_creation() {
    ApiTester::new()
        .await
        .assert_enabled_validators_count(0)
        .assert_validators_count(0)
        .create_hd_validators(HdValidatorScenario {
            count: 2,
            specify_mnemonic: true,
            disabled: vec![],
        })
        .await
        .assert_enabled_validators_count(2)
        .assert_validators_count(2)
        .create_hd_validators(HdValidatorScenario {
            count: 1,
            specify_mnemonic: false,
            disabled: vec![0],
        })
        .await
        .assert_enabled_validators_count(2)
        .assert_validators_count(3)
        .create_hd_validators(HdValidatorScenario {
            count: 0,
            specify_mnemonic: true,
            disabled: vec![],
        })
        .await
        .assert_enabled_validators_count(2)
        .assert_validators_count(3);
}

#[tokio::test(core_threads = 2)]
async fn keystore_validator_creation() {
    ApiTester::new()
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
}

#[tokio::test(core_threads = 2)]
async fn validator_enabling() {
    ApiTester::new()
        .await
        .create_hd_validators(HdValidatorScenario {
            count: 2,
            specify_mnemonic: false,
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
}

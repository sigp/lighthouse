#[cfg(test)]
mod tests {
    use account_utils::validator_definitions::{
        SigningDefinition, ValidatorDefinition, ValidatorDefinitions,
    };
    use eth2_keystore::KeystoreBuilder;
    use serde::Serialize;
    use slot_clock::{SlotClock, TestingSlotClock};
    use std::env;
    use std::fs::{self, File};
    use std::future::Future;
    use std::path::PathBuf;
    use std::process::{Child, Command};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use task_executor::TaskExecutor;
    use tempfile::TempDir;
    use tokio::time::sleep;
    use types::{
        Epoch, EthSpec, Hash256, Keypair, MainnetEthSpec, PublicKeyBytes, SecretKey, Signature,
        Slot,
    };
    use url::Url;
    use validator_client::{
        validator_store::ValidatorStore, InitializedValidators, SlashingDatabase,
        SLASHING_PROTECTION_FILENAME,
    };

    type E = MainnetEthSpec;

    #[derive(Serialize)]
    struct Web3SignerKeyConfig {
        #[serde(rename = "type")]
        config_type: String,
        #[serde(rename = "keyType")]
        key_type: String,
        #[serde(rename = "keystoreFile")]
        keystore_file: String,
        #[serde(rename = "keystorePasswordFile")]
        keystore_password_file: String,
    }

    const KEYSTORE_PASSWORD: &str = "hi mum";
    const WEB3SIGNER_LISTEN_ADDRESS: &str = "127.0.0.1";
    const WEB3SIGNER_LISTEN_PORT: u16 = 4242;

    fn testing_keypair() -> Keypair {
        // Just an arbitrary secret key.
        let sk = SecretKey::deserialize(&[
            85, 40, 245, 17, 84, 193, 234, 155, 24, 234, 181, 58, 171, 193, 209, 164, 120, 147, 10,
            174, 189, 228, 119, 48, 181, 19, 117, 223, 2, 240, 7, 108,
        ])
        .unwrap();
        let pk = sk.public_key();
        Keypair::from_components(pk, sk)
    }

    fn web3signer_binary() -> PathBuf {
        PathBuf::from(env::var("OUT_DIR").unwrap())
            .join("web3signer")
            .join("bin")
            .join("web3signer")
    }

    struct Web3SignerRig {
        keypair: Keypair,
        _keystore_dir: TempDir,
        keystore_path: PathBuf,
        web3signer_child: Child,
        url: Url,
    }

    impl Drop for Web3SignerRig {
        fn drop(&mut self) {
            self.web3signer_child.kill().unwrap();
        }
    }

    impl Web3SignerRig {
        pub async fn new(listen_address: &str, listen_port: u16) -> Self {
            let keystore_dir = TempDir::new().unwrap();
            let keypair = testing_keypair();
            let keystore =
                KeystoreBuilder::new(&keypair, KEYSTORE_PASSWORD.as_bytes(), "".to_string())
                    .unwrap()
                    .build()
                    .unwrap();
            let keystore_filename = "keystore.json";
            let keystore_path = keystore_dir.path().join(keystore_filename);
            let keystore_file = File::create(&keystore_path).unwrap();
            keystore.to_json_writer(&keystore_file).unwrap();

            let keystore_password_filename = "password.txt";
            let keystore_password_path = keystore_dir.path().join(keystore_password_filename);
            fs::write(&keystore_password_path, KEYSTORE_PASSWORD.as_bytes()).unwrap();

            let key_config = Web3SignerKeyConfig {
                config_type: "file-keystore".to_string(),
                key_type: "BLS".to_string(),
                keystore_file: keystore_filename.to_string(),
                keystore_password_file: keystore_password_filename.to_string(),
            };
            let key_config_file =
                File::create(&keystore_dir.path().join("key-config.yaml")).unwrap();
            serde_yaml::to_writer(key_config_file, &key_config).unwrap();

            let web3signer_child = Command::new(web3signer_binary())
                .arg(format!(
                    "--key-store-path={}",
                    keystore_dir.path().to_str().unwrap()
                ))
                .arg(format!("--http-listen-host={}", listen_address))
                .arg(format!("--http-listen-port={}", listen_port))
                .arg("eth2")
                .arg("--network=mainnet")
                .arg("--slashing-protection-enabled=false")
                .spawn()
                .unwrap();

            let url = Url::parse(&format!("http://{}:{}", listen_address, listen_port)).unwrap();

            let s = Self {
                keypair,
                _keystore_dir: keystore_dir,
                keystore_path,
                web3signer_child,
                url,
            };

            s.wait_until_up(Duration::from_secs(5)).await;

            s
        }

        pub async fn wait_until_up(&self, timeout: Duration) {
            let start = Instant::now();
            loop {
                if self.upcheck().await.is_ok() {
                    return;
                } else if Instant::now().duration_since(start) > timeout {
                    panic!("upcheck failed with timeout {:?}", timeout)
                } else {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }

        pub async fn upcheck(&self) -> Result<(), ()> {
            let url = self.url.join("upcheck").unwrap();
            reqwest::get(url)
                .await
                .map_err(|_| ())?
                .error_for_status()
                .map(|_| ())
                .map_err(|_| ())
        }
    }

    struct ValidatorStoreRig {
        validator_store: Arc<ValidatorStore<TestingSlotClock, E>>,
        _validator_dir: TempDir,
        runtime: Arc<tokio::runtime::Runtime>,
        _runtime_shutdown: exit_future::Signal,
    }

    impl ValidatorStoreRig {
        pub async fn new(validator_definitions: Vec<ValidatorDefinition>) -> Self {
            let log = environment::null_logger().unwrap();
            let validator_dir = TempDir::new().unwrap();

            let validator_definitions = ValidatorDefinitions::from(validator_definitions);
            let initialized_validators = InitializedValidators::from_definitions(
                validator_definitions,
                validator_dir.path().into(),
                log.clone(),
            )
            .await
            .unwrap();

            let runtime = Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap(),
            );
            let (runtime_shutdown, exit) = exit_future::signal();
            let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
            let executor =
                TaskExecutor::new(Arc::downgrade(&runtime), exit, log.clone(), shutdown_tx);
            let slashing_db_path = validator_dir.path().join(SLASHING_PROTECTION_FILENAME);
            let slashing_protection = SlashingDatabase::open_or_create(&slashing_db_path).unwrap();
            let slot_clock =
                TestingSlotClock::new(Slot::new(0), Duration::from_secs(0), Duration::from_secs(1));
            let spec = E::default_spec();

            let validator_store = ValidatorStore::<_, E>::new(
                initialized_validators,
                slashing_protection,
                Hash256::repeat_byte(42),
                spec,
                None,
                slot_clock,
                executor,
                log.clone(),
            );

            Self {
                validator_store: Arc::new(validator_store),
                _validator_dir: validator_dir,
                runtime,
                _runtime_shutdown: runtime_shutdown,
            }
        }

        pub fn shutdown(self) {
            Arc::try_unwrap(self.runtime).unwrap().shutdown_background()
        }
    }

    struct TestingRig {
        _signer_rig: Web3SignerRig,
        validator_rigs: Vec<ValidatorStoreRig>,
        validator_pubkey: PublicKeyBytes,
    }

    impl Drop for TestingRig {
        fn drop(&mut self) {
            for rig in std::mem::replace(&mut self.validator_rigs, vec![]) {
                rig.shutdown();
            }
        }
    }

    impl TestingRig {
        pub async fn new() -> Self {
            let signer_rig =
                Web3SignerRig::new(WEB3SIGNER_LISTEN_ADDRESS, WEB3SIGNER_LISTEN_PORT).await;
            let validator_pubkey = signer_rig.keypair.pk.clone();

            let local_signer_validator_store = {
                let validator_definition = ValidatorDefinition {
                    enabled: true,
                    voting_public_key: validator_pubkey.clone(),
                    graffiti: None,
                    description: String::default(),
                    signing_definition: SigningDefinition::LocalKeystore {
                        voting_keystore_path: signer_rig.keystore_path.clone(),
                        voting_keystore_password_path: None,
                        voting_keystore_password: Some(KEYSTORE_PASSWORD.to_string().into()),
                    },
                };
                ValidatorStoreRig::new(vec![validator_definition]).await
            };

            let remote_signer_validator_store = {
                let validator_definition = ValidatorDefinition {
                    enabled: true,
                    voting_public_key: validator_pubkey.clone(),
                    graffiti: None,
                    description: String::default(),
                    signing_definition: SigningDefinition::Web3Signer {
                        url: signer_rig.url.to_string(),
                        root_certificate_path: None,
                        request_timeout_ms: None,
                    },
                };
                ValidatorStoreRig::new(vec![validator_definition]).await
            };

            Self {
                _signer_rig: signer_rig,
                validator_rigs: vec![local_signer_validator_store, remote_signer_validator_store],
                validator_pubkey: PublicKeyBytes::from(&validator_pubkey),
            }
        }

        pub async fn assert_signatures_match<F, R>(self, case_name: &str, generate_sig: F) -> Self
        where
            F: Fn(PublicKeyBytes, Arc<ValidatorStore<TestingSlotClock, E>>) -> R,
            R: Future<Output = Signature>,
        {
            let mut prev_signature = None;
            for (i, validator_rig) in self.validator_rigs.iter().enumerate() {
                let signature =
                    generate_sig(self.validator_pubkey, validator_rig.validator_store.clone())
                        .await;

                if let Some(prev_signature) = &prev_signature {
                    assert_eq!(
                        prev_signature, &signature,
                        "signature mismatch at index {} for case {}",
                        i, case_name
                    );
                }

                prev_signature = Some(signature)
            }
            assert!(prev_signature.is_some(), "sanity check");
            self
        }
    }

    #[tokio::test]
    async fn all_signature_types() {
        TestingRig::new()
            .await
            .assert_signatures_match("rando_reveal", |pubkey, validator_store| async move {
                validator_store
                    .randao_reveal(pubkey, Epoch::new(0))
                    .await
                    .unwrap()
            })
            .await;
    }
}

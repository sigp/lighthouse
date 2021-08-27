#[cfg(test)]
mod tests {
    use account_utils::validator_definitions::{
        SigningDefinition, ValidatorDefinition, ValidatorDefinitions,
    };
    use eth2_keystore::{Keystore, KeystoreBuilder};
    use slot_clock::{SlotClock, TestingSlotClock};
    use std::env;
    use std::fs::File;
    use std::path::PathBuf;
    use std::process::{Child, Command};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use task_executor::TaskExecutor;
    use tempfile::TempDir;
    use tokio::time::sleep;
    use types::{EthSpec, Hash256, Keypair, MainnetEthSpec, PublicKey, SecretKey, Slot};
    use url::Url;
    use validator_client::{
        validator_store::ValidatorStore, InitializedValidators, SlashingDatabase,
        SLASHING_PROTECTION_FILENAME,
    };

    type E = MainnetEthSpec;

    const KEYSTORE_PASSWORD: &[u8] = &[13, 37, 42, 42];
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
        keystore: Keystore,
        keystore_dir: TempDir,
        keystore_path: PathBuf,
        web3signer_child: Child,
        url: Url,
        listen_address: String,
        listen_port: u16,
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
            let keystore = KeystoreBuilder::new(&keypair, KEYSTORE_PASSWORD, "".to_string())
                .unwrap()
                .build()
                .unwrap();
            let keystore_path = keystore_dir.path().join("keystore.json");
            let keystore_file = File::create(&keystore_path).unwrap();
            keystore.to_json_writer(&keystore_file).unwrap();

            let web3signer_child = Command::new(web3signer_binary())
                .arg(format!("--key-store-path={:?}", keystore_dir.path()))
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
                keystore,
                keystore_dir,
                keystore_path,
                web3signer_child,
                url,
                listen_address: listen_address.to_string(),
                listen_port,
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
        validator_store: ValidatorStore<TestingSlotClock, E>,
        validator_dir: TempDir,
        _runtime_shutdown: exit_future::Signal,
    }

    impl ValidatorStoreRig {
        pub async fn new(remote_signer_url: &Url, voting_public_key: PublicKey) -> Self {
            let log = environment::null_logger().unwrap();
            let validator_dir = TempDir::new().unwrap();

            let validator_definition = ValidatorDefinition {
                enabled: true,
                voting_public_key,
                graffiti: None,
                description: String::default(),
                signing_definition: SigningDefinition::Web3Signer {
                    url: remote_signer_url.to_string(),
                    root_certificate_path: None,
                    request_timeout_ms: None,
                },
            };
            let validator_definitions = ValidatorDefinitions::from(vec![validator_definition]);
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
                validator_store,
                validator_dir,
                _runtime_shutdown: runtime_shutdown,
            }
        }
    }

    #[tokio::test]
    async fn it_works() {
        let signer_rig =
            Web3SignerRig::new(WEB3SIGNER_LISTEN_ADDRESS, WEB3SIGNER_LISTEN_PORT).await;
        let validator_rig =
            ValidatorStoreRig::new(&signer_rig.url, signer_rig.keypair.pk.clone()).await;
    }
}

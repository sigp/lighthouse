#[cfg(test)]
mod tests {
    use eth2_keystore::{Keystore, KeystoreBuilder};
    use std::env;
    use std::fs::File;
    use std::path::PathBuf;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;
    use tokio::time::sleep;
    use types::{Keypair, SecretKey};
    use url::Url;

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

            s.wait_until_up(Duration::from_secs(5));

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

    #[tokio::test]
    async fn it_works() {
        let rig = Web3SignerRig::new(WEB3SIGNER_LISTEN_ADDRESS, WEB3SIGNER_LISTEN_PORT).await;
    }
}

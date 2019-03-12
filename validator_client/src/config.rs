use bls::Keypair;
use std::fs;
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use types::ChainSpec;

/// Stores the core configuration for this validator instance.
#[derive(Clone)]
pub struct ClientConfig {
    pub data_dir: PathBuf,
    pub key_dir: PathBuf,
    pub server: String,
    pub spec: ChainSpec,
}

const DEFAULT_LIGHTHOUSE_DIR: &str = ".lighthouse-validators";
const DEFAULT_KEYSTORE_SUBDIR: &str = "keystore";

impl ClientConfig {
    /// Build a new configuration from defaults.
    pub fn default() -> Result<Self, Error> {
        let data_dir = {
            let home = dirs::home_dir().expect("Unable to determine home dir.");
            home.join(DEFAULT_LIGHTHOUSE_DIR)
        };
        fs::create_dir_all(&data_dir)?;

        let key_dir = data_dir.join(DEFAULT_KEYSTORE_SUBDIR);
        fs::create_dir_all(&key_dir)?;

        let server = "localhost:50051".to_string();
        let spec = ChainSpec::foundation();
        Ok(Self {
            data_dir,
            key_dir,
            server,
            spec,
        })
    }

    // Try to load keys from datadir, or fail
    pub fn fetch_keys(&self) -> Result<Option<Vec<Keypair>>, Error> {
        let mut key_files = fs::read_dir(&self.key_dir)?.peekable();

        if key_files.peek().is_none() {
            return Ok(None);
        }

        let mut key_pairs: Vec<Keypair> = Vec::new();

        for key_filename in key_files {
            let mut key_file = File::open(key_filename?.path())?;

            let key: Keypair = bincode::deserialize_from(&mut key_file)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

            key_pairs.push(key);
        }

        Ok(Some(key_pairs))
    }

    pub fn save_key(&self, key: &Keypair) -> Result<(), Error> {
        let key_path = self.key_dir.join(key.identifier() + ".key");
        let mut key_file = File::create(&key_path)?;
        bincode::serialize_into(&mut key_file, &key)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        Ok(())
    }
}

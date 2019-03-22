use std::fs;
use std::path::PathBuf;
use types::ChainSpec;

/// Stores the core configuration for this validator instance.
#[derive(Clone)]
pub struct ClientConfig {
    pub data_dir: PathBuf,
    pub server: String,
    pub spec: ChainSpec,
}

const DEFAULT_LIGHTHOUSE_DIR: &str = ".lighthouse-validators";

impl ClientConfig {
    /// Build a new configuration from defaults.
    pub fn default() -> Self {
        let data_dir = {
            let home = dirs::home_dir().expect("Unable to determine home dir.");
            home.join(DEFAULT_LIGHTHOUSE_DIR)
        };
        fs::create_dir_all(&data_dir)
            .unwrap_or_else(|_| panic!("Unable to create {:?}", &data_dir));
        let server = "localhost:5051".to_string();
        let spec = ChainSpec::foundation();
        Self {
            data_dir,
            server,
            spec,
        }
    }
}

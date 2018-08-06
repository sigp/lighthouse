use std::env; 
use std::path::PathBuf; 

#[derive(Clone)]
pub struct LighthouseConfig {
    pub data_dir: PathBuf,
    pub p2p_listen_port: String,
}

const DEFAULT_LIGHTHOUSE_DIR: &str = ".lighthouse";

impl LighthouseConfig {
    /// Build a new lighthouse configuration from defaults.
    pub fn default() -> Self{
        let data_dir = {
            let home = env::home_dir()
                .expect("Unable to determine home dir.");
            home.join(DEFAULT_LIGHTHOUSE_DIR)
        };
        let p2p_listen_port = "0".to_string();
        Self {
            data_dir,
            p2p_listen_port,
        }
    }
}

extern crate dirs;

use std::fs;
use std::path::PathBuf;

/// Stores the core configuration for this Lighthouse instance.
/// This struct is general, other components may implement more
/// specialized config structs.
#[derive(Clone)]
pub struct LighthouseConfig {
    pub data_dir: PathBuf,
    pub p2p_listen_port: u16,
}

const DEFAULT_LIGHTHOUSE_DIR: &str = ".lighthouse";

impl LighthouseConfig {
    /// Build a new lighthouse configuration from defaults.
    pub fn default() -> Self{
        let data_dir = {
            let home = dirs::home_dir()
                .expect("Unable to determine home dir.");
            home.join(DEFAULT_LIGHTHOUSE_DIR)
        };
        fs::create_dir_all(&data_dir)
            .unwrap_or_else(|_| panic!("Unable to create {:?}", &data_dir));
        let p2p_listen_port = 0;
        Self {
            data_dir,
            p2p_listen_port,
        }
    }
}

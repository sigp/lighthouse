pub mod types;
use std::time::Duration;

use futures::stream::StreamExt;
pub use reqwest;
use task_executor::TaskExecutor;
use tokio::time::{interval_at, Instant};
use types::*;

/// Placeholder
const DEFAULT_EXPLORER_ENDPOINT: &str = "https://beaconcha.in/tbd/metrics";
const DEFAULT_UPDATE_DURATION: u64 = 60;

#[derive(Debug, Clone)]
pub struct Config {
    /// Beacon metrics endpoint.
    beacon_endpoint: String,
    /// Validator metrics endpoint.
    validator_endpoint: String,
    /// Explorer endpoint
    explorer_endpoint: String,
    /// Api key for the explorer endpoint
    api_key: Option<String>,
    /// Duration sending metrics to explorer
    update_interval_seconds: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            beacon_endpoint: "http://localhost:5054".to_string(),
            validator_endpoint: "http://localhost:5054".to_string(),
            explorer_endpoint: DEFAULT_EXPLORER_ENDPOINT.to_string(),
            api_key: None,
            update_interval_seconds: Duration::from_secs(DEFAULT_UPDATE_DURATION),
        }
    }
}

#[derive(Clone)]
pub struct ExplorerHttpClient {
    client: reqwest::Client,
    config: Config,
    // metrics: ExplorerMetrics,
}

impl ExplorerHttpClient {
    pub fn new(config: Config) -> Self {
        Self {
            client: reqwest::Client::new(),
            config,
            // metrics: Default::default(),
        }
    }

    pub fn auto_update(self, executor: TaskExecutor) {
        let mut interval = interval_at(Instant::now(), self.config.update_interval_seconds);

        let update_future = async move {
            while interval.next().await.is_some() {
                self.do_update().await;
            }
        };

        executor.spawn(update_future, "explorer_api");
    }

    async fn do_update(&self) {
        self.get_and_update_beacon_metrics();
        self.get_and_update_validator_metrics();
        self.send_metrics();
    }

    /// Gets beacon metrics and updates the metrics struct
    pub fn get_and_update_beacon_metrics(&self) {
        unimplemented!()
    }

    /// Gets validator metrics and updates the metrics struct
    pub fn get_and_update_validator_metrics(&self) {
        unimplemented!()
    }

    /// Send metrics to the remote server
    pub fn send_metrics(&self) {
        unimplemented!()
    }
}

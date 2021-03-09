pub mod types;
use std::time::Duration;

use eth2::lighthouse::SystemHealth;
use reqwest::{IntoUrl, Response};
pub use reqwest::{StatusCode, Url};
use serde::{de::DeserializeOwned, Serialize};
use task_executor::TaskExecutor;
use tokio::time::{interval_at, Instant};
use types::*;

/// Placeholder
pub const DEFAULT_EXPLORER_ENDPOINT: &str = "https://beaconcha.in/tbd/metrics";
pub const DEFAULT_BEACON_ENDPOINT: &str = "http://localhost:5054/beacon_process";
pub const DEFAULT_VALIDATOR_ENDPOINT: &str = "http://localhost:5064/validator_process";
pub const DEFAULT_UPDATE_DURATION: u64 = 60;

#[derive(Debug)]
pub enum Error {
    /// The `reqwest` client raised an error.
    Reqwest(reqwest::Error),
    /// The supplied URL is badly formatted. It should look something like `http://127.0.0.1:5052`.
    InvalidUrl(Url),
    /// Failed to observe system metrics
    SystemMetricsFailed(String),
    /// The server returned an invalid JSON response.
    InvalidJson(serde_json::Error),
    /// The server returned an error message where the body was able to be parsed.
    ServerMessage(ErrorMessage),
    /// The server returned an error message where the body was unable to be parsed.
    StatusCode(StatusCode),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Beacon metrics endpoint.
    beacon_endpoint: Url,
    /// Validator metrics endpoint.
    validator_endpoint: Url,
    /// Explorer endpoint where we post the data to
    explorer_endpoint: Url,
    /// Duration sending metrics to explorer endpoint
    update_interval_seconds: Duration,
}

#[derive(Clone)]
pub struct ExplorerHttpClient {
    client: reqwest::Client,
    config: Config,
}

impl ExplorerHttpClient {
    pub fn new(config: Config) -> Self {
        Self {
            client: reqwest::Client::new(),
            config,
        }
    }

    /// Perform a HTTP GET request.
    async fn get<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<T, Error> {
        let response = self.client.get(url).send().await.map_err(Error::Reqwest)?;
        ok_or_error(response)
            .await?
            .json()
            .await
            .map_err(Error::Reqwest)
    }

    /// Perform a HTTP POST request.
    async fn _post<T: Serialize, U: IntoUrl>(&self, url: U, body: &T) -> Result<(), Error> {
        let response = self
            .client
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(Error::Reqwest)?;
        ok_or_error(response).await?;
        Ok(())
    }

    pub fn auto_update(self, executor: TaskExecutor) {
        let mut interval = interval_at(Instant::now(), self.config.update_interval_seconds);

        let update_future = async move {
            loop {
                interval.tick().await;
                // self.do_update().await;
            }
        };

        executor.spawn(update_future, "explorer_api");
    }

    /// Gets beacon metrics and updates the metrics struct
    pub async fn get_beacon_metrics(&self) -> Result<ExplorerMetrics, Error> {
        let path = self.config.beacon_endpoint.clone();
        let resp: BeaconProcessMetrics = self.get(path).await?;
        Ok(ExplorerMetrics {
            metadata: Metadata::new(ProcessType::Beacon),
            process_metrics: Process::Beacon(resp),
        })
    }

    /// Gets validator process metrics by querying the validator metrics endpoint
    pub async fn get_validator_metrics(&self) -> Result<ExplorerMetrics, Error> {
        let path = self.config.validator_endpoint.clone();
        let resp: ValidatorProcessMetrics = self.get(path).await?;
        Ok(ExplorerMetrics {
            metadata: Metadata::new(ProcessType::Beacon),
            process_metrics: Process::Validator(resp),
        })
    }

    /// Gets system metrics by observing capturing the SystemHealth metrics.
    pub async fn get_system_metrics(&self) -> Result<ExplorerMetrics, Error> {
        let system_health = SystemHealth::observe().map_err(Error::SystemMetricsFailed)?;
        Ok(ExplorerMetrics {
            metadata: Metadata::new(ProcessType::System),
            process_metrics: Process::System(system_health.into()),
        })
    }

    /// Send metrics to the remote endpoint
    pub fn send_metrics(&self) {
        unimplemented!()
    }
}

/// Returns `Ok(response)` if the response is a `200 OK` response. Otherwise, creates an
/// appropriate error message.
async fn ok_or_error(response: Response) -> Result<Response, Error> {
    let status = response.status();

    if status == StatusCode::OK {
        Ok(response)
    } else if let Ok(message) = response.json().await {
        Err(Error::ServerMessage(message))
    } else {
        Err(Error::StatusCode(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_api() {
        let config = Config {
            beacon_endpoint: Url::parse(DEFAULT_BEACON_ENDPOINT).unwrap(),
            validator_endpoint: Url::parse(DEFAULT_VALIDATOR_ENDPOINT).unwrap(),
            explorer_endpoint: Url::parse(DEFAULT_BEACON_ENDPOINT).unwrap(),
            update_interval_seconds: Duration::from_secs(DEFAULT_UPDATE_DURATION),
        };

        let client = ExplorerHttpClient::new(config);
        let beacon_metrics = client.get_beacon_metrics().await;
        let validator_metrics =
            client.get_validator_metrics().await;
        let system_metrics = client.get_system_metrics().await;

        assert!(beacon_metrics.is_ok());
        assert!(validator_metrics.is_ok());
        assert!(system_metrics.is_ok());
    }
}

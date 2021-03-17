mod types;
use std::time::Duration;

use eth2::lighthouse::SystemHealth;
use reqwest::{IntoUrl, Response};
pub use reqwest::{StatusCode, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use slog::{debug, error, info};
use task_executor::TaskExecutor;
use tokio::time::{interval_at, Instant};
use types::*;

pub use types::ProcessType;

/// Endpoint for metrics server to get beacon process metrics.
pub const BEACON_ENDPOINT: &str = "beacon_process";
/// Endpoint for metrics server to get validator process metrics.
pub const VALIDATOR_ENDPOINT: &str = "validator_process";
/// Duration after which we collect and send metrics to remote endpoint.
pub const UPDATE_DURATION: u64 = 60;
/// Timeout for HTTP requests.
pub const TIMEOUT_DURATION: u64 = 5;

#[derive(Debug)]
pub enum Error {
    /// The `reqwest` client raised an error.
    Reqwest(reqwest::Error),
    /// The supplied URL is badly formatted. It should look something like `http://127.0.0.1:5052`.
    InvalidUrl(Url),
    SystemMetricsFailed(String),
    BeaconMetricsFailed(String),
    ValidatorMetricsFailed(String),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Beacon metrics endpoint.
    pub beacon_endpoint: Option<String>,
    /// Validator metrics endpoint.
    pub validator_endpoint: Option<String>,
    /// Explorer endpoint where we post the data to
    pub explorer_endpoint: String,
}

#[derive(Clone)]
pub struct ExplorerHttpClient {
    client: reqwest::Client,
    beacon_endpoint: Option<Url>,
    validator_endpoint: Option<Url>,
    explorer_endpoint: Url,
    log: slog::Logger,
}

impl ExplorerHttpClient {
    pub fn new(config: &Config, log: slog::Logger) -> Result<Self, String> {
        Ok(Self {
            client: reqwest::Client::new(),
            beacon_endpoint: config
                .beacon_endpoint
                .as_ref()
                .map(|u| Url::parse(&format!("{}/{}", u, BEACON_ENDPOINT)))
                .transpose()
                .map_err(|e| format!("Invalid beacon endpoint: {}", e))?,
            validator_endpoint: config
                .validator_endpoint
                .as_ref()
                .map(|u| Url::parse(&format!("{}/{}", u, VALIDATOR_ENDPOINT)))
                .transpose()
                .map_err(|e| format!("Invalid validator endpoint: {}", e))?,
            explorer_endpoint: Url::parse(&config.explorer_endpoint)
                .map_err(|e| format!("Invalid explorer endpoint: {}", e))?,
            log,
        })
    }

    /// Perform a HTTP GET request.
    async fn get<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<T, Error> {
        let response = self
            .client
            .get(url)
            .timeout(Duration::from_secs(TIMEOUT_DURATION))
            .send()
            .await
            .map_err(Error::Reqwest)?;
        ok_or_error(response)
            .await?
            .json()
            .await
            .map_err(Error::Reqwest)
    }

    /// Perform a HTTP POST request.
    async fn post<T: Serialize, U: IntoUrl>(&self, url: U, body: &T) -> Result<(), Error> {
        let response = self
            .client
            .post(url)
            .json(body)
            .timeout(Duration::from_secs(TIMEOUT_DURATION))
            .send()
            .await
            .map_err(Error::Reqwest)?;
        ok_or_error(response).await?;
        Ok(())
    }

    /// Creates a task which periodically sends the provided process metrics
    /// to the configured remote endpoint.
    pub fn auto_update(self, executor: TaskExecutor, processes: Vec<ProcessType>) {
        let mut interval = interval_at(
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(UPDATE_DURATION),
        );

        info!(self.log, "Starting explorer api");

        let update_future = async move {
            loop {
                interval.tick().await;
                match self.send_metrics(&processes).await {
                    Ok(()) => {
                        debug!(self.log, "Sent metrics to remote server"; "endpoint" => ?self.explorer_endpoint);
                    }
                    Err(e) => {
                        error!(self.log, "Failed to send metrics to remote endpoint"; "error" => ?e)
                    }
                }
            }
        };

        executor.spawn(update_future, "explorer_api");
    }

    /// Gets beacon metrics and updates the metrics struct
    pub async fn get_beacon_metrics(&self) -> Result<ExplorerMetrics, Error> {
        let path = self
            .beacon_endpoint
            .clone()
            .ok_or(Error::BeaconMetricsFailed(
                "Beacon metrics endpoint not provided".to_string(),
            ))?;
        let resp: BeaconProcessMetrics = self.get(path).await?;
        Ok(ExplorerMetrics {
            metadata: Metadata::new(ProcessType::Beacon),
            process_metrics: Process::Beacon(resp),
        })
    }

    /// Gets validator process metrics by querying the validator metrics endpoint
    pub async fn get_validator_metrics(&self) -> Result<ExplorerMetrics, Error> {
        let path = self
            .validator_endpoint
            .clone()
            .ok_or(Error::ValidatorMetricsFailed(
                "Validator metrics endpoint not provided".to_string(),
            ))?;
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

    /// Return explorer metric based on process type.
    pub async fn get_metrics(&self, process_type: &ProcessType) -> Result<ExplorerMetrics, Error> {
        match process_type {
            ProcessType::Beacon => self.get_beacon_metrics().await,
            ProcessType::System => self.get_system_metrics().await,
            ProcessType::Validator => self.get_validator_metrics().await,
        }
    }

    /// Send metrics to the remote endpoint
    pub async fn send_metrics(&self, processes: &[ProcessType]) -> Result<(), Error> {
        let mut metrics = Vec::new();
        for process in processes {
            match self.get_metrics(process).await {
                Err(e) => error!(
                    self.log,
                    "Failed to get metrics";
                    "process_type" => ?process,
                    "error" => ?e
                ),
                Ok(metric) => metrics.push(metric),
            }
        }
        info!(
            self.log,
            "Sending metrics to remote endpoint";
            "endpoint" => ?self.explorer_endpoint
        );
        self.post(self.explorer_endpoint.clone(), &metrics).await
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

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn test_api() {
//         // let config = Config {
//         //     beacon_endpoint: Url::parse(DEFAULT_BEACON_ENDPOINT).unwrap(),
//         //     validator_endpoint: Url::parse(DEFAULT_VALIDATOR_ENDPOINT).unwrap(),
//         //     explorer_endpoint: Url::parse(DEFAULT_BEACON_ENDPOINT).unwrap(),
//         //     update_interval_seconds: Duration::from_secs(DEFAULT_UPDATE_DURATION),
//         // };

//         // let client = ExplorerHttpClient::new(config);
//         // let beacon_metrics = client.get_beacon_metrics().await;
//         // let validator_metrics = client.get_validator_metrics().await;
//         // let system_metrics = client.get_system_metrics().await;

//         // assert!(beacon_metrics.is_ok());
//         // assert!(validator_metrics.is_ok());
//         // assert!(system_metrics.is_ok());
//     }
// }

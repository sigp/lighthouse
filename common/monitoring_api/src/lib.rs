mod gather;
mod types;
use std::{path::PathBuf, time::Duration};

use eth2::lighthouse::SystemHealth;
use gather::{gather_beacon_metrics, gather_validator_metrics};
use reqwest::{IntoUrl, Response};
pub use reqwest::{StatusCode, Url};
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use slog::{debug, error, info};
use task_executor::TaskExecutor;
use tokio::time::{interval_at, Instant};
use types::*;

pub use types::ProcessType;

/// Duration after which we collect and send metrics to remote endpoint.
pub const UPDATE_DURATION: u64 = 60;
/// Timeout for HTTP requests.
pub const TIMEOUT_DURATION: u64 = 5;

#[derive(Debug)]
pub enum Error {
    /// The `reqwest` client raised an error.
    Reqwest(reqwest::Error),
    /// The supplied URL is badly formatted. It should look something like `http://127.0.0.1:5052`.
    InvalidUrl(SensitiveUrl),
    SystemMetricsFailed(String),
    BeaconMetricsFailed(String),
    ValidatorMetricsFailed(String),
    /// The server returned an error message where the body was able to be parsed.
    ServerMessage(ErrorMessage),
    /// The server returned an error message where the body was unable to be parsed.
    StatusCode(StatusCode),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Error::Reqwest(e) => write!(f, "Reqwest error: {}", e),
            // Print the debug value
            e => write!(f, "{:?}", e),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Endpoint
    pub monitoring_endpoint: String,
    /// Path for the hot database required for fetching beacon db size metrics.
    /// Note: not relevant for validator and system metrics.
    pub db_path: Option<PathBuf>,
    /// Path for the cold database required for fetching beacon db size metrics.
    /// Note: not relevant for validator and system metrics.
    pub freezer_db_path: Option<PathBuf>,
}

#[derive(Clone)]
pub struct MonitoringHttpClient {
    client: reqwest::Client,
    /// Path to the hot database. Required for getting db size metrics
    db_path: Option<PathBuf>,
    /// Path to the freezer database.
    freezer_db_path: Option<PathBuf>,
    monitoring_endpoint: SensitiveUrl,
    log: slog::Logger,
}

impl MonitoringHttpClient {
    pub fn new(config: &Config, log: slog::Logger) -> Result<Self, String> {
        Ok(Self {
            client: reqwest::Client::new(),
            db_path: config.db_path.clone(),
            freezer_db_path: config.freezer_db_path.clone(),
            monitoring_endpoint: SensitiveUrl::parse(&config.monitoring_endpoint)
                .map_err(|e| format!("Invalid monitoring endpoint: {:?}", e))?,
            log,
        })
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
            // Have some initial delay for the metrics to get initialized
            Instant::now() + Duration::from_secs(25),
            Duration::from_secs(UPDATE_DURATION),
        );

        info!(self.log, "Starting monitoring api"; "endpoint" => %self.monitoring_endpoint);

        let update_future = async move {
            loop {
                interval.tick().await;
                match self.send_metrics(&processes).await {
                    Ok(()) => {
                        debug!(self.log, "Metrics sent to remote server"; "endpoint" => %self.monitoring_endpoint);
                    }
                    Err(e) => {
                        error!(self.log, "Failed to send metrics to remote endpoint"; "error" => %e)
                    }
                }
            }
        };

        executor.spawn(update_future, "monitoring_api");
    }

    /// Gets beacon metrics and updates the metrics struct
    pub fn get_beacon_metrics(&self) -> Result<MonitoringMetrics, Error> {
        let db_path = self.db_path.as_ref().ok_or_else(|| {
            Error::BeaconMetricsFailed("Beacon metrics require db path".to_string())
        })?;

        let freezer_db_path = self.db_path.as_ref().ok_or_else(|| {
            Error::BeaconMetricsFailed("Beacon metrics require freezer db path".to_string())
        })?;
        let metrics = gather_beacon_metrics(&db_path, &freezer_db_path)
            .map_err(Error::BeaconMetricsFailed)?;
        Ok(MonitoringMetrics {
            metadata: Metadata::new(ProcessType::BeaconNode),
            process_metrics: Process::Beacon(metrics),
        })
    }

    /// Gets validator process metrics by querying the validator metrics endpoint
    pub fn get_validator_metrics(&self) -> Result<MonitoringMetrics, Error> {
        let metrics = gather_validator_metrics().map_err(Error::BeaconMetricsFailed)?;
        Ok(MonitoringMetrics {
            metadata: Metadata::new(ProcessType::Validator),
            process_metrics: Process::Validator(metrics),
        })
    }

    /// Gets system metrics by observing capturing the SystemHealth metrics.
    pub fn get_system_metrics(&self) -> Result<MonitoringMetrics, Error> {
        let system_health = SystemHealth::observe().map_err(Error::SystemMetricsFailed)?;
        Ok(MonitoringMetrics {
            metadata: Metadata::new(ProcessType::System),
            process_metrics: Process::System(system_health.into()),
        })
    }

    /// Return metric based on process type.
    pub async fn get_metrics(
        &self,
        process_type: &ProcessType,
    ) -> Result<MonitoringMetrics, Error> {
        match process_type {
            ProcessType::BeaconNode => self.get_beacon_metrics(),
            ProcessType::System => self.get_system_metrics(),
            ProcessType::Validator => self.get_validator_metrics(),
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
                    "error" => %e
                ),
                Ok(metric) => metrics.push(metric),
            }
        }
        info!(
            self.log,
            "Sending metrics to remote endpoint";
            "endpoint" => %self.monitoring_endpoint
        );
        self.post(self.monitoring_endpoint.full.clone(), &metrics)
            .await
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

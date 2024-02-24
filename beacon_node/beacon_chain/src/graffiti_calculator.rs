use crate::BeaconChain;
use crate::BeaconChainTypes;
use clap::ArgMatches;
use execution_layer::{http::ENGINE_CLIENT_VERSION_V1, CommitPrefix, ExecutionLayer};
use serde::{Deserialize, Serialize};
use slog::{crit, debug, error, warn, Logger};
use slot_clock::SlotClock;
use std::{fmt::Debug, time::Duration};
use task_executor::TaskExecutor;
use types::{EthSpec, Graffiti, GRAFFITI_BYTES_LEN};

const ENGINE_VERSION_AGE_LIMIT_EPOCH_MULTIPLE: u32 = 6; // 6 epochs
const ENGINE_VERSION_CACHE_REFRESH_EPOCH_MULTIPLE: u32 = 2; // 2 epochs
const ENGINE_VERSION_CACHE_PRELOAD_STARTUP_DELAY: Duration = Duration::from_secs(60);

/// Represents the source and content of graffiti for block production, excluding
/// inputs from the validator client and execution engine. Graffiti is categorized
/// as either user-specified or calculated to facilitate decisions on graffiti
/// selection.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum GraffitiOrigin {
    UserSpecified(Graffiti),
    Calculated(Graffiti),
}

impl GraffitiOrigin {
    pub fn new(cli_args: &ArgMatches) -> Result<Self, String> {
        let mut bytes = [0u8; GRAFFITI_BYTES_LEN];

        if let Some(graffiti) = cli_args.value_of("graffiti") {
            if graffiti.len() > GRAFFITI_BYTES_LEN {
                return Err(format!(
                    "Your graffiti is too long! {} bytes maximum!",
                    GRAFFITI_BYTES_LEN
                ));
            }
            bytes[..graffiti.len()].copy_from_slice(graffiti.as_bytes());
            Ok(Self::UserSpecified(Graffiti::from(bytes)))
        } else if cli_args.is_present("private") {
            // When 'private' flag is present, use a zero-initialized bytes array.
            Ok(Self::UserSpecified(Graffiti::from(bytes)))
        } else {
            // Use the default lighthouse graffiti if no user-specified graffiti flags are present
            Ok(Self::default())
        }
    }

    pub fn graffiti(&self) -> Graffiti {
        match self {
            GraffitiOrigin::UserSpecified(graffiti) => *graffiti,
            GraffitiOrigin::Calculated(graffiti) => *graffiti,
        }
    }
}

impl Default for GraffitiOrigin {
    fn default() -> Self {
        let version_bytes = lighthouse_version::VERSION.as_bytes();
        let trimmed_len = std::cmp::min(version_bytes.len(), GRAFFITI_BYTES_LEN);
        let mut bytes = [0u8; GRAFFITI_BYTES_LEN];
        bytes[..trimmed_len].copy_from_slice(&version_bytes[..trimmed_len]);
        Self::Calculated(Graffiti::from(bytes))
    }
}

impl Debug for GraffitiOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.graffiti().fmt(f)
    }
}

pub struct GraffitiCalculator<T: BeaconChainTypes> {
    pub beacon_graffiti: GraffitiOrigin,
    execution_layer: Option<ExecutionLayer<T::EthSpec>>,
    pub epoch_duration: Duration,
    log: Logger,
}

impl<T: BeaconChainTypes> GraffitiCalculator<T> {
    pub fn new(
        beacon_graffiti: GraffitiOrigin,
        execution_layer: Option<ExecutionLayer<T::EthSpec>>,
        epoch_duration: Duration,
        log: Logger,
    ) -> Self {
        Self {
            beacon_graffiti,
            execution_layer,
            epoch_duration,
            log,
        }
    }

    /// Returns the appropriate graffiti to use for block production, prioritizing
    /// sources in the following order:
    /// 1. Graffiti specified by the validator client.
    /// 2. Graffiti specified by the user via beacon node CLI options.
    /// 3. The EL & CL client version string, applicable when the EL supports version specification.
    /// 4. The default lighthouse version string, used if the EL lacks version specification support.
    pub async fn get_graffiti(&self, validator_graffiti: Option<Graffiti>) -> Graffiti {
        if let Some(graffiti) = validator_graffiti {
            return graffiti;
        }

        match self.beacon_graffiti {
            GraffitiOrigin::UserSpecified(graffiti) => graffiti,
            GraffitiOrigin::Calculated(default_graffiti) => {
                let Some(execution_layer) = self.execution_layer.as_ref() else {
                    // Return default graffiti if there is no execution layer. This
                    // shouldn't occur if we're actually producing blocks.
                    crit!(self.log, "No execution layer available for graffiti calculation during block production!");
                    return default_graffiti;
                };

                // The engine version cache refresh service ensures this will almost always retrieve this data from the
                // cache instead of making a request to the execution engine. A cache miss would only occur if lighthouse
                // has recently started or the EL recently went offline.
                let engine_versions_response = execution_layer
                    .get_engine_version(Some(
                        self.epoch_duration * ENGINE_VERSION_AGE_LIMIT_EPOCH_MULTIPLE,
                    ))
                    .await;
                let engine_versions = match engine_versions_response {
                    Err(el_error) => {
                        if el_error.is_method_unsupported(ENGINE_CLIENT_VERSION_V1) {
                            debug!(
                                self.log,
                                "Using default lighthouse graffiti: EL does not support {} method",
                                ENGINE_CLIENT_VERSION_V1
                            );
                        } else {
                            warn!(self.log, "Failed to determine execution engine version for graffiti"; "error" => format!("{:?}", el_error));
                        }
                        return default_graffiti;
                    }
                    Ok(engine_versions) => engine_versions,
                };

                let Some(engine_version) = engine_versions.first() else {
                    // Some kind of error occurred, return default graffiti.
                    error!(
                        self.log,
                        "Got empty engine version response from execution layer"
                    );
                    return default_graffiti;
                };
                if engine_versions.len() != 1 {
                    // More than one version implies lighthouse is connected to
                    // an EL multiplexer. We don't support modifying the graffiti
                    // with these configurations.
                    warn!(self.log, "Multiplexer detected, using default graffiti");
                    return default_graffiti;
                }

                let lighthouse_commit_prefix = CommitPrefix::try_from(lighthouse_version::COMMIT_PREFIX.to_string())
                .unwrap_or_else(|error_message| {
                    // This really shouldn't happen but we want to definitly log if it does
                    crit!(self.log, "Failed to parse lighthouse commit prefix"; "error" => error_message);
                    CommitPrefix("00000000".to_string())
                });

                engine_version.calculate_graffiti(lighthouse_commit_prefix)
            }
        }
    }
}

pub fn start_engine_version_cache_refresh_service<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    executor: TaskExecutor,
) {
    let Some(el_ref) = chain.execution_layer.as_ref() else {
        debug!(
            chain.log,
            "No execution layer configured, not starting engine version cache refresh service"
        );
        return;
    };

    let execution_layer = el_ref.clone();
    let log = chain.log.clone();
    let slot_clock = chain.slot_clock.clone();
    let epoch_duration = chain.graffiti_calculator.epoch_duration;
    executor.spawn(
        async move {
            engine_version_cache_refresh_service::<T>(
                execution_layer,
                slot_clock,
                epoch_duration,
                log,
            )
            .await
        },
        "engine_version_cache_refresh_service",
    );
}

async fn engine_version_cache_refresh_service<T: BeaconChainTypes>(
    execution_layer: ExecutionLayer<T::EthSpec>,
    slot_clock: T::SlotClock,
    epoch_duration: Duration,
    log: Logger,
) {
    // Preload the engine version cache after a brief delay to allow for EL initialization.
    // This initial priming ensures cache readiness before the service's regular update cycle begins.
    tokio::time::sleep(ENGINE_VERSION_CACHE_PRELOAD_STARTUP_DELAY).await;
    if let Err(e) = execution_layer.get_engine_version(None).await {
        debug!(log, "Failed to preload engine version cache"; "error" => format!("{:?}", e));
    }

    // this service should run 3/8 of the way through the epoch
    let epoch_delay = (epoch_duration * 3) / 8;
    // the duration of 1 epoch less than the total duration between firing of this service
    let partial_firing_delay =
        epoch_duration * ENGINE_VERSION_CACHE_REFRESH_EPOCH_MULTIPLE.saturating_sub(1);
    loop {
        match slot_clock.duration_to_next_epoch(T::EthSpec::slots_per_epoch()) {
            Some(duration_to_next_epoch) => {
                let firing_delay = partial_firing_delay + duration_to_next_epoch + epoch_delay;
                tokio::time::sleep(firing_delay).await;

                debug!(
                    log,
                    "Engine version cache refresh service firing";
                );

                if let Err(el_error) = execution_layer.get_engine_version(None).await {
                    if el_error.is_method_unsupported(ENGINE_CLIENT_VERSION_V1) {
                        debug!(
                            log,
                            "EL does not support {} method. Sleeping twice as long before retry",
                            ENGINE_CLIENT_VERSION_V1
                        );
                        tokio::time::sleep(
                            epoch_duration * ENGINE_VERSION_CACHE_REFRESH_EPOCH_MULTIPLE,
                        )
                        .await;
                    } else {
                        debug!(log, "Failed to populate engine version cache"; "error" => format!("{:?}", el_error));
                    }
                }
            }
            None => {
                error!(log, "Failed to read slot clock");
                // If we can't read the slot clock, just wait another slot.
                tokio::time::sleep(slot_clock.slot_duration()).await;
            }
        };
    }
}

use crate::BeaconChain;
use crate::BeaconChainTypes;
use execution_layer::{http::ENGINE_GET_CLIENT_VERSION_V1, CommitPrefix, ExecutionLayer};
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
                let engine_versions = match execution_layer
                    .get_engine_version(Some(
                        self.epoch_duration * ENGINE_VERSION_AGE_LIMIT_EPOCH_MULTIPLE,
                    ))
                    .await
                {
                    Ok(engine_versions) => engine_versions,
                    Err(el_error) => {
                        warn!(self.log, "Failed to determine execution engine version for graffiti"; "error" => ?el_error);
                        return default_graffiti;
                    }
                };

                let Some(engine_version) = engine_versions.first() else {
                    // Got an empty array which indicates the EL doesn't support the method
                    debug!(
                        self.log,
                        "Using default lighthouse graffiti: EL does not support {} method",
                        ENGINE_GET_CLIENT_VERSION_V1;
                    );
                    return default_graffiti;
                };
                if engine_versions.len() != 1 {
                    // More than one version implies lighthouse is connected to
                    // an EL multiplexer. We don't support modifying the graffiti
                    // with these configurations.
                    warn!(
                        self.log,
                        "Execution Engine multiplexer detected, using default graffiti"
                    );
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
    if matches!(
        chain.graffiti_calculator.beacon_graffiti,
        GraffitiOrigin::UserSpecified(_)
    ) {
        debug!(
            chain.log,
            "Graffiti is user-specified, not starting engine version cache refresh service"
        );
        return;
    }

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

                match execution_layer.get_engine_version(None).await {
                    Err(e) => warn!(log, "Failed to populate engine version cache"; "error" => ?e),
                    Ok(versions) => {
                        if versions.is_empty() {
                            // Empty array indicates the EL doesn't support the method
                            debug!(
                                log,
                                "EL does not support {} method. Sleeping twice as long before retry",
                                ENGINE_GET_CLIENT_VERSION_V1
                            );
                            tokio::time::sleep(
                                epoch_duration * ENGINE_VERSION_CACHE_REFRESH_EPOCH_MULTIPLE,
                            )
                            .await;
                        }
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

#[cfg(test)]
mod tests {
    use crate::test_utils::{test_spec, BeaconChainHarness, EphemeralHarnessType};
    use crate::ChainConfig;
    use execution_layer::test_utils::{DEFAULT_CLIENT_VERSION, DEFAULT_ENGINE_CAPABILITIES};
    use execution_layer::EngineCapabilities;
    use lazy_static::lazy_static;
    use slog::info;
    use std::time::Duration;
    use types::{ChainSpec, Graffiti, Keypair, MinimalEthSpec, GRAFFITI_BYTES_LEN};

    const VALIDATOR_COUNT: usize = 48;
    lazy_static! {
        /// A cached set of keys.
        static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
    }

    fn get_harness(
        validator_count: usize,
        spec: ChainSpec,
        chain_config: Option<ChainConfig>,
    ) -> BeaconChainHarness<EphemeralHarnessType<MinimalEthSpec>> {
        let harness = BeaconChainHarness::builder(MinimalEthSpec)
            .spec(spec)
            .chain_config(chain_config.unwrap_or_default())
            .keypairs(KEYPAIRS[0..validator_count].to_vec())
            .logger(logging::test_logger())
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();

        harness.advance_slot();

        harness
    }

    #[tokio::test]
    async fn check_graffiti_without_el_version_support() {
        let spec = test_spec::<MinimalEthSpec>();
        let harness = get_harness(VALIDATOR_COUNT, spec, None);
        // modify execution engine so it doesn't support engine_getClientVersionV1 method
        let mock_execution_layer = harness.mock_execution_layer.as_ref().unwrap();
        mock_execution_layer
            .server
            .set_engine_capabilities(EngineCapabilities {
                get_client_version_v1: false,
                ..DEFAULT_ENGINE_CAPABILITIES
            });
        // refresh capabilities cache
        harness
            .chain
            .execution_layer
            .as_ref()
            .unwrap()
            .get_engine_capabilities(Some(Duration::ZERO))
            .await
            .unwrap();

        let version_bytes = std::cmp::min(
            lighthouse_version::VERSION.as_bytes().len(),
            GRAFFITI_BYTES_LEN,
        );
        // grab the slice of the graffiti that corresponds to the lighthouse version
        let graffiti_slice =
            &harness.chain.graffiti_calculator.get_graffiti(None).await.0[..version_bytes];

        // convert graffiti bytes slice to ascii for easy debugging if this test should fail
        let graffiti_str =
            std::str::from_utf8(graffiti_slice).expect("bytes should convert nicely to ascii");

        info!(harness.chain.log, "results"; "lighthouse_version" => lighthouse_version::VERSION, "graffiti_str" => graffiti_str);
        println!("lighthouse_version: '{}'", lighthouse_version::VERSION);
        println!("graffiti_str:       '{}'", graffiti_str);

        assert!(lighthouse_version::VERSION.starts_with(graffiti_str));
    }

    #[tokio::test]
    async fn check_graffiti_with_el_version_support() {
        let spec = test_spec::<MinimalEthSpec>();
        let harness = get_harness(VALIDATOR_COUNT, spec, None);

        let found_graffiti_bytes = harness.chain.graffiti_calculator.get_graffiti(None).await.0;

        let mock_commit = DEFAULT_CLIENT_VERSION.commit.clone();
        let expected_graffiti_string = format!(
            "{}{}{}{}",
            DEFAULT_CLIENT_VERSION.code,
            mock_commit
                .strip_prefix("0x")
                .unwrap_or(&mock_commit)
                .get(0..4)
                .expect("should get first 2 bytes in hex"),
            "LH",
            lighthouse_version::COMMIT_PREFIX
                .get(0..4)
                .expect("should get first 2 bytes in hex")
        );

        let expected_graffiti_prefix_bytes = expected_graffiti_string.as_bytes();
        let expected_graffiti_prefix_len =
            std::cmp::min(expected_graffiti_prefix_bytes.len(), GRAFFITI_BYTES_LEN);

        let found_graffiti_string =
            std::str::from_utf8(&found_graffiti_bytes[..expected_graffiti_prefix_len])
                .expect("bytes should convert nicely to ascii");

        info!(harness.chain.log, "results"; "expected_graffiti_string" => &expected_graffiti_string, "found_graffiti_string" => &found_graffiti_string);
        println!("expected_graffiti_string: '{}'", expected_graffiti_string);
        println!("found_graffiti_string:    '{}'", found_graffiti_string);

        assert_eq!(expected_graffiti_string, found_graffiti_string);

        let mut expected_graffiti_bytes = [0u8; GRAFFITI_BYTES_LEN];
        expected_graffiti_bytes[..expected_graffiti_prefix_len]
            .copy_from_slice(expected_graffiti_string.as_bytes());
        assert_eq!(found_graffiti_bytes, expected_graffiti_bytes);
    }

    #[tokio::test]
    async fn check_graffiti_with_validator_specified_value() {
        let spec = test_spec::<MinimalEthSpec>();
        let harness = get_harness(VALIDATOR_COUNT, spec, None);

        let graffiti_str = "nice graffiti bro";
        let mut graffiti_bytes = [0u8; GRAFFITI_BYTES_LEN];
        graffiti_bytes[..graffiti_str.as_bytes().len()].copy_from_slice(graffiti_str.as_bytes());

        let found_graffiti = harness
            .chain
            .graffiti_calculator
            .get_graffiti(Some(Graffiti::from(graffiti_bytes)))
            .await;

        assert_eq!(
            found_graffiti.to_string(),
            "0x6e6963652067726166666974692062726f000000000000000000000000000000"
        );
    }
}

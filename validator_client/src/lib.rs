mod attestation_service;
mod block_service;
mod cli;
mod config;
mod duties_service;
mod fork_service;
mod is_synced;
mod notifier;
mod validator_store;

pub use cli::cli_app;
pub use config::Config;

use attestation_service::{AttestationService, AttestationServiceBuilder};
use block_service::{BlockService, BlockServiceBuilder};
use clap::ArgMatches;
use config::SLASHING_PROTECTION_FILENAME;
use duties_service::{DutiesService, DutiesServiceBuilder};
use environment::RuntimeContext;
use fork_service::{ForkService, ForkServiceBuilder};
use notifier::spawn_notifier;
use remote_beacon_node::RemoteBeaconNode;
use slog::{error, info, warn, Logger};
use slot_clock::SlotClock;
use slot_clock::SystemTimeSlotClock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{delay_for, Duration};
use types::EthSpec;
use validator_dir::Manager as ValidatorManager;
use validator_store::ValidatorStore;

/// The interval between attempts to contact the beacon node during startup.
const RETRY_DELAY: Duration = Duration::from_secs(2);

/// The global timeout for HTTP requests to the beacon node.
const HTTP_TIMEOUT: Duration = Duration::from_secs(12);

pub struct ProductionValidatorClient<T: EthSpec> {
    context: RuntimeContext<T>,
    duties_service: DutiesService<SystemTimeSlotClock, T>,
    fork_service: ForkService<SystemTimeSlotClock, T>,
    block_service: BlockService<SystemTimeSlotClock, T>,
    attestation_service: AttestationService<SystemTimeSlotClock, T>,
    config: Config,
}

impl<T: EthSpec> ProductionValidatorClient<T> {
    /// Instantiates the validator client, _without_ starting the timers to trigger block
    /// and attestation production.
    pub async fn new_from_cli(
        context: RuntimeContext<T>,
        cli_args: &ArgMatches<'_>,
    ) -> Result<Self, String> {
        let config = Config::from_cli(&cli_args)
            .map_err(|e| format!("Unable to initialize config: {}", e))?;
        Self::new(context, config).await
    }

    /// Instantiates the validator client, _without_ starting the timers to trigger block
    /// and attestation production.
    pub async fn new(mut context: RuntimeContext<T>, config: Config) -> Result<Self, String> {
        let log = context.log().clone();

        info!(
            log,
            "Starting validator client";
            "beacon_node" => &config.http_server,
            "datadir" => format!("{:?}", config.data_dir),
        );

        if !config.data_dir.join(SLASHING_PROTECTION_FILENAME).exists() && !config.auto_register {
            warn!(
                log,
                "Will not register any validators";
                "msg" => "strongly consider using --auto-register on the first use",
            );
        }

        let validators = ValidatorManager::open(&config.data_dir)
            .map_err(|e| format!("unable to read data_dir: {:?}", e))?
            .decrypt_all_validators(config.secrets_dir.clone(), Some(&log))
            .map_err(|e| format!("unable to decrypt all validator directories: {:?}", e))?;

        info!(
            log,
            "Decrypted validator keystores";
            "count" => validators.len(),
        );

        let beacon_node =
            RemoteBeaconNode::new_with_timeout(config.http_server.clone(), HTTP_TIMEOUT)
                .map_err(|e| format!("Unable to init beacon node http client: {}", e))?;

        // TODO: check if all logs in wait_for_node are produed while awaiting
        let beacon_node = wait_for_node(beacon_node, &log).await?;
        let eth2_config = beacon_node
            .http
            .spec()
            .get_eth2_config()
            .await
            .map_err(|e| format!("Unable to read eth2 config from beacon node: {:?}", e))?;
        let genesis_time = beacon_node
            .http
            .beacon()
            .get_genesis_time()
            .await
            .map_err(|e| format!("Unable to read genesis time from beacon node: {:?}", e))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Unable to read system time: {:?}", e))?;
        let genesis = Duration::from_secs(genesis_time);

        // If the time now is less than (prior to) genesis, then delay until the
        // genesis instant.
        //
        // If the validator client starts before genesis, it will get errors from
        // the slot clock.
        if now < genesis {
            info!(
                log,
                "Starting node prior to genesis";
                "seconds_to_wait" => (genesis - now).as_secs()
            );

            delay_for(genesis - now).await
        } else {
            info!(
                log,
                "Genesis has already occurred";
                "seconds_ago" => (now - genesis).as_secs()
            );
        }
        let genesis_validators_root = beacon_node
            .http
            .beacon()
            .get_genesis_validators_root()
            .await
            .map_err(|e| {
                format!(
                    "Unable to read genesis validators root from beacon node: {:?}",
                    e
                )
            })?;

        // Do not permit a connection to a beacon node using different spec constants.
        if context.eth2_config.spec_constants != eth2_config.spec_constants {
            return Err(format!(
                "Beacon node is using an incompatible spec. Got {}, expected {}",
                eth2_config.spec_constants, context.eth2_config.spec_constants
            ));
        }

        // Note: here we just assume the spec variables of the remote node. This is very useful
        // for testnets, but perhaps a security issue when it comes to mainnet.
        //
        // A damaging attack would be for a beacon node to convince the validator client of a
        // different `SLOTS_PER_EPOCH` variable. This could result in slashable messages being
        // produced. We are safe from this because `SLOTS_PER_EPOCH` is a type-level constant
        // for Lighthouse.
        context.eth2_config = eth2_config;

        let slot_clock = SystemTimeSlotClock::new(
            context.eth2_config.spec.genesis_slot,
            Duration::from_secs(genesis_time),
            Duration::from_millis(context.eth2_config.spec.milliseconds_per_slot),
        );

        let fork_service = ForkServiceBuilder::new()
            .slot_clock(slot_clock.clone())
            .beacon_node(beacon_node.clone())
            .runtime_context(context.service_context("fork".into()))
            .build()?;

        let validator_store: ValidatorStore<SystemTimeSlotClock, T> = ValidatorStore::new(
            validators,
            &config,
            genesis_validators_root,
            context.eth2_config.spec.clone(),
            fork_service.clone(),
            log.clone(),
        )?;

        info!(
            log,
            "Loaded validator keypair store";
            "voting_validators" => validator_store.num_voting_validators()
        );

        if config.auto_register {
            info!(log, "Registering all validators for slashing protection");
            validator_store.register_all_validators_for_slashing_protection()?;
            info!(log, "Validator auto-registration complete");
        }

        let duties_service = DutiesServiceBuilder::new()
            .slot_clock(slot_clock.clone())
            .validator_store(validator_store.clone())
            .beacon_node(beacon_node.clone())
            .runtime_context(context.service_context("duties".into()))
            .allow_unsynced_beacon_node(config.allow_unsynced_beacon_node)
            .build()?;

        let block_service = BlockServiceBuilder::new()
            .duties_service(duties_service.clone())
            .slot_clock(slot_clock.clone())
            .validator_store(validator_store.clone())
            .beacon_node(beacon_node.clone())
            .runtime_context(context.service_context("block".into()))
            .build()?;

        let attestation_service = AttestationServiceBuilder::new()
            .duties_service(duties_service.clone())
            .slot_clock(slot_clock)
            .validator_store(validator_store)
            .beacon_node(beacon_node)
            .runtime_context(context.service_context("attestation".into()))
            .build()?;

        Ok(Self {
            context,
            duties_service,
            fork_service,
            block_service,
            attestation_service,
            config,
        })
    }

    pub fn start_service(&mut self) -> Result<(), String> {
        self.duties_service
            .clone()
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start duties service: {}", e))?;

        self.fork_service
            .clone()
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start fork service: {}", e))?;

        self.block_service
            .clone()
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start block service: {}", e))?;

        self.attestation_service
            .clone()
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start attestation service: {}", e))?;

        spawn_notifier(self).map_err(|e| format!("Failed to start notifier: {}", e))?;

        Ok(())
    }
}

/// Request the version from the node, looping back and trying again on failure. Exit once the node
/// has been contacted.
async fn wait_for_node<E: EthSpec>(
    beacon_node: RemoteBeaconNode<E>,
    log: &Logger,
) -> Result<RemoteBeaconNode<E>, String> {
    // Try to get the version string from the node, looping until success is returned.
    loop {
        let log = log.clone();
        let result = beacon_node
            .clone()
            .http
            .node()
            .get_version()
            .await
            .map_err(|e| format!("{:?}", e));

        match result {
            Ok(version) => {
                info!(
                    log,
                    "Connected to beacon node";
                    "version" => version,
                );

                return Ok(beacon_node);
            }
            Err(e) => {
                error!(
                    log,
                    "Unable to connect to beacon node";
                    "error" => format!("{:?}", e),
                );
                delay_for(RETRY_DELAY).await;
            }
        }
    }
}

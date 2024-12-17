use crate::{common::vc_http_client, DumpConfig};

use clap::{Arg, ArgAction, ArgMatches, Command};
use clap_utils::FLAG_HEADER;
use eth2::types::{ConfigAndPreset, Epoch, StateId, ValidatorId, ValidatorStatus};
use eth2::{BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use serde::{Deserialize, Serialize};
use serde_json;
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::path::PathBuf;
use std::time::Duration;
// use tokio::time::sleep;
use types::{ChainSpec, EthSpec, PublicKeyBytes};
// use validator_http_api::create_signed_voluntary_exit::get_current_epoch;

pub const CMD: &str = "exit";
pub const BEACON_URL_FLAG: &str = "beacon-node";
pub const VC_URL_FLAG: &str = "vc-url";
pub const VC_TOKEN_FLAG: &str = "vc-token";
pub const VALIDATOR_FLAG: &str = "validators";
pub const EXIT_EPOCH_FLAG: &str = "exit-epoch";
pub const SIGNATURE_FLAG: &str = "signature";

pub fn cli_app() -> Command {
    Command::new(CMD)
        .about("Exit validator using the HTTP API for a given validator keystore.")
        .arg(
            Arg::new(BEACON_URL_FLAG)
                .long(BEACON_URL_FLAG)
                .value_name("NETWORK_ADDRESS")
                .help("Address to a beacon node HTTP API")
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new(VC_URL_FLAG)
                .long(VC_URL_FLAG)
                .value_name("HTTP_ADDRESS")
                .help("A HTTP(S) address of a validator client using the keymanager-API.")
                .default_value("http://localhost:5062")
                .requires(VC_TOKEN_FLAG)
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new(VC_TOKEN_FLAG)
                .long(VC_TOKEN_FLAG)
                .value_name("PATH")
                .help("The file containing a token required by the validator client.")
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new(VALIDATOR_FLAG)
                .long(VALIDATOR_FLAG)
                .value_name("STRING")
                .help("List of validators (pubkey) to exit.")
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new(EXIT_EPOCH_FLAG)
                .long(EXIT_EPOCH_FLAG)
                .value_name("EPOCH")
                .help("Provide the minimum epoch for processing voluntary exit.")
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new(SIGNATURE_FLAG)
                .long(SIGNATURE_FLAG)
                .help("Display the signature of the voluntary exit.")
                .help_heading(FLAG_HEADER)
                .action(ArgAction::SetTrue)
                .display_order(0),
        )
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ExitConfig {
    pub vc_url: SensitiveUrl,
    pub vc_token_path: PathBuf,
    pub validators_to_exit: Vec<PublicKeyBytes>,
    pub beacon_url: Option<SensitiveUrl>,
    pub exit_epoch: Option<Epoch>,
    pub signature: bool,
}

impl ExitConfig {
    fn from_cli(matches: &ArgMatches) -> Result<Self, String> {
        let validators_to_exit_str = clap_utils::parse_required::<String>(matches, VALIDATOR_FLAG)?;

        let validators_to_exit = if validators_to_exit_str.trim() == "all" {
            Vec::new()
        } else {
            validators_to_exit_str
                .split(',')
                .map(|s| s.trim().parse())
                .collect::<Result<Vec<PublicKeyBytes>, _>>()?
        };

        Ok(Self {
            vc_url: clap_utils::parse_required(matches, VC_URL_FLAG)?,
            vc_token_path: clap_utils::parse_required(matches, VC_TOKEN_FLAG)?,
            validators_to_exit,
            beacon_url: clap_utils::parse_optional(matches, BEACON_URL_FLAG)?,
            exit_epoch: clap_utils::parse_optional(matches, EXIT_EPOCH_FLAG)?,
            signature: matches.get_flag(SIGNATURE_FLAG),
        })
    }
}

pub async fn cli_run<E: EthSpec>(
    matches: &ArgMatches,
    dump_config: DumpConfig,
) -> Result<(), String> {
    let config = ExitConfig::from_cli(matches)?;

    if dump_config.should_exit_early(&config)? {
        Ok(())
    } else {
        run::<E>(config).await
    }
}

async fn run<E: EthSpec>(config: ExitConfig) -> Result<(), String> {
    let ExitConfig {
        vc_url,
        vc_token_path,
        mut validators_to_exit,
        beacon_url,
        exit_epoch,
        signature,
    } = config;

    let (http_client, validators) = vc_http_client(vc_url.clone(), &vc_token_path).await?;

    // Exit all validators on the VC
    if validators_to_exit.is_empty() {
        validators_to_exit = validators.iter().map(|v| v.validating_pubkey).collect();
    }

    // Check that the validators_to_exit is in the validator client
    for validator_to_exit in &validators_to_exit {
        if !validators
            .iter()
            .any(|validator| &validator.validating_pubkey == validator_to_exit)
        {
            return Err(format!("Validator {} doesn't exist", validator_to_exit));
        }
    }

    for validator_to_exit in validators_to_exit {
        let exit_message = http_client
            .post_validator_voluntary_exit(&validator_to_exit, exit_epoch)
            .await
            .map_err(|e| format!("Failed to generate voluntary exit message: {}", e))?;

        if signature {
            let exit_message_json = serde_json::to_string(&exit_message.data);
            match exit_message_json {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("Failed to serialize voluntary exit message: {}", e),
            }
        }

        // only publish the voluntary exit if the --beacon-node flag is present
        if beacon_url.is_some() {
            let beacon_node = if let Some(ref beacon_url) = beacon_url {
                BeaconNodeHttpClient::new(
                    SensitiveUrl::parse(beacon_url.as_ref())
                        .map_err(|e| format!("Failed to parse beacon http server: {:?}", e))?,
                    Timeouts::set_all(Duration::from_secs(12)),
                )
            } else {
                return Err("Beacon URL is not provided".into());
            };

            if beacon_node
                .get_node_syncing()
                .await
                .map_err(|e| format!("Failed to get beacon node sync status: {:?}", e))?
                .data
                .is_syncing
            {
                return Err(
                    "Beacon node is syncing, submit the voluntary exit later when beacon node is synced"
                        .to_string(),
                );
            }

            // Get beacon node spec to be used later
            let genesis_data = beacon_node
                .get_beacon_genesis()
                .await
                .map_err(|e| format!("Failed to get genesis data: {}", e))?
                .data;

            let config_and_preset = beacon_node
                .get_config_spec::<ConfigAndPreset>()
                .await
                .map_err(|e| format!("Failed to get config spec: {}", e))?
                .data;

            let spec = ChainSpec::from_config::<E>(config_and_preset.config())
                .ok_or_else(|| "Failed to create chain spec".to_string())?;

            let validator_data = beacon_node
            .get_beacon_states_validator_id(
                StateId::Head,
                &ValidatorId::PublicKey(validator_to_exit),
            )
            .await
            .map_err(|e| format!("Failed to get validator details: {:?}", e))?
            .ok_or_else(|| {
                format!(
                    "Validator {} is not present in the beacon state. \
                    Please ensure that your beacon node is synced and the validator has been deposited.",
                    validator_to_exit)})?
            .data;

            let activation_epoch = validator_data.validator.activation_epoch;
            let current_epoch = get_current_epoch::<E>(genesis_data.genesis_time, &spec)
                .ok_or("Failed to get current epoch. Please check your system time")?;

            // Check if validator is eligible for exit
            if validator_data.status == ValidatorStatus::ActiveOngoing
                && current_epoch < activation_epoch + spec.shard_committee_period
            {
                eprintln!(
                    "Validator {} is not eligible for exit. It will become eligible at epoch {}",
                    validator_to_exit,
                    activation_epoch + spec.shard_committee_period
                )
            } else if validator_data.status != ValidatorStatus::ActiveOngoing {
                eprintln!(
                    "Validator {} is not eligible for exit. Validator status is: {:?}",
                    validator_to_exit, validator_data.status
                )
            } else {
                // Only publish voluntary exit if validator is ActiveOngoing
                beacon_node
                    .post_beacon_pool_voluntary_exits(&exit_message.data)
                    .await
                    .map_err(|e| format!("Failed to publish voluntary exit: {}", e))?;
                // tokio::time::sleep(std::time::Duration::from_secs(1)).await; // Provides nicer UX.
                eprintln!(
                    "Successfully validated and published voluntary exit for validator {}",
                    validator_to_exit
                );

                // sleep(Duration::from_secs(spec.seconds_per_slot)).await;

                // Check validator status after publishing voluntary exit
                match validator_data.status {
                    ValidatorStatus::ActiveExiting => {
                        let exit_epoch = validator_data.validator.exit_epoch;
                        let withdrawal_epoch = validator_data.validator.withdrawable_epoch;

                        // let slot_clock = SystemTimeSlotClock::new(
                        //     spec.genesis_slot,
                        //     Duration::from_secs(genesis_data.genesis_time),
                        //     Duration::from_secs(spec.config().seconds_per_slot),
                        // );

                        // let current_epoch = get_current_epoch::<SystemTimeSlotClock, E>(slot_clock)
                        //     .ok_or_else(|| "Unable to determine current epoch".to_string())?;

                        eprintln!("Voluntary exit has been accepted into the beacon chain, but not yet finalized. \
                        Finalization may take several minutes or longer. Before finalization there is a low \
                        probability that the exit may be reverted.");
                        eprintln!(
                            "Current epoch: {}, Exit epoch: {}, Withdrawable epoch: {}",
                            current_epoch, exit_epoch, withdrawal_epoch
                        );
                        eprintln!("Please keep your validator running till exit epoch");
                        eprintln!(
                            "Exit epoch in approximately {} secs",
                            (exit_epoch - current_epoch)
                                * spec.seconds_per_slot
                                * E::slots_per_epoch()
                        );
                    }

                    _ => {
                        eprintln!(
                            "Waiting for voluntary exit to be accepted into the beacon chain..."
                        )
                    } // fn get_current_epoch<T: 'static + SlotClock + Clone, E: EthSpec>(
                      //     slot_clock: T,
                      // ) -> Option<Epoch> {
                      //     slot_clock.now().map(|s| s.epoch(E::slots_per_epoch()))
                      // }

                      // let spec = ChainSpec::mainnet();

                      // let current_epoch =
                      //     get_current_epoch::<E>(genesis_time, &spec).ok_or("Failed to get current epoch")?;
                      //let current_epoch = get_current_epoch::<E>(genesis_data.genesis_time, spec);
                }
            }
        }
    }
    Ok(())
}

fn get_current_epoch<E: EthSpec>(genesis_time: u64, spec: &ChainSpec) -> Option<Epoch> {
    let slot_clock = SystemTimeSlotClock::new(
        spec.genesis_slot,
        Duration::from_secs(genesis_time),
        Duration::from_secs(spec.seconds_per_slot),
    );
    slot_clock.now().map(|s| s.epoch(E::slots_per_epoch()))
}
#[cfg(not(debug_assertions))]
#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        common::ValidatorSpecification, import_validators::tests::TestBuilder as ImportTestBuilder,
    };
    use account_utils::eth2_keystore::KeystoreBuilder;
    use account_utils::ZeroizeString;
    use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
    use eth2::lighthouse_vc::types::KeystoreJsonStr;
    use http_api::test_utils::InteractiveTester;
    use std::{
        fs::{self, File},
        io::Write,
        str::FromStr,
        sync::Arc,
    };
    use types::{ChainSpec, MainnetEthSpec};
    use validator_http_api::{test_utils::ApiTester, Config as HttpConfig};
    type E = MainnetEthSpec;

    struct TestBuilder {
        exit_config: Option<ExitConfig>,
        src_import_builder: Option<ImportTestBuilder>,
        http_config: HttpConfig,
        vc_token: Option<String>,
        validators: Vec<ValidatorSpecification>,
        beacon_node: InteractiveTester<E>,
        index_of_validators_to_exit: usize,
        spec: Arc<ChainSpec>,
    }

    impl TestBuilder {
        async fn new() -> Self {
            let mut spec = ChainSpec::mainnet();
            spec.shard_committee_period = 1;
            spec.altair_fork_epoch = Some(Epoch::new(0));
            spec.bellatrix_fork_epoch = Some(Epoch::new(1));
            spec.capella_fork_epoch = Some(Epoch::new(2));
            spec.deneb_fork_epoch = Some(Epoch::new(3));

            let beacon_node = InteractiveTester::new(Some(spec.clone()), 64).await;

            let harness = &beacon_node.harness;
            let mock_el = harness.mock_execution_layer.as_ref().unwrap();
            let execution_ctx = mock_el.server.ctx.clone();

            // Move to terminal block.
            mock_el.server.all_payloads_valid();
            execution_ctx
                .execution_block_generator
                .write()
                .move_to_terminal_block()
                .unwrap();

            println!("Beacon node spec: {:?}", beacon_node.harness.chain.spec);

            Self {
                exit_config: None,
                src_import_builder: None,
                http_config: ApiTester::default_http_config(),
                vc_token: None,
                validators: vec![],
                beacon_node,
                index_of_validators_to_exit: 0,
                spec: spec.into(),
            }
        }

        async fn with_validators(mut self, index_of_validators_to_exit: usize) -> Self {
            // Ensure genesis validators root matches the beacon node.
            let genesis_validators_root = self
                .beacon_node
                .harness
                .get_current_state()
                .genesis_validators_root();
            // And use a single slot clock for BN and VC to keep things simple.
            let slot_clock = self.beacon_node.harness.chain.slot_clock.clone();
            let vc = ApiTester::new_with_options(
                self.http_config.clone(),
                slot_clock,
                genesis_validators_root,
                self.spec.clone(),
            )
            .await;
            let mut builder = ImportTestBuilder::new_with_vc(vc).await;

            println!("Validator client spec: {:?}", builder.vc.spec);

            self.vc_token =
                Some(fs::read_to_string(builder.get_import_config().vc_token_path).unwrap());

            let keystore = KeystoreBuilder::new(
                &self.beacon_node.harness.validator_keypairs[index_of_validators_to_exit],
                "password".as_bytes(),
                "".into(),
            )
            .unwrap()
            .build()
            .unwrap();

            let local_validators: Vec<ValidatorSpecification> = vec![ValidatorSpecification {
                voting_keystore: KeystoreJsonStr(keystore),
                voting_keystore_password: ZeroizeString::from_str("password").unwrap(),
                slashing_protection: None,
                fee_recipient: None,
                gas_limit: None,
                builder_proposals: None,
                builder_boost_factor: None,
                prefer_builder_proposals: None,
                enabled: Some(true),
            }];

            let beacon_url = SensitiveUrl::parse(self.beacon_node.client.as_ref()).unwrap();

            println!(
                "Validator pubkey on beacon chain = {:?}",
                self.beacon_node.harness.validator_keypairs[index_of_validators_to_exit].pk
            );

            let validators_to_exit = self.beacon_node.harness.validator_keypairs
                [index_of_validators_to_exit]
                .pk
                .clone()
                .into();

            let import_config = builder.get_import_config();

            let validators_dir = import_config.vc_token_path.parent().unwrap();
            let validators_file = validators_dir.join("validators.json");

            builder = builder.mutate_import_config(|config| {
                config.validators_file_path = Some(validators_file.clone());
            });

            fs::write(
                &validators_file,
                serde_json::to_string(&local_validators).unwrap(),
            )
            .unwrap();

            //println!("{:?}", builder.get_import_config());

            self.exit_config = Some(ExitConfig {
                vc_url: import_config.vc_url,
                vc_token_path: import_config.vc_token_path,
                validators_to_exit,
                beacon_url: Some(beacon_url),
                exit_epoch: None,
            });

            self.validators = local_validators.clone();
            self.src_import_builder = Some(builder);
            self.index_of_validators_to_exit = index_of_validators_to_exit;
            self
        }

        pub async fn run_test(self) -> TestResult {
            let import_builder = self.src_import_builder.unwrap();
            let initialized_validators = import_builder.vc.initialized_validators.clone();
            let import_test_result = import_builder.run_test().await;
            assert!(import_test_result.result.is_ok());

            // only assign the validator index after validator is imported to the VC
            initialized_validators.write().set_index(
                &self.beacon_node.harness.validator_keypairs[self.index_of_validators_to_exit]
                    .pk
                    .compress(),
                self.index_of_validators_to_exit as u64,
            );

            let path = self.exit_config.clone().unwrap().vc_token_path;
            let url = self.exit_config.clone().unwrap().vc_url;
            let parent = path.parent().unwrap();

            fs::create_dir_all(parent).expect("Was not able to create parent directory");

            File::options()
                .write(true)
                .read(true)
                .create(true)
                .truncate(true)
                .open(path.clone())
                .unwrap()
                .write_all(self.vc_token.clone().unwrap().as_bytes())
                .unwrap();

            let (_, validators) = vc_http_client(url, path).await.unwrap();
            println!("Validators pubkey on VC = {:?}", validators);

            // Advance beacon chain
            self.beacon_node.harness.advance_slot();

            println!(
                "current slot_first_advance_slot: {:?}",
                self.beacon_node.harness.get_current_slot()
            );

            self.beacon_node
                .harness
                .extend_chain(
                    100,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;

            println!(
                "current slot_extend_chain: {:?}",
                self.beacon_node.harness.get_current_slot()
            );

            self.beacon_node.harness.advance_slot();

            println!(
                "current slot_second_advance_slot: {:?}",
                self.beacon_node.harness.get_current_slot()
            );

            let validator_to_exit = self.exit_config.as_ref().unwrap().validators_to_exit;
            println!("Attempting to exit validator {:?}", validator_to_exit);

            let mut current_state = self.beacon_node.harness.get_current_state();
            let validator_index = current_state
                .get_validator_index(&validator_to_exit)
                .expect("should find validator");
            let validator = &current_state
                .validators()
                .get(validator_index.unwrap())
                .expect("validator should exist");

            println!(
                "validator status: activation_epoch={},exit_epoch{}",
                validator.activation_epoch, validator.exit_epoch
            );

            let result = run(self.exit_config.clone().unwrap()).await;

            if result.is_ok() {
                return TestResult { result: Ok(()) };
            }

            TestResult {
                result: Err(result.unwrap_err()),
            }
        }
    }

    #[must_use]
    struct TestResult {
        result: Result<(), String>,
    }

    impl TestResult {
        fn assert_ok(self) {
            assert_eq!(self.result, Ok(()))
        }
    }
    #[tokio::test]
    async fn exit_single_validator() {
        TestBuilder::new()
            .await
            .with_validators(0)
            .await
            .run_test()
            .await
            .assert_ok();
    }
}

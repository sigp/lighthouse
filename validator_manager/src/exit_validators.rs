use crate::{DumpConfig, common::vc_http_client};

use clap::{Arg, ArgAction, ArgMatches, Command};
use clap_utils::FLAG_HEADER;
use eth2::types::{ConfigAndPreset, Epoch, StateId, ValidatorId, ValidatorStatus};
use eth2::{BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use serde::{Deserialize, Serialize};
use serde_json;
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::fs::write;
use std::path::PathBuf;
use std::time::Duration;
use types::{ChainSpec, EthSpec, PublicKeyBytes};

pub const CMD: &str = "exit";
pub const BEACON_URL_FLAG: &str = "beacon-node";
pub const VC_URL_FLAG: &str = "vc-url";
pub const VC_TOKEN_FLAG: &str = "vc-token";
pub const VALIDATOR_FLAG: &str = "validators";
pub const EXIT_EPOCH_FLAG: &str = "exit-epoch";
pub const PRESIGN_FLAG: &str = "presign";

pub fn cli_app() -> Command {
    Command::new(CMD)
        .about(
            "Exits one or more validators using the HTTP API. It can \
        also be used to generate a presigned voluntary exit message for a particular future epoch.",
        )
        .arg(
            Arg::new(BEACON_URL_FLAG)
                .long(BEACON_URL_FLAG)
                .value_name("NETWORK_ADDRESS")
                .help("Address to a beacon node HTTP API")
                .action(ArgAction::Set)
                .display_order(0)
                .conflicts_with(PRESIGN_FLAG),
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
                .help(
                    "Comma-separated list of validators (pubkey) to exit. \
                 To exit all validators, use the keyword \"all\".",
                )
                .action(ArgAction::Set)
                .required(true)
                .display_order(0),
        )
        .arg(
            Arg::new(EXIT_EPOCH_FLAG)
                .long(EXIT_EPOCH_FLAG)
                .value_name("EPOCH")
                .help(
                    "Provide the minimum epoch for processing voluntary exit. \
                This flag is required to be used in combination with `--presign` to \
                save the voluntary exit presign to a file for future use.",
                )
                .action(ArgAction::Set)
                .display_order(0)
                .requires(PRESIGN_FLAG)
                .conflicts_with(BEACON_URL_FLAG),
        )
        .arg(
            Arg::new(PRESIGN_FLAG)
                .long(PRESIGN_FLAG)
                .help(
                    "Generate the voluntary exit presign and save it to a file \
                named {validator_pubkey}.json. Note: Using this without the \
                `--beacon-node` flag will not publish the voluntary exit to the network.",
                )
                .help_heading(FLAG_HEADER)
                .action(ArgAction::SetTrue)
                .display_order(0)
                .conflicts_with(BEACON_URL_FLAG),
        )
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ExitConfig {
    pub vc_url: SensitiveUrl,
    pub vc_token_path: PathBuf,
    pub validators_to_exit: Vec<PublicKeyBytes>,
    pub beacon_url: Option<SensitiveUrl>,
    pub exit_epoch: Option<Epoch>,
    pub presign: bool,
}

impl ExitConfig {
    fn from_cli(matches: &ArgMatches) -> Result<Self, String> {
        let validators_to_exit_str = clap_utils::parse_required::<String>(matches, VALIDATOR_FLAG)?;

        // Keyword "all" to exit all validators, vector to be created later
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
            presign: matches.get_flag(PRESIGN_FLAG),
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
        presign,
    } = config;

    let (http_client, validators) = vc_http_client(vc_url.clone(), &vc_token_path).await?;

    if validators_to_exit.is_empty() {
        validators_to_exit = validators.iter().map(|v| v.validating_pubkey).collect();
    }

    for validator_to_exit in validators_to_exit {
        // Check that the validators_to_exit is in the validator client
        if !validators
            .iter()
            .any(|validator| validator.validating_pubkey == validator_to_exit)
        {
            return Err(format!("Validator {} doesn't exist", validator_to_exit));
        }

        let exit_message = http_client
            .post_validator_voluntary_exit(&validator_to_exit, exit_epoch)
            .await
            .map_err(|e| format!("Failed to generate voluntary exit message: {}", e))?;

        if presign {
            let exit_message_json = serde_json::to_string(&exit_message.data);

            match exit_message_json {
                Ok(json) => {
                    // Save the exit message to JSON file(s)
                    let file_path = format!("{}.json", validator_to_exit);
                    write(&file_path, json).map_err(|e| {
                        format!("Failed to write voluntary exit message to file: {}", e)
                    })?;
                    println!("Voluntary exit message saved to {}", file_path);
                }
                Err(e) => eprintln!("Failed to serialize voluntary exit message: {}", e),
            }
        }

        // Only publish the voluntary exit if the --beacon-node flag is present
        if let Some(ref beacon_url) = beacon_url {
            let beacon_node = BeaconNodeHttpClient::new(
                SensitiveUrl::parse(beacon_url.as_ref())
                    .map_err(|e| format!("Failed to parse beacon http server: {:?}", e))?,
                Timeouts::set_all(Duration::from_secs(12)),
            );

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
                .ok_or("Failed to create chain spec")?;

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
                        Please ensure that your beacon node is synced \
                        and the validator has been deposited.",
                        validator_to_exit
                    )
                })?
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
                // Only publish voluntary exit if validator status is ActiveOngoing
                beacon_node
                    .post_beacon_pool_voluntary_exits(&exit_message.data)
                    .await
                    .map_err(|e| format!("Failed to publish voluntary exit: {}", e))?;
                eprintln!(
                    "Successfully validated and published voluntary exit for validator {}",
                    validator_to_exit
                );
            }
        }
    }

    Ok(())
}

pub fn get_current_epoch<E: EthSpec>(genesis_time: u64, spec: &ChainSpec) -> Option<Epoch> {
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
    use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
    use eth2::lighthouse_vc::types::KeystoreJsonStr;
    use http_api::test_utils::InteractiveTester;
    use std::{
        fs::{self, File},
        io::Write,
        sync::Arc,
    };
    use types::{ChainSpec, MainnetEthSpec};
    use validator_http_api::{Config as HttpConfig, test_utils::ApiTester};
    use zeroize::Zeroizing;
    type E = MainnetEthSpec;

    struct TestBuilder {
        exit_config: Option<ExitConfig>,
        src_import_builder: Option<ImportTestBuilder>,
        http_config: HttpConfig,
        vc_token: Option<String>,
        validators: Vec<ValidatorSpecification>,
        beacon_node: InteractiveTester<E>,
        index_of_validators_to_exit: Vec<usize>,
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

            Self {
                exit_config: None,
                src_import_builder: None,
                http_config: ApiTester::default_http_config(),
                vc_token: None,
                validators: vec![],
                beacon_node,
                index_of_validators_to_exit: vec![],
                spec: spec.into(),
            }
        }

        async fn with_validators(mut self, index_of_validators_to_exit: Vec<usize>) -> Self {
            // Ensure genesis validators root matches the beacon node.
            let genesis_validators_root = self
                .beacon_node
                .harness
                .get_current_state()
                .genesis_validators_root();
            // And use a single slot clock and same spec for BN and VC to keep things simple.
            let slot_clock = self.beacon_node.harness.chain.slot_clock.clone();
            let vc = ApiTester::new_with_options(
                self.http_config.clone(),
                slot_clock,
                genesis_validators_root,
                self.spec.clone(),
            )
            .await;
            let mut builder = ImportTestBuilder::new_with_vc(vc).await;

            self.vc_token =
                Some(fs::read_to_string(builder.get_import_config().vc_token_path).unwrap());

            let local_validators: Vec<ValidatorSpecification> = index_of_validators_to_exit
                .iter()
                .map(|&index| {
                    let keystore = KeystoreBuilder::new(
                        &self.beacon_node.harness.validator_keypairs[index],
                        "password".as_bytes(),
                        "".into(),
                    )
                    .unwrap()
                    .build()
                    .unwrap();

                    ValidatorSpecification {
                        voting_keystore: KeystoreJsonStr(keystore),
                        voting_keystore_password: Zeroizing::new("password".into()),
                        slashing_protection: None,
                        fee_recipient: None,
                        gas_limit: None,
                        builder_proposals: None,
                        builder_boost_factor: None,
                        prefer_builder_proposals: None,
                        enabled: Some(true),
                    }
                })
                .collect();

            let beacon_url = SensitiveUrl::parse(self.beacon_node.client.as_ref()).unwrap();

            let validators_to_exit = index_of_validators_to_exit
                .iter()
                .map(|&index| {
                    self.beacon_node.harness.validator_keypairs[index]
                        .pk
                        .clone()
                        .into()
                })
                .collect();

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

            self.exit_config = Some(ExitConfig {
                vc_url: import_config.vc_url,
                vc_token_path: import_config.vc_token_path,
                validators_to_exit,
                beacon_url: Some(beacon_url),
                exit_epoch: None,
                presign: false,
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
            for &index in &self.index_of_validators_to_exit {
                initialized_validators.write().set_index(
                    &self.beacon_node.harness.validator_keypairs[index]
                        .pk
                        .compress(),
                    index as u64,
                );
            }

            let path = self.exit_config.clone().unwrap().vc_token_path;
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

            // Advance beacon chain
            self.beacon_node.harness.advance_slot();

            self.beacon_node
                .harness
                .extend_chain(
                    100,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;

            let result = run::<E>(self.exit_config.clone().unwrap()).await;

            self.beacon_node.harness.advance_slot();

            self.beacon_node
                .harness
                .extend_chain(
                    1,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;

            let validator_data = self
                .index_of_validators_to_exit
                .iter()
                .map(|&index| {
                    self.beacon_node
                        .harness
                        .get_current_state()
                        .get_validator(index)
                        .unwrap()
                        .clone()
                })
                .collect::<Vec<_>>();

            let validator_exit_epoch = validator_data
                .iter()
                .map(|validator| validator.exit_epoch)
                .collect::<Vec<_>>();

            let validator_withdrawable_epoch = validator_data
                .iter()
                .map(|validator| validator.withdrawable_epoch)
                .collect::<Vec<_>>();

            let current_epoch = self.beacon_node.harness.get_current_state().current_epoch();
            let max_seed_lookahead = self.beacon_node.harness.spec.max_seed_lookahead;
            let min_withdrawability_delay = self
                .beacon_node
                .harness
                .spec
                .min_validator_withdrawability_delay;

            // As per the spec:
            // https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#compute_activation_exit_epoch
            let beacon_exit_epoch = current_epoch + 1 + max_seed_lookahead;
            let beacon_withdrawable_epoch = beacon_exit_epoch + min_withdrawability_delay;

            assert!(
                validator_exit_epoch
                    .iter()
                    .all(|&epoch| epoch == beacon_exit_epoch)
            );

            assert!(
                validator_withdrawable_epoch
                    .iter()
                    .all(|&epoch| epoch == beacon_withdrawable_epoch)
            );

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
            .with_validators(vec![0])
            .await
            .run_test()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn exit_multiple_validators() {
        TestBuilder::new()
            .await
            .with_validators(vec![10, 20, 30])
            .await
            .run_test()
            .await
            .assert_ok();
    }
}

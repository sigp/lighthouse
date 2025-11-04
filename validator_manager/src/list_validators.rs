use clap::{Arg, ArgAction, ArgMatches, Command};
use eth2::lighthouse_vc::types::SingleKeystoreResponse;
use eth2::types::{ConfigAndPreset, StateId, ValidatorId, ValidatorStatus};
use eth2::{BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use types::{ChainSpec, EthSpec, PublicKeyBytes};

use crate::exit_validators::get_current_epoch;
use crate::{DumpConfig, common::vc_http_client};

pub const CMD: &str = "list";
pub const VC_URL_FLAG: &str = "vc-url";
pub const VC_TOKEN_FLAG: &str = "vc-token";
pub const BEACON_URL_FLAG: &str = "beacon-node";
pub const VALIDATOR_FLAG: &str = "validators";

pub fn cli_app() -> Command {
    Command::new(CMD)
        .about("Lists all validators in a validator client using the HTTP API.")
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
            Arg::new(BEACON_URL_FLAG)
                .long(BEACON_URL_FLAG)
                .value_name("NETWORK_ADDRESS")
                .help(
                    "Address to a beacon node HTTP API. When supplied, \
                    the status of validators (with regard to voluntary exit) \
                    will be displayed. This flag is to be used together with \
                    the --validators flag.",
                )
                .action(ArgAction::Set)
                .display_order(0)
                .requires(VALIDATOR_FLAG),
        )
        .arg(
            Arg::new(VALIDATOR_FLAG)
                .long(VALIDATOR_FLAG)
                .value_name("STRING")
                .help(
                    "Comma-separated list of validators (pubkey) to display status for. \
                 To display the status for all validators, use the keyword \"all\". \
                 This flag is to be used together with the --beacon-node flag.",
                )
                .action(ArgAction::Set)
                .display_order(0)
                .requires(BEACON_URL_FLAG),
        )
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ListConfig {
    pub vc_url: SensitiveUrl,
    pub vc_token_path: PathBuf,
    pub beacon_url: Option<SensitiveUrl>,
    pub validators_to_display: Vec<PublicKeyBytes>,
}

impl ListConfig {
    fn from_cli(matches: &ArgMatches) -> Result<Self, String> {
        let validators_to_display_str =
            clap_utils::parse_optional::<String>(matches, VALIDATOR_FLAG)?;

        // Keyword "all" to list all validators, vector to be created later
        let validators_to_display = match validators_to_display_str {
            Some(str) => {
                if str.trim() == "all" {
                    Vec::new()
                } else {
                    str.split(',')
                        .map(|s| s.trim().parse())
                        .collect::<Result<Vec<PublicKeyBytes>, _>>()?
                }
            }
            None => Vec::new(),
        };

        Ok(Self {
            vc_token_path: clap_utils::parse_required(matches, VC_TOKEN_FLAG)?,
            vc_url: clap_utils::parse_required(matches, VC_URL_FLAG)?,
            beacon_url: clap_utils::parse_optional(matches, BEACON_URL_FLAG)?,
            validators_to_display,
        })
    }
}

pub async fn cli_run<E: EthSpec>(
    matches: &ArgMatches,
    dump_config: DumpConfig,
) -> Result<(), String> {
    let config = ListConfig::from_cli(matches)?;
    if dump_config.should_exit_early(&config)? {
        Ok(())
    } else {
        run::<E>(config).await?;
        Ok(())
    }
}

async fn run<E: EthSpec>(config: ListConfig) -> Result<Vec<SingleKeystoreResponse>, String> {
    let ListConfig {
        vc_url,
        vc_token_path,
        beacon_url,
        mut validators_to_display,
    } = config;

    let (_, validators) = vc_http_client(vc_url.clone(), &vc_token_path).await?;

    println!("List of validators ({}):", validators.len());

    if validators_to_display.is_empty() {
        validators_to_display = validators.iter().map(|v| v.validating_pubkey).collect();
    }

    if let Some(ref beacon_url) = beacon_url {
        for validator in &validators_to_display {
            let beacon_node = BeaconNodeHttpClient::new(
                SensitiveUrl::parse(beacon_url.as_ref())
                    .map_err(|e| format!("Failed to parse beacon http server: {:?}", e))?,
                Timeouts::set_all(Duration::from_secs(12)),
            );

            let validator_data = beacon_node
                .get_beacon_states_validator_id(StateId::Head, &ValidatorId::PublicKey(*validator))
                .await
                .map_err(|e| format!("Failed to get updated validator details: {:?}", e))?
                .ok_or_else(|| {
                    format!("Validator {} is not present in the beacon state", validator)
                })?
                .data;

            match validator_data.status {
                ValidatorStatus::ActiveExiting => {
                    let exit_epoch = validator_data.validator.exit_epoch;
                    let withdrawal_epoch = validator_data.validator.withdrawable_epoch;

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

                    let current_epoch = get_current_epoch::<E>(genesis_data.genesis_time, &spec)
                        .ok_or("Failed to get current epoch. Please check your system time")?;

                    eprintln!(
                        "Voluntary exit for validator {} has been accepted into the beacon chain. \
                        Note that the voluntary exit is subject chain finalization. \
                        Before the chain has finalized, there is a low \
                        probability that the exit may be reverted.",
                        validator
                    );
                    eprintln!(
                        "Current epoch: {}, Exit epoch: {}, Withdrawable epoch: {}",
                        current_epoch, exit_epoch, withdrawal_epoch
                    );
                    eprintln!("Please keep your validator running till exit epoch");
                    eprintln!(
                        "Exit epoch in approximately {} secs",
                        (exit_epoch - current_epoch) * spec.seconds_per_slot * E::slots_per_epoch()
                    );
                }
                ValidatorStatus::ExitedSlashed | ValidatorStatus::ExitedUnslashed => {
                    eprintln!(
                        "Validator {} has exited at epoch: {}",
                        validator, validator_data.validator.exit_epoch
                    );
                }
                _ => {
                    eprintln!(
                        "Validator {} has not initiated voluntary exit or the voluntary exit \
                    is yet to be accepted into the beacon chain. Validator status is: {}",
                        validator, validator_data.status
                    )
                }
            }
        }
    } else {
        for validator in &validators {
            println!("{}", validator.validating_pubkey);
        }
    }
    Ok(validators)
}

#[cfg(not(debug_assertions))]
#[cfg(test)]
mod test {
    use std::{
        fs::{self, File},
        io::Write,
    };

    use super::*;
    use crate::{
        common::ValidatorSpecification, import_validators::tests::TestBuilder as ImportTestBuilder,
    };
    use types::MainnetEthSpec;
    use validator_http_api::{Config as HttpConfig, test_utils::ApiTester};
    type E = MainnetEthSpec;

    struct TestBuilder {
        list_config: Option<ListConfig>,
        src_import_builder: Option<ImportTestBuilder>,
        http_config: HttpConfig,
        vc_token: Option<String>,
        validators: Vec<ValidatorSpecification>,
    }

    impl TestBuilder {
        async fn new() -> Self {
            Self {
                list_config: None,
                src_import_builder: None,
                http_config: ApiTester::default_http_config(),
                vc_token: None,
                validators: vec![],
            }
        }

        async fn with_validators(mut self, count: u32, first_index: u32) -> Self {
            let builder = ImportTestBuilder::new_with_http_config(self.http_config.clone())
                .await
                .create_validators(count, first_index)
                .await;
            self.list_config = Some(ListConfig {
                vc_url: builder.get_import_config().vc_url,
                vc_token_path: builder.get_import_config().vc_token_path,
                beacon_url: None,
                validators_to_display: vec![],
            });

            self.vc_token =
                Some(fs::read_to_string(builder.get_import_config().vc_token_path).unwrap());

            let local_validators: Vec<ValidatorSpecification> = {
                let contents =
                    fs::read_to_string(builder.get_import_config().validators_file_path.unwrap())
                        .unwrap();
                serde_json::from_str(&contents).unwrap()
            };

            self.validators = local_validators.clone();
            self.src_import_builder = Some(builder);
            self
        }

        pub async fn run_test(self) -> TestResult {
            let import_test_result = self.src_import_builder.unwrap().run_test().await;
            assert!(import_test_result.result.is_ok());

            let path = self.list_config.clone().unwrap().vc_token_path;
            let parent = path.parent().unwrap();

            fs::create_dir_all(parent).expect("Was not able to create parent directory");

            File::options()
                .write(true)
                .read(true)
                .create(true)
                .truncate(true)
                .open(path)
                .unwrap()
                .write_all(self.vc_token.clone().unwrap().as_bytes())
                .unwrap();

            let result = run::<E>(self.list_config.clone().unwrap()).await;

            if let Ok(result_ref) = &result {
                for local_validator in &self.validators {
                    let local_keystore = &local_validator.voting_keystore.0;
                    let local_pubkey = local_keystore.public_key().unwrap();
                    assert!(
                        result_ref
                            .iter()
                            .any(|validator| validator.validating_pubkey
                                == local_pubkey.clone().into()),
                        "local validator pubkey not found in result"
                    );
                }

                return TestResult { result: Ok(()) };
            }

            TestResult {
                result: Err(result.unwrap_err()),
            }
        }
    }

    #[must_use] // Use the `assert_ok` or `assert_err` fns to "use" this value.
    struct TestResult {
        result: Result<(), String>,
    }

    impl TestResult {
        fn assert_ok(self) {
            assert_eq!(self.result, Ok(()))
        }
    }
    #[tokio::test]
    async fn list_all_validators() {
        TestBuilder::new()
            .await
            .with_validators(3, 0)
            .await
            .run_test()
            .await
            .assert_ok();
    }
}

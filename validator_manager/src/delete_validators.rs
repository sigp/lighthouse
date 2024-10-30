use clap::{Arg, ArgAction, ArgMatches, Command};
use eth2::{
    lighthouse_vc::types::{DeleteKeystoreStatus, DeleteKeystoresRequest},
    SensitiveUrl,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use types::PublicKeyBytes;

use crate::{common::vc_http_client, DumpConfig};

pub const CMD: &str = "delete";
pub const VC_URL_FLAG: &str = "vc-url";
pub const VC_TOKEN_FLAG: &str = "vc-token";
pub const VALIDATOR_FLAG: &str = "validators";

#[derive(Debug)]
pub enum DeleteError {
    InvalidPublicKey,
    DeleteFailed(eth2::Error),
}

pub fn cli_app() -> Command {
    Command::new(CMD)
        .about("Deletes one or more validators from a validator client using the HTTP API.")
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
                .help("Comma-separated list of validators (pubkey) that will be deleted.")
                .action(ArgAction::Set)
                .required(true)
                .display_order(0),
        )
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct DeleteConfig {
    pub vc_url: SensitiveUrl,
    pub vc_token_path: PathBuf,
    pub validators_to_delete: Vec<PublicKeyBytes>,
}

impl DeleteConfig {
    fn from_cli(matches: &ArgMatches) -> Result<Self, String> {
        let validators_to_delete_str =
            clap_utils::parse_required::<String>(matches, VALIDATOR_FLAG)?;

        let validators_to_delete = validators_to_delete_str
            .split(',')
            .map(|s| s.trim().parse())
            .collect::<Result<Vec<PublicKeyBytes>, _>>()?;

        Ok(Self {
            vc_token_path: clap_utils::parse_required(matches, VC_TOKEN_FLAG)?,
            validators_to_delete,
            vc_url: clap_utils::parse_required(matches, VC_URL_FLAG)?,
        })
    }
}

pub async fn cli_run(matches: &ArgMatches, dump_config: DumpConfig) -> Result<(), String> {
    let config = DeleteConfig::from_cli(matches)?;
    if dump_config.should_exit_early(&config)? {
        Ok(())
    } else {
        run(config).await
    }
}

async fn run<'a>(config: DeleteConfig) -> Result<(), String> {
    let DeleteConfig {
        vc_url,
        vc_token_path,
        validators_to_delete,
    } = config;

    let (http_client, validators) = vc_http_client(vc_url.clone(), &vc_token_path).await?;

    for validator_to_delete in &validators_to_delete {
        if !validators
            .iter()
            .any(|validator| &validator.validating_pubkey == validator_to_delete)
        {
            return Err(format!("Validator {} doesn't exist", validator_to_delete));
        }
    }

    let delete_request = DeleteKeystoresRequest {
        pubkeys: validators_to_delete.clone(),
    };

    let responses = http_client
        .delete_keystores(&delete_request)
        .await
        .map_err(|e| format!("Error deleting keystore {}", e))?
        .data;

    let mut error = false;
    for (validator_to_delete, response) in validators_to_delete.iter().zip(responses.iter()) {
        if response.status == DeleteKeystoreStatus::Error
            || response.status == DeleteKeystoreStatus::NotFound
            || response.status == DeleteKeystoreStatus::NotActive
        {
            error = true;
            eprintln!(
                "Problem with removing validator {:?}, status: {:?}",
                validator_to_delete, response.status
            );
        }
    }
    if error {
        return Err("Problem with removing one or more validators".to_string());
    }

    eprintln!("Validator(s) deleted");
    Ok(())
}

#[cfg(not(debug_assertions))]
#[cfg(test)]
mod test {
    use std::{
        fs::{self, File},
        io::Write,
        str::FromStr,
    };

    use super::*;
    use crate::{
        common::ValidatorSpecification, import_validators::tests::TestBuilder as ImportTestBuilder,
    };
    use validator_http_api::{test_utils::ApiTester, Config as HttpConfig};

    struct TestBuilder {
        delete_config: Option<DeleteConfig>,
        src_import_builder: Option<ImportTestBuilder>,
        http_config: HttpConfig,
        vc_token: Option<String>,
        validators: Vec<ValidatorSpecification>,
    }

    impl TestBuilder {
        async fn new() -> Self {
            Self {
                delete_config: None,
                src_import_builder: None,
                http_config: ApiTester::default_http_config(),
                vc_token: None,
                validators: vec![],
            }
        }

        async fn with_validators(
            mut self,
            count: u32,
            first_index: u32,
            indices_of_validators_to_delete: Vec<usize>,
        ) -> Self {
            let builder = ImportTestBuilder::new_with_http_config(self.http_config.clone())
                .await
                .create_validators(count, first_index)
                .await;

            self.vc_token =
                Some(fs::read_to_string(builder.get_import_config().vc_token_path).unwrap());

            let local_validators: Vec<ValidatorSpecification> = {
                let contents =
                    fs::read_to_string(builder.get_import_config().validators_file_path.unwrap())
                        .unwrap();
                serde_json::from_str(&contents).unwrap()
            };

            let import_config = builder.get_import_config();

            let validators_to_delete = indices_of_validators_to_delete
                .iter()
                .map(|&index| {
                    PublicKeyBytes::from_str(
                        format!("0x{}", local_validators[index].voting_keystore.pubkey()).as_str(),
                    )
                    .unwrap()
                })
                .collect();

            self.delete_config = Some(DeleteConfig {
                vc_url: import_config.vc_url,
                vc_token_path: import_config.vc_token_path,
                validators_to_delete,
            });

            self.validators = local_validators.clone();
            self.src_import_builder = Some(builder);
            self
        }

        pub async fn run_test(self) -> TestResult {
            let import_builder = self.src_import_builder.unwrap();
            let import_test_result = import_builder.run_test().await;
            assert!(import_test_result.result.is_ok());

            let path = self.delete_config.clone().unwrap().vc_token_path;
            let url = self.delete_config.clone().unwrap().vc_url;
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

            let result = run(self.delete_config.clone().unwrap()).await;

            if result.is_ok() {
                let (_, list_keystores_response) = vc_http_client(url, path.clone()).await.unwrap();

                // The remaining number of active keystores (left) = Total validators - Deleted validators (right)
                assert_eq!(
                    list_keystores_response.len(),
                    self.validators.len()
                        - self
                            .delete_config
                            .clone()
                            .unwrap()
                            .validators_to_delete
                            .len()
                );

                // Check the remaining validator keys are not in validators_to_delete
                assert!(list_keystores_response.iter().all(|keystore| {
                    !self
                        .delete_config
                        .clone()
                        .unwrap()
                        .validators_to_delete
                        .contains(&keystore.validating_pubkey)
                }));

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
    async fn delete_multiple_validators() {
        TestBuilder::new()
            .await
            .with_validators(3, 0, vec![0, 1, 2])
            .await
            .run_test()
            .await
            .assert_ok();
    }
}

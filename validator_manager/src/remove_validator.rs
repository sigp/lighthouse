use std::path::PathBuf;

use types::PublicKeyBytes;
use clap::{App, Arg, ArgMatches};
use eth2::{lighthouse_vc::types::{DeleteKeystoreStatus, DeleteKeystoresRequest}, SensitiveUrl};
use serde::{Deserialize, Serialize};

use crate::{common::vc_http_client, DumpConfig};

pub const CMD: &str = "remove";
pub const VC_URL_FLAG: &str = "vc-url";
pub const VC_TOKEN_FLAG: &str = "vc-token";
pub const VALIDATOR_FLAG: &str = "validator";

#[derive(Debug)]
pub enum RemoveError {
    InvalidPublicKey,
    RemoveFailed(eth2::Error)
}

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
    .about("Removes validator from VC")
    .arg(
        Arg::with_name(VC_URL_FLAG)
        .long(VC_URL_FLAG)
        .value_name("HTTP_ADDRESS")
        .help(
            "A HTTP(S) address of a validator client using the keymanager-API. \
            If this value is not supplied then a 'dry run' will be conducted where \
            no changes are made to the validator client.",
        )
        .default_value("http://localhost:5062")
        .requires(VC_TOKEN_FLAG)
        .takes_value(true)
    )
    .arg(
        Arg::with_name(VC_TOKEN_FLAG)
            .long(VC_TOKEN_FLAG)
            .value_name("PATH")
            .help("The file containing a token required by the validator client.")
            .takes_value(true),
    )
    .arg(
        Arg::with_name(VALIDATOR_FLAG)
            .long(VALIDATOR_FLAG)
            .value_name("STRING")
            .help("Validator that will be removed (pubkey).")
            .takes_value(true),
    )
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct RemoveConfig {
    pub vc_url: SensitiveUrl,
    pub vc_token_path: PathBuf,
    pub validator_to_remove: PublicKeyBytes,
}

impl RemoveConfig {
    fn from_cli(matches: &ArgMatches) -> Result<Self, String> {
        Ok(Self {
            vc_token_path: clap_utils::parse_required(matches, VC_TOKEN_FLAG)?,
            validator_to_remove: clap_utils::parse_required(matches, VALIDATOR_FLAG)?,
            vc_url: clap_utils::parse_required(matches, VC_URL_FLAG)?,
        })
    }
}

pub async fn cli_run<'a>(
    matches: &'a ArgMatches<'a>,
    dump_config: DumpConfig
) -> Result<(), String> {
    let config = RemoveConfig::from_cli(matches)?;
    if dump_config.should_exit_early(&config)? {
        Ok(())
    } else {
        run(config).await
    }
}

pub async fn run<'a>(
    config: RemoveConfig
) -> Result<(), String> {

    let RemoveConfig {
        vc_url,
        vc_token_path,
        validator_to_remove,
    } = config;

    let (http_client, _keystores) = vc_http_client(vc_url.clone(), &vc_token_path).await?;

    let validators = http_client.get_keystores().await.unwrap().data;

    if !validators.iter().any(|validator| validator.validating_pubkey == validator_to_remove) {
        eprintln!("Validator {} doesn't exists", validator_to_remove);
        return Err(format!("Validator {} doesn't exists", validator_to_remove));
    }

    let delete_request = DeleteKeystoresRequest {
        pubkeys: vec![validator_to_remove]
    };

    let response = http_client.delete_keystores(&delete_request)
        .await
        .map_err(|e|  format!("Error deleting keystore {}", e))?
        .data;

    if response[0].status == DeleteKeystoreStatus::Error || response[0].status == DeleteKeystoreStatus::NotFound || response[0].status == DeleteKeystoreStatus::NotActive {
        eprintln!("Problem with removing validator {}", validator_to_remove);
        return Err(format!("Problem with removing validator {}", validator_to_remove));
    }

    eprintln!("Validator deleted");
    Ok(())
}


#[cfg(not(debug_assertions))]
#[cfg(test)]
mod test {
    use std::{fs::{self, File}, io::Write, str::FromStr};

    use super::*;
    use crate::{common::ValidatorSpecification, import_validators::tests::TestBuilder as ImportTestBuilder};
    use validator_client::http_api::{test_utils::ApiTester, Config as HttpConfig};


    struct TestBuilder {
        remove_config: Option<RemoveConfig>,
        src_import_builder: Option<ImportTestBuilder>,
        http_config: HttpConfig,
        vc_token: Option<String>,
        validators: Vec<ValidatorSpecification>,
    }

    impl TestBuilder {
        async fn new() -> Self {
            Self {
                remove_config: None,
                src_import_builder: None,
                http_config: ApiTester::default_http_config(),
                vc_token: None,
                validators: vec![],
            }
        }

        async fn with_validators(mut self, count: u32, first_index: u32, index_of_validator_to_remove: usize) -> Self {
            let builder = ImportTestBuilder::new_with_http_config(self.http_config.clone())
                .await
                .create_validators(count, first_index)
                .await;

            self.vc_token = Some(fs::read_to_string(builder.get_import_config().vc_token_path).unwrap());

            let local_validators: Vec<ValidatorSpecification> = {
                let contents =
                    fs::read_to_string(builder.get_import_config().validators_file_path).unwrap();
                serde_json::from_str(&contents).unwrap()
            };

            let import_config= builder.get_import_config();

            self.remove_config = Some(RemoveConfig {
                vc_url: import_config.vc_url,
                vc_token_path: import_config.vc_token_path,
                validator_to_remove: PublicKeyBytes::from_str(format!("0x{}", local_validators[index_of_validator_to_remove].voting_keystore.pubkey()).as_str()).unwrap(),
            });

            self.validators = local_validators.clone();
            self.src_import_builder = Some(builder);
            self
        }


        pub async fn run_test(self) -> TestResult {
            let import_builder = self.src_import_builder.unwrap();
            let import_test_result = import_builder.run_test().await;
            assert!(import_test_result.result.is_ok());

            let path = self.remove_config.clone().unwrap().vc_token_path;
            let url = self.remove_config.clone().unwrap().vc_url;
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

            let result = run(self.remove_config.clone().unwrap()).await;

            if result.is_ok() {

                let (http_client, _keystores) = vc_http_client(url, path.clone()).await.unwrap();
                let list_keystores_response = http_client.get_keystores().await.unwrap().data;

                assert_eq!(list_keystores_response.len(), self.validators.len() - 1);
                assert!(list_keystores_response.iter().all(|keystore| keystore.validating_pubkey != self.remove_config.clone().unwrap().validator_to_remove));

                return TestResult {
                    result: Ok(()),
                };
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
    async fn list_all_validators() {
        TestBuilder::new()
            .await
            .with_validators(3, 0, 0)
            .await
            .run_test()
            .await
            .assert_ok();
    }
}


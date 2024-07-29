use std::path::PathBuf;

use clap::{App, Arg, ArgMatches};
use eth2::SensitiveUrl;
use serde::{Deserialize, Serialize};

use crate::{common::vc_http_client, DumpConfig};

pub const CMD: &str = "list";
pub const VC_URL_FLAG: &str = "vc-url";
pub const VC_TOKEN_FLAG: &str = "vc-token";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
    .about("Lists all the validators in VC")
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
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ListConfig {
    pub vc_url: SensitiveUrl,
    pub vc_token_path: PathBuf,
}

impl ListConfig {
    fn from_cli(matches: &ArgMatches) -> Result<Self, String> {
        Ok(Self {
            vc_token_path: clap_utils::parse_required(matches, VC_TOKEN_FLAG)?,
            vc_url: clap_utils::parse_required(matches, VC_URL_FLAG)?,
        })
    }
}

pub async fn cli_run<'a>(
    matches: &'a ArgMatches<'a>,
    dump_config: DumpConfig
) -> Result<(), String> {
    let config = ListConfig::from_cli(matches)?;
    if dump_config.should_exit_early(&config)? {
        Ok(())
    } else {
        println!("{}", run(config).await.unwrap());
        Ok(())
    }
}

pub async fn run<'a>(
    config: ListConfig
) -> Result<String, String> {

    let ListConfig {
        vc_url,
        vc_token_path,
    } = config;

    let (http_client, _keystores) = vc_http_client(vc_url.clone(), &vc_token_path).await?;

    let validators = http_client.get_keystores().await.unwrap().data;

    let mut result = String::new();

    result.push_str(format!("List of validators ({}):", validators.len()).as_str());
    result.push('\n');
    for validator in validators {
        result.push_str(format!("{}", validator.validating_pubkey).as_str());
        result.push('\n');
    }

    Ok(result)
}

#[cfg(not(debug_assertions))]
#[cfg(test)]
mod test {
    use std::{fs::{self, File}, io::Write};

    use super::*;
    use crate::{common::ValidatorSpecification, import_validators::tests::TestBuilder as ImportTestBuilder};
    use validator_client::http_api::{test_utils::ApiTester, Config as HttpConfig};


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
            });

            self.vc_token = Some(fs::read_to_string(builder.get_import_config().vc_token_path).unwrap());

            let local_validators: Vec<ValidatorSpecification> = {
                let contents =
                    fs::read_to_string(builder.get_import_config().validators_file_path).unwrap();
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

            let result = run(self.list_config.clone().unwrap()).await;

            if result.is_ok() {
                let result_ref = result.as_ref().unwrap();

                for local_validator in &self.validators {
                    let local_keystore = &local_validator.voting_keystore.0;
                    let local_pubkey = local_keystore.public_key().unwrap().as_hex_string();
                    assert!(result_ref.contains(&local_pubkey), "local validator pubkey not found in result");
                }

                return TestResult {
                    result: Ok(()),
                };
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


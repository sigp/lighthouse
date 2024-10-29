use super::common::*;
use crate::DumpConfig;
use account_utils::{eth2_keystore::Keystore, ZeroizeString};
use clap::{Arg, ArgAction, ArgMatches, Command};
use clap_utils::FLAG_HEADER;
use derivative::Derivative;
use eth2::lighthouse_vc::types::KeystoreJsonStr;
use eth2::{lighthouse_vc::std_types::ImportKeystoreStatus, SensitiveUrl};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use types::Address;

pub const CMD: &str = "import";
pub const VALIDATORS_FILE_FLAG: &str = "validators-file";
pub const KEYSTORE_FILE_FLAG: &str = "keystore-file";
pub const VC_URL_FLAG: &str = "vc-url";
pub const VC_TOKEN_FLAG: &str = "vc-token";
pub const PASSWORD: &str = "password";
pub const FEE_RECIPIENT: &str = "suggested-fee-recipient";
pub const GAS_LIMIT: &str = "gas-limit";
pub const BUILDER_PROPOSALS: &str = "builder-proposals";
pub const BUILDER_BOOST_FACTOR: &str = "builder-boost-factor";
pub const PREFER_BUILDER_PROPOSALS: &str = "prefer-builder-proposals";
pub const ENABLED: &str = "enabled";

pub const DETECTED_DUPLICATE_MESSAGE: &str = "Duplicate validator detected!";

pub fn cli_app() -> Command {
    Command::new(CMD)
        .about(
            "Uploads validators to a validator client using the HTTP API. The validators \
                are defined in a JSON file which can be generated using the \"create-validators\" \
                command.",
        )
        .arg(
            Arg::new(VALIDATORS_FILE_FLAG)
                .long(VALIDATORS_FILE_FLAG)
                .value_name("PATH_TO_JSON_FILE")
                .help(
                    "The path to a JSON file containing a list of validators to be \
                    imported to the validator client. This file is usually named \
                    \"validators.json\".",
                )
                .action(ArgAction::Set)
                .display_order(0)
                .required_unless_present("keystore-file")
                .conflicts_with("keystore-file"),
        )
        .arg(
            Arg::new(KEYSTORE_FILE_FLAG)
                .long(KEYSTORE_FILE_FLAG)
                .value_name("PATH_TO_KEYSTORE_FILE")
                .help(
                    "The path to a keystore JSON file to be \
                    imported to the validator client. This file is usually created \
                    using staking-deposit-cli or ethstaker-deposit-cli",
                )
                .action(ArgAction::Set)
                .display_order(0)
                .conflicts_with("validators-file")
                .required_unless_present("validators-file")
                .requires(PASSWORD),
        )
        .arg(
            Arg::new(VC_URL_FLAG)
                .long(VC_URL_FLAG)
                .value_name("HTTP_ADDRESS")
                .help(
                    "A HTTP(S) address of a validator client using the keymanager-API.")
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
            Arg::new(IGNORE_DUPLICATES_FLAG)
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .long(IGNORE_DUPLICATES_FLAG)
                .help(
                    "If present, ignore any validators which already exist on the VC. \
                    Without this flag, the process will terminate without making any changes. \
                    This flag should be used with caution, whilst it does not directly cause \
                    slashable conditions, it might be an indicator that something is amiss. \
                    Users should also be careful to avoid submitting duplicate deposits for \
                    validators that already exist on the VC.",
                )
                .display_order(0),
        )
        .arg(
            Arg::new(PASSWORD)
                .long(PASSWORD)
                .value_name("STRING")
                .help("Password of the keystore file.")
                .action(ArgAction::Set)
                .display_order(0)
                .requires(KEYSTORE_FILE_FLAG),
        )
        .arg(
            Arg::new(FEE_RECIPIENT)
                .long(FEE_RECIPIENT)
                .value_name("ETH1_ADDRESS")
                .help("When provided, the imported validator will use the suggested fee recipient. Omit this flag to use the default value from the VC.")
                .action(ArgAction::Set)
                .display_order(0)
                .requires(KEYSTORE_FILE_FLAG),
        )
        .arg(
            Arg::new(GAS_LIMIT)
                .long(GAS_LIMIT)
                .value_name("UINT64")
                .help("When provided, the imported validator will use this gas limit. It is recommended \
                to leave this as the default value by not specifying this flag.",)
                .action(ArgAction::Set)
                .display_order(0)
                .requires(KEYSTORE_FILE_FLAG),
        )
        .arg(
            Arg::new(BUILDER_PROPOSALS)
                .long(BUILDER_PROPOSALS)
                .help("When provided, the imported validator will attempt to create \
                blocks via builder rather than the local EL.",)
                .value_parser(["true","false"])
                .action(ArgAction::Set)
                .display_order(0)
                .requires(KEYSTORE_FILE_FLAG),
        )
        .arg(
            Arg::new(BUILDER_BOOST_FACTOR)
                .long(BUILDER_BOOST_FACTOR)
                .value_name("UINT64")
                .help("When provided, the imported validator will use this \
                percentage multiplier to apply to the builder's payload value \
                when choosing between a builder payload header and payload from \
                the local execution node.",)
                .action(ArgAction::Set)
                .display_order(0)
                .requires(KEYSTORE_FILE_FLAG),
        )
        .arg(
            Arg::new(PREFER_BUILDER_PROPOSALS)
                .long(PREFER_BUILDER_PROPOSALS)
                .help("When provided, the imported validator will always prefer blocks \
                constructed by builders, regardless of payload value.",)
                .value_parser(["true","false"])
                .action(ArgAction::Set)
                .display_order(0)
                .requires(KEYSTORE_FILE_FLAG),
        )
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct ImportConfig {
    pub validators_file_path: Option<PathBuf>,
    pub keystore_file_path: Option<PathBuf>,
    pub vc_url: SensitiveUrl,
    pub vc_token_path: PathBuf,
    pub ignore_duplicates: bool,
    #[derivative(Debug = "ignore")]
    pub password: Option<ZeroizeString>,
    pub fee_recipient: Option<Address>,
    pub gas_limit: Option<u64>,
    pub builder_proposals: Option<bool>,
    pub builder_boost_factor: Option<u64>,
    pub prefer_builder_proposals: Option<bool>,
    pub enabled: Option<bool>,
}

impl ImportConfig {
    fn from_cli(matches: &ArgMatches) -> Result<Self, String> {
        Ok(Self {
            validators_file_path: clap_utils::parse_optional(matches, VALIDATORS_FILE_FLAG)?,
            keystore_file_path: clap_utils::parse_optional(matches, KEYSTORE_FILE_FLAG)?,
            vc_url: clap_utils::parse_required(matches, VC_URL_FLAG)?,
            vc_token_path: clap_utils::parse_required(matches, VC_TOKEN_FLAG)?,
            ignore_duplicates: matches.get_flag(IGNORE_DUPLICATES_FLAG),
            password: clap_utils::parse_optional(matches, PASSWORD)?,
            fee_recipient: clap_utils::parse_optional(matches, FEE_RECIPIENT)?,
            gas_limit: clap_utils::parse_optional(matches, GAS_LIMIT)?,
            builder_proposals: clap_utils::parse_optional(matches, BUILDER_PROPOSALS)?,
            builder_boost_factor: clap_utils::parse_optional(matches, BUILDER_BOOST_FACTOR)?,
            prefer_builder_proposals: clap_utils::parse_optional(
                matches,
                PREFER_BUILDER_PROPOSALS,
            )?,
            enabled: clap_utils::parse_optional(matches, ENABLED)?,
        })
    }
}

pub async fn cli_run(matches: &ArgMatches, dump_config: DumpConfig) -> Result<(), String> {
    let config = ImportConfig::from_cli(matches)?;

    if dump_config.should_exit_early(&config)? {
        Ok(())
    } else {
        run(config).await
    }
}

async fn run<'a>(config: ImportConfig) -> Result<(), String> {
    let ImportConfig {
        validators_file_path,
        keystore_file_path,
        vc_url,
        vc_token_path,
        ignore_duplicates,
        password,
        fee_recipient,
        gas_limit,
        builder_proposals,
        builder_boost_factor,
        prefer_builder_proposals,
        enabled,
    } = config;

    let validators: Vec<ValidatorSpecification> =
        if let Some(validators_format_path) = &validators_file_path {
            if !validators_format_path.exists() {
                return Err(format!(
                    "Unable to find file at {:?}",
                    validators_format_path
                ));
            }

            let validators_file = fs::OpenOptions::new()
                .read(true)
                .create(false)
                .open(validators_format_path)
                .map_err(|e| format!("Unable to open {:?}: {:?}", validators_format_path, e))?;

            serde_json::from_reader(&validators_file).map_err(|e| {
                format!(
                    "Unable to parse JSON in {:?}: {:?}",
                    validators_format_path, e
                )
            })?
        } else if let Some(keystore_format_path) = &keystore_file_path {
            vec![ValidatorSpecification {
                voting_keystore: KeystoreJsonStr(
                    Keystore::from_json_file(keystore_format_path).map_err(|e| format!("{e:?}"))?,
                ),
                voting_keystore_password: password.ok_or_else(|| {
                    "The --password flag is required to supply the keystore password".to_string()
                })?,
                slashing_protection: None,
                fee_recipient,
                gas_limit,
                builder_proposals,
                builder_boost_factor,
                prefer_builder_proposals,
                enabled,
            }]
        } else {
            return Err(format!(
                "One of the flag --{VALIDATORS_FILE_FLAG} or --{KEYSTORE_FILE_FLAG} is required."
            ));
        };

    let count = validators.len();

    let (http_client, _keystores) = vc_http_client(vc_url.clone(), &vc_token_path).await?;

    eprintln!(
        "Starting to submit {} validators to VC, each validator may take several seconds",
        count
    );

    for (i, validator) in validators.into_iter().enumerate() {
        match validator.upload(&http_client, ignore_duplicates).await {
            Ok(status) => {
                match status.status {
                    ImportKeystoreStatus::Imported => {
                        eprintln!("Uploaded keystore {} of {} to the VC", i + 1, count)
                    }
                    ImportKeystoreStatus::Duplicate => {
                        if ignore_duplicates {
                            eprintln!("Re-uploaded keystore {} of {} to the VC", i + 1, count)
                        } else {
                            eprintln!(
                                "Keystore {} of {} was uploaded to the VC, but it was a duplicate. \
                                Exiting now, use --{} to allow duplicates.",
                                i + 1, count, IGNORE_DUPLICATES_FLAG
                            );
                            return Err(DETECTED_DUPLICATE_MESSAGE.to_string());
                        }
                    }
                    ImportKeystoreStatus::Error => {
                        eprintln!(
                            "Upload of keystore {} of {} failed with message: {:?}. \
                                A potential solution is run this command again \
                                using the --{} flag, however care should be taken to ensure \
                                that there are no duplicate deposits submitted.",
                            i + 1,
                            count,
                            status.message,
                            IGNORE_DUPLICATES_FLAG
                        );
                        return Err(format!("Upload failed with {:?}", status.message));
                    }
                }
            }
            e @ Err(UploadError::InvalidPublicKey) => {
                eprintln!("Validator {} has an invalid public key", i);
                return Err(format!("{:?}", e));
            }
            ref e @ Err(UploadError::DuplicateValidator(voting_public_key)) => {
                eprintln!(
                    "Duplicate validator {:?} already exists on the destination validator client. \
                    This may indicate that some validators are running in two places at once, which \
                    can lead to slashing. If you are certain that there is no risk, add the --{} flag.",
                    voting_public_key, IGNORE_DUPLICATES_FLAG
                );
                return Err(format!("{:?}", e));
            }
            Err(UploadError::FailedToListKeys(e)) => {
                eprintln!(
                    "Failed to list keystores. Some keys may have been imported whilst \
                    others may not have been imported. A potential solution is run this command again \
                    using the --{} flag, however care should be taken to ensure that there are no \
                    duplicate deposits submitted.",
                    IGNORE_DUPLICATES_FLAG
                );
                return Err(format!("{:?}", e));
            }
            Err(UploadError::KeyUploadFailed(e)) => {
                eprintln!(
                    "Failed to upload keystore. Some keys may have been imported whilst \
                    others may not have been imported. A potential solution is run this command again \
                    using the --{} flag, however care should be taken to ensure that there are no \
                    duplicate deposits submitted.",
                    IGNORE_DUPLICATES_FLAG
                );
                return Err(format!("{:?}", e));
            }
            Err(UploadError::IncorrectStatusCount(count)) => {
                eprintln!(
                    "Keystore was uploaded, however the validator client returned an invalid response. \
                    A potential solution is run this command again using the --{} flag, however care \
                    should be taken to ensure that there are no duplicate deposits submitted.",
                    IGNORE_DUPLICATES_FLAG
                );
                return Err(format!(
                    "Invalid status count in import response: {}",
                    count
                ));
            }
            Err(UploadError::FeeRecipientUpdateFailed(e)) => {
                eprintln!(
                    "Failed to set fee recipient for validator {}. This value may need \
                    to be set manually. Continuing with other validators. Error was {:?}",
                    i, e
                );
            }
            Err(UploadError::PatchValidatorFailed(e)) => {
                eprintln!(
                    "Failed to set some values on validator {} (e.g., builder, enabled or gas limit. \
                    These values value may need to be set manually. Continuing with other validators. \
                    Error was {:?}",
                    i, e
                );
            }
        }
    }

    Ok(())
}

// The tests use crypto and are too slow in debug.
#[cfg(not(debug_assertions))]
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::create_validators::tests::TestBuilder as CreateTestBuilder;
    use std::{
        fs::{self, File},
        str::FromStr,
    };
    use tempfile::{tempdir, TempDir};
    use validator_http_api::{test_utils::ApiTester, Config as HttpConfig};

    const VC_TOKEN_FILE_NAME: &str = "vc_token.json";

    pub struct TestBuilder {
        import_config: ImportConfig,
        pub vc: ApiTester,
        /// Holds the temp directory owned by the `CreateTestBuilder` so it doesn't get cleaned-up
        /// before we can read it.
        create_dir: Option<TempDir>,
        _dir: TempDir,
    }

    impl TestBuilder {
        pub async fn new() -> Self {
            Self::new_with_http_config(ApiTester::default_http_config()).await
        }

        pub async fn new_with_http_config(http_config: HttpConfig) -> Self {
            let dir = tempdir().unwrap();
            let vc = ApiTester::new_with_http_config(http_config).await;
            let vc_token_path = dir.path().join(VC_TOKEN_FILE_NAME);
            fs::write(&vc_token_path, &vc.api_token).unwrap();

            Self {
                import_config: ImportConfig {
                    // This field will be overwritten later on.
                    validators_file_path: Some(dir.path().into()),
                    keystore_file_path: Some(dir.path().into()),
                    vc_url: vc.url.clone(),
                    vc_token_path,
                    ignore_duplicates: false,
                    password: Some(ZeroizeString::from_str("password").unwrap()),
                    fee_recipient: None,
                    builder_boost_factor: None,
                    gas_limit: None,
                    builder_proposals: None,
                    enabled: None,
                    prefer_builder_proposals: None,
                },
                vc,
                create_dir: None,
                _dir: dir,
            }
        }

        pub fn mutate_import_config<F: Fn(&mut ImportConfig)>(mut self, func: F) -> Self {
            func(&mut self.import_config);
            self
        }

        pub fn get_import_config(&self) -> ImportConfig {
            self.import_config.clone()
        }

        pub async fn create_validators(mut self, count: u32, first_index: u32) -> Self {
            let create_result = CreateTestBuilder::default()
                .mutate_config(|config| {
                    config.count = count;
                    config.first_index = first_index;
                })
                .run_test()
                .await;
            assert!(
                create_result.result.is_ok(),
                "precondition: validators are created"
            );
            self.import_config.validators_file_path = Some(create_result.validators_file_path());
            self.create_dir = Some(create_result.output_dir);
            self
        }

        // Keystore JSON requires a different format when creating valdiators
        pub async fn create_validators_keystore_format(
            mut self,
            count: u32,
            first_index: u32,
        ) -> Self {
            let create_result = CreateTestBuilder::default()
                .mutate_config(|config| {
                    config.count = count;
                    config.first_index = first_index;
                })
                .run_test()
                .await;
            assert!(
                create_result.result.is_ok(),
                "precondition: validators are created"
            );

            let validators_file_path = create_result.validators_file_path();

            let validators_file = fs::OpenOptions::new()
                .read(true)
                .create(false)
                .open(&validators_file_path)
                .map_err(|e| format!("Unable to open {:?}: {:?}", validators_file_path, e))
                .unwrap();

            let validators: Vec<ValidatorSpecification> = serde_json::from_reader(&validators_file)
                .map_err(|e| {
                    format!(
                        "Unable to parse JSON in {:?}: {:?}",
                        validators_file_path, e
                    )
                })
                .unwrap();

            let validator = &validators[0];
            let validator_json = validator.voting_keystore.0.clone();

            let keystore_file = File::create(&validators_file_path).unwrap();
            let _ = validator_json.to_json_writer(keystore_file);

            self.import_config.keystore_file_path = Some(create_result.validators_file_path());
            self.import_config.password = Some(validator.voting_keystore_password.clone());
            self.create_dir = Some(create_result.output_dir);
            self
        }

        /// Imports validators without running the entire test suite in `Self::run_test`. This is
        /// useful for simulating duplicate imports.
        pub async fn import_validators_without_checks(self) -> Self {
            run(self.import_config.clone()).await.unwrap();
            self
        }

        pub async fn run_test(self) -> TestResult {
            let result = run(self.import_config.clone()).await;

            if result.is_ok() {
                self.vc.ensure_key_cache_consistency().await;

                let local_validators: Vec<ValidatorSpecification> = {
                    let contents =
                        fs::read_to_string(&self.import_config.validators_file_path.unwrap())
                            .unwrap();
                    serde_json::from_str(&contents).unwrap()
                };
                let list_keystores_response = self.vc.client.get_keystores().await.unwrap().data;

                assert_eq!(
                    local_validators.len(),
                    list_keystores_response.len(),
                    "vc should have exactly the number of validators imported"
                );

                for local_validator in &local_validators {
                    let local_keystore = &local_validator.voting_keystore.0;
                    let local_pubkey = local_keystore.public_key().unwrap().into();
                    let remote_validator = list_keystores_response
                        .iter()
                        .find(|validator| validator.validating_pubkey == local_pubkey)
                        .expect("validator must exist on VC");
                    assert_eq!(&remote_validator.derivation_path, &local_keystore.path());
                    assert_eq!(remote_validator.readonly, Some(false));
                }
            }

            TestResult {
                result,
                vc: self.vc,
            }
        }

        pub async fn run_test_keystore_format(self) -> TestResult {
            let result = run(self.import_config.clone()).await;

            if result.is_ok() {
                self.vc.ensure_key_cache_consistency().await;

                let local_keystore: Keystore =
                    Keystore::from_json_file(&self.import_config.keystore_file_path.unwrap())
                        .unwrap();

                let list_keystores_response = self.vc.client.get_keystores().await.unwrap().data;

                assert_eq!(
                    1,
                    list_keystores_response.len(),
                    "vc should have exactly the number of validators imported"
                );

                let local_pubkey = local_keystore.public_key().unwrap().into();
                let remote_validator = list_keystores_response
                    .iter()
                    .find(|validator| validator.validating_pubkey == local_pubkey)
                    .expect("validator must exist on VC");
                assert_eq!(&remote_validator.derivation_path, &local_keystore.path());
                assert_eq!(remote_validator.readonly, Some(false));
            }

            TestResult {
                result,
                vc: self.vc,
            }
        }
    }

    #[must_use] // Use the `assert_ok` or `assert_err` fns to "use" this value.
    pub struct TestResult {
        pub result: Result<(), String>,
        pub vc: ApiTester,
    }

    impl TestResult {
        fn assert_ok(self) {
            assert_eq!(self.result, Ok(()))
        }

        fn assert_err_contains(self, msg: &str) {
            assert!(self.result.unwrap_err().contains(msg))
        }
    }

    #[tokio::test]
    async fn create_one_validator() {
        TestBuilder::new()
            .await
            .create_validators(1, 0)
            .await
            .run_test()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn create_three_validators() {
        TestBuilder::new()
            .await
            .create_validators(3, 0)
            .await
            .run_test()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn create_one_validator_with_offset() {
        TestBuilder::new()
            .await
            .create_validators(1, 42)
            .await
            .run_test()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn create_three_validators_with_offset() {
        TestBuilder::new()
            .await
            .create_validators(3, 1337)
            .await
            .run_test()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn import_duplicates_when_disallowed() {
        TestBuilder::new()
            .await
            .create_validators(1, 0)
            .await
            .import_validators_without_checks()
            .await
            .run_test()
            .await
            .assert_err_contains("DuplicateValidator");
    }

    #[tokio::test]
    async fn import_duplicates_when_allowed() {
        TestBuilder::new()
            .await
            .mutate_import_config(|config| {
                config.ignore_duplicates = true;
            })
            .create_validators(1, 0)
            .await
            .import_validators_without_checks()
            .await
            .run_test()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn create_one_validator_keystore_format() {
        TestBuilder::new()
            .await
            .mutate_import_config(|config| {
                // Set validators_file_path to None so that keystore_file_path is used for tests with the keystore format
                config.validators_file_path = None;
            })
            .create_validators_keystore_format(1, 0)
            .await
            .run_test_keystore_format()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn create_one_validator_with_offset_keystore_format() {
        TestBuilder::new()
            .await
            .mutate_import_config(|config| {
                config.validators_file_path = None;
            })
            .create_validators_keystore_format(1, 42)
            .await
            .run_test_keystore_format()
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn import_duplicates_when_disallowed_keystore_format() {
        TestBuilder::new()
            .await
            .mutate_import_config(|config| {
                config.validators_file_path = None;
            })
            .create_validators_keystore_format(1, 0)
            .await
            .import_validators_without_checks()
            .await
            .run_test_keystore_format()
            .await
            .assert_err_contains("DuplicateValidator");
    }

    #[tokio::test]
    async fn import_duplicates_when_allowed_keystore_format() {
        TestBuilder::new()
            .await
            .mutate_import_config(|config| {
                config.ignore_duplicates = true;
                config.validators_file_path = None;
            })
            .create_validators_keystore_format(1, 0)
            .await
            .import_validators_without_checks()
            .await
            .run_test_keystore_format()
            .await
            .assert_ok();
    }
}

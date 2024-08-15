use super::common::*;
use crate::DumpConfig;
use account_utils::{eth2_keystore::Keystore, ZeroizeString};
use clap::{Arg, ArgAction, ArgMatches, Command};
use eth2::lighthouse_vc::types::KeystoreJsonStr;
use eth2::{lighthouse_vc::std_types::ImportKeystoreStatus, SensitiveUrl};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use types::Address;

#[derive(Serialize, Deserialize, Debug)]
struct KeystoreStandard {
    pub address: String,
    pub crypto: CryptoStandard,
    pub id: String,
    pub version: u8,
}

#[derive(Serialize, Deserialize, Debug)]
struct CryptoStandard {
    pub cipher: String,
    pub ciphertext: String,
    pub cipherparams: CipherParamsStandard,
    pub kdf: String,
    pub kdfparams: KdfParamsStandard,
    pub mac: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CipherParamsStandard {
    pub iv: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct KdfParamsStandard {
    pub dklen: u32,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    pub salt: String,
}

pub const CMD: &str = "import-standard";
pub const VALIDATOR_FILE_FLAG: &str = "validator-file";
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
                are defined in a JSON file which can be generated using the staking deposit CLI.",
        )
        .arg(
            Arg::new(VALIDATOR_FILE_FLAG)
                .long(VALIDATOR_FILE_FLAG)
                .value_name("PATH_TO_JSON_FILE")
                .help(
                    "The path to a JSON file containing a validators to be \
                    imported to the validator client.",
                )
                .required(true)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new(VC_URL_FLAG)
                .long(VC_URL_FLAG)
                .value_name("HTTP_ADDRESS")
                .help(
                    "A HTTP(S) address of a validator client using the keymanager-API. \
                    If this value is not supplied then a 'dry run' will be conducted where \
                    no changes are made to the validator client.",
                )
                .default_value("http://localhost:5062")
                .requires(VC_TOKEN_FLAG)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new(VC_TOKEN_FLAG)
                .long(VC_TOKEN_FLAG)
                .value_name("PATH")
                .help("The file containing a token required by the validator client.")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new(IGNORE_DUPLICATES_FLAG)
                .action(ArgAction::Set)
                .long(IGNORE_DUPLICATES_FLAG)
                .help(
                    "If present, ignore any validators which already exist on the VC. \
                    Without this flag, the process will terminate without making any changes. \
                    This flag should be used with caution, whilst it does not directly cause \
                    slashable conditions, it might be an indicator that something is amiss. \
                    Users should also be careful to avoid submitting duplicate deposits for \
                    validators that already exist on the VC.",
                )
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(PASSWORD)
                .long(PASSWORD)
                .value_name("STRING")
                .help("Password of the keystore file.")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new(FEE_RECIPIENT)
                .long(FEE_RECIPIENT)
                .value_name("ETH1_ADDRESS")
                .help("When provided, the imported validator will use the suggested fee recipient. Omit this flag to use the default value from the VC.")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new(GAS_LIMIT)
                .long(GAS_LIMIT)
                .value_name("UINT64")
                .help("When provided, the imported validator will use this gas limit. It is recommended \
                to leave this as the default value by not specifying this flag.",)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new(BUILDER_PROPOSALS)
                .long(BUILDER_PROPOSALS)
                .help("When provided, the imported validator will attempt to create \
                blocks via builder rather than the local EL.",)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(BUILDER_BOOST_FACTOR)
                .long(BUILDER_BOOST_FACTOR)
                .value_name("UINT64")
                .help("When provided, the imported validator will use this \
                percentage multiplier to apply to the builder's payload value \
                when choosing between a builder payload header and payload from \
                the local execution node.",)
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new(PREFER_BUILDER_PROPOSALS)
                .long(PREFER_BUILDER_PROPOSALS)
                .help("When provided, the imported validator will always prefer blocks \
                constructed by builders, regardless of payload value.",)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(ENABLED)
                .long(ENABLED)
                .value_name("BOOL")
                .help("Enabled or disable the imported validator.")
                .action(ArgAction::Set),
        )
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportConfig {
    pub validator_file_path: PathBuf,
    pub vc_url: SensitiveUrl,
    pub vc_token_path: PathBuf,
    pub ignore_duplicates: bool,
    pub password: ZeroizeString,
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
            validator_file_path: clap_utils::parse_required(matches, VALIDATOR_FILE_FLAG)?,
            vc_url: clap_utils::parse_required(matches, VC_URL_FLAG)?,
            vc_token_path: clap_utils::parse_required(matches, VC_TOKEN_FLAG)?,
            ignore_duplicates: matches.get_flag(IGNORE_DUPLICATES_FLAG),
            password: clap_utils::parse_required(matches, PASSWORD)?,
            fee_recipient: clap_utils::parse_optional(matches, FEE_RECIPIENT)?,
            gas_limit: clap_utils::parse_optional(matches, GAS_LIMIT)?,
            builder_proposals: Some(matches.get_flag(BUILDER_PROPOSALS)),
            builder_boost_factor: clap_utils::parse_optional(matches, BUILDER_BOOST_FACTOR)?,
            prefer_builder_proposals: Some(matches.get_flag(PREFER_BUILDER_PROPOSALS)),
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
        validator_file_path,
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

    if !validator_file_path.exists() {
        return Err(format!("Unable to find file at {:?}", validator_file_path));
    }

    let (http_client, _keystores) = vc_http_client(vc_url.clone(), &vc_token_path).await?;

    eprintln!("Starting to submit validator it may take several seconds");

    let validator_specification = ValidatorSpecification {
        voting_keystore: KeystoreJsonStr(
            Keystore::from_json_file(&validator_file_path).map_err(|e| format!("{e:?}"))?,
        ),
        voting_keystore_password: password,
        slashing_protection: None,
        fee_recipient,
        gas_limit,
        builder_proposals,
        builder_boost_factor,
        prefer_builder_proposals,
        enabled,
    };

    match validator_specification
        .upload(&http_client, ignore_duplicates)
        .await
    {
        Ok(status) => match status.status {
            ImportKeystoreStatus::Imported => {
                eprintln!("Keystore uploaded");
            }
            ImportKeystoreStatus::Duplicate => {
                if ignore_duplicates {
                    eprintln!("Keystore re-uploaded")
                } else {
                    eprintln!(
                        "Keystore uploaded to the VC, but it was a duplicate. \
                            Exiting now, use --{} to allow duplicates.",
                        IGNORE_DUPLICATES_FLAG
                    );
                    return Err(DETECTED_DUPLICATE_MESSAGE.to_string());
                }
            }
            ImportKeystoreStatus::Error => {
                eprintln!(
                    "Upload of keystore failed with message: {:?}. \
                            A potential solution is run this command again \
                            using the --{} flag, however care should be taken to ensure \
                            that there are no duplicate deposits submitted.",
                    status.message, IGNORE_DUPLICATES_FLAG
                );
                return Err(format!("Upload failed with {:?}", status.message));
            }
        },
        e @ Err(UploadError::InvalidPublicKey) => {
            eprintln!("Validator has an invalid public key");
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
                "Failed to set fee recipient for validator. This value may need \
                to be set manually. Continuing with other validators. Error was {:?}",
                e
            );
        }
        Err(UploadError::PatchValidatorFailed(e)) => {
            eprintln!(
                "Failed to set some values on validator (e.g., builder, enabled or gas limit. \
                These values value may need to be set manually. Continuing with other validators. \
                Error was {:?}",
                e
            );
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
    use validator_client::http_api::{test_utils::ApiTester, Config as HttpConfig};

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
            fs::write(&vc_token_path, &vc.api_token);

            Self {
                import_config: ImportConfig {
                    // This field will be overwritten later on.
                    validator_file_path: dir.path().into(),
                    vc_url: vc.url.clone(),
                    vc_token_path,
                    ignore_duplicates: false,
                    password: ZeroizeString::from_str("password"),
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

            let validators_file_path = create_result.validators_file_path();

            let validators_file = fs::OpenOptions::new()
                .read(true)
                .create(false)
                .open(&validators_file_path)
                .map_err(|e| format!("Unable to open {:?}: {:?}", validators_file_path, e));

            let validators: Vec<ValidatorSpecification> = serde_json::from_reader(&validators_file)
                .map_err(|e| {
                    format!(
                        "Unable to parse JSON in {:?}: {:?}",
                        validators_file_path, e
                    )
                });

            let validator = &validators[0];
            let validator_json = validator.voting_keystore.0.clone();

            let keystore_file = File::create(&validators_file_path);
            validator_json.to_json_writer(keystore_file);

            self.import_config.validator_file_path = create_result.validators_file_path();
            self.import_config.password = validator.voting_keystore_password.clone();
            self.create_dir = Some(create_result.output_dir);
            self
        }

        /// Imports validator without running the entire test suite in `Self::run_test`. This is
        /// useful for simulating duplicate imports.
        pub async fn import_validators_without_checks(self) -> Self {
            run(self.import_config.clone()).await.unwrap();
            self
        }

        pub async fn run_test(self) -> TestResult {
            let result = run(self.import_config.clone()).await;

            if result.is_ok() {
                self.vc.ensure_key_cache_consistency().await;

                let validators_file = fs::read_to_string(&self.import_config.validator_file_path)
                    .map_err(|e| {
                        format!(
                            "Unable to open {:?}: {:?}",
                            &self.import_config.validator_file_path, e
                        )
                    });

                let local_keystore: Keystore = Keystore::from_json_file(
                    serde_json::from_str(&validators_file).expect("JSON was not well formatted"),
                );

                let list_keystores_response = self.vc.client.get_keystores().await.unwrap().data;

                assert_eq!(
                    1,
                    list_keystores_response.len(),
                    "vc should have exactly the number of validators imported"
                );

                let local_pubkey = local_keystore.public_key().into();
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
    async fn create_one_validator_standard() {
        TestBuilder::new()
            .await
            .create_validators(1, 0)
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
}

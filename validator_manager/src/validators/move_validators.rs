use super::common::*;
use crate::DumpConfig;
use clap::{App, Arg, ArgMatches};
use eth2::{
    lighthouse_vc::{
        std_types::{DeleteKeystoreStatus, DeleteKeystoresRequest, InterchangeJsonStr, Status},
        types::{ExportKeystoresResponse, SingleExportKeystoresResponse},
    },
    SensitiveUrl,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use types::{Address, PublicKeyBytes};

pub const MOVE_DIR_NAME: &str = "lighthouse-validator-move";

pub const CMD: &str = "move";
pub const WORKING_DIRECTORY_FLAG: &str = "working-directory";
pub const SRC_VALIDATOR_CLIENT_URL_FLAG: &str = "src-validator-client-url";
pub const SRC_VALIDATOR_CLIENT_TOKEN_FLAG: &str = "src-validator-client-token";
pub const DEST_VALIDATOR_CLIENT_URL_FLAG: &str = "dest-validator-client-url";
pub const DEST_VALIDATOR_CLIENT_TOKEN_FLAG: &str = "dest-validator-client-token";
pub const VALIDATORS_FLAG: &str = "validators";
pub const GAS_LIMIT_FLAG: &str = "gas-limit";
pub const FEE_RECIPIENT_FLAG: &str = "suggested-fee-recipient";
pub const BUILDER_PROPOSALS_FLAG: &str = "builder-proposals";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about(
            "Uploads validators to a validator client using the HTTP API. The validators \
                are defined in a JSON file which can be generated using the \"create-validators\" \
                command.",
        )
        .arg(
            Arg::with_name(WORKING_DIRECTORY_FLAG)
                .long(WORKING_DIRECTORY_FLAG)
                .value_name("PATH_TO_DIRECTORY")
                .help(
                    "The path to a directory where the application can write files.\
                    Under certain failure scenarios this directory may contain files which \
                    can be used to recover validators.",
                )
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(SRC_VALIDATOR_CLIENT_URL_FLAG)
                .long(SRC_VALIDATOR_CLIENT_URL_FLAG)
                .value_name("HTTP_ADDRESS")
                .help(
                    "A HTTP(S) address of a validator client using the keymanager-API. \
                    This validator client is the \"source\" and contains the validators \
                    that are to be moved.",
                )
                .required(true)
                .requires(SRC_VALIDATOR_CLIENT_TOKEN_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(SRC_VALIDATOR_CLIENT_TOKEN_FLAG)
                .long(SRC_VALIDATOR_CLIENT_TOKEN_FLAG)
                .value_name("PATH")
                .help("The file containing a token required by the source validator client.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(DEST_VALIDATOR_CLIENT_URL_FLAG)
                .long(DEST_VALIDATOR_CLIENT_URL_FLAG)
                .value_name("HTTP_ADDRESS")
                .help(
                    "A HTTP(S) address of a validator client using the keymanager-API. \
                    This validator client is the \"destination\" and will have new validators \
                    added as they are removed from the \"source\" validator client.",
                )
                .required(true)
                .requires(DEST_VALIDATOR_CLIENT_TOKEN_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(DEST_VALIDATOR_CLIENT_TOKEN_FLAG)
                .long(DEST_VALIDATOR_CLIENT_TOKEN_FLAG)
                .value_name("PATH")
                .help("The file containing a token required by the destination validator client.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(VALIDATORS_FLAG)
                .long(VALIDATORS_FLAG)
                .value_name("STRING")
                .help(
                    "One or more validator public keys (as 0x-prefixed hex) to be moved from \
                    the source to destination validator clients. Alternatively, use \"all\" to \
                    move all the validators from the source validator client.",
                )
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(GAS_LIMIT_FLAG)
                .long(GAS_LIMIT_FLAG)
                .value_name("UINT64")
                .help(
                    "All created validators will use this gas limit. It is recommended \
                    to leave this as the default value by not specifying this flag.",
                )
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(FEE_RECIPIENT_FLAG)
                .long(FEE_RECIPIENT_FLAG)
                .value_name("ETH1_ADDRESS")
                .help(
                    "All created validators will use this value for the suggested \
                    fee recipient. Omit this flag to use the default value from the VC.",
                )
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(BUILDER_PROPOSALS_FLAG)
                .long(BUILDER_PROPOSALS_FLAG)
                .help(
                    "When provided, all created validators will attempt to create \
                    blocks via builder rather than the local EL.",
                )
                .required(false),
        )
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum Validators {
    All,
    Some(Vec<PublicKeyBytes>),
}

impl FromStr for Validators {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(Validators::All),
            other => other
                .split(',')
                .map(PublicKeyBytes::from_str)
                .collect::<Result<_, _>>()
                .map(Validators::Some),
        }
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MoveConfig {
    pub working_directory_path: PathBuf,
    pub src_vc_url: SensitiveUrl,
    pub src_vc_token_path: PathBuf,
    pub dest_vc_url: SensitiveUrl,
    pub dest_vc_token_path: PathBuf,
    pub validators: Validators,
    pub builder_proposals: bool,
    pub fee_recipient: Option<Address>,
    pub gas_limit: Option<u64>,
}

impl MoveConfig {
    fn from_cli(matches: &ArgMatches) -> Result<Self, String> {
        Ok(Self {
            working_directory_path: clap_utils::parse_required(matches, WORKING_DIRECTORY_FLAG)?,
            src_vc_url: clap_utils::parse_required(matches, SRC_VALIDATOR_CLIENT_URL_FLAG)?,
            src_vc_token_path: clap_utils::parse_required(
                matches,
                SRC_VALIDATOR_CLIENT_TOKEN_FLAG,
            )?,
            dest_vc_url: clap_utils::parse_required(matches, DEST_VALIDATOR_CLIENT_URL_FLAG)?,
            dest_vc_token_path: clap_utils::parse_required(
                matches,
                DEST_VALIDATOR_CLIENT_TOKEN_FLAG,
            )?,
            validators: clap_utils::parse_required(matches, VALIDATORS_FLAG)?,
            builder_proposals: matches.is_present(BUILDER_PROPOSALS_FLAG),
            fee_recipient: clap_utils::parse_optional(matches, FEE_RECIPIENT_FLAG)?,
            gas_limit: clap_utils::parse_optional(matches, GAS_LIMIT_FLAG)?,
        })
    }
}

pub async fn cli_run<'a>(
    matches: &'a ArgMatches<'a>,
    dump_config: DumpConfig,
) -> Result<(), String> {
    let config = MoveConfig::from_cli(matches)?;
    if dump_config.should_exit_early(&config)? {
        Ok(())
    } else {
        run(config).await
    }
}

async fn run<'a>(config: MoveConfig) -> Result<(), String> {
    let MoveConfig {
        working_directory_path,
        src_vc_url,
        src_vc_token_path,
        dest_vc_url,
        dest_vc_token_path,
        validators,
        builder_proposals,
        fee_recipient,
        gas_limit,
    } = config;

    if !working_directory_path.exists() {
        return Err(format!("{:?} does not exist", working_directory_path));
    }

    // Append another directory to the "working directory" provided by the user. By creating a new
    // directory we can prove (to some degree) that we can write in the given directory.
    //
    // It also allows us to easily detect when another identical process is running or the previous
    // run failed by checking to see if the directory already exists.
    let working_directory_path = working_directory_path.join(MOVE_DIR_NAME);
    if working_directory_path.exists() {
        return Err(format!(
            "{:?} already exists, exiting",
            working_directory_path
        ));
    }

    fs::create_dir(&working_directory_path)
        .map_err(|e| format!("Failed to create {:?}: {:?}", working_directory_path, e))?;

    // Moving validators between the same VC is unlikely to be useful and probably indicates a user
    // error.
    if src_vc_url == dest_vc_url {
        return Err(format!(
            "--{} and --{} must be different",
            SRC_VALIDATOR_CLIENT_URL_FLAG, DEST_VALIDATOR_CLIENT_URL_FLAG
        ));
    }

    let (src_http_client, src_keystores) =
        vc_http_client(src_vc_url.clone(), &src_vc_token_path).await?;
    let (dest_http_client, dest_keystores) =
        vc_http_client(dest_vc_url.clone(), &dest_vc_token_path).await?;

    let pubkeys_to_move = match validators {
        Validators::All => src_keystores.iter().map(|v| v.validating_pubkey).collect(),
        Validators::Some(request_pubkeys) => {
            let request_pubkeys_set: HashSet<_> = request_pubkeys.iter().collect();
            let src_pubkeys_set: HashSet<_> =
                src_keystores.iter().map(|v| &v.validating_pubkey).collect();
            let difference = request_pubkeys_set
                .difference(&src_pubkeys_set)
                .collect::<Vec<_>>();
            if !difference.is_empty() {
                for pk in &difference {
                    eprintln!("{:?} is not present on {:?}", pk, src_vc_url);
                }
                return Err(format!(
                    "{} validators not found on {:?}",
                    difference.len(),
                    src_vc_url
                ));
            }
            request_pubkeys
        }
    };

    let src_keystores_map: HashMap<_, _> = src_keystores
        .iter()
        .map(|k| (k.validating_pubkey, k))
        .collect();

    for pubkey_to_move in pubkeys_to_move {
        // Skip read-only validators rather than exiting. This makes it a bit easier to use the
        // "all" flag.
        if src_keystores_map
            .get(&pubkey_to_move)
            .ok_or("Inconsistent src keystore map")?
            .readonly
            .unwrap_or(true)
        {
            eprintln!("Skipping read-only validator {:?}", pubkey_to_move);
        }

        let request = DeleteKeystoresRequest {
            pubkeys: vec![pubkey_to_move],
        };
        let deleted = match src_http_client.delete_lighthouse_keystores(&request).await {
            Ok(deleted) => deleted,
            Err(e) => {
                match src_http_client.get_keystores().await {
                    Ok(response) => {
                        if response
                            .data
                            .iter()
                            .find(|v| v.validating_pubkey == pubkey_to_move)
                            .is_some()
                        {
                            eprintln!(
                                "There was an error removing a validator, however the validator \
                            is still present on the source validator client. The recommended \
                            solution is to run this command again."
                            );
                        }
                    }
                    Err(_) => {
                        eprintln!(
                            "There was an error removing a validator and it's unclear if \
                            the validator was removed or not. Manual user intervention is \
                            required."
                        );
                    }
                };

                return Err(format!("Deleting {:?} failed with {:?}", pubkey_to_move, e));
            }
        };

        let ExportKeystoresResponse {
            mut data,
            slashing_protection,
        } = deleted;

        if data.len() != 1 {
            return Err(format!(
                "Too many deleted validators from VC: {}",
                data.len()
            ));
        }

        let exported_validator = data
            .pop()
            .ok_or("VC responded with zero deleted validators")?;

        let (voting_keystore, voting_keystore_password) = match exported_validator {
            SingleExportKeystoresResponse {
                status:
                    Status {
                        status: DeleteKeystoreStatus::Deleted,
                        message: _,
                    },
                validating_keystore,
                validating_keystore_password,
            } => match (validating_keystore, validating_keystore_password) {
                (Some(keystore), Some(password)) => (keystore, password),
                (keystore_opt, password_opt) => {
                    eprintln!(
                        "Validator {:?} was not moved since the validator client did \
                            not return both a keystore and password. It is likely that the \
                            validator has been deleted from the source validator client \
                            without being moved to the destination validator client. \
                            This validator will most likely need to be manually recovered \
                            from a mnemonic or backup.",
                        pubkey_to_move
                    );
                    return Err(format!(
                        "VC returned deleted but keystore {}, password {}",
                        keystore_opt.is_some(),
                        password_opt.is_some()
                    ));
                }
            },
            SingleExportKeystoresResponse {
                status: Status { status, .. },
                ..
            } if matches!(
                status,
                DeleteKeystoreStatus::NotFound | DeleteKeystoreStatus::NotActive
            ) =>
            {
                eprintln!(
                    "Validator {:?} was not moved since it was not found or not active. This scenario \
                    is unexpected and might indicate that another process is also performing \
                    an export from the source validator client. Exiting now for safety. \
                    If there is definitely no other process exporting validators then it \
                    may be safe to run this command again.",
                    pubkey_to_move
                );
                return Err(format!(
                    "VC indicated that a previously known validator was {:?}",
                    status,
                ));
            }
            SingleExportKeystoresResponse {
                status: Status { status, message },
                ..
            } => {
                eprintln!(
                    "Validator {:?} was not moved because the source validator client \
                    indicated there was an error disabling it. Manual intervention is \
                    required to recover from this scenario.",
                    pubkey_to_move
                );
                return Err(format!(
                    "VC returned status {:?} with message {:?}",
                    status, message
                ));
            }
        };

        let validator_specification = ValidatorSpecification {
            voting_keystore,
            voting_keystore_password,
            slashing_protection: Some(InterchangeJsonStr(slashing_protection)),
            fee_recipient,
            gas_limit,
            builder_proposals: Some(builder_proposals),
            enabled: Some(true),
        };
    }

    Ok(())
}

/*
#[cfg(test)]
mod test {
    use super::*;
    use crate::validators::create_validators::tests::TestBuilder as CreateTestBuilder;
    use std::fs;
    use tempfile::{tempdir, TempDir};
    use validator_client::http_api::test_utils::ApiTester;

    const VC_TOKEN_FILE_NAME: &str = "vc_token.json";

    struct TestBuilder {
        import_config: MoveConfig,
        vc: ApiTester,
        /// Holds the temp directory owned by the `CreateTestBuilder` so it doesn't get cleaned-up
        /// before we can read it.
        create_dir: Option<TempDir>,
        _dir: TempDir,
    }

    impl TestBuilder {
        async fn new() -> Self {
            let dir = tempdir().unwrap();
            let vc = ApiTester::new().await;
            let vc_token_path = dir.path().join(VC_TOKEN_FILE_NAME);
            fs::write(&vc_token_path, &vc.api_token).unwrap();

            Self {
                import_config: MoveConfig {
                    // This field will be overwritten later on.
                    validators_file_path: dir.path().into(),
                    vc_url: vc.url.clone(),
                    vc_token_path,
                    ignore_duplicates: false,
                },
                vc,
                create_dir: None,
                _dir: dir,
            }
        }

        pub fn mutate_import_config<F: Fn(&mut MoveConfig)>(mut self, func: F) -> Self {
            func(&mut self.import_config);
            self
        }

        async fn create_validators(mut self, count: u32, first_index: u32) -> Self {
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
            self.import_config.validators_file_path = create_result.validators_file_path();
            self.create_dir = Some(create_result.output_dir);
            self
        }

        /// Imports validators without running the entire test suite in `Self::run_test`. This is
        /// useful for simulating duplicate imports.
        async fn import_validators_without_checks(self) -> Self {
            run(self.import_config.clone()).await.unwrap();
            self
        }

        async fn run_test(self) -> TestResult {
            let result = run(self.import_config.clone()).await;

            if result.is_ok() {
                let local_validators: Vec<ValidatorSpecification> = {
                    let contents =
                        fs::read_to_string(&self.import_config.validators_file_path).unwrap();
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
                    // It's not immediately clear why Lighthouse returns `None` rather than
                    // `Some(false)` here, I would expect the latter to be the most accurate.
                    // However, it doesn't seem like a big deal.
                    //
                    // See: https://github.com/sigp/lighthouse/pull/3490
                    //
                    // If that PR changes we'll need to change this line.
                    assert_eq!(remote_validator.readonly, None);
                }
            }

            TestResult { result }
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

        fn assert_err_is(self, msg: String) {
            assert_eq!(self.result, Err(msg))
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
            .assert_err_is(DETECTED_DUPLICATE_MESSAGE.to_string());
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
*/

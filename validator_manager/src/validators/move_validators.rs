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
use std::path::{Path, PathBuf};
use std::str::FromStr;
use types::{Address, PublicKeyBytes};

pub const MOVE_DIR_NAME: &str = "lighthouse-validator-move";
pub const VALIDATOR_SPECIFICATION_FILE: &str = "validator-specification.json";

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
    let (dest_http_client, _dest_keystores) =
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

    let count = pubkeys_to_move.len();
    for (i, &pubkey_to_move) in pubkeys_to_move.iter().enumerate() {
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
                            .any(|v| v.validating_pubkey == pubkey_to_move)
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

        // We might as well just ignore validators that already exist on the destination machine,
        // there doesn't appear to be much harm just adding them again.
        let ignore_duplicates = true;

        match validator_specification
            .clone()
            .upload(&dest_http_client, ignore_duplicates)
            .await
        {
            Ok(()) => eprintln!(
                "Uploaded keystore {} of {} to the destination VC",
                i + 1,
                count
            ),
            e @ Err(UploadError::InvalidPublicKey) => {
                eprintln!("Validator {} has an invalid public key", i);
                return Err(format!("{:?}", e));
            }
            Err(UploadError::DuplicateValidator(_)) => {
                return Err("Duplicate validator detected when duplicates are ignored".to_string());
            }
            Err(UploadError::FailedToListKeys(e)) => {
                eprintln!(
                    "Failed to list keystores. Some keys may have been moved whilst \
                    others may not.",
                );
                backup_validator(
                    &validator_specification,
                    &working_directory_path,
                    &dest_vc_url,
                    &dest_vc_token_path,
                );
                return Err(format!("{:?}", e));
            }
            Err(UploadError::KeyUploadFailed(e)) => {
                eprintln!(
                    "Failed to upload keystore. Some keys may have been moved whilst \
                    others may not.",
                );
                backup_validator(
                    &validator_specification,
                    &working_directory_path,
                    &dest_vc_url,
                    &dest_vc_token_path,
                );
                return Err(format!("{:?}", e));
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

pub fn backup_validator<P: AsRef<Path>>(
    validator_specification: &ValidatorSpecification,
    working_directory_path: P,
    dest_vc_url: &SensitiveUrl,
    dest_vc_token_path: P,
) {
    use crate::validators::import_validators::{
        CMD, VALIDATORS_FILE_FLAG, VALIDATOR_CLIENT_TOKEN_FLAG, VALIDATOR_CLIENT_URL_FLAG,
    };

    let validator_specification_path = working_directory_path
        .as_ref()
        .join(VALIDATOR_SPECIFICATION_FILE);
    if let Err(e) = write_to_json_file(&validator_specification_path, &validator_specification) {
        eprintln!(
            "A validator was removed from the source validator client but it could not be \
            saved to disk after an upload failure. The validator may need to be recovered \
            from a backup or mnemonic. Error was {:?}",
            e
        );
    }

    eprintln!(
        "It may be possible to recover this validator by running the following command: \n\n\
        lighthouse {} {} {} --{} {:?} --{} {} --{} {:?} \n\n\
        The {:?} directory contains a backup of the validator that was unable to be uploaded. \
        That backup contains the unencrypted validator secret key and should not be shared with \
        anyone. If the recovery command (above) succeeds, it is safe to remove that directory.",
        crate::CMD,
        crate::validators::CMD,
        CMD,
        VALIDATORS_FILE_FLAG,
        validator_specification_path.as_os_str(),
        VALIDATOR_CLIENT_URL_FLAG,
        dest_vc_url.full,
        VALIDATOR_CLIENT_TOKEN_FLAG,
        dest_vc_token_path.as_ref().as_os_str(),
        working_directory_path.as_ref().as_os_str(),
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::validators::import_validators::tests::TestBuilder as ImportTestBuilder;
    use std::fs;
    use tempfile::{tempdir, TempDir};
    use validator_client::http_api::test_utils::ApiTester;

    const SRC_VC_TOKEN_FILE_NAME: &str = "src_vc_token.json";
    const DEST_VC_TOKEN_FILE_NAME: &str = "dest_vc_token.json";

    struct TestBuilder {
        import_builder: Option<ImportTestBuilder>,
        dir: TempDir,
    }

    impl TestBuilder {
        async fn new() -> Self {
            let dir = tempdir().unwrap();
            Self {
                import_builder: None,
                dir: dir,
            }
        }

        async fn with_src_validators(mut self, count: u32, first_index: u32) -> Self {
            let builder = ImportTestBuilder::new()
                .await
                .create_validators(count, first_index)
                .await;
            self.import_builder = Some(builder);
            self
        }

        async fn run_test<F>(self, gen_validators_enum: F) -> TestResult
        where
            F: Fn(&[PublicKeyBytes]) -> Validators,
        {
            let import_test_result = self
                .import_builder
                .expect("test requires an import builder")
                .run_test()
                .await;
            assert!(import_test_result.result.is_ok());
            let src_vc = import_test_result.vc;
            let src_vc_token_path = self.dir.path().join(SRC_VC_TOKEN_FILE_NAME);
            fs::write(&src_vc_token_path, &src_vc.api_token).unwrap();
            let (src_vc_client, src_vc_initial_keystores) =
                vc_http_client(src_vc.url.clone(), &src_vc_token_path)
                    .await
                    .unwrap();

            let src_vc_initial_pubkeys: Vec<_> = src_vc_initial_keystores
                .iter()
                .map(|k| k.validating_pubkey)
                .collect();
            let validators = gen_validators_enum(&src_vc_initial_pubkeys);

            let dest_vc = ApiTester::new().await;
            let dest_vc_token_path = self.dir.path().join(DEST_VC_TOKEN_FILE_NAME);
            fs::write(&dest_vc_token_path, &dest_vc.api_token).unwrap();

            let move_config = MoveConfig {
                working_directory_path: self.dir.path().into(),
                src_vc_url: src_vc.url.clone(),
                src_vc_token_path,
                dest_vc_url: dest_vc.url.clone(),
                dest_vc_token_path: dest_vc_token_path.clone(),
                validators: validators.clone(),
                builder_proposals: false,
                fee_recipient: None,
                gas_limit: None,
            };

            let result = run(move_config).await;

            let (dest_vc_client, dest_vc_keystores) =
                vc_http_client(dest_vc.url.clone(), &dest_vc_token_path)
                    .await
                    .unwrap();
            let src_vc_final_keystores = src_vc_client.get_keystores().await.unwrap().data;

            match validators {
                Validators::All => {
                    assert!(src_vc_final_keystores.is_empty());
                    for initial_keystore in &src_vc_initial_keystores {
                        assert!(dest_vc_keystores.contains(initial_keystore))
                    }
                }
                Validators::Some(_) => unimplemented!(),
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
    async fn one_validator_move_all() {
        TestBuilder::new()
            .await
            .with_src_validators(1, 0)
            .await
            .run_test(|_| Validators::All)
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn one_validator_move_one() {
        TestBuilder::new()
            .await
            .with_src_validators(1, 0)
            .await
            .run_test(|pubkeys| Validators::Some(pubkeys.to_vec()))
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn three_validators_move_all() {
        TestBuilder::new()
            .await
            .with_src_validators(3, 0)
            .await
            .run_test(|_| Validators::All)
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn three_validators_move_one() {
        TestBuilder::new()
            .await
            .with_src_validators(3, 0)
            .await
            .run_test(|pubkeys| Validators::Some(pubkeys[0..1].to_vec()))
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn three_validators_move_two() {
        TestBuilder::new()
            .await
            .with_src_validators(3, 0)
            .await
            .run_test(|pubkeys| Validators::Some(pubkeys[0..2].to_vec()))
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn three_validators_move_three() {
        TestBuilder::new()
            .await
            .with_src_validators(3, 42)
            .await
            .run_test(|pubkeys| Validators::Some(pubkeys.to_vec()))
            .await
            .assert_ok();
    }
}

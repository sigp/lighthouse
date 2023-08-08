use super::common::*;
use crate::DumpConfig;
use account_utils::{read_password_from_user, ZeroizeString};
use clap::{App, Arg, ArgMatches};
use eth2::{
    lighthouse_vc::{
        std_types::{
            DeleteKeystoreStatus, DeleteKeystoresRequest, ImportKeystoreStatus, InterchangeJsonStr,
            Status,
        },
        types::{ExportKeystoresResponse, SingleExportKeystoresResponse},
    },
    SensitiveUrl,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;
use types::{Address, PublicKeyBytes};

pub const MOVE_DIR_NAME: &str = "lighthouse-validator-move";
pub const VALIDATOR_SPECIFICATION_FILE: &str = "validator-specification.json";

pub const CMD: &str = "move";
pub const SRC_VC_URL_FLAG: &str = "src-vc-url";
pub const SRC_VC_TOKEN_FLAG: &str = "src-vc-token";
pub const DEST_VC_URL_FLAG: &str = "dest-vc-url";
pub const DEST_VC_TOKEN_FLAG: &str = "dest-vc-token";
pub const VALIDATORS_FLAG: &str = "validators";
pub const GAS_LIMIT_FLAG: &str = "gas-limit";
pub const FEE_RECIPIENT_FLAG: &str = "suggested-fee-recipient";
pub const BUILDER_PROPOSALS_FLAG: &str = "builder-proposals";

const NO_VALIDATORS_MSG: &str = "No validators present on source validator client";

const UPLOAD_RETRY_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum PasswordSource {
    /// Reads the password from the user via the terminal.
    Interactive { stdin_inputs: bool },
    /// This variant is panic-y and should only be used during testing.
    Testing(HashMap<PublicKeyBytes, Vec<String>>),
}

impl PasswordSource {
    fn read_password(&mut self, pubkey: &PublicKeyBytes) -> Result<ZeroizeString, String> {
        match self {
            PasswordSource::Interactive { stdin_inputs } => {
                eprintln!("Please enter a password for keystore {:?}:", pubkey);
                read_password_from_user(*stdin_inputs)
            }
            // This path with panic if the password list is empty. Since the
            // password prompt will just keep retrying on a failed password, the
            // panic helps us break the loop if we misconfigure the test.
            PasswordSource::Testing(passwords) => Ok(passwords
                .get_mut(pubkey)
                .expect("pubkey should be known")
                .remove(0)
                .into()),
        }
    }
}

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about(
            "Uploads validators to a validator client using the HTTP API. The validators \
                are defined in a JSON file which can be generated using the \"create-validators\" \
                command. This command only supports validators signing via a keystore on the local \
                file system (i.e., not Web3Signer validators).",
        )
        .arg(
            Arg::with_name(SRC_VC_URL_FLAG)
                .long(SRC_VC_URL_FLAG)
                .value_name("HTTP_ADDRESS")
                .help(
                    "A HTTP(S) address of a validator client using the keymanager-API. \
                    This validator client is the \"source\" and contains the validators \
                    that are to be moved.",
                )
                .required(true)
                .requires(SRC_VC_TOKEN_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(SRC_VC_TOKEN_FLAG)
                .long(SRC_VC_TOKEN_FLAG)
                .value_name("PATH")
                .help("The file containing a token required by the source validator client.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(DEST_VC_URL_FLAG)
                .long(DEST_VC_URL_FLAG)
                .value_name("HTTP_ADDRESS")
                .help(
                    "A HTTP(S) address of a validator client using the keymanager-API. \
                    This validator client is the \"destination\" and will have new validators \
                    added as they are removed from the \"source\" validator client.",
                )
                .required(true)
                .requires(DEST_VC_TOKEN_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(DEST_VC_TOKEN_FLAG)
                .long(DEST_VC_TOKEN_FLAG)
                .value_name("PATH")
                .help("The file containing a token required by the destination validator client.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(VALIDATORS_FLAG)
                .long(VALIDATORS_FLAG)
                .value_name("STRING")
                .help(
                    "The validators to be moved. Either a list of 0x-prefixed \
                    validator pubkeys or the keyword \"all\".",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name(COUNT_FLAG)
                .long(COUNT_FLAG)
                .value_name("VALIDATOR_COUNT")
                .help("The number of validators to move.")
                .conflicts_with(VALIDATORS_FLAG)
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
                .required(false)
                .possible_values(&["true", "false"])
                .takes_value(true),
        )
        .arg(
            Arg::with_name(STDIN_INPUTS_FLAG)
                .takes_value(false)
                .hidden(cfg!(windows))
                .long(STDIN_INPUTS_FLAG)
                .help("If present, read all user inputs from stdin instead of tty."),
        )
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum Validators {
    All,
    Count(usize),
    Specific(Vec<PublicKeyBytes>),
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MoveConfig {
    pub src_vc_url: SensitiveUrl,
    pub src_vc_token_path: PathBuf,
    pub dest_vc_url: SensitiveUrl,
    pub dest_vc_token_path: PathBuf,
    pub validators: Validators,
    pub builder_proposals: Option<bool>,
    pub fee_recipient: Option<Address>,
    pub gas_limit: Option<u64>,
    pub password_source: PasswordSource,
}

impl MoveConfig {
    fn from_cli(matches: &ArgMatches) -> Result<Self, String> {
        let count_flag = clap_utils::parse_optional(matches, COUNT_FLAG)?;
        let validators_flag = matches.value_of(VALIDATORS_FLAG);
        let validators = match (count_flag, validators_flag) {
            (Some(count), None) => Validators::Count(count),
            (None, Some(string)) => match string {
                "all" => Validators::All,
                pubkeys => pubkeys
                    .split(',')
                    .map(PublicKeyBytes::from_str)
                    .collect::<Result<Vec<_>, _>>()
                    .map(Validators::Specific)?,
            },
            (None, None) => Err(format!(
                "Must supply either --{VALIDATORS_FLAG} or --{COUNT_FLAG}."
            ))?,
            (Some(_), Some(_)) => {
                Err("Cannot supply both --{VALIDATORS_FLAG} and --{COUNT_FLAG}.")?
            }
        };

        Ok(Self {
            src_vc_url: clap_utils::parse_required(matches, SRC_VC_URL_FLAG)?,
            src_vc_token_path: clap_utils::parse_required(matches, SRC_VC_TOKEN_FLAG)?,
            dest_vc_url: clap_utils::parse_required(matches, DEST_VC_URL_FLAG)?,
            dest_vc_token_path: clap_utils::parse_required(matches, DEST_VC_TOKEN_FLAG)?,
            validators,
            builder_proposals: clap_utils::parse_optional(matches, BUILDER_PROPOSALS_FLAG)?,
            fee_recipient: clap_utils::parse_optional(matches, FEE_RECIPIENT_FLAG)?,
            gas_limit: clap_utils::parse_optional(matches, GAS_LIMIT_FLAG)?,
            password_source: PasswordSource::Interactive {
                stdin_inputs: cfg!(windows) || matches.is_present(STDIN_INPUTS_FLAG),
            },
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
        src_vc_url,
        src_vc_token_path,
        dest_vc_url,
        dest_vc_token_path,
        validators,
        builder_proposals,
        fee_recipient,
        gas_limit,
        mut password_source,
    } = config;

    // Moving validators between the same VC is unlikely to be useful and probably indicates a user
    // error.
    if src_vc_url == dest_vc_url {
        return Err(format!(
            "--{} and --{} must be different",
            SRC_VC_URL_FLAG, DEST_VC_URL_FLAG
        ));
    }

    let (src_http_client, src_keystores) =
        vc_http_client(src_vc_url.clone(), &src_vc_token_path).await?;
    let (dest_http_client, _dest_keystores) =
        vc_http_client(dest_vc_url.clone(), &dest_vc_token_path).await?;

    if src_keystores.is_empty() {
        return Err(NO_VALIDATORS_MSG.to_string());
    }

    let pubkeys_to_move = match validators {
        Validators::All => src_keystores.iter().map(|v| v.validating_pubkey).collect(),
        Validators::Count(count) => {
            let mut viable_pubkeys: Vec<_> = src_keystores
                .iter()
                .filter(|v| !v.readonly.unwrap_or(true))
                .map(|v| v.validating_pubkey)
                .collect();
            viable_pubkeys.sort_unstable_by_key(PublicKeyBytes::serialize);
            viable_pubkeys
                .get(0..count)
                .ok_or_else(|| {
                    format!(
                        "Cannot move {} keystores since source validator client only has {} \
                        keystores which are able to be moved (not read-only).",
                        count,
                        viable_pubkeys.len()
                    )
                })?
                .to_vec()
        }
        Validators::Specific(request_pubkeys) => {
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
                (Some(keystore), None) => {
                    eprintln!(
                        "Validator {:?} requires a password, please provide it to continue \
                            moving validators. \
                            The dest VC will store this password on its filesystem and the password \
                            will not be required next time the dest VC starts. \
                            If the provided password is incorrect the user will \
                            be asked to provide another password. \
                            Failing to provide the correct password now will \
                            result in the keystore being deleted from the src VC \
                            without being transfered to the dest VC. \
                            It is strongly recommend to provide a password now rather than exiting.",
                        pubkey_to_move
                    );

                    // Read the password from the user, retrying if the password is incorrect.
                    loop {
                        match password_source.read_password(&pubkey_to_move) {
                            Ok(password) => {
                                if let Err(e) = keystore.decrypt_keypair(password.as_ref()) {
                                    eprintln!("Failed to decrypt keystore: {:?}", e);
                                } else {
                                    break (keystore, password);
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "Retrying after error: {:?}. If this error persists the user will need to \
                                        manually recover their keystore for validator {:?} from the mnemonic."
                                    ,
                                    e, pubkey_to_move
                                );
                            }
                        }

                        // Add a sleep here to prevent spamming the console.
                        sleep(Duration::from_secs(1)).await;
                    }
                }
                (None, password_opt) => {
                    eprintln!(
                        "Validator {:?} was not moved since the validator client did \
                            not return a keystore. It is likely that the \
                            validator has been deleted from the source validator client \
                            without being moved to the destination validator client. \
                            This validator will most likely need to be manually recovered \
                            from a mnemonic or backup.",
                        pubkey_to_move
                    );
                    return Err(format!(
                        "VC returned deleted but keystore not present (password {})",
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

        let keystore_derivation_path = voting_keystore.0.path();

        let validator_specification = ValidatorSpecification {
            voting_keystore,
            voting_keystore_password,
            slashing_protection: Some(InterchangeJsonStr(slashing_protection)),
            fee_recipient,
            gas_limit,
            builder_proposals,
            // Allow the VC to choose a default "enabled" state. Since "enabled" is not part of
            // the standard API, leaving this as `None` means we are not forced to use the
            // non-standard API.
            enabled: None,
        };

        // We might as well just ignore validators that already exist on the destination machine,
        // there doesn't appear to be much harm just adding them again and removing them from the
        // source VC is an improvement.
        let ignore_duplicates = true;

        loop {
            match validator_specification
                .clone()
                .upload(&dest_http_client, ignore_duplicates)
                .await
            {
                Ok(status) => {
                    match status.status {
                        ImportKeystoreStatus::Imported => {
                            eprintln!("Moved keystore {} of {}", i + 1, count);
                            break;
                        }
                        ImportKeystoreStatus::Duplicate => {
                            eprintln!("Moved duplicate keystore {} of {} to the VC", i + 1, count);
                            break;
                        }
                        ImportKeystoreStatus::Error => {
                            eprintln!(
                                "Upload of keystore {} of {} failed with message: {:?}.",
                                i + 1,
                                count,
                                status.message,
                            );
                            // Retry uploading this validator.
                            sleep_with_retry_message(
                                &pubkey_to_move,
                                keystore_derivation_path.as_deref(),
                            )
                            .await;
                        }
                    }
                }
                e @ Err(UploadError::InvalidPublicKey) => {
                    eprintln!("Validator {} has an invalid public key", i);
                    return Err(format!("{:?}", e));
                }
                Err(UploadError::DuplicateValidator(_)) => {
                    return Err(
                        "Duplicate validator detected when duplicates are ignored".to_string()
                    );
                }
                Err(UploadError::FailedToListKeys(e)) => {
                    eprintln!(
                        "Failed to list keystores. Some keys may have been moved whilst \
                        others may not. Error was {:?}",
                        e
                    );
                    // Retry uploading this validator.
                    sleep_with_retry_message(&pubkey_to_move, keystore_derivation_path.as_deref())
                        .await;
                }
                Err(UploadError::KeyUploadFailed(e)) => {
                    eprintln!(
                        "Failed to upload keystore. Some keys may have been moved whilst \
                        others may not. Error was {:?}",
                        e
                    );
                    // Retry uploading this validator.
                    sleep_with_retry_message(&pubkey_to_move, keystore_derivation_path.as_deref())
                        .await;
                }
                Err(UploadError::IncorrectStatusCount(count)) => {
                    eprintln!(
                        "Keystore was uploaded, however the validator client returned an invalid response."
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
                    // Continue onto the next validator.
                    break;
                }
                Err(UploadError::PatchValidatorFailed(e)) => {
                    eprintln!(
                        "Failed to set some values on validator {} (e.g., builder, enabled or gas limit). \
                        These values value may need to be set manually. Continuing with other validators. \
                        Error was {:?}",
                        i, e
                    );
                    // Continue onto the next validator.
                    break;
                }
            }
            eprintln!(
                "Uploaded keystore {} of {} to the destination VC",
                i + 1,
                count
            );
        }
    }

    eprintln!("Done.");

    Ok(())
}

async fn sleep_with_retry_message(pubkey: &PublicKeyBytes, path: Option<&str>) {
    let path = path.unwrap_or("<unspecified>");
    eprintln!(
        "Sleeping for {:?} before retrying. Exiting the application before it completes \
        may result in the loss of a validator keystore. The keystore would need to be \
        restored from a backup or mnemonic. The keystore which may be lost has a public \
        key of {:?} and a derivation path of {}",
        UPLOAD_RETRY_WAIT, pubkey, path
    );
    sleep(UPLOAD_RETRY_WAIT).await
}

// The tests use crypto and are too slow in debug.
#[cfg(not(debug_assertions))]
#[cfg(test)]
mod test {
    use super::*;
    use crate::import_validators::tests::TestBuilder as ImportTestBuilder;
    use account_utils::validator_definitions::SigningDefinition;
    use std::fs;
    use tempfile::{tempdir, TempDir};
    use validator_client::http_api::{test_utils::ApiTester, Config as HttpConfig};

    const SRC_VC_TOKEN_FILE_NAME: &str = "src_vc_token.json";
    const DEST_VC_TOKEN_FILE_NAME: &str = "dest_vc_token.json";

    type MutatePasswordFn = Box<dyn Fn(&mut HashMap<PublicKeyBytes, Vec<String>>)>;

    struct TestBuilder {
        src_import_builder: Option<ImportTestBuilder>,
        dest_import_builder: Option<ImportTestBuilder>,
        http_config: HttpConfig,
        duplicates: usize,
        dir: TempDir,
        move_back_again: bool,
        remove_passwords_from_src_vc: bool,
        mutate_passwords: Option<MutatePasswordFn>,
        passwords: HashMap<PublicKeyBytes, Vec<String>>,
        use_password_files: bool,
        reuse_password_files: Option<usize>,
    }

    impl TestBuilder {
        async fn new() -> Self {
            let dir = tempdir().unwrap();
            Self {
                src_import_builder: None,
                dest_import_builder: None,
                http_config: ApiTester::default_http_config(),
                duplicates: 0,
                dir,
                move_back_again: false,
                remove_passwords_from_src_vc: false,
                mutate_passwords: None,
                passwords: <_>::default(),
                use_password_files: false,
                reuse_password_files: None,
            }
        }

        fn move_back_again(mut self) -> Self {
            self.move_back_again = true;
            self
        }

        fn use_password_files(mut self) -> Self {
            self.use_password_files = true;
            self.http_config.store_passwords_in_secrets_dir = true;
            self
        }

        fn reuse_password_files(mut self, index: usize) -> Self {
            self.reuse_password_files = Some(index);
            self
        }

        async fn with_src_validators(mut self, count: u32, first_index: u32) -> Self {
            let builder = ImportTestBuilder::new_with_http_config(self.http_config.clone())
                .await
                .create_validators(count, first_index)
                .await;
            self.src_import_builder = Some(builder);
            self
        }

        async fn with_dest_validators(mut self, count: u32, first_index: u32) -> Self {
            let builder = ImportTestBuilder::new_with_http_config(self.http_config.clone())
                .await
                .create_validators(count, first_index)
                .await;
            self.dest_import_builder = Some(builder);
            self
        }

        fn register_duplicates(mut self, num_duplicates: usize) -> Self {
            self.duplicates = num_duplicates;
            self
        }

        fn remove_passwords_from_src_vc(mut self) -> Self {
            self.remove_passwords_from_src_vc = true;
            self
        }

        fn mutate_passwords<F: Fn(&mut HashMap<PublicKeyBytes, Vec<String>>) + 'static>(
            mut self,
            func: F,
        ) -> Self {
            self.mutate_passwords = Some(Box::new(func));
            self
        }

        async fn move_validators<F>(
            &self,
            gen_validators_enum: F,
            src_vc: &ApiTester,
            dest_vc: &ApiTester,
        ) -> Result<(), String>
        where
            F: Fn(&[PublicKeyBytes]) -> Validators,
        {
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

            let dest_vc_token_path = self.dir.path().join(DEST_VC_TOKEN_FILE_NAME);
            fs::write(&dest_vc_token_path, &dest_vc.api_token).unwrap();

            let (dest_vc_client, dest_vc_initial_keystores) =
                vc_http_client(dest_vc.url.clone(), &dest_vc_token_path)
                    .await
                    .unwrap();

            let move_config = MoveConfig {
                src_vc_url: src_vc.url.clone(),
                src_vc_token_path,
                dest_vc_url: dest_vc.url.clone(),
                dest_vc_token_path: dest_vc_token_path.clone(),
                validators: validators.clone(),
                builder_proposals: None,
                fee_recipient: None,
                gas_limit: None,
                password_source: PasswordSource::Testing(self.passwords.clone()),
            };

            let result = run(move_config).await;

            if result.is_ok() {
                let src_vc_final_keystores = src_vc_client.get_keystores().await.unwrap().data;
                let dest_vc_final_keystores = dest_vc_client.get_keystores().await.unwrap().data;

                src_vc.ensure_key_cache_consistency().await;
                dest_vc.ensure_key_cache_consistency().await;

                match validators {
                    Validators::All => {
                        assert!(
                            src_vc_final_keystores.is_empty(),
                            "all keystores should be removed from source vc"
                        );
                        assert_eq!(
                            dest_vc_final_keystores.len(),
                            dest_vc_initial_keystores.len() + src_vc_initial_keystores.len()
                                - self.duplicates,
                            "the correct count of keystores should have been moved to the dest"
                        );
                        for initial_keystore in &src_vc_initial_keystores {
                            assert!(
                                dest_vc_final_keystores.contains(initial_keystore),
                                "the source keystore should be present at the dest"
                            );
                            assert!(
                                !src_vc
                                    .secrets_dir
                                    .path()
                                    .join(format!("{:?}", initial_keystore.validating_pubkey))
                                    .exists(),
                                "the source password file should be deleted"
                            )
                        }
                    }
                    Validators::Count(count) => {
                        assert_eq!(
                            src_vc_final_keystores.len(),
                            src_vc_initial_keystores.len() - count,
                            "keystores should be removed from source vc"
                        );
                        assert_eq!(
                            dest_vc_final_keystores.len(),
                            dest_vc_initial_keystores.len() + count - self.duplicates,
                            "the correct count of keystores should have been moved to the dest"
                        );
                        let moved_keystores: Vec<_> = {
                            let initial_set: HashSet<_> = src_vc_initial_keystores.iter().collect();
                            let final_set: HashSet<_> = src_vc_final_keystores.iter().collect();
                            initial_set.difference(&final_set).cloned().collect()
                        };
                        assert_eq!(moved_keystores.len(), count);
                        for moved_keystore in &moved_keystores {
                            assert!(
                                dest_vc_final_keystores.contains(moved_keystore),
                                "the moved keystore should be present at the dest"
                            );
                            assert!(
                                !src_vc
                                    .secrets_dir
                                    .path()
                                    .join(format!("{:?}", moved_keystore.validating_pubkey))
                                    .exists(),
                                "the source password file should be deleted"
                            )
                        }
                    }
                    Validators::Specific(pubkeys) => {
                        assert_eq!(
                            src_vc_final_keystores.len(),
                            src_vc_initial_keystores
                                .len()
                                .checked_sub(pubkeys.len())
                                .unwrap(),
                            "the correct count of validators should have been removed from the src"
                        );
                        assert_eq!(
                            dest_vc_final_keystores.len(),
                            dest_vc_initial_keystores.len() + pubkeys.len() - self.duplicates,
                            "the correct count of keystores should have been moved to the dest"
                        );
                        for pubkey in pubkeys {
                            let initial_keystore = src_vc_initial_keystores
                                .iter()
                                .find(|k| k.validating_pubkey == pubkey)
                                .unwrap();
                            assert!(
                                !src_vc_final_keystores.contains(initial_keystore),
                                "the keystore should not be present at the source"
                            );
                            assert!(
                                dest_vc_final_keystores.contains(initial_keystore),
                                "the keystore should be present at the dest"
                            );
                            if self.reuse_password_files.is_some() {
                                assert!(
                                src_vc
                                    .secrets_dir
                                    .path()
                                    .join(format!("{:?}", pubkey))
                                    .exists(),
                                "the source password file was used by another validator and should not be deleted"
                            )
                            } else {
                                assert!(
                                    !src_vc
                                        .secrets_dir
                                        .path()
                                        .join(format!("{:?}", pubkey))
                                        .exists(),
                                    "the source password file should be deleted"
                                )
                            }
                        }
                    }
                }

                // If enabled, check that all VCs still have the password files for their validators.
                if self.use_password_files {
                    src_vc_final_keystores
                        .iter()
                        .map(|keystore| (&src_vc, keystore))
                        .chain(
                            dest_vc_final_keystores
                                .iter()
                                .map(|keystore| (&dest_vc, keystore)),
                        )
                        .for_each(|(vc, keystore)| {
                            assert!(
                                vc.secrets_dir
                                    .path()
                                    .join(format!("{:?}", keystore.validating_pubkey))
                                    .exists(),
                                "the password file should exist"
                            )
                        });
                }
            }

            result
        }

        async fn run_test<F>(mut self, gen_validators_enum: F) -> TestResult
        where
            F: Fn(&[PublicKeyBytes]) -> Validators + Copy,
        {
            let src_vc = if let Some(import_builder) = self.src_import_builder.take() {
                let import_test_result = import_builder.run_test().await;
                assert!(import_test_result.result.is_ok());
                import_test_result.vc
            } else {
                ApiTester::new_with_http_config(self.http_config.clone()).await
            };

            // If enabled, set all the validator definitions on the src_vc to
            // use the same password path as the given `master_index`. This
            // helps test that we don't delete a password file if it's in use by
            // another validator.
            if let Some(primary_index) = self.reuse_password_files {
                let mut initialized_validators = src_vc.initialized_validators.write();
                let definitions = initialized_validators.as_mut_slice_testing_only();
                // Find the path of the "primary" definition.
                let primary_path = definitions
                    .get(primary_index)
                    .map(|def| match &def.signing_definition {
                        SigningDefinition::LocalKeystore {
                            voting_keystore_password_path: Some(path),
                            ..
                        } => path.clone(),
                        _ => panic!("primary index does not have password path"),
                    })
                    .unwrap();
                // Set all definitions to use the same password path as the primary.
                definitions.iter_mut().enumerate().for_each(|(_, def)| {
                    match &mut def.signing_definition {
                        SigningDefinition::LocalKeystore {
                            voting_keystore_password_path: Some(path),
                            ..
                        } => *path = primary_path.clone(),
                        _ => (),
                    }
                })
            }

            let dest_vc = if let Some(import_builder) = self.dest_import_builder.take() {
                let import_test_result = import_builder.run_test().await;
                assert!(import_test_result.result.is_ok());
                import_test_result.vc
            } else {
                ApiTester::new_with_http_config(self.http_config.clone()).await
            };

            if self.remove_passwords_from_src_vc {
                let passwords = src_vc
                    .initialized_validators
                    .write()
                    .delete_passwords_from_validator_definitions()
                    .unwrap();

                self.passwords = passwords
                    .into_iter()
                    .map(|(pubkey, password)| {
                        (
                            PublicKeyBytes::from(&pubkey),
                            vec![password.as_str().to_string()],
                        )
                    })
                    .collect();

                if let Some(func) = self.mutate_passwords.take() {
                    func(&mut self.passwords)
                }
            }

            let result = self
                .move_validators(gen_validators_enum, &src_vc, &dest_vc)
                .await;

            if self.move_back_again {
                self.move_validators(gen_validators_enum, &dest_vc, &src_vc)
                    .await
                    .unwrap();
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

        fn assert_err(self) {
            assert!(self.result.is_err())
        }

        fn assert_err_is(self, msg: String) {
            assert_eq!(self.result, Err(msg))
        }
    }

    #[tokio::test]
    async fn no_validators() {
        TestBuilder::new()
            .await
            .run_test(|_| Validators::All)
            .await
            .assert_err_is(NO_VALIDATORS_MSG.to_string());
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
            .run_test(|pubkeys| Validators::Specific(pubkeys.to_vec()))
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn one_validator_to_non_empty_dest() {
        TestBuilder::new()
            .await
            .with_src_validators(1, 0)
            .await
            .with_dest_validators(1, 10)
            .await
            .run_test(|_| Validators::All)
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn two_validators_move_all_where_one_is_a_duplicate() {
        TestBuilder::new()
            .await
            .with_src_validators(2, 0)
            .await
            .with_dest_validators(1, 1)
            .await
            .register_duplicates(1)
            .run_test(|_| Validators::All)
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn two_validators_move_one_where_one_is_a_duplicate() {
        TestBuilder::new()
            .await
            .with_src_validators(2, 0)
            .await
            .with_dest_validators(2, 0)
            .await
            .register_duplicates(1)
            .run_test(|pubkeys| Validators::Specific(pubkeys[0..1].to_vec()))
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
            .run_test(|pubkeys| Validators::Specific(pubkeys[0..1].to_vec()))
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn three_validators_move_two() {
        TestBuilder::new()
            .await
            .with_src_validators(3, 0)
            .await
            .run_test(|pubkeys| Validators::Specific(pubkeys[0..2].to_vec()))
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn three_validators_move_three() {
        TestBuilder::new()
            .await
            .with_src_validators(3, 42)
            .await
            .run_test(|pubkeys| Validators::Specific(pubkeys.to_vec()))
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn three_validators_move_one_by_count() {
        TestBuilder::new()
            .await
            .with_src_validators(3, 0)
            .await
            .run_test(|_| Validators::Count(1))
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn three_validators_move_two_by_count() {
        TestBuilder::new()
            .await
            .with_src_validators(3, 0)
            .await
            .run_test(|_| Validators::Count(2))
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn one_validators_move_two_by_count() {
        TestBuilder::new()
            .await
            .with_src_validators(1, 0)
            .await
            .run_test(|_| Validators::Count(2))
            .await
            .assert_err();
    }

    #[tokio::test]
    async fn two_validator_move_all_and_back_again() {
        TestBuilder::new()
            .await
            .with_src_validators(2, 0)
            .await
            .move_back_again()
            .run_test(|_| Validators::All)
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn two_validator_move_all_passwords_removed() {
        TestBuilder::new()
            .await
            .with_src_validators(2, 0)
            .await
            .remove_passwords_from_src_vc()
            .run_test(|_| Validators::All)
            .await
            .assert_ok();
    }

    /// This test simulates a src VC that doesn't know the keystore passwords
    /// and provide the wrong password before providing the correct password.
    #[tokio::test]
    async fn two_validator_move_all_passwords_removed_failed_password_attempt() {
        TestBuilder::new()
            .await
            .with_src_validators(2, 0)
            .await
            .remove_passwords_from_src_vc()
            .mutate_passwords(|passwords| {
                passwords.iter_mut().for_each(|(_, passwords)| {
                    passwords.insert(0, "wrong-password".to_string());
                    passwords.push("wrong-password".to_string());
                })
            })
            .run_test(|_| Validators::All)
            .await
            .assert_ok();
    }

    /// This test simulates a src VC that doesn't know the keystore passwords
    /// and we have not provided the correct password.
    #[should_panic]
    #[tokio::test]
    async fn two_validator_move_all_passwords_removed_without_correct_password() {
        TestBuilder::new()
            .await
            .with_src_validators(2, 0)
            .await
            .remove_passwords_from_src_vc()
            .mutate_passwords(|passwords| {
                passwords
                    .iter_mut()
                    .for_each(|(_, passwords)| *passwords = vec!["wrong-password".to_string()])
            })
            .run_test(|_| Validators::All)
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn one_validator_move_all_with_password_files() {
        TestBuilder::new()
            .await
            .use_password_files()
            .with_src_validators(1, 0)
            .await
            .run_test(|_| Validators::All)
            .await
            .assert_ok();
    }

    #[tokio::test]
    async fn two_validators_move_one_with_identical_password_files() {
        TestBuilder::new()
            .await
            .use_password_files()
            // The password file for validator 0 will be shared with other
            // validators on the src vc.
            .reuse_password_files(0)
            .with_src_validators(2, 0)
            .await
            .run_test(|validators| Validators::Specific(validators[0..1].to_vec()))
            .await
            .assert_ok();
    }
}

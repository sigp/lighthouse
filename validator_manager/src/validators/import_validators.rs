use super::common::*;
use clap::{App, Arg, ArgMatches};
use eth2::{
    lighthouse_vc::{
        http_client::ValidatorClientHttpClient, std_types::ImportKeystoresRequest,
        types::UpdateFeeRecipientRequest,
    },
    SensitiveUrl,
};
use std::fs;
use std::path::PathBuf;

pub const CMD: &str = "import";
pub const VALIDATORS_FILE_FLAG: &str = "validators-file";
pub const VALIDATOR_CLIENT_URL_FLAG: &str = "validator-client-url";
pub const VALIDATOR_CLIENT_TOKEN_FLAG: &str = "validator-client-token";
pub const IGNORE_DUPLICATES_FLAG: &str = "ignore-duplicates";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about(
            "Uploads validators to a validator client using the HTTP API. The validators \
                are defined in a JSON file which can be generated using the \"create-validators\" \
                command.",
        )
        .arg(
            Arg::with_name(VALIDATORS_FILE_FLAG)
                .long(VALIDATORS_FILE_FLAG)
                .value_name("PATH_TO_JSON_FILE")
                .help(
                    "The path to a JSON file containing a list of validators to be \
                    imported to the validator client. This file is usually named \
                    \"validators.json\".",
                )
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(VALIDATOR_CLIENT_URL_FLAG)
                .long(VALIDATOR_CLIENT_URL_FLAG)
                .value_name("HTTP_ADDRESS")
                .help(
                    "A HTTP(S) address of a validator client using the keymanager-API. \
                    If this value is not supplied then a 'dry run' will be conducted where \
                    no changes are made to the validator client.",
                )
                .default_value("http://localhost:5062")
                .requires(VALIDATOR_CLIENT_TOKEN_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(VALIDATOR_CLIENT_TOKEN_FLAG)
                .long(VALIDATOR_CLIENT_TOKEN_FLAG)
                .value_name("PATH")
                .help("The file containing a token required by the validator client.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(IGNORE_DUPLICATES_FLAG)
                .takes_value(false)
                .long(IGNORE_DUPLICATES_FLAG)
                .help(
                    "If present, ignore any validators which already exist on the VC. \
                    Without this flag, the process will terminate without making any changes. \
                    This flag should be used with caution, whilst it does not directly cause \
                    slashable conditions, it might be an indicator that something is amiss. \
                    Users should also be careful to avoid submitting duplicate deposits for \
                    validators that already exist on the VC.",
                ),
        )
}

pub async fn cli_run<'a>(matches: &'a ArgMatches<'a>) -> Result<(), String> {
    let validators_file_path: PathBuf = clap_utils::parse_required(matches, VALIDATORS_FILE_FLAG)?;
    if !validators_file_path.exists() {
        return Err(format!("Unable to find file at {:?}", validators_file_path));
    }

    let validators_file = fs::OpenOptions::new()
        .read(true)
        .create(false)
        .open(&validators_file_path)
        .map_err(|e| format!("Unable to open {:?}: {:?}", validators_file_path, e))?;
    let validators = serde_json::from_reader(&validators_file).map_err(|e| {
        format!(
            "Unable to parse JSON in {:?}: {:?}",
            validators_file_path, e
        )
    })?;

    import_validators(matches, validators).await
}

pub async fn import_validators<'a>(
    matches: &'a ArgMatches<'a>,
    validators: Vec<ValidatorSpecification>,
) -> Result<(), String> {
    let count = validators.len();

    let vc_url: Option<SensitiveUrl> =
        clap_utils::parse_optional(matches, VALIDATOR_CLIENT_URL_FLAG)?;
    let vc_token_path: Option<PathBuf> =
        clap_utils::parse_optional(matches, VALIDATOR_CLIENT_TOKEN_FLAG)?;

    let http_client = match (vc_url, vc_token_path) {
        (Some(vc_url), Some(vc_token_path)) => {
            let token_bytes = fs::read(&vc_token_path)
                .map_err(|e| format!("Failed to read {:?}: {:?}", vc_token_path, e))?;
            let token_string = String::from_utf8(token_bytes)
                .map_err(|e| format!("Failed to parse {:?} as utf8: {:?}", vc_token_path, e))?;
            let http_client = ValidatorClientHttpClient::new(vc_url.clone(), token_string)
                .map_err(|e| {
                    format!(
                        "Could not instantiate HTTP client from URL and secret: {:?}",
                        e
                    )
                })?;

            // Perform a request to check that the connection works
            let remote_keystores = http_client
                .get_keystores()
                .await
                .map_err(|e| format!("Failed to list keystores on VC: {:?}", e))?;
            eprintln!(
                "Validator client is reachable at {} and reports {} validators",
                vc_url,
                remote_keystores.data.len()
            );

            Some(http_client)
        }
        _ => {
            return Err(format!(
                "Inconsistent use of {} and {}",
                VALIDATOR_CLIENT_URL_FLAG, VALIDATOR_CLIENT_TOKEN_FLAG
            ))
        }
    };

    if let Some(http_client) = http_client {
        eprintln!(
            "Starting to submit validators {} to VC, each validator may take several seconds",
            count
        );

        for (i, validator) in validators.into_iter().enumerate() {
            let ValidatorSpecification {
                voting_keystore,
                voting_keystore_password,
                slashing_protection,
                fee_recipient,
                gas_limit,
                builder_proposals,
                enabled,
            } = validator;

            let voting_public_key = voting_keystore
                .public_key()
                .ok_or_else(|| {
                    format!("Validator keystore at index {} is missing a public key", i)
                })?
                .into();

            let request = ImportKeystoresRequest {
                keystores: vec![voting_keystore],
                passwords: vec![voting_keystore_password],
                slashing_protection,
            };

            if let Err(e) = http_client.post_keystores(&request).await {
                eprintln!(
                    "Failed to upload batch {}. Some keys were imported whilst \
                    others may not have been imported. A potential solution is to use the \
                    --{} flag, however care should be taken to ensure that there are no \
                    duplicate deposits submitted.",
                    i, IGNORE_DUPLICATES_FLAG
                );
                // Return here *without* writing the deposit JSON file. This might help prevent
                // users from submitting duplicate deposits or deposits for validators that weren't
                // initialized on a VC.
                //
                // Next the the user runs with the --ignore-duplicates flag there should be a new,
                // complete deposit JSON file created.
                return Err(format!("Key upload failed: {:?}", e));
            }

            if let Some(fee_recipient) = fee_recipient {
                http_client
                    .post_fee_recipient(
                        &voting_public_key,
                        &UpdateFeeRecipientRequest {
                            ethaddress: fee_recipient,
                        },
                    )
                    .await
                    .map_err(|e| format!("Failed to update fee recipient on VC: {:?}", e))?;
            }

            if gas_limit.is_some() || builder_proposals.is_some() || enabled.is_some() {
                http_client
                    .patch_lighthouse_validators(
                        &voting_public_key,
                        enabled,
                        gas_limit,
                        builder_proposals,
                    )
                    .await
                    .map_err(|e| format!("Failed to update lighthouse validator on VC: {:?}", e))?;
            }

            eprintln!("Uploaded keystore {} of {} to the VC", i + 1, count);
        }
    }

    Ok(())
}

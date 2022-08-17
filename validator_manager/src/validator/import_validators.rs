use super::common::*;
use account_utils::{
    random_password_string, read_mnemonic_from_cli, read_password_from_user, ZeroizeString,
};
use clap::{App, Arg, ArgMatches};
use environment::Environment;
use eth2::{
    lighthouse_vc::{
        http_client::ValidatorClientHttpClient,
        std_types::{ImportKeystoresRequest, KeystoreJsonStr},
        types::UpdateFeeRecipientRequest,
    },
    SensitiveUrl,
};
use eth2_keystore::Keystore;
use eth2_wallet::{
    bip39::{Language, Mnemonic},
    WalletBuilder,
};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use types::*;

pub const CMD: &str = "import";
pub const VALIDATORS_FILE_FLAG: &str = "validators-file";
pub const VALIDATOR_CLIENT_URL_FLAG: &str = "validator-client-url";
pub const VALIDATOR_CLIENT_TOKEN_FLAG: &str = "validator-client-token";
pub const IGNORE_DUPLICATES_FLAG: &str = "ignore-duplicates";

struct ValidatorKeystore {
    voting_keystore: Keystore,
    voting_keystore_password: ZeroizeString,
    voting_pubkey_bytes: PublicKeyBytes,
    fee_recipient: Option<Address>,
    gas_limit: Option<u64>,
    builder_proposals: Option<bool>,
    enabled: Option<bool>,
}

struct ValidatorsAndDeposits {
    validators: Vec<ValidatorSpecification>,
    deposits: Option<Vec<StandardDepositDataJson>>,
}

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Uploads validators to a validator client.")
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

pub async fn cli_run<'a, T: EthSpec>(
    matches: &'a ArgMatches<'a>,
    mut env: Environment<T>,
) -> Result<(), String> {
    let spec = &env.core_context().eth2_config.spec;

    let create_spec = build_validator_spec_from_cli(matches, spec)?;
    enact_spec(create_spec, spec).await
}

pub async fn enact_spec<'a>(create_spec: CreateSpec, spec: &ChainSpec) -> Result<(), String> {
    let CreateSpec {
        mnemonic,
        validator_client_url,
        validator_client_token_path,
        json_deposit_data_path,
        ignore_duplicates,
        validators,
    } = create_spec;

    let count = validators.len();

    let mnemonic = Mnemonic::from_phrase(&mnemonic, Language::English)
        .map_err(|e| format!("Failed to parse mnemonic from create spec: {:?}", e))?;

    let http_client = match (validator_client_url, validator_client_token_path) {
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
        (None, None) => None,
        _ => {
            return Err(format!(
                "Inconsistent use of {} and {}",
                VALIDATOR_CLIENT_URL_FLAG, VALIDATOR_CLIENT_TOKEN_FLAG
            ))
        }
    };

    // A random password is always appropriate for the wallet since it is ephemeral.
    let wallet_password = random_password_string();
    // A random password is always appropriate for the withdrawal keystore since we don't ever store
    // it anywhere.
    let withdrawal_keystore_password = random_password_string();

    let mut wallet =
        WalletBuilder::from_mnemonic(&mnemonic, wallet_password.as_ref(), "".to_string())
            .map_err(|e| format!("Unable create seed from mnemonic: {:?}", e))?
            .build()
            .map_err(|e| format!("Unable to create wallet: {:?}", e))?;

    let mut validator_keystores = Vec::with_capacity(count);

    eprintln!("Starting key generation. Each validator may take several seconds.");

    for (i, validator) in validators.into_iter().enumerate() {
        let CreateValidatorSpec {
            voting_keystore,
            voting_keystore_password,
            fee_recipient,
            gas_limit,
            builder_proposals,
            enabled,
        } = validator;

        let voting_keystore = voting_keystore.0;

        let voting_keypair = voting_keystore
            .decrypt_keypair(voting_keystore_password.as_ref())
            .map_err(|e| format!("Failed to decrypt voting keystore {}: {:?}", i, e))?;
        let voting_pubkey_bytes = voting_keypair.pk.clone().into();

        // Check to see if this validator already exists in the VC.
        if let Some(http_client) = &http_client {
            let remote_keystores = http_client
                .get_keystores()
                .await
                .map_err(|e| format!("Failed to list keystores on VC: {:?}", e))?;

            if remote_keystores
                .data
                .iter()
                .find(|keystore| keystore.validating_pubkey == voting_pubkey_bytes)
                .is_some()
            {
                if ignore_duplicates {
                    eprintln!(
                        "Validator {:?} already exists in the VC, be cautious of submitting \
                        duplicate deposits",
                        IGNORE_DUPLICATES_FLAG
                    );
                } else {
                    return Err(format!(
                        "Duplicate validator {:?} detected, see --{} for more information",
                        voting_keypair.pk, IGNORE_DUPLICATES_FLAG
                    ));
                }
            }
        }

        eprintln!(
            "{}/{}: {:?}",
            i.saturating_add(1),
            count,
            &voting_keypair.pk
        );

        validator_keystores.push(ValidatorKeystore {
            voting_keystore,
            voting_keystore_password,
            voting_pubkey_bytes,
            fee_recipient,
            gas_limit,
            builder_proposals,
            enabled,
        });
    }

    if let Some(http_client) = http_client {
        eprintln!(
            "Generated {} keystores. Starting to submit keystores to VC, \
            each keystore may take several seconds",
            count
        );

        for (i, validator_keystore) in validator_keystores.into_iter().enumerate() {
            let ValidatorKeystore {
                voting_keystore,
                voting_keystore_password,
                voting_pubkey_bytes,
                fee_recipient,
                gas_limit,
                builder_proposals,
                enabled,
            } = validator_keystore;

            let request = ImportKeystoresRequest {
                keystores: vec![KeystoreJsonStr(voting_keystore)],
                passwords: vec![voting_keystore_password],
                // New validators have no slashing protection history.
                slashing_protection: None,
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
                        &voting_pubkey_bytes,
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
                        &voting_pubkey_bytes,
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

    // If configured, create a single JSON file which contains deposit data information for all
    // validators.
    if let Some(json_deposit_data_path) = json_deposit_data_path {
        let json_deposits = json_deposits.ok_or("Internal error: JSON deposit data is None")?;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&json_deposit_data_path)
            .map_err(|e| format!("Unable to create {:?}: {:?}", json_deposit_data_path, e))?;

        serde_json::to_writer(&mut file, &json_deposits)
            .map_err(|e| format!("Unable write JSON to {:?}: {:?}", json_deposit_data_path, e))?;
    }

    Ok(())
}

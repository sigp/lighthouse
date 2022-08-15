use super::create::STORE_WITHDRAW_FLAG;
use crate::common::read_mnemonic_from_cli;
use crate::validator::create::COUNT_FLAG;
use crate::wallet::create::STDIN_INPUTS_FLAG;
use crate::SECRETS_DIR_FLAG;
use account_utils::eth2_keystore::{keypair_from_secret, Keystore, KeystoreBuilder};
use account_utils::random_password;
use clap::{App, Arg, ArgMatches};
use directory::ensure_dir_exists;
use directory::{parse_path_or_default_with_flag, DEFAULT_SECRET_DIR};
use environment::Environment;
use eth2_wallet::bip39::Seed;
use eth2_wallet::{recover_validator_secret_from_mnemonic, KeyType, ValidatorKeystores};
use std::fs;
use std::path::PathBuf;
use types::*;
use validator_dir::Builder as ValidatorDirBuilder;

pub const CMD: &str = "recover";
pub const FIRST_INDEX_FLAG: &str = "first-index";
pub const MNEMONIC_FLAG: &str = "mnemonic-path";
pub const JSON_DEPOSIT_DATA_PATH: &str = "json-deposit-data-path";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about(
            "Recovers validator private keys given a BIP-39 mnemonic phrase. \
            If you did not specify a `--first-index` or count `--count`, by default this will \
            only recover the keys associated with the validator at index 0 for an HD wallet \
            in accordance with the EIP-2333 spec.")
        .arg(
            Arg::with_name(FIRST_INDEX_FLAG)
                .long(FIRST_INDEX_FLAG)
                .value_name("FIRST_INDEX")
                .help("The first of consecutive key indexes you wish to recover.")
                .takes_value(true)
                .required(false)
                .default_value("0"),
        )
        .arg(
            Arg::with_name(COUNT_FLAG)
                .long(COUNT_FLAG)
                .value_name("COUNT")
                .help("The number of validator keys you wish to recover. Counted consecutively from the provided `--first_index`.")
                .takes_value(true)
                .required(false)
                .default_value("1"),
        )
        .arg(
            Arg::with_name(MNEMONIC_FLAG)
                .long(MNEMONIC_FLAG)
                .value_name("MNEMONIC_PATH")
                .help(
                    "If present, the mnemonic will be read in from this file.",
                )
                .takes_value(true)
        )
        .arg(
            Arg::with_name(SECRETS_DIR_FLAG)
                .long(SECRETS_DIR_FLAG)
                .value_name("SECRETS_DIR")
                .help(
                    "The path where the validator keystore passwords will be stored. \
                    Defaults to ~/.lighthouse/{network}/secrets",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name(STORE_WITHDRAW_FLAG)
                .long(STORE_WITHDRAW_FLAG)
                .help(
                    "If present, the withdrawal keystore will be stored alongside the voting \
                    keypair. It is generally recommended to *not* store the withdrawal key and \
                    instead generate them from the wallet seed when required.",
                ),
        )
        .arg(
            Arg::with_name(STDIN_INPUTS_FLAG)
                .takes_value(false)
                .hidden(cfg!(windows))
                .long(STDIN_INPUTS_FLAG)
                .help("If present, read all user inputs from stdin instead of tty."),
        )
        .arg(
            Arg::with_name(JSON_DEPOSIT_DATA_PATH)
                .long(JSON_DEPOSIT_DATA_PATH)
                .value_name("PATH")
                .help(
                    "When provided, outputs a JSON file containing deposit data which \
                    is equivalent to the 'deposit-data-*.json' file used by the \
                    staking-deposit-cli tool.",
                )
                .takes_value(true),
        )
}

pub fn cli_run<T: EthSpec>(
    matches: &ArgMatches,
    mut env: Environment<T>,
    validator_dir: PathBuf,
) -> Result<(), String> {
    let spec = env.core_context().eth2_config.spec;

    let secrets_dir = if matches.value_of("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_SECRET_DIR)
    } else {
        parse_path_or_default_with_flag(matches, SECRETS_DIR_FLAG, DEFAULT_SECRET_DIR)?
    };
    let first_index: u32 = clap_utils::parse_required(matches, FIRST_INDEX_FLAG)?;
    let count: u32 = clap_utils::parse_required(matches, COUNT_FLAG)?;
    let mnemonic_path: Option<PathBuf> = clap_utils::parse_optional(matches, MNEMONIC_FLAG)?;
    let stdin_inputs = cfg!(windows) || matches.is_present(STDIN_INPUTS_FLAG);
    let json_deposit_data_path: Option<PathBuf> =
        clap_utils::parse_optional(matches, JSON_DEPOSIT_DATA_PATH)?;

    eprintln!("secrets-dir path: {:?}", secrets_dir);

    ensure_dir_exists(&validator_dir)?;
    ensure_dir_exists(&secrets_dir)?;

    eprintln!();
    eprintln!("WARNING: KEY RECOVERY CAN LEAD TO DUPLICATING VALIDATORS KEYS, WHICH CAN LEAD TO SLASHING.");
    eprintln!();

    let mnemonic = read_mnemonic_from_cli(mnemonic_path, stdin_inputs)?;

    let seed = Seed::new(&mnemonic, "");

    let mut json_deposit_data = Some(vec![]).filter(|_| json_deposit_data_path.is_some());

    for index in first_index..first_index + count {
        let voting_password = random_password();
        let withdrawal_password = random_password();

        let derive = |key_type: KeyType, password: &[u8]| -> Result<Keystore, String> {
            let (secret, path) =
                recover_validator_secret_from_mnemonic(seed.as_bytes(), index, key_type)
                    .map_err(|e| format!("Unable to recover validator keys: {:?}", e))?;

            let keypair = keypair_from_secret(secret.as_bytes())
                .map_err(|e| format!("Unable build keystore: {:?}", e))?;

            KeystoreBuilder::new(&keypair, password, format!("{}", path))
                .map_err(|e| format!("Unable build keystore: {:?}", e))?
                .build()
                .map_err(|e| format!("Unable build keystore: {:?}", e))
        };

        let keystores = ValidatorKeystores {
            voting: derive(KeyType::Voting, voting_password.as_bytes())?,
            withdrawal: derive(KeyType::Withdrawal, withdrawal_password.as_bytes())?,
        };

        let voting_pubkey = keystores.voting.pubkey().to_string();

        let validator_dir = ValidatorDirBuilder::new(validator_dir.clone())
            .password_dir(secrets_dir.clone())
            .voting_keystore(keystores.voting, voting_password.as_bytes())
            .withdrawal_keystore(keystores.withdrawal, withdrawal_password.as_bytes())
            .store_withdrawal_keystore(matches.is_present(STORE_WITHDRAW_FLAG))
            .build()
            .map_err(|e| format!("Unable to build validator directory: {:?}", e))?;

        if let Some(json_deposit_data) = &mut json_deposit_data {
            let standard_deposit_data_json = validator_dir
                .standard_deposit_data_json(&spec)
                .map_err(|e| format!("Unable to create standard JSON deposit data: {:?}", e))?;
            json_deposit_data.push(standard_deposit_data_json);
        }

        println!(
            "{}/{}\tIndex: {}\t0x{}",
            index - first_index,
            count - first_index,
            index,
            voting_pubkey
        );
    }

    // If configured, create a single JSON file which contains deposit data information for all
    // validators.
    if let Some(json_deposit_data_path) = json_deposit_data_path {
        let json_deposit_data =
            json_deposit_data.ok_or("Internal error: JSON deposit data is None")?;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&json_deposit_data_path)
            .map_err(|e| format!("Unable to create {:?}: {:?}", json_deposit_data_path, e))?;

        serde_json::to_writer(&mut file, &json_deposit_data)
            .map_err(|e| format!("Unable write JSON to {:?}: {:?}", json_deposit_data_path, e))?;
    }

    Ok(())
}

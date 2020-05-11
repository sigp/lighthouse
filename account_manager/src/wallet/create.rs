use clap::{App, Arg, ArgMatches};
use eth2_wallet::{
    bip39::{Language, Mnemonic, MnemonicType},
    PlainText,
};
use eth2_wallet_manager::{WalletManager, WalletType};
use rand::{distributions::Alphanumeric, Rng};
use std::fs::{self};
use std::path::PathBuf;
use std::str::from_utf8;
use types::EthSpec;

pub const CMD: &str = "create";
pub const HD_TYPE: &str = "hd";

/// The `Alphanumeric` crate only generates a-Z, A-Z, 0-9, therefore it has a range of 62
/// characters.
///
/// 62**48 is greater than 255**32, therefore this password has more bits of entropy than a byte
/// array of length 32.
const DEFAULT_PASSWORD_LEN: usize = 48;

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Creates a new HD (hierarchical-deterministic) wallet in the --wallet-dir.")
        .arg(
            Arg::with_name("name")
                .long("name")
                .value_name("WALLET_NAME")
                .help(
                    "The wallet will be created with this name. It is not allowed to \
                            create two wallets with the same name for the same --base-dir.",
                )
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("wallet-password")
                .long("wallet-passphrase")
                .value_name("WALLET_PASSWORD_PATH")
                .help(
                    "A path to a file containing the password which will unlock the wallet. \
                            If the file does not exist, a random password will be generated and \
                            saved at that path.",
                )
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("type")
                .long("type")
                .value_name("WALLET_TYPE")
                .help(
                    "The type of wallet to create. Only HD (hierarchical-deterministic) \
                            wallets are supported presently..",
                )
                .takes_value(true)
                .possible_values(&[HD_TYPE])
                .default_value(HD_TYPE),
        )
        .arg(
            Arg::with_name("mnemonic")
                .long("mnemonic")
                .value_name("MNEMONIC_PATH")
                .help(
                    "A path to a file containing the 12-word BIP-39 mnemonic which will form the \
                            base, unencrypted secret of the wallet. The mnemonic can be used \
                            to fully restore the wallet without requiring any other password. \
                            If the file does not exist, a random mnemonic will be generated and \
                            saved at that path. \
                            DO NOT LOSE THE MNEMONIC. DO NOT SHARE THE MNEMONIC.",
                )
                .takes_value(true)
                .required(true),
        )
}

pub fn cli_run<T: EthSpec>(matches: &ArgMatches, base_dir: PathBuf) -> Result<(), String> {
    let name: String = clap_utils::parse_required(matches, "name")?;
    let wallet_password_path: PathBuf = clap_utils::parse_required(matches, "wallet-password")?;
    let type_field: String = clap_utils::parse_required(matches, "type")?;
    let mnemonic_path: PathBuf = clap_utils::parse_required(matches, "mnemonic")?;

    let wallet_type = match type_field.as_ref() {
        HD_TYPE => WalletType::Hd,
        unknown => return Err(format!("--type {} is not supported", unknown)),
    };

    let mgr = WalletManager::open(&base_dir)
        .map_err(|e| format!("Unable to open --base-dir: {:?}", e))?;

    // Create a random mnemonic if the file does not exist.
    if !mnemonic_path.exists() {
        let m = Mnemonic::new(MnemonicType::Words12, Language::English);

        // TODO: better file permissions for this.
        fs::write(&mnemonic_path, m.phrase().as_bytes())
            .map_err(|e| format!("Unable to write to {:?}: {:?}", mnemonic_path, e))?;
    }

    // Create a random password if the file does not exist.
    if !wallet_password_path.exists() {
        let password: PlainText = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(DEFAULT_PASSWORD_LEN)
            .collect::<String>()
            .into_bytes()
            .into();

        // TODO: better file permissions for this.
        fs::write(&wallet_password_path, password.as_bytes())
            .map_err(|e| format!("Unable to write to {:?}: {:?}", mnemonic_path, e))?;
    }

    let mnemonic = fs::read(&mnemonic_path)
        .map_err(|e| format!("Unable to read {:?}: {:?}", mnemonic_path, e))
        .map(|bytes| PlainText::from(bytes))
        .and_then(|plain_text| {
            let s = from_utf8(plain_text.as_bytes())
                .map_err(|e| format!("Mnemonic is not utf8: {:?}", e))?;

            Mnemonic::from_phrase(s, Language::English)
                .map_err(|e| format!("Unable to parse mnemonic: {:?}", e))
        })?;

    let wallet_password = fs::read(&wallet_password_path)
        .map_err(|e| format!("Unable to read {:?}: {:?}", mnemonic_path, e))
        .map(|bytes| PlainText::from(bytes))?;

    let wallet = mgr
        .create_wallet(name, wallet_type, &mnemonic, wallet_password.as_bytes())
        .map_err(|e| format!("Unable to create wallet: {:?}", e))?;

    println!("{}", wallet.wallet().uuid());

    Ok(())
}

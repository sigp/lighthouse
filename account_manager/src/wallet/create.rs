use crate::common::random_password;
use clap::{App, Arg, ArgMatches};
use eth2_wallet::{
    bip39::{Language, Mnemonic, MnemonicType},
    PlainText,
};
use eth2_wallet_manager::{WalletManager, WalletType};
use std::fs::{self, File};
use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const CMD: &str = "create";
pub const HD_TYPE: &str = "hd";

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
            Arg::with_name("wallet-passphrase")
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
            Arg::with_name("mnemonic-output-path")
                .long("mnemonic-output-path")
                .value_name("MNEMONIC_PATH")
                .help(
                    "If present, the mnemonic will be saved to this file. DO NOT SHARE THE MNEMONIC.",
                )
                .takes_value(true)
        )
}

pub fn cli_run(matches: &ArgMatches, base_dir: PathBuf) -> Result<(), String> {
    let name: String = clap_utils::parse_required(matches, "name")?;
    let wallet_password_path: PathBuf = clap_utils::parse_required(matches, "wallet-passphrase")?;
    let mnemonic_output_path: Option<PathBuf> =
        clap_utils::parse_optional(matches, "mnemonic-output-path")?;
    let type_field: String = clap_utils::parse_required(matches, "type")?;

    let wallet_type = match type_field.as_ref() {
        HD_TYPE => WalletType::Hd,
        unknown => return Err(format!("--type {} is not supported", unknown)),
    };

    let mgr = WalletManager::open(&base_dir)
        .map_err(|e| format!("Unable to open --base-dir: {:?}", e))?;

    // Create a new random mnemonic.
    //
    // TODO: what entropy does this use?
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);

    // Create a random password if the file does not exist.
    if !wallet_password_path.exists() {
        create_with_600_perms(&wallet_password_path, random_password().as_bytes())
            .map_err(|e| format!("Unable to write to {:?}: {:?}", wallet_password_path, e))?;
    }

    let wallet_password = fs::read(&wallet_password_path)
        .map_err(|e| format!("Unable to read {:?}: {:?}", wallet_password_path, e))
        .map(|bytes| PlainText::from(bytes))?;

    let wallet = mgr
        .create_wallet(name, wallet_type, &mnemonic, wallet_password.as_bytes())
        .map_err(|e| format!("Unable to create wallet: {:?}", e))?;

    if let Some(path) = mnemonic_output_path {
        create_with_600_perms(&path, mnemonic.phrase().as_bytes())
            .map_err(|e| format!("Unable to write mnemonic to {:?}: {:?}", path, e))?;
    }

    println!("Your wallet's 12-word BIP-39 mnemonic is:");
    println!("");
    println!("\t{}", mnemonic.phrase());
    println!("");
    println!("This mnemonic can be used to fully restore your wallet, should ");
    println!("you lose the JSON file or your password. ");
    println!("");
    println!("It is very important that you DO NOT SHARE this mnemonic as it will ");
    println!("reveal the private keys of all validators and keys generated with  ");
    println!("this wallet. That would be catastrophic.");
    println!("");
    println!("It is also import to store a backup of this mnemonic so you can ");
    println!("recover your private keys in the case of data loss. Writing it on ");
    println!("a piece of paper and storing it in a safe place would be prudent.");
    println!("");
    println!("Your wallet's UUID is:");
    println!("");
    println!("\t{}", wallet.wallet().uuid());
    println!("");
    println!("You do not need to backup your UUID or keep it secret.");

    Ok(())
}

/// Creates a file with `600 (-rw-------)` permissions.
pub fn create_with_600_perms<P: AsRef<Path>>(path: P, bytes: &[u8]) -> Result<(), String> {
    let path = path.as_ref();

    let mut file =
        File::create(&path).map_err(|e| format!("Unable to create {:?}: {}", path, e))?;

    let mut perm = file
        .metadata()
        .map_err(|e| format!("Unable to get {:?} metadata: {}", path, e))?
        .permissions();

    perm.set_mode(0o600);

    file.set_permissions(perm)
        .map_err(|e| format!("Unable to set {:?} permissions: {}", path, e))?;

    file.write_all(bytes)
        .map_err(|e| format!("Unable to write to {:?}: {}", path, e))?;

    Ok(())
}

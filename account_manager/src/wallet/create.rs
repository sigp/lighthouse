use crate::BASE_DIR_FLAG;
use account_utils::{random_password, strip_off_newlines};
use clap::{App, Arg, ArgMatches};
use eth2_wallet_manager::{WalletManager, WalletType};
use std::fs::File;
use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const CMD: &str = "create";
pub const HD_TYPE: &str = "hd";
pub const NAME_FLAG: &str = "name";
pub const PASSPHRASE_FLAG: &str = "passphrase-file";
pub const TYPE_FLAG: &str = "type";
pub const MNEMONIC_FLAG: &str = "mnemonic-output-path";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Creates a new HD (hierarchical-deterministic) EIP-2386 wallet.")
        .arg(
            Arg::with_name(NAME_FLAG)
                .long(NAME_FLAG)
                .value_name("WALLET_NAME")
                .help(
                    "The wallet will be created with this name. It is not allowed to \
                            create two wallets with the same name for the same --base-dir.",
                )
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name(PASSPHRASE_FLAG)
                .long(PASSPHRASE_FLAG)
                .value_name("WALLET_PASSWORD_PATH")
                .help(
                    "A path to a file containing the password which will unlock the wallet. \
                    If the file does not exist, a random password will be generated and \
                    saved at that path. To avoid confusion, if the file does not already \
                    exist it must include a '.pass' suffix.",
                )
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name(TYPE_FLAG)
                .long(TYPE_FLAG)
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
            Arg::with_name(MNEMONIC_FLAG)
                .long(MNEMONIC_FLAG)
                .value_name("MNEMONIC_PATH")
                .help(
                    "If present, the mnemonic will be saved to this file. DO NOT SHARE THE MNEMONIC.",
                )
                .takes_value(true)
        )
}

pub fn cli_run(matches: &ArgMatches, base_dir: PathBuf) -> Result<(), String> {
    let name: String = clap_utils::parse_required(matches, NAME_FLAG)?;
    let wallet_password_path: PathBuf = clap_utils::parse_required(matches, PASSPHRASE_FLAG)?;
    let mnemonic_output_path: Option<PathBuf> = clap_utils::parse_optional(matches, MNEMONIC_FLAG)?;
    let type_field: String = clap_utils::parse_required(matches, TYPE_FLAG)?;

    let wallet_type = match type_field.as_ref() {
        HD_TYPE => WalletType::Hd,
        unknown => return Err(format!("--{} {} is not supported", TYPE_FLAG, unknown)),
    };

    let mgr = WalletManager::open(&base_dir)
        .map_err(|e| format!("Unable to open --{}: {:?}", BASE_DIR_FLAG, e))?;

    let (wallet, mnemonic) = mgr
        .create_wallet_and_secrets(
            name,
            wallet_type,
            wallet_password_path,
            None,
            mnemonic_output_path,
        )
        .map_err(|e| format!("Unable to create wallet: {:?}", e))?;

    let mnemonic = mnemonic.ok_or_else(|| "Failed to generate mnemonic".to_string())?;

    println!("Your wallet's 12-word BIP-39 mnemonic is:");
    println!();
    println!("\t{}", mnemonic.phrase());
    println!();
    println!("This mnemonic can be used to fully restore your wallet, should ");
    println!("you lose the JSON file or your password. ");
    println!();
    println!("It is very important that you DO NOT SHARE this mnemonic as it will ");
    println!("reveal the private keys of all validators and keys generated with  ");
    println!("this wallet. That would be catastrophic.");
    println!();
    println!("It is also important to store a backup of this mnemonic so you can ");
    println!("recover your private keys in the case of data loss. Writing it on ");
    println!("a piece of paper and storing it in a safe place would be prudent.");
    println!();
    println!("Your wallet's UUID is:");
    println!();
    println!("\t{}", wallet.wallet().uuid());
    println!();
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

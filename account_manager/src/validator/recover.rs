use crate::common::read_mnemonic_from_cli;
use crate::validator::cli::Recover;
use account_utils::eth2_keystore::{keypair_from_secret, Keystore, KeystoreBuilder};
use account_utils::random_password;
use clap_utils::GlobalConfig;
use directory::ensure_dir_exists;
use directory::{parse_path_or_default_with_flag, DEFAULT_SECRET_DIR};
use eth2_wallet::bip39::Seed;
use eth2_wallet::{recover_validator_secret_from_mnemonic, KeyType, ValidatorKeystores};
use std::path::PathBuf;
use validator_dir::Builder as ValidatorDirBuilder;

pub const CMD: &str = "recover";
pub const FIRST_INDEX_FLAG: &str = "first-index";
pub const MNEMONIC_FLAG: &str = "mnemonic-path";

pub fn cli_run(
    recover_config: &Recover,
    global_config: &GlobalConfig,
    validator_dir: PathBuf,
) -> Result<(), String> {
    let secrets_dir = if let Some(datadir) = global_config.datadir.as_ref() {
        datadir.join(DEFAULT_SECRET_DIR)
    } else {
        parse_path_or_default_with_flag(
            recover_config.secrets_dir.clone(),
            global_config,
            DEFAULT_SECRET_DIR,
        )?
    };
    let first_index: u32 = recover_config.first_index;
    let count: u32 = recover_config.count;
    let mnemonic_path: Option<PathBuf> = recover_config.mnemonic.clone();
    let stdin_inputs = cfg!(windows) || recover_config.stdin_inputs;

    eprintln!("secrets-dir path: {:?}", secrets_dir);

    ensure_dir_exists(&validator_dir)?;
    ensure_dir_exists(&secrets_dir)?;

    eprintln!();
    eprintln!("WARNING: KEY RECOVERY CAN LEAD TO DUPLICATING VALIDATORS KEYS, WHICH CAN LEAD TO SLASHING.");
    eprintln!();

    let mnemonic = read_mnemonic_from_cli(mnemonic_path, stdin_inputs)?;

    let seed = Seed::new(&mnemonic, "");

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

        ValidatorDirBuilder::new(validator_dir.clone())
            .password_dir(secrets_dir.clone())
            .voting_keystore(keystores.voting, voting_password.as_bytes())
            .withdrawal_keystore(keystores.withdrawal, withdrawal_password.as_bytes())
            .store_withdrawal_keystore(recover_config.store_withdraw)
            .build()
            .map_err(|e| format!("Unable to build validator directory: {:?}", e))?;

        println!(
            "{}/{}\tIndex: {}\t0x{}",
            index - first_index,
            count - first_index,
            index,
            voting_pubkey
        );
    }

    Ok(())
}

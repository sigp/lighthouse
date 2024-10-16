use account_utils::eth2_keystore::{keypair_from_secret, Keystore, KeystoreBuilder};
use account_utils::{random_password, read_mnemonic_from_cli, STDIN_INPUTS_FLAG};
use clap::ArgMatches;
use directory::ensure_dir_exists;
use directory::{parse_path_or_default_with_flag_v2, DEFAULT_SECRET_DIR};
use eth2_wallet::bip39::Seed;
use eth2_wallet::{recover_validator_secret_from_mnemonic, KeyType, ValidatorKeystores};
use std::path::PathBuf;
use validator_dir::Builder as ValidatorDirBuilder;

use super::cli::Recover;

pub fn cli_run(
    recover_config: &Recover,
    matches: &ArgMatches,
    validator_dir: PathBuf,
) -> Result<(), String> {
    let secrets_dir = if matches.get_one::<String>("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_SECRET_DIR)
    } else {
        parse_path_or_default_with_flag_v2(
            matches,
            recover_config.secrets_dir.clone(),
            DEFAULT_SECRET_DIR,
        )?
    };
    let first_index = recover_config.first_index;
    let count = recover_config.count;
    let mnemonic_path = recover_config.mnemonic_path.clone();
    let stdin_inputs = cfg!(windows) || matches.get_flag(STDIN_INPUTS_FLAG);

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
            .store_withdrawal_keystore(recover_config.store_withdrawal_keystore)
            .build()
            .map_err(|e| format!("Unable to build validator directory: {:?}", e))?;

        println!(
            "{}/{}\tIndex: {}\t0x{}",
            index - first_index + 1,
            count,
            index,
            voting_pubkey
        );
    }

    Ok(())
}

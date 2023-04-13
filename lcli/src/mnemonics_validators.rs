use account_utils::eth2_keystore::{keypair_from_secret, Keystore, KeystoreBuilder};
use account_utils::random_password;
use clap::ArgMatches;
use eth2_wallet::bip39::{Language, Mnemonic};
use std::path::PathBuf;
use validator_dir::Builder as ValidatorBuilder;

use eth2_wallet::bip39::Seed;
use eth2_wallet::{recover_validator_secret_from_mnemonic, KeyType, ValidatorKeystores};

/// Generates validator directories with keys derived from the given mnemonic.
pub fn generate_validator_dirs(
    indices: &[usize],
    mnemonic_phrase: &str,
    validators_dir: PathBuf,
    secrets_dir: PathBuf,
) -> Result<(), String> {
    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).map_err(|e| {
        format!(
            "Unable to derive mnemonic from string {:?}: {:?}",
            mnemonic_phrase, e
        )
    })?;

    let seed = Seed::new(&mnemonic, "");

    for index in indices {
        let voting_password = random_password();
        let withdrawal_password = random_password();

        let derive = |key_type: KeyType, password: &[u8]| -> Result<Keystore, String> {
            let (secret, path) =
                recover_validator_secret_from_mnemonic(seed.as_bytes(), *index as u32, key_type)
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

        println!("Validator {}", index + 1);

        ValidatorBuilder::new(validators_dir.clone())
            .password_dir(secrets_dir.clone())
            .store_withdrawal_keystore(true)
            .voting_keystore(keystores.voting, voting_password.as_bytes())
            .build()
            .map_err(|e| format!("Unable to build validator: {:?}", e))?;
    }

    Ok(())
}

pub fn run(matches: &ArgMatches) -> Result<(), String> {
    let validator_count: usize = clap_utils::parse_required(matches, "count")?;
    let base_dir: PathBuf = clap_utils::parse_required(matches, "base-dir")?;
    let node_count: Option<usize> = clap_utils::parse_optional(matches, "node-count")?;
    let mnemonics_phrase: String = clap_utils::parse_required(matches, "mnemonics-phrase")?;
    if let Some(node_count) = node_count {
        let validators_per_node = validator_count / node_count;
        let validator_range = (0..validator_count).collect::<Vec<_>>();
        let indices_range = validator_range
            .chunks(validators_per_node)
            .collect::<Vec<_>>();

        for (i, indices) in indices_range.iter().enumerate() {
            let validators_dir = base_dir.join(format!("node_{}", i + 1)).join("validators");
            let secrets_dir = base_dir.join(format!("node_{}", i + 1)).join("secrets");
            generate_validator_dirs(indices, &mnemonics_phrase, validators_dir, secrets_dir)?;
        }
    } else {
        let validators_dir = base_dir.join("validators");
        let secrets_dir = base_dir.join("secrets");
        generate_validator_dirs(
            (0..validator_count).collect::<Vec<_>>().as_slice(),
            &mnemonics_phrase,
            validators_dir,
            secrets_dir,
        )?;
    }
    Ok(())
}

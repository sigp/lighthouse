use clap::ArgMatches;
use std::fs;
use std::path::PathBuf;
use validator_dir::Builder as ValidatorBuilder;

/// Generates validator directories with INSECURE, deterministic keypairs given the range
/// of indices, validator and secret directories.
pub fn generate_validator_dirs(
    indices: &[usize],
    validators_dir: PathBuf,
    secrets_dir: PathBuf,
) -> Result<(), String> {
    if !validators_dir.exists() {
        fs::create_dir_all(&validators_dir)
            .map_err(|e| format!("Unable to create validators dir: {:?}", e))?;
    }

    if !secrets_dir.exists() {
        fs::create_dir_all(&secrets_dir)
            .map_err(|e| format!("Unable to create secrets dir: {:?}", e))?;
    }

    for i in indices {
        println!("Validator {}", i + 1);

        ValidatorBuilder::new(validators_dir.clone())
            .password_dir(secrets_dir.clone())
            .store_withdrawal_keystore(false)
            .insecure_voting_keypair(*i)
            .map_err(|e| format!("Unable to generate keys: {:?}", e))?
            .build()
            .map_err(|e| format!("Unable to build validator: {:?}", e))?;
    }

    Ok(())
}

pub fn run(matches: &ArgMatches) -> Result<(), String> {
    let validator_count: usize = clap_utils::parse_required(matches, "count")?;
    let base_dir: PathBuf = clap_utils::parse_required(matches, "base-dir")?;
    let node_count: Option<usize> = clap_utils::parse_optional(matches, "node-count")?;
    if let Some(node_count) = node_count {
        let validators_per_node = validator_count / node_count;
        let validator_range = (0..validator_count).collect::<Vec<_>>();
        let indices_range = validator_range
            .chunks(validators_per_node)
            .collect::<Vec<_>>();

        for (i, indices) in indices_range.iter().enumerate() {
            let validators_dir = base_dir.join(format!("node_{}", i + 1)).join("validators");
            let secrets_dir = base_dir.join(format!("node_{}", i + 1)).join("secrets");
            generate_validator_dirs(indices, validators_dir, secrets_dir)?;
        }
    } else {
        let validators_dir = base_dir.join("validators");
        let secrets_dir = base_dir.join("secrets");
        generate_validator_dirs(
            (0..validator_count).collect::<Vec<_>>().as_slice(),
            validators_dir,
            secrets_dir,
        )?;
    }
    Ok(())
}

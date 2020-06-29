use clap::{App, Arg, ArgMatches};
use clap_utils;
use copy_dir::copy_dir;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use types::EthSpec;
use validator_dir::{Error as ValidatorError, Manager as ValidatorManager};

pub const CMD: &str = "move";
pub const SRC_VALIDATORS_FLAG: &str = "src-validators";
pub const SRC_SECRETS_FLAG: &str = "src-secrets";
pub const DST_VALIDATORS_FLAG: &str = "dst-validators";
pub const DST_SECRETS_FLAG: &str = "dst-secrets";
pub const COUNT_FLAG: &str = "count";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("move")
        .visible_aliases(&["mv", CMD])
        .about(
            "Moves one or more validators from one directory into another. \
            It is recommended to use this command instead of manual file-system
            commands since it ensures no files are left behind and respects
            lockfiles.",
        )
        .arg(
            Arg::with_name(SRC_VALIDATORS_FLAG)
                .long(SRC_VALIDATORS_FLAG)
                .value_name("DIRECTORY")
                .help("The source validators directory (e.g., ~/.lighthouse/validators)")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name(SRC_SECRETS_FLAG)
                .long(SRC_SECRETS_FLAG)
                .value_name("DIRECTORY")
                .help("The source secrets directory (e.g., ~/.lighthouse/secrets)")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name(DST_VALIDATORS_FLAG)
                .long(DST_VALIDATORS_FLAG)
                .value_name("DIRECTORY")
                .help("The destination validators directory (e.g., ~/.lighthouse-2/validators)")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name(DST_SECRETS_FLAG)
                .long(DST_SECRETS_FLAG)
                .value_name("DIRECTORY")
                .help("The destination secrets directory (e.g., ~/.lighthouse-2/secrets)")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name(COUNT_FLAG)
                .long(COUNT_FLAG)
                .value_name("VALIDATOR_COUNT")
                .help("The first VALIDATOR_COUNT unlocked validators will be moved.")
                .takes_value(true)
                .required(true),
        )
}

struct ValidatorPaths {
    validator_dir: PathBuf,
    voting_password: PathBuf,
    withdrawal_password: Option<PathBuf>,
}

impl ValidatorPaths {
    pub fn moved_paths<P: AsRef<Path>>(
        &self,
        dst_validators_dir: P,
        dst_secrets_dir: P,
    ) -> Result<Self, String> {
        Ok(ValidatorPaths {
            validator_dir: moved_path(&self.validator_dir, &dst_validators_dir)?,
            voting_password: moved_path(&self.voting_password, &dst_secrets_dir)?,
            withdrawal_password: self
                .withdrawal_password
                .as_ref()
                .map(|src| moved_path(src, dst_secrets_dir))
                .transpose()?,
        })
    }
}

fn moved_path<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> Result<PathBuf, String> {
    let file_name = src
        .as_ref()
        .file_name()
        .ok_or_else(|| format!("Invalid path: {:?}", src.as_ref()))?;
    Ok(dst.as_ref().join(file_name))
}

fn log_failed_to_remove<P: AsRef<Path>, E: Debug>(src: P, e: E) {
    eprintln!(
        "Failed to remove {:?} due to {:?}, continuing to avoid leaving an inconsistent state. \
        It is strongly advise to manually ensure {:?} does not exist!",
        src.as_ref(),
        e,
        src.as_ref(),
    );
}

fn move_dir<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> Result<(), String> {
    let (src, dst) = (src.as_ref(), dst.as_ref());

    match copy_dir(&src, &dst) {
        Ok(_) => {
            if let Err(e) = fs::remove_dir_all(&src) {
                log_failed_to_remove(src, e);
            } else {
                eprintln!("Moved {:?} to {:?}", src, dst);
            }
        }
        Err(e) => {
            // Ignore the error if we're unable to delete the dst dir, we're just doing our
            // best to clean up after an unexpected error.
            let _ = fs::remove_dir_all(&dst);
            return Err(format!("Failed to move {:?} to {:?}: {:?}", src, dst, e));
        }
    }

    Ok(())
}

fn move_file<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> Result<(), String> {
    let (src, dst) = (src.as_ref(), dst.as_ref());

    match fs::copy(&src, &dst) {
        Ok(_) => {
            if let Err(e) = fs::remove_file(&src) {
                log_failed_to_remove(src, e);
            } else {
                eprintln!("Moved {:?} to {:?}", src, dst);
            }
        }
        Err(e) => {
            // Ignore the error if we're unable to delete the dst file, we're just doing our
            // best to clean up after an unexpected error.
            let _ = fs::remove_file(&dst);
            return Err(format!("Failed to move {:?} to {:?}: {:?}", src, dst, e));
        }
    }

    Ok(())
}

pub fn cli_run<T: EthSpec>(matches: &ArgMatches<'_>) -> Result<(), String> {
    let src_validators_dir: PathBuf = clap_utils::parse_required(matches, SRC_VALIDATORS_FLAG)?;
    let src_secrets_dir: PathBuf = clap_utils::parse_required(matches, SRC_SECRETS_FLAG)?;
    let dst_validators_dir: PathBuf = clap_utils::parse_required(matches, DST_VALIDATORS_FLAG)?;
    let dst_secrets_dir: PathBuf = clap_utils::parse_required(matches, DST_SECRETS_FLAG)?;
    let count: usize = clap_utils::parse_required(matches, COUNT_FLAG)?;

    fs::create_dir_all(&dst_validators_dir)
        .map_err(|e| format!("Unable to create {:?}: {:?}", dst_validators_dir, e))?;
    fs::create_dir_all(&dst_secrets_dir)
        .map_err(|e| format!("Unable to create {:?}: {:?}", dst_secrets_dir, e))?;

    let manager = ValidatorManager::open(&src_validators_dir)
        .map_err(|e| format!("Unable to read --{}: {:?}", SRC_VALIDATORS_FLAG, e))?;

    let to_move = manager
        .directory_names()
        .map_err(|e| format!("Unable to iterate --{}: {:?}", SRC_VALIDATORS_FLAG, e))?
        .into_iter()
        .take(count)
        .filter_map(|(_, path)| manager.open_validator(path).ok())
        .map(|v| {
            Ok(ValidatorPaths {
                validator_dir: v.dir().into(),
                voting_password: v.voting_keypair_password_path(&src_secrets_dir)?,
                withdrawal_password: v.withdrawal_keypair_password_path(&src_secrets_dir).ok(),
            })
        })
        .collect::<Result<Vec<_>, ValidatorError>>()
        .map_err(|e| format!("Unable to collect validator passwords: {:?}", e))?;

    if to_move.len() != count {
        return Err(format!(
            "Unable to collect {} unlocked validators, only {}",
            count,
            to_move.len()
        ));
    }

    for src in to_move {
        let dst = src.moved_paths(&dst_validators_dir, &dst_secrets_dir)?;

        move_dir(&src.validator_dir, dst.validator_dir)?;
        move_file(&src.voting_password, &dst.voting_password)?;
        if let Some(src) = src.withdrawal_password {
            let dst = dst
                .withdrawal_password
                .as_ref()
                .ok_or_else(|| "Internal error: withdrawal_password should be Some")?;
            move_file(&src, &dst)?;
        }
    }

    Ok(())
}

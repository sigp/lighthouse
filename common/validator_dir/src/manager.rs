use crate::{Error as ValidatorDirError, ValidatorDir};
use bls::Keypair;
use rayon::prelude::*;
use slog::{info, warn, Logger};
use std::collections::HashMap;
use std::fs::read_dir;
use std::io;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum Error {
    DirectoryDoesNotExist(PathBuf),
    UnableToReadBaseDir(io::Error),
    UnableToReadFile(io::Error),
    ValidatorDirError(ValidatorDirError),
}

/// Manages a directory containing multiple `ValidatorDir` directories.
///
/// ## Example
///
/// ```ignore
/// validators
/// └── 0x91494d3ac4c078049f37aa46934ba8cdf5a9cca6e1b9a9e12403d69d8a2c43a25a7f576df2a5a3d7cb3f45e6aa5e2812
///     ├── eth1_deposit_data.rlp
///     ├── deposit-tx-hash.txt
///     ├── voting-keystore.json
///     └── withdrawal-keystore.json
/// ```
pub struct Manager {
    dir: PathBuf,
}

impl Manager {
    /// Open a directory containing multiple validators.
    ///
    /// Pass the `validators` director as `dir` (see struct-level example).
    pub fn open<P: AsRef<Path>>(dir: P) -> Result<Self, Error> {
        let dir: PathBuf = dir.as_ref().into();

        if dir.exists() {
            Ok(Self { dir })
        } else {
            Err(Error::DirectoryDoesNotExist(dir))
        }
    }

    /// Iterate the nodes in `self.dir`, filtering out things that are unlikely to be a validator
    /// directory.
    fn iter_dir(&self) -> Result<Vec<PathBuf>, Error> {
        read_dir(&self.dir)
            .map_err(Error::UnableToReadBaseDir)?
            .map(|file_res| file_res.map(|f| f.path()))
            // We use `map_or` with `true` here to ensure that we always fail if there is any
            // error.
            .filter(|path_res| path_res.as_ref().map_or(true, |p| p.is_dir()))
            .map(|res| res.map_err(Error::UnableToReadFile))
            .collect()
    }

    /// Open a `ValidatorDir` at the given `path`.
    ///
    /// ## Note
    ///
    /// It is not enforced that `path` is contained in `self.dir`.
    pub fn open_validator<P: AsRef<Path>>(&self, path: P) -> Result<ValidatorDir, Error> {
        ValidatorDir::open(path).map_err(Error::ValidatorDirError)
    }

    /// Opens all the validator directories in `self`.
    ///
    /// ## Errors
    ///
    /// Returns an error if any of the directories is unable to be opened, perhaps due to a
    /// file-system error or directory with an active lockfile.
    pub fn open_all_validators(&self) -> Result<Vec<ValidatorDir>, Error> {
        self.iter_dir()?
            .into_iter()
            .map(|path| ValidatorDir::open(path).map_err(Error::ValidatorDirError))
            .collect()
    }

    /// Opens all the validator directories in `self` and decrypts the validator keypairs,
    /// regardless if a lockfile exists or not.
    ///
    /// If `log.is_some()`, an `info` log will be generated for each decrypted validator.
    /// Additionally, a warning log will be created if a lockfile existed already.
    ///
    /// ## Errors
    ///
    /// Returns an error if any of the directories is unable to be opened.
    pub fn force_decrypt_all_validators(
        &self,
        secrets_dir: PathBuf,
        log_opt: Option<&Logger>,
    ) -> Result<Vec<(Keypair, ValidatorDir)>, Error> {
        self.iter_dir()?
            .into_par_iter()
            .map(|path| {
                ValidatorDir::force_open(path)
                    .and_then(|(v, existed)| {
                        v.voting_keypair(&secrets_dir).map(|kp| (kp, v, existed))
                    })
                    .map(|(kp, v, lockfile_existed)| {
                        if let Some(log) = log_opt {
                            info!(
                                log,
                                "Decrypted validator keystore";
                                "voting_pubkey" => kp.pk.to_hex_string()
                            );
                            if lockfile_existed {
                                warn!(
                                    log,
                                    "Lockfile already existed";
                                    "msg" => "ensure no other validator client is running on this host",
                                    "voting_pubkey" => kp.pk.to_hex_string()
                                );
                            }
                        }
                        (kp, v)
                    })
                    .map_err(Error::ValidatorDirError)
            })
            .collect()
    }

    /// Opens all the validator directories in `self` and decrypts the validator keypairs.
    ///
    /// If `log.is_some()`, an `info` log will be generated for each decrypted validator.
    ///
    /// ## Errors
    ///
    /// Returns an error if any of the directories is unable to be opened.
    pub fn decrypt_all_validators(
        &self,
        secrets_dir: PathBuf,
        log_opt: Option<&Logger>,
    ) -> Result<Vec<(Keypair, ValidatorDir)>, Error> {
        self.iter_dir()?
            .into_par_iter()
            .map(|path| {
                ValidatorDir::open(path)
                    .and_then(|v| v.voting_keypair(&secrets_dir).map(|kp| (kp, v)))
                    .map(|(kp, v)| {
                        if let Some(log) = log_opt {
                            info!(
                                log,
                                "Decrypted validator keystore";
                                "voting_pubkey" => kp.pk.to_hex_string()
                            )
                        }
                        (kp, v)
                    })
                    .map_err(Error::ValidatorDirError)
            })
            .collect()
    }

    /// Returns a map of directory name to full directory path. E.g., `myval -> /home/vals/myval`.
    /// Filters out nodes in `self.dir` that are unlikely to be a validator directory.
    ///
    /// ## Errors
    ///
    /// Returns an error if a directory is unable to be read.
    pub fn directory_names(&self) -> Result<HashMap<String, PathBuf>, Error> {
        Ok(HashMap::from_iter(
            self.iter_dir()?
                .into_iter()
                .map(|path| (format!("{:?}", path), path)),
        ))
    }
}

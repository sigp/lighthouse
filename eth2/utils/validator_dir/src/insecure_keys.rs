//! These features exist to allow for generating deterministic, well-known, unsafe keys for use in
//! testing.
//!
//! **NEVER** use these keys in production!
#![cfg(feature = "insecure_keys")]

use crate::{Builder, BuilderError};
use eth2_keystore::{Keystore, KeystoreBuilder, PlainText};
use std::path::PathBuf;
use types::test_utils::generate_deterministic_keypair;

/// A very weak password with which to encrypt the keystores.
pub const INSECURE_PASSWORD: &[u8] = &[30; 32];

impl<'a> Builder<'a> {
    /// Generate the voting and withdrawal keystores using deterministic, well-known, **unsafe**
    /// keypairs.
    ///
    /// **NEVER** use these keys in production!
    pub fn insecure_keys(mut self, deterministic_key_index: usize) -> Result<Self, BuilderError> {
        self.voting_keystore = Some(
            generate_deterministic_keystore(deterministic_key_index)
                .map_err(BuilderError::InsecureKeysError)?,
        );
        self.withdrawal_keystore = Some(
            generate_deterministic_keystore(deterministic_key_index)
                .map_err(BuilderError::InsecureKeysError)?,
        );
        Ok(self)
    }
}

/// Generate a keystore, encrypted with `INSECURE_PASSWORD` using a deterministic, well-known,
/// **unsafe** secret key.
///
/// **NEVER** use these keys in production!
pub fn generate_deterministic_keystore(i: usize) -> Result<(Keystore, PlainText), String> {
    let keypair = generate_deterministic_keypair(i);

    let keystore = KeystoreBuilder::new(&keypair, INSECURE_PASSWORD, "".into())
        .map_err(|e| format!("Unable to create keystore builder: {:?}", e))?
        .build()
        .map_err(|e| format!("Unable to build keystore: {:?}", e))?;

    Ok((keystore, INSECURE_PASSWORD.to_vec().into()))
}

/// A helper function to use the `Builder` to generate deterministic, well-known, **unsafe**
/// validator directories for the given validator `indices`.
///
/// **NEVER** use these keys in production!
pub fn build_deterministic_validator_dirs(
    validators_dir: PathBuf,
    password_dir: PathBuf,
    indices: &[usize],
) -> Result<(), String> {
    for &i in indices {
        Builder::new(validators_dir.clone(), password_dir.clone())
            .insecure_keys(i)
            .map_err(|e| format!("Unable to generate insecure keypair: {:?}", e))?
            .store_withdrawal_keystore(false)
            .build()
            .map_err(|e| format!("Unable to build keystore: {:?}", e))?;
    }

    Ok(())
}

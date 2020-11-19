//! These features exist to allow for generating deterministic, well-known, unsafe keys for use in
//! testing.
//!
//! **NEVER** use these keys in production!
#![cfg(feature = "insecure_keys")]

use crate::{Builder, BuilderError};
use eth2_keystore::{
    json_keystore::{Kdf, Scrypt},
    Keystore, KeystoreBuilder, PlainText, DKLEN,
};
use std::path::PathBuf;
use types::test_utils::generate_deterministic_keypair;

/// A very weak password with which to encrypt the keystores.
pub const INSECURE_PASSWORD: &[u8] = &[50; 51];

impl<'a> Builder<'a> {
    /// Generate the voting keystore using a deterministic, well-known, **unsafe** keypair.
    ///
    /// **NEVER** use these keys in production!
    pub fn insecure_voting_keypair(
        mut self,
        deterministic_key_index: usize,
    ) -> Result<Self, BuilderError> {
        self.voting_keystore = Some(
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
        .kdf(insecure_kdf())
        .build()
        .map_err(|e| format!("Unable to build keystore: {:?}", e))?;

    Ok((keystore, INSECURE_PASSWORD.to_vec().into()))
}

/// Returns an INSECURE key derivation function.
///
/// **NEVER** use this KDF in production!
fn insecure_kdf() -> Kdf {
    Kdf::Scrypt(Scrypt {
        dklen: DKLEN,
        // `n` is set very low, making it cheap to encrypt/decrypt keystores.
        //
        // This is very insecure, only use during testing.
        n: 2,
        p: 1,
        r: 8,
        salt: vec![1; 32].into(),
    })
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
        Builder::new(validators_dir.clone())
            .password_dir(password_dir.clone())
            .insecure_voting_keypair(i)
            .map_err(|e| format!("Unable to generate insecure keypair: {:?}", e))?
            .store_withdrawal_keystore(false)
            .build()
            .map_err(|e| format!("Unable to build keystore: {:?}", e))?;
    }

    Ok(())
}

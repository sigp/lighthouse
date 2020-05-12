#![cfg(feature = "insecure_keys")]

use crate::{Builder, BuilderError};
use eth2_keystore::{Keystore, KeystoreBuilder, PlainText};
use std::path::PathBuf;
use types::test_utils::generate_deterministic_keypair;

const INSECURE_PASSWORD: &[u8] = &[30; 32];

impl<'a> Builder<'a> {
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

pub fn generate_deterministic_keystore(i: usize) -> Result<(Keystore, PlainText), String> {
    let keypair = generate_deterministic_keypair(i);

    let keystore = KeystoreBuilder::new(&keypair, INSECURE_PASSWORD, "".into())
        .map_err(|e| format!("Unable to create keystore builder: {:?}", e))?
        .build()
        .map_err(|e| format!("Unable to build keystore: {:?}", e))?;

    Ok((keystore, INSECURE_PASSWORD.to_vec().into()))
}

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

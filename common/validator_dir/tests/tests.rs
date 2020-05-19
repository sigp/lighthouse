#![cfg(not(debug_assertions))]

use eth2_keystore::{Keystore, KeystoreBuilder, PlainText};
use std::fs::{self, File};
use std::path::Path;
use tempfile::{tempdir, TempDir};
use types::{test_utils::generate_deterministic_keypair, EthSpec, Keypair, MainnetEthSpec};
use validator_dir::{
    Builder, ValidatorDir, ETH1_DEPOSIT_TX_HASH_FILE, VOTING_KEYSTORE_FILE,
    WITHDRAWAL_KEYSTORE_FILE,
};

/// A very weak password with which to encrypt the keystores.
pub const INSECURE_PASSWORD: &[u8] = &[30; 32];

/// Helper struct for configuring tests.
struct BuildConfig {
    random_voting_keystore: bool,
    random_withdrawal_keystore: bool,
    deposit_amount: Option<u64>,
    store_withdrawal_keystore: bool,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            random_voting_keystore: true,
            random_withdrawal_keystore: true,
            deposit_amount: None,
            store_withdrawal_keystore: true,
        }
    }
}

/// Check that a keystore exists and can be decrypted with a password in password_dir
fn check_keystore<P: AsRef<Path>>(path: P, password_dir: P) -> Keypair {
    let mut file = File::open(path).unwrap();
    let keystore = Keystore::from_json_reader(&mut file).unwrap();
    let pubkey = keystore.pubkey();
    let password_path = password_dir.as_ref().join(format!("0x{}", pubkey));
    let password = fs::read(password_path).unwrap();
    keystore.decrypt_keypair(&password).unwrap()
}

/// Creates a keystore using `generate_deterministic_keypair`.
pub fn generate_deterministic_keystore(i: usize) -> Result<(Keystore, PlainText), String> {
    let keypair = generate_deterministic_keypair(i);

    let keystore = KeystoreBuilder::new(&keypair, INSECURE_PASSWORD, "".into())
        .map_err(|e| format!("Unable to create keystore builder: {:?}", e))?
        .build()
        .map_err(|e| format!("Unable to build keystore: {:?}", e))?;

    Ok((keystore, INSECURE_PASSWORD.to_vec().into()))
}

/// A testing harness for generating validator directories.
struct Harness {
    validators_dir: TempDir,
    password_dir: TempDir,
}

impl Harness {
    /// Create a new harness using temporary directories.
    pub fn new() -> Self {
        Self {
            validators_dir: tempdir().unwrap(),
            password_dir: tempdir().unwrap(),
        }
    }

    /// Create a `ValidatorDir` from the `config`, then assert that the `ValidatorDir` was generated
    /// correctly with respect to the `config`.
    pub fn create_and_test(&self, config: &BuildConfig) -> ValidatorDir {
        let spec = MainnetEthSpec::default_spec();

        /*
         * Build the `ValidatorDir`.
         */

        let builder = Builder::new(
            self.validators_dir.path().into(),
            self.password_dir.path().into(),
        )
        .store_withdrawal_keystore(config.store_withdrawal_keystore);

        let builder = if config.random_voting_keystore {
            builder
        } else {
            let (keystore, password) = generate_deterministic_keystore(0).unwrap();
            builder.voting_keystore(keystore, password.as_bytes())
        };

        let builder = if config.random_withdrawal_keystore {
            builder
        } else {
            let (keystore, password) = generate_deterministic_keystore(1).unwrap();
            builder.withdrawal_keystore(keystore, password.as_bytes())
        };

        let builder = if let Some(amount) = config.deposit_amount {
            builder.create_eth1_tx_data(amount, &spec)
        } else {
            builder
        };

        let mut validator = builder.build().unwrap();

        /*
         * Assert that the dir is consistent with the config.
         */

        let withdrawal_keystore_path = validator.dir().join(WITHDRAWAL_KEYSTORE_FILE);
        let password_dir = self.password_dir.path().into();

        // Ensure the voting keypair exists and can be decrypted.
        let voting_keypair =
            check_keystore(&validator.dir().join(VOTING_KEYSTORE_FILE), &password_dir);

        if !config.random_voting_keystore {
            assert_eq!(voting_keypair.pk, generate_deterministic_keypair(0).pk)
        }

        // Use OR here instead of AND so we *always* check for the withdrawal keystores if random
        // keystores were generated.
        if config.random_withdrawal_keystore || config.store_withdrawal_keystore {
            // Ensure the withdrawal keypair exists and can be decrypted.
            let withdrawal_keypair = check_keystore(&withdrawal_keystore_path, &password_dir);

            if !config.random_withdrawal_keystore {
                assert_eq!(withdrawal_keypair.pk, generate_deterministic_keypair(1).pk)
            }

            // The withdrawal keys should be distinct from the voting keypairs.
            assert_ne!(withdrawal_keypair.pk, voting_keypair.pk);
        }

        if !config.store_withdrawal_keystore && !config.random_withdrawal_keystore {
            assert!(!withdrawal_keystore_path.exists())
        }

        if let Some(amount) = config.deposit_amount {
            // Check that the deposit data can be decoded.
            let data = validator.eth1_deposit_data().unwrap().unwrap();

            // Ensure the amount is consistent.
            assert_eq!(data.deposit_data.amount, amount);
        } else {
            // If there was no deposit then we should return `Ok(None)`.
            assert!(validator.eth1_deposit_data().unwrap().is_none());
        }

        let tx_hash_path = validator.dir().join(ETH1_DEPOSIT_TX_HASH_FILE);

        // The eth1 deposit file should not exist, yet.
        assert!(!tx_hash_path.exists());

        let tx = "junk data";

        // Save a tx hash.
        validator.save_eth1_deposit_tx_hash(tx).unwrap();

        // Ensure the saved tx hash is correct.
        assert_eq!(fs::read(tx_hash_path).unwrap(), tx.as_bytes().to_vec());

        // Saving a second tx hash should fail.
        validator.save_eth1_deposit_tx_hash(tx).unwrap_err();

        validator
    }
}

#[test]
fn concurrency() {
    let harness = Harness::new();

    let val_dir = harness.create_and_test(&BuildConfig::default());
    let path = val_dir.dir().clone();

    // Should not re-open whilst opened after build.
    ValidatorDir::open(&path).unwrap_err();

    drop(val_dir);

    // Should re-open after drop.
    let val_dir = ValidatorDir::open(&path).unwrap();

    // Should not re-open when opened via ValidatorDir.
    ValidatorDir::open(&path).unwrap_err();

    drop(val_dir);

    // Should re-open again.
    ValidatorDir::open(&path).unwrap();
}

#[test]
fn deterministic_voting_keystore() {
    let harness = Harness::new();

    let config = BuildConfig {
        random_voting_keystore: false,
        ..BuildConfig::default()
    };

    harness.create_and_test(&config);
}

#[test]
fn deterministic_withdrawal_keystore_without_saving() {
    let harness = Harness::new();

    let config = BuildConfig {
        random_withdrawal_keystore: false,
        store_withdrawal_keystore: false,
        ..BuildConfig::default()
    };

    harness.create_and_test(&config);
}

#[test]
fn deterministic_withdrawal_keystore_with_saving() {
    let harness = Harness::new();

    let config = BuildConfig {
        random_withdrawal_keystore: false,
        store_withdrawal_keystore: true,
        ..BuildConfig::default()
    };

    harness.create_and_test(&config);
}

#[test]
fn both_keystores_deterministic_without_saving() {
    let harness = Harness::new();

    let config = BuildConfig {
        random_voting_keystore: false,
        random_withdrawal_keystore: false,
        store_withdrawal_keystore: false,
        ..BuildConfig::default()
    };

    harness.create_and_test(&config);
}

#[test]
fn both_keystores_deterministic_with_saving() {
    let harness = Harness::new();

    let config = BuildConfig {
        random_voting_keystore: false,
        random_withdrawal_keystore: false,
        store_withdrawal_keystore: true,
        ..BuildConfig::default()
    };

    harness.create_and_test(&config);
}

#[test]
fn eth1_data() {
    let harness = Harness::new();

    let config = BuildConfig {
        deposit_amount: Some(123456),
        ..BuildConfig::default()
    };

    harness.create_and_test(&config);
}

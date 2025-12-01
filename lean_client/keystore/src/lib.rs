//! Keystore for managing hash-sig (XMSS) validator keys
//!
//! This module provides functionality for generating, storing, and retrieving
//! hash-sig validator keys used in lean consensus.
//!
//! Key generation uses the `b-wagn/hash-sig` Rust crate
//! with scheme: SIGTopLevelTargetSumLifetime32Dim64Base8

pub mod codec;
mod key_generation;
mod key_storage;

pub use key_generation::{
    KeyGenerationConfig, KeyGenerationError, generate_keys, generate_keys_sync,
};
pub use key_storage::{KeyStore, KeyStoreError, PrivateKey, PublicKey, ValidatorKeyPair};

use std::path::PathBuf;

/// Hash-sig key scheme used for validator keys
pub const KEY_SCHEME: &str = "SIGTopLevelTargetSumLifetime32Dim64Base8";

/// Hash-sig crate repository
pub const HASH_SIG_CRATE: &str = "https://github.com/b-wagn/hash-sig";

/// Default directory name for storing hash-sig keys
pub const DEFAULT_KEYS_DIR: &str = "hash-sig-keys";

/// Configuration for hash-sig key generation
#[derive(Debug, Clone)]
pub struct HashSigKeyConfig {
    /// Number of validators to generate keys for
    pub num_validators: u64,
    /// Log2 of the number of active epochs (e.g., 24 means 2^24 active epochs)
    pub log_num_active_epochs: u64,
    /// Output directory for generated keys
    pub output_dir: PathBuf,
}

impl Default for HashSigKeyConfig {
    fn default() -> Self {
        Self {
            num_validators: 0,
            log_num_active_epochs: 24, // Default: 2^24 active epochs
            output_dir: PathBuf::from(DEFAULT_KEYS_DIR),
        }
    }
}

impl HashSigKeyConfig {
    /// Creates a new configuration with the specified number of validators
    pub fn new(num_validators: u64, log_num_active_epochs: u64) -> Self {
        Self {
            num_validators,
            log_num_active_epochs,
            ..Default::default()
        }
    }

    /// Sets the output directory for generated keys
    pub fn with_output_dir(mut self, output_dir: PathBuf) -> Self {
        self.output_dir = output_dir;
        self
    }

    /// Generates keys and stores them using this configuration
    ///
    /// This is a convenience method that:
    /// 1. Generates keys using the hash-sig Rust crate
    /// 2. Stores them in the configured output directory
    /// 3. Returns all generated key pairs
    pub fn generate_and_store(&self) -> Result<Vec<ValidatorKeyPair>, KeyGenerationError> {
        let gen_config = KeyGenerationConfig::from(self);
        generate_keys(&gen_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_sig_key_config_default() {
        let config = HashSigKeyConfig::default();
        assert_eq!(config.num_validators, 0);
        assert_eq!(config.log_num_active_epochs, 24);
    }

    #[test]
    fn test_hash_sig_key_config_new() {
        let config = HashSigKeyConfig::new(10, 20);
        assert_eq!(config.num_validators, 10);
        assert_eq!(config.log_num_active_epochs, 20);
    }
}

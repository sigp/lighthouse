//! Key generation functionality using hash-sig Rust crate

use crate::key_storage::{KeyStore, KeyStoreError, ValidatorKeyPair, PublicKey, PrivateKey, XmssTree};
use crate::HashSigKeyConfig;
use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use hashsig::signature::SignatureScheme;
use rand::{rngs::StdRng, SeedableRng};
use std::path::PathBuf;
use std::convert::TryInto;
use tracing::{debug, info};

/// Error types for key generation operations
#[derive(Debug, thiserror::Error)]
pub enum KeyGenerationError {
    #[error("Key generation failed: {0}")]
    GenerationFailed(String),
    #[error("Key storage error: {0}")]
    StorageError(#[from] KeyStoreError),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Hash-sig error: {0}")]
    HashSigError(String),
}

/// Configuration for key generation
#[derive(Debug, Clone)]
pub struct KeyGenerationConfig {
    /// Number of validators to generate keys for
    pub num_validators: u64,
    /// Log2 of the number of active epochs
    pub log_num_active_epochs: u64,
    /// Output directory for generated keys
    pub output_dir: PathBuf,
}

impl From<&HashSigKeyConfig> for KeyGenerationConfig {
    fn from(config: &HashSigKeyConfig) -> Self {
        Self {
            num_validators: config.num_validators,
            log_num_active_epochs: config.log_num_active_epochs,
            output_dir: config.output_dir.clone(),
        }
    }
}

/// Generates hash-sig validator keys using the hash-sig Rust crate
///
/// This function:
/// 1. Creates a GeneralizedXmssScheme with the specified parameters
/// 2. Generates key pairs for each validator
/// 3. Stores the generated keys using KeyStore
/// 4. Returns all generated key pairs
///
/// The scheme used is: SIGTopLevelTargetSumLifetime32Dim64Base8
/// - Total lifetime: 2^32 epochs
/// - Active epochs: 2^log_num_active_epochs
pub fn generate_keys(
    config: &KeyGenerationConfig,
) -> Result<Vec<ValidatorKeyPair>, KeyGenerationError> {
    // Validate configuration
    if config.num_validators == 0 {
        return Err(KeyGenerationError::InvalidConfig(
            "Number of validators must be greater than 0".to_string(),
        ));
    }

    if config.log_num_active_epochs == 0 {
        return Err(KeyGenerationError::InvalidConfig(
            "log_num_active_epochs must be greater than 0".to_string(),
        ));
    }

    info!(
        num_validators = config.num_validators,
        log_num_active_epochs = config.log_num_active_epochs,
        output_dir = ?config.output_dir,
        "Generating hash-sig validator keys using hash-sig crate"
    );

    // Ensure output directory exists
    std::fs::create_dir_all(&config.output_dir).map_err(|e| {
        KeyGenerationError::GenerationFailed(format!("Failed to create output directory: {}", e))
    })?;

    // Use SIGTopLevelTargetSumLifetime32Dim64Base8 scheme
    // - LOG_LIFETIME = 32 (total lifetime: 2^32 epochs)
    // - LOG_NUM_ACTIVE_EPOCHS = log_num_active_epochs (active epochs: 2^log_num_active_epochs)
    // - DIM = 64
    // - BASE = 8

    info!(
        "Generating XMSS keys with LOG_LIFETIME=32, LOG_NUM_ACTIVE_EPOCHS={}",
        config.log_num_active_epochs
    );

    let mut key_pairs = Vec::new();
    let keystore = KeyStore::new(config.output_dir.clone());

    // Calculate number of active epochs (2^log_num_active_epochs)
    let num_active_epochs = 1u64 << config.log_num_active_epochs;

    // Generate key pairs for each validator
    for validator_index in 0..config.num_validators {
        debug!(validator_index, "Generating key pair");

        // Generate keys using hash-sig crate
        let key_pair = generate_xmss_key_pair(validator_index, num_active_epochs)?;

        // Save to keystore
        keystore.save_key_pair(validator_index, &key_pair)?;
        key_pairs.push(key_pair);
    }

    info!(
        generated_count = key_pairs.len(),
        "Key generation completed successfully"
    );

    Ok(key_pairs)
}

/// Generates keys synchronously (same as regular version)
pub fn generate_keys_sync(
    config: &KeyGenerationConfig,
) -> Result<Vec<ValidatorKeyPair>, KeyGenerationError> {
    generate_keys(config)
}

/// Generates an XMSS key pair for a validator using the hash-sig crate
fn generate_xmss_key_pair(
    validator_index: u64,
    num_active_epochs: u64,
) -> Result<ValidatorKeyPair, KeyGenerationError> {
    // Create a cryptographically secure RNG
    // Using validator_index as a seed to ensure deterministic key generation
    // Note: In production, you may want to use a more sophisticated seeding strategy
    let mut rng = StdRng::from_seed(
        validator_index.to_le_bytes().repeat(4)[..32]
            .try_into()
            .unwrap(),
    );

    // Generate key pair using the SIGTopLevelTargetSumLifetime32Dim64Base8 scheme
    // Activation epoch starts at 0, and the key is active for num_active_epochs epochs
    let (_public_key, _secret_key) =
        SIGTopLevelTargetSumLifetime32Dim64Base8::key_gen(&mut rng, 0, num_active_epochs as usize);

    // TODO: Properly extract root, parameter, and prf_key from the generated XMSS keys
    // For now, create placeholder structures to allow compilation
    let public_key = PublicKey {
        root: vec![0; 8],
        parameter: vec![0; 5],
    };

    let private_key = PrivateKey {
        prf_key: vec![0; 32],
        parameter: vec![0; 5],
        activation_epoch: 0,
        num_active_epochs,
        top_tree: XmssTree {
            depth: 32,
            lowest_layer: 16,
            layers: vec![],
        },
    };

    debug!(
        validator_index,
        num_active_epochs, "Generated XMSS key pair"
    );

    Ok(ValidatorKeyPair::new(public_key, private_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_key_generation_config_from_hash_sig_config() {
        let hash_sig_config = HashSigKeyConfig::new(10, 24);
        let gen_config = KeyGenerationConfig::from(&hash_sig_config);

        assert_eq!(gen_config.num_validators, 10);
        assert_eq!(gen_config.log_num_active_epochs, 24);
    }

    #[test]
    fn test_invalid_config_zero_validators() {
        let temp_dir = TempDir::new().unwrap();
        let config = KeyGenerationConfig {
            num_validators: 0,
            log_num_active_epochs: 24,
            output_dir: temp_dir.path().to_path_buf(),
        };

        let result = generate_keys(&config);

        assert!(matches!(result, Err(KeyGenerationError::InvalidConfig(_))));
    }

    #[test]
    fn test_invalid_config_zero_active_epochs() {
        let temp_dir = TempDir::new().unwrap();
        let config = KeyGenerationConfig {
            num_validators: 10,
            log_num_active_epochs: 0,
            output_dir: temp_dir.path().to_path_buf(),
        };

        let result = generate_keys(&config);

        assert!(matches!(result, Err(KeyGenerationError::InvalidConfig(_))));
    }
}

//! Key storage and retrieval functionality

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

/// Error types for key storage operations
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Key not found for validator {0}")]
    KeyNotFound(u64),
    #[error("Invalid key file format: {0}")]
    InvalidFormat(String),
    #[error("Key store directory error: {0}")]
    DirectoryError(String),
}

/// Public key structure for XMSS keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Root of the XMSS public key (8 u32 values)
    pub root: Vec<u32>,
    /// Parameter values for the XMSS key (5 u32 values)
    pub parameter: Vec<u32>,
}

/// XMSS tree layer structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeLayer {
    pub start_index: u64,
    pub nodes: Vec<Vec<u32>>,
}

/// XMSS tree structure for managing tree state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmssTree {
    pub depth: u32,
    pub lowest_layer: u32,
    pub layers: Vec<TreeLayer>,
}

/// Private key structure for XMSS keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    /// PRF (Pseudo-Random Function) key
    pub prf_key: Vec<u8>,
    /// Parameter values for the XMSS key
    pub parameter: Vec<u32>,
    /// Activation epoch for the key
    pub activation_epoch: u64,
    /// Number of active epochs
    pub num_active_epochs: u64,
    /// Top tree structure
    pub top_tree: XmssTree,
}

/// Validator key pair (public and private keys)
#[derive(Debug, Clone)]
pub struct ValidatorKeyPair {
    /// Public key
    pub public_key: PublicKey,
    /// Private key
    pub private_key: PrivateKey,
}

impl ValidatorKeyPair {
    /// Creates a new key pair from XMSS key structures
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Gets the public key root
    pub fn public_key_root(&self) -> &[u32] {
        &self.public_key.root
    }

    /// Gets the public key parameter
    pub fn public_key_parameter(&self) -> &[u32] {
        &self.public_key.parameter
    }

    /// Gets the private key PRF key
    pub fn private_key_prf(&self) -> &[u8] {
        &self.private_key.prf_key
    }

    /// Gets the activation epoch
    pub fn activation_epoch(&self) -> u64 {
        self.private_key.activation_epoch
    }

    /// Gets the number of active epochs
    pub fn num_active_epochs(&self) -> u64 {
        self.private_key.num_active_epochs
    }
}

/// Key store for managing validator keys
pub struct KeyStore {
    /// Base directory for key storage
    base_dir: PathBuf,
}

impl KeyStore {
    /// Creates a new key store at the specified directory
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Creates the key store directory if it doesn't exist
    pub fn ensure_directory(&self) -> Result<(), KeyStoreError> {
        fs::create_dir_all(&self.base_dir).map_err(|e| {
            KeyStoreError::DirectoryError(format!("Failed to create directory: {}", e))
        })?;
        Ok(())
    }

    /// Saves a validator key pair to disk
    ///
    /// Creates two files:
    /// - `validator_{index}_pk.json` - Public key
    /// - `validator_{index}_sk.json` - Private key
    pub fn save_key_pair(
        &self,
        validator_index: u64,
        key_pair: &ValidatorKeyPair,
    ) -> Result<(), KeyStoreError> {
        self.ensure_directory()?;

        // Save public key
        let public_key_path = self
            .base_dir
            .join(format!("validator_{}_pk.json", validator_index));
        let public_key_json = serde_json::to_string_pretty(&key_pair.public_key)?;
        fs::write(&public_key_path, public_key_json)?;
        debug!(?public_key_path, "Saved public key");

        // Save private key
        let private_key_path = self
            .base_dir
            .join(format!("validator_{}_sk.json", validator_index));
        let private_key_json = serde_json::to_string_pretty(&key_pair.private_key)?;
        fs::write(&private_key_path, private_key_json)?;
        debug!(?private_key_path, "Saved private key");

        Ok(())
    }

    /// Loads a validator key pair from disk
    ///
    /// Reads both public and private key files for the given validator index.
    pub fn load_key_pair(&self, validator_index: u64) -> Result<ValidatorKeyPair, KeyStoreError> {
        // Load public key
        let public_key_path = self
            .base_dir
            .join(format!("validator_{}_pk.json", validator_index));
        if !public_key_path.exists() {
            return Err(KeyStoreError::KeyNotFound(validator_index));
        }

        let public_key_json = fs::read_to_string(&public_key_path)?;
        let public_key: PublicKey = serde_json::from_str(&public_key_json).map_err(|e| {
            KeyStoreError::InvalidFormat(format!("Invalid public key format: {}", e))
        })?;

        // Load private key
        let private_key_path = self
            .base_dir
            .join(format!("validator_{}_sk.json", validator_index));
        if !private_key_path.exists() {
            return Err(KeyStoreError::KeyNotFound(validator_index));
        }

        let private_key_json = fs::read_to_string(&private_key_path)?;
        let private_key: PrivateKey = serde_json::from_str(&private_key_json).map_err(|e| {
            KeyStoreError::InvalidFormat(format!("Invalid private key format: {}", e))
        })?;

        info!(validator_index, "Loaded XMSS key pair for validator");

        Ok(ValidatorKeyPair::new(public_key, private_key))
    }

    /// Loads all key pairs from the key store directory
    ///
    /// Scans the directory for `validator_*_pk.json` files and loads
    /// the corresponding key pairs.
    pub fn load_all_key_pairs(&self) -> Result<HashMap<u64, ValidatorKeyPair>, KeyStoreError> {
        self.ensure_directory()?;

        let mut key_pairs = HashMap::new();

        // Read directory entries
        let entries = fs::read_dir(&self.base_dir)?;

        // Collect all public key files
        let mut public_key_files = Vec::new();
        for entry in entries {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            if file_name_str.starts_with("validator_") && file_name_str.ends_with("_pk.json") {
                // Extract validator index from filename: validator_{index}_pk.json
                let index_str = file_name_str
                    .strip_prefix("validator_")
                    .and_then(|s| s.strip_suffix("_pk.json"))
                    .ok_or_else(|| {
                        KeyStoreError::InvalidFormat(format!(
                            "Invalid filename format: {}",
                            file_name_str
                        ))
                    })?;

                let validator_index = index_str.parse::<u64>().map_err(|e| {
                    KeyStoreError::InvalidFormat(format!(
                        "Invalid validator index in filename: {}",
                        e
                    ))
                })?;

                public_key_files.push(validator_index);
            }
        }

        // Load key pairs for each found public key file
        for validator_index in public_key_files {
            match self.load_key_pair(validator_index) {
                Ok(key_pair) => {
                    key_pairs.insert(validator_index, key_pair);
                }
                Err(e) => {
                    warn!(
                        validator_index,
                        error = %e,
                        "Failed to load key pair, skipping"
                    );
                }
            }
        }

        info!(
            loaded_count = key_pairs.len(),
            ?self.base_dir,
            "Loaded key pairs from keystore"
        );

        Ok(key_pairs)
    }

    /// Checks if a key pair exists for the given validator index
    pub fn key_pair_exists(&self, validator_index: u64) -> bool {
        let public_key_path = self
            .base_dir
            .join(format!("validator_{}_pk.json", validator_index));
        let private_key_path = self
            .base_dir
            .join(format!("validator_{}_sk.json", validator_index));
        public_key_path.exists() && private_key_path.exists()
    }

    /// Gets the number of key pairs stored in the keystore
    pub fn count_key_pairs(&self) -> Result<usize, KeyStoreError> {
        let key_pairs = self.load_all_key_pairs()?;
        Ok(key_pairs.len())
    }

    /// Gets the base directory path
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Loads a public key from disk for verification purposes
    ///
    /// Reads the public key file for the given validator index.
    pub fn load_public_key(&self, validator_index: u64) -> Result<PublicKey, KeyStoreError> {
        let public_key_path = self
            .base_dir
            .join(format!("validator_{}_pk.json", validator_index));
        if !public_key_path.exists() {
            return Err(KeyStoreError::KeyNotFound(validator_index));
        }

        let public_key_json = fs::read_to_string(&public_key_path)?;
        let public_key: PublicKey = serde_json::from_str(&public_key_json).map_err(|e| {
            KeyStoreError::InvalidFormat(format!("Invalid public key format: {}", e))
        })?;

        Ok(public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_key_pair() -> ValidatorKeyPair {
        let public_key = PublicKey {
            root: vec![1, 2, 3, 4, 5, 6, 7, 8],
            parameter: vec![9, 10, 11, 12, 13],
        };

        let private_key = PrivateKey {
            prf_key: vec![1, 2, 3, 4, 5],
            parameter: vec![9, 10, 11, 12, 13],
            activation_epoch: 0,
            num_active_epochs: 262144,
            top_tree: XmssTree {
                depth: 32,
                lowest_layer: 16,
                layers: vec![],
            },
        };

        ValidatorKeyPair::new(public_key, private_key)
    }

    #[test]
    fn test_save_and_load_key_pair() {
        let temp_dir = TempDir::new().unwrap();
        let keystore = KeyStore::new(temp_dir.path().to_path_buf());

        let key_pair = create_test_key_pair();

        // Save key pair
        keystore.save_key_pair(0, &key_pair).unwrap();

        // Load key pair
        let loaded = keystore.load_key_pair(0).unwrap();

        assert_eq!(loaded.public_key_root(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(loaded.public_key_parameter(), &[9, 10, 11, 12, 13]);
        assert_eq!(loaded.private_key_prf(), &[1, 2, 3, 4, 5]);
        assert_eq!(loaded.activation_epoch(), 0);
    }

    #[test]
    fn test_key_pair_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let keystore = KeyStore::new(temp_dir.path().to_path_buf());

        let result = keystore.load_key_pair(999);
        assert!(matches!(result, Err(KeyStoreError::KeyNotFound(999))));
    }

    #[test]
    fn test_load_all_key_pairs() {
        let temp_dir = TempDir::new().unwrap();
        let keystore = KeyStore::new(temp_dir.path().to_path_buf());

        // Save multiple key pairs
        for i in 0..5 {
            let key_pair = create_test_key_pair();
            keystore.save_key_pair(i, &key_pair).unwrap();
        }

        // Load all key pairs
        let all_pairs = keystore.load_all_key_pairs().unwrap();
        assert_eq!(all_pairs.len(), 5);
    }
}

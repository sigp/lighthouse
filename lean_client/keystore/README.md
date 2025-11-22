# Lean Keystore

Keystore crate for managing hash-sig (XMSS) validator keys used in lean consensus.

## Overview

This crate provides functionality for:
- Generating hash-sig validator keys using the `b-wagn/hash-sig` Rust crate
- Storing and retrieving validator key pairs
- Managing key files in JSON format

## Key Generation

Key generation uses the `b-wagn/hash-sig` Rust crate with scheme:
`SIGTopLevelTargetSumLifetime32Dim64Base8`

### Prerequisites

- The `hashsig` crate dependency (automatically included)
- No Docker required - uses native Rust implementation

## Usage

### Basic Key Generation

```rust
use lean_keystore::{HashSigKeyConfig, KeyStore};
use std::path::PathBuf;

// Configure key generation
let config = HashSigKeyConfig::new(
    10,  // num_validators
    24,  // log_num_active_epochs (2^24 active epochs)
)
.with_output_dir(PathBuf::from("./keys"));

// Generate keys synchronously
let key_pairs = config.generate_and_store()?;
```

### Key Storage and Retrieval

```rust
use lean_keystore::KeyStore;
use std::path::PathBuf;

// Create a keystore
let keystore = KeyStore::new(PathBuf::from("./keys"));

// Load a specific key pair
let key_pair = keystore.load_key_pair(0)?;

// Load all key pairs
let all_keys = keystore.load_all_key_pairs()?;

// Check if a key exists
if keystore.key_pair_exists(5) {
    println!("Validator 5 has keys");
}

// Get count of stored keys
let count = keystore.count_key_pairs()?;
```

### Key File Format

Keys are stored as JSON files:
- `validator_{index}_pk.json` - Public key
- `validator_{index}_sk.json` - Private key

Example public key file:
```json
{
  "bytes": [/* 52 bytes for XMSS public key */],
  "validator_index": 0
}
```

Example private key file:
```json
{
  "bytes": [/* private key bytes */],
  "validator_index": 0
}
```

## API Reference

### `HashSigKeyConfig`

Configuration for key generation.

```rust
pub struct HashSigKeyConfig {
    pub num_validators: u64,
    pub log_num_active_epochs: u64,
    pub output_dir: PathBuf,
    pub docker_image: String,
}
```

**Methods:**
- `new(num_validators, log_num_active_epochs)` - Create new config
- `with_output_dir(output_dir)` - Set output directory
- `with_docker_image(image)` - Set custom Docker image
- `generate_and_store()` - Generate keys async
- `generate_and_store_sync()` - Generate keys sync

### `KeyStore`

Manages key storage and retrieval.

```rust
pub struct KeyStore {
    base_dir: PathBuf,
}
```

**Methods:**
- `new(base_dir)` - Create new keystore
- `save_key_pair(key_pair)` - Save a key pair
- `load_key_pair(index)` - Load a specific key pair
- `load_all_key_pairs()` - Load all key pairs
- `key_pair_exists(index)` - Check if key exists
- `count_key_pairs()` - Get count of stored keys

### `ValidatorKeyPair`

Represents a validator's public and private key pair.

```rust
pub struct ValidatorKeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}
```

**Methods:**
- `validator_index()` - Get validator index
- `public_key_bytes()` - Get public key bytes
- `private_key_bytes()` - Get private key bytes

## Error Handling

The crate uses `thiserror` for error types:

- `KeyGenerationError` - Errors during key generation
- `KeyStoreError` - Errors during storage/retrieval

All errors implement `std::error::Error` and can be converted to strings.

## Examples

### Generate Keys for Genesis

```rust
use lean_keystore::HashSigKeyConfig;
use std::path::PathBuf;

async fn generate_genesis_keys() -> Result<(), Box<dyn std::error::Error>> {
    let config = HashSigKeyConfig::new(
        64,  // 64 validators
        24,  // 2^24 active epochs
    )
    .with_output_dir(PathBuf::from("./genesis/hash-sig-keys"));

    let key_pairs = config.generate_and_store().await?;
    
    println!("Generated {} key pairs", key_pairs.len());
    Ok(())
}
```

### Load Keys for Validator

```rust
use lean_keystore::KeyStore;
use std::path::PathBuf;

fn load_validator_keys(validator_index: u64) -> Result<(), Box<dyn std::error::Error>> {
    let keystore = KeyStore::new(PathBuf::from("./keys"));
    
    let key_pair = keystore.load_key_pair(validator_index)?;
    
    println!("Loaded keys for validator {}", validator_index);
    println!("Public key: {:?}", key_pair.public_key_bytes());
    
    Ok(())
}
```

## Integration with Genesis Generation

This keystore is designed to work with the genesis generation process:

1. Generate keys using `HashSigKeyConfig::generate_and_store()`
2. Use generated keys to create validators in genesis state
3. Store keys for later use by validators

## Notes

- Key generation requires Docker and the hash-sig-cli image
- Keys are stored in JSON format for easy inspection
- The keystore automatically creates directories as needed
- Key files follow the naming convention: `validator_{index}_{pk|sk}.json`

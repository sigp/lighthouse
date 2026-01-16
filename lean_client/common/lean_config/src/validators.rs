use lean_consensus::validator::Validator;
use lean_keystore::ValidatorKeyPair;
use std::collections::HashMap;
use ssz_types::FixedVector;

/// Build validator list from raw key pairs loaded from the keystore.
#[allow(dead_code)]
pub fn build_validators(
    all_key_pairs: HashMap<u64, ValidatorKeyPair>,
) -> Result<Vec<Validator>, String> {
    let mut validators_list = Vec::new();
    let mut sorted_indices: Vec<u64> = all_key_pairs.keys().copied().collect();
    sorted_indices.sort();

    for validator_index in sorted_indices {
        let key_pair = all_key_pairs
            .get(&validator_index)
            .ok_or_else(|| format!("Validator index {} not found in key pairs", validator_index))?;

        // PublicKey is already 52 bytes
        let pubkey_bytes = key_pair.public_key.as_bytes().to_vec();

        let pubkey_fixed = FixedVector::new(pubkey_bytes).map_err(|e| {
            format!(
                "Failed to create FixedVector from public key bytes: {:?}",
                e
            )
        })?;
        let validator = Validator {
            pubkey: pubkey_fixed,
            index: validator_index,
        };
        validators_list.push(validator);
    }

    Ok(validators_list)
}

/// Build validator list from hex-encoded public keys in config.yaml GENESIS_VALIDATORS field.
pub fn build_validators_from_config(config_bytes: &[u8]) -> Result<Vec<Validator>, String> {
    let config: serde_yaml::Value = serde_yaml::from_slice(config_bytes)
        .map_err(|e| format!("Failed to parse config.yaml: {}", e))?;

    let genesis_validators = config
        .get("GENESIS_VALIDATORS")
        .or_else(|| config.get("genesis_validators"))
        .ok_or_else(|| "GENESIS_VALIDATORS not found in config.yaml".to_string())?;

    let validators_seq = genesis_validators
        .as_sequence()
        .ok_or_else(|| "GENESIS_VALIDATORS must be a list".to_string())?;

    let mut validators_list = Vec::new();

    for (index, pubkey_val) in validators_seq.iter().enumerate() {
        let pubkey_hex = pubkey_val
            .as_str()
            .ok_or_else(|| format!("Validator {} must be a hex string", index))?;

        // Debug: Log what we're parsing
        tracing::info!("Parsing validator {}: pubkey_hex={}", index, pubkey_hex);

        let pubkey_bytes = hex_to_bytes52(pubkey_hex)
            .map_err(|e| format!("Failed to parse validator {} pubkey: {}", index, e))?;

        let pubkey_fixed = FixedVector::new(pubkey_bytes.to_vec()).map_err(|e| {
            format!(
                "Failed to create FixedVector from public key bytes: {:?}",
                e
            )
        })?;

        let validator = Validator {
            pubkey: pubkey_fixed,
            index: index as u64,
        };
        validators_list.push(validator);
    }

    Ok(validators_list)
}

/// Convert hex string to 52 bytes array
fn hex_to_bytes52(hex_str: &str) -> Result<[u8; 52], String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    if hex_str.len() != 104 {
        // 52 bytes * 2 hex chars per byte
        return Err(format!(
            "Invalid pubkey hex length: expected 104 chars, got {}",
            hex_str.len()
        ));
    }

    let mut bytes = [0u8; 52];
    for i in 0..52 {
        bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("Invalid hex character: {}", e))?;
    }

    Ok(bytes)
}

/// Get current time in seconds since epoch.
#[allow(dead_code)]
pub fn current_unix_timestamp() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("Failed to get current time: {}", e))
}

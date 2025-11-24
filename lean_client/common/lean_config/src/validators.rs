use lean_consensus::validator::Validator;
use lean_keystore::ValidatorKeyPair;
use std::collections::HashMap;
use types::FixedVector;

/// Build validator list from raw key pairs loaded from the keystore.
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

        // Convert PublicKey to FixedVector<u8, U52>
        let mut pubkey_bytes = Vec::with_capacity(52);

        // Serialize root (8 u32 values = 32 bytes)
        for &val in &key_pair.public_key.root {
            pubkey_bytes.extend_from_slice(&val.to_le_bytes());
        }

        // Serialize parameter (5 u32 values = 20 bytes)
        for &val in &key_pair.public_key.parameter {
            pubkey_bytes.extend_from_slice(&val.to_le_bytes());
        }

        if pubkey_bytes.len() != 52 {
            return Err(format!(
                "Invalid public key size: expected 52 bytes, got {} bytes (root: {} u32, parameter: {} u32)",
                pubkey_bytes.len(),
                key_pair.public_key.root.len(),
                key_pair.public_key.parameter.len()
            ));
        }

        let pubkey_fixed = FixedVector::new(pubkey_bytes).map_err(|e| {
            format!(
                "Failed to create FixedVector from public key bytes: {:?}",
                e
            )
        })?;
        let validator = Validator {
            pubkey: pubkey_fixed,
        };
        validators_list.push(validator);
    }

    Ok(validators_list)
}

/// Get current time in seconds since epoch.
pub fn current_unix_timestamp() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("Failed to get current time: {}", e))
}

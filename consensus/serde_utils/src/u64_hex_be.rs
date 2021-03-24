//! Formats `u64` as a 0x-prefixed, big-endian hex string.
//!
//! E.g., `0` serializes as `"0x0000000000000000"`.

use crate::hex::PrefixedHexVisitor;
use serde::de::Error;
use serde::{Deserializer, Serializer};

const BYTES_LEN: usize = 8;

pub fn serialize<S>(num: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // TODO: this trim_start isn't consistent with eth2 formatting.
    let mut raw = hex::encode(num.to_be_bytes())
        .trim_start_matches('0')
        .to_string();
    if raw == "" {
        raw = "0".to_string()
    };
    let hex = format!("0x{}", raw);
    dbg!(&hex);
    serializer.serialize_str(&hex)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let decoded = deserializer.deserialize_str(PrefixedHexVisitor)?;

    // TODO: this is not strict about byte length like other methods.
    if decoded.len() > BYTES_LEN {
        return Err(D::Error::custom(format!(
            "expected max {} bytes for array, got {}",
            BYTES_LEN,
            decoded.len()
        )));
    }

    let mut array = [0; BYTES_LEN];
    array[BYTES_LEN - decoded.len()..].copy_from_slice(&decoded);
    Ok(u64::from_be_bytes(array))
}

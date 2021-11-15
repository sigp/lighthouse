//! Formats `[u8; n]` as a 0x-prefixed hex string.
//!
//! E.g., `[0, 1, 2, 3]` serializes as `"0x00010203"`.

use crate::hex::PrefixedHexVisitor;
use serde::de::Error;
use serde::{Deserializer, Serializer};

macro_rules! bytes_hex {
    ($num_bytes: tt) => {
        use super::*;

        const BYTES_LEN: usize = $num_bytes;

        pub fn serialize<S>(bytes: &[u8; BYTES_LEN], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut hex_string: String = "0x".to_string();
            hex_string.push_str(&hex::encode(&bytes));

            serializer.serialize_str(&hex_string)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; BYTES_LEN], D::Error>
        where
            D: Deserializer<'de>,
        {
            let decoded = deserializer.deserialize_str(PrefixedHexVisitor)?;

            if decoded.len() != BYTES_LEN {
                return Err(D::Error::custom(format!(
                    "expected {} bytes for array, got {}",
                    BYTES_LEN,
                    decoded.len()
                )));
            }

            let mut array = [0; BYTES_LEN];
            array.copy_from_slice(&decoded);
            Ok(array)
        }
    };
}

pub mod bytes_4_hex {
    bytes_hex!(4);
}

pub mod bytes_8_hex {
    bytes_hex!(8);
}

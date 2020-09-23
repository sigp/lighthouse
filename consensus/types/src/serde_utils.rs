use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

pub use serde_utils::*;

pub const FORK_BYTES_LEN: usize = 4;
pub const GRAFFITI_BYTES_LEN: usize = 32;

/// Type for a slice of `GRAFFITI_BYTES_LEN` bytes.
///
/// Gets included inside each `BeaconBlockBody`.
pub type Graffiti = [u8; GRAFFITI_BYTES_LEN];

pub mod u32_hex {
    use super::*;

    pub fn serialize<S>(num: &u32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut hex: String = "0x".to_string();
        let bytes = num.to_le_bytes();
        hex.push_str(&::hex::encode(&bytes));

        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let start = s
            .as_str()
            .get(2..)
            .ok_or_else(|| D::Error::custom("string length too small"))?;

        u32::from_str_radix(&start, 16)
            .map_err(D::Error::custom)
            .map(u32::from_be)
    }
}

pub mod u8_hex {
    use super::*;

    pub fn serialize<S>(byte: &u8, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut hex: String = "0x".to_string();
        hex.push_str(&::hex::encode(&[*byte]));

        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u8, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;

        let start = match s.as_str().get(2..) {
            Some(start) => start,
            None => return Err(D::Error::custom("string length too small")),
        };
        u8::from_str_radix(&start, 16).map_err(D::Error::custom)
    }
}

pub mod fork_bytes_4 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; FORK_BYTES_LEN], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut hex_string: String = "0x".to_string();
        hex_string.push_str(&::hex::encode(&bytes));

        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; FORK_BYTES_LEN], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let mut array = [0 as u8; FORK_BYTES_LEN];

        let start = s
            .as_str()
            .get(2..)
            .ok_or_else(|| D::Error::custom("string length too small"))?;
        let decoded: Vec<u8> = ::hex::decode(&start).map_err(D::Error::custom)?;

        if decoded.len() != FORK_BYTES_LEN {
            return Err(D::Error::custom("Fork length too long"));
        }

        for (i, item) in array.iter_mut().enumerate() {
            if i > decoded.len() {
                break;
            }
            *item = decoded[i];
        }
        Ok(array)
    }
}

pub mod graffiti {
    use super::*;

    pub fn serialize<S>(bytes: &Graffiti, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut hex_string: String = "0x".to_string();
        hex_string.push_str(&::hex::encode(&bytes));

        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Graffiti, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let mut array = Graffiti::default();

        let start = s
            .as_str()
            .get(2..)
            .ok_or_else(|| D::Error::custom("string length too small"))?;
        let decoded: Vec<u8> = ::hex::decode(&start).map_err(D::Error::custom)?;

        if decoded.len() > GRAFFITI_BYTES_LEN {
            return Err(D::Error::custom("Fork length too long"));
        }

        for (i, item) in array.iter_mut().enumerate() {
            if i > decoded.len() {
                break;
            }
            *item = decoded[i];
        }
        Ok(array)
    }
}

use hex;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

pub const FORK_BYTES_LEN: usize = 4;
pub const GRAFFITI_BYTES_LEN: usize = 32;

pub fn u8_from_hex_str<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;

    u8::from_str_radix(&s.as_str()[2..], 16).map_err(D::Error::custom)
}

#[allow(clippy::trivially_copy_pass_by_ref)] // Serde requires the `byte` to be a ref.
pub fn u8_to_hex_str<S>(byte: &u8, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut hex: String = "0x".to_string();
    hex.push_str(&hex::encode(&[*byte]));

    serializer.serialize_str(&hex)
}

pub fn fork_from_hex_str<'de, D>(deserializer: D) -> Result<[u8; FORK_BYTES_LEN], D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let mut array = [0 as u8; FORK_BYTES_LEN];
    let decoded: Vec<u8> = hex::decode(&s.as_str()[2..]).map_err(D::Error::custom)?;

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

#[allow(clippy::trivially_copy_pass_by_ref)]
pub fn fork_to_hex_str<S>(bytes: &[u8; FORK_BYTES_LEN], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut hex_string: String = "0x".to_string();
    hex_string.push_str(&hex::encode(&bytes));

    serializer.serialize_str(&hex_string)
}

pub fn graffiti_to_hex_str<S>(
    bytes: &[u8; GRAFFITI_BYTES_LEN],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut hex_string: String = "0x".to_string();
    hex_string.push_str(&hex::encode(&bytes));

    serializer.serialize_str(&hex_string)
}

pub fn graffiti_from_hex_str<'de, D>(deserializer: D) -> Result<[u8; GRAFFITI_BYTES_LEN], D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let mut array = [0 as u8; GRAFFITI_BYTES_LEN];
    let decoded: Vec<u8> = hex::decode(&s.as_str()[2..]).map_err(D::Error::custom)?;

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

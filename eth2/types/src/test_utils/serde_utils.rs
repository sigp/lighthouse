use serde::de::Error;
use serde::{Deserialize, Deserializer};

pub fn u8_from_hex_str<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;

    u8::from_str_radix(&s.as_str()[2..], 16).map_err(D::Error::custom)
}

pub fn fork_from_hex_str<'de, D>(deserializer: D) -> Result<[u8; 4], D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let mut array = [0 as u8; 4];
    let decoded: Vec<u8> = hex::decode(&s.as_str()[2..]).map_err(D::Error::custom)?;

    for (i, item) in array.iter_mut().enumerate() {
        if i > decoded.len() {
            break;
        }
        *item = decoded[i];
    }
    Ok(array)
}

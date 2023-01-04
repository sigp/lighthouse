use serde::de::Deserializer;
use serde_derive::Deserialize;

const BYTES_PER_G1_POINT: usize = 48;
const BYTES_PER_G2_POINT: usize = 96;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TrustedSetup {
    #[serde(rename = "SETUP_G1")]
    #[serde(deserialize_with = "deserialize_g1_array")]
    pub g1_points: Vec<[u8; BYTES_PER_G1_POINT]>,
    #[serde(rename = "SETUP_G2")]
    #[serde(deserialize_with = "deserialize_g2_array")]
    pub g2_points: Vec<[u8; BYTES_PER_G2_POINT]>,
}

fn deserialize_g1_array<'de, D>(deserializer: D) -> Result<Vec<[u8; BYTES_PER_G1_POINT]>, D::Error>
where
    D: Deserializer<'de>,
{
    let decoded: Vec<Vec<u8>> = serde::de::Deserialize::deserialize(deserializer)?;
    let decoded: Vec<[u8; BYTES_PER_G1_POINT]> = decoded
        .into_iter()
        .map(|point| {
            let mut res = [0; BYTES_PER_G1_POINT];
            res.copy_from_slice(point.as_ref());
            res
        })
        .collect();

    Ok(decoded)
}

fn deserialize_g2_array<'de, D>(deserializer: D) -> Result<Vec<[u8; BYTES_PER_G2_POINT]>, D::Error>
where
    D: Deserializer<'de>,
{
    let decoded: Vec<Vec<u8>> = serde::de::Deserialize::deserialize(deserializer)?;
    let decoded: Vec<[u8; BYTES_PER_G2_POINT]> = decoded
        .into_iter()
        .map(|point| {
            let mut res = [0; BYTES_PER_G2_POINT];
            res.copy_from_slice(point.as_ref());
            res
        })
        .collect();

    Ok(decoded)
}

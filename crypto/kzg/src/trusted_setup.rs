use crate::PeerDASTrustedSetup;
use c_kzg::{BYTES_PER_G1_POINT, BYTES_PER_G2_POINT};
use serde::{
    de::{self, Deserializer, Visitor},
    Deserialize, Serialize,
};

pub const TRUSTED_SETUP_BYTES: &[u8] = include_bytes!("../trusted_setup.json");

pub fn get_trusted_setup() -> Vec<u8> {
    TRUSTED_SETUP_BYTES.into()
}

/// Wrapper over a BLS G1 point's byte representation.
#[derive(Debug, Clone, PartialEq)]
struct G1Point([u8; BYTES_PER_G1_POINT]);

/// Wrapper over a BLS G2 point's byte representation.
#[derive(Debug, Clone, PartialEq)]
struct G2Point([u8; BYTES_PER_G2_POINT]);

/// Contains the trusted setup parameters that are required to instantiate a
/// `c_kzg::KzgSettings` object.
///
/// The serialize/deserialize implementations are written according to
/// the format specified in the the ethereum consensus specs trusted setup files.
///
/// See https://github.com/ethereum/consensus-specs/blob/dev/presets/mainnet/trusted_setups/trusted_setup_4096.json
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustedSetup {
    #[serde(rename = "g1_monomial")]
    g1_monomial_points: Vec<G1Point>,
    #[serde(rename = "g1_lagrange")]
    g1_points: Vec<G1Point>,
    #[serde(rename = "g2_monomial")]
    g2_points: Vec<G2Point>,
}

impl TrustedSetup {
    pub fn g1_points(&self) -> Vec<[u8; BYTES_PER_G1_POINT]> {
        self.g1_points.iter().map(|p| p.0).collect()
    }

    pub fn g2_points(&self) -> Vec<[u8; BYTES_PER_G2_POINT]> {
        self.g2_points.iter().map(|p| p.0).collect()
    }

    pub fn g1_len(&self) -> usize {
        self.g1_points.len()
    }
}

impl From<&TrustedSetup> for PeerDASTrustedSetup {
    fn from(trusted_setup: &TrustedSetup) -> Self {
        Self {
            g1_monomial: trusted_setup
                .g1_monomial_points
                .iter()
                .map(|g1_point| format!("0x{}", hex::encode(g1_point.0)))
                .collect::<Vec<_>>(),
            g1_lagrange: trusted_setup
                .g1_points
                .iter()
                .map(|g1_point| format!("0x{}", hex::encode(g1_point.0)))
                .collect::<Vec<_>>(),
            g2_monomial: trusted_setup
                .g2_points
                .iter()
                .map(|g2_point| format!("0x{}", hex::encode(g2_point.0)))
                .collect::<Vec<_>>(),
        }
    }
}

impl Serialize for G1Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let point = hex::encode(self.0);
        serializer.serialize_str(&point)
    }
}

impl Serialize for G2Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let point = hex::encode(self.0);
        serializer.serialize_str(&point)
    }
}

impl<'de> Deserialize<'de> for G1Point {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct G1PointVisitor;

        impl Visitor<'_> for G1PointVisitor {
            type Value = G1Point;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A 48 byte hex encoded string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let point = hex::decode(strip_prefix(v))
                    .map_err(|e| de::Error::custom(format!("Failed to decode G1 point: {}", e)))?;
                if point.len() != BYTES_PER_G1_POINT {
                    return Err(de::Error::custom(format!(
                        "G1 point has invalid length. Expected {} got {}",
                        BYTES_PER_G1_POINT,
                        point.len()
                    )));
                }
                let mut res = [0; BYTES_PER_G1_POINT];
                res.copy_from_slice(&point);
                Ok(G1Point(res))
            }
        }

        deserializer.deserialize_str(G1PointVisitor)
    }
}

impl<'de> Deserialize<'de> for G2Point {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct G2PointVisitor;

        impl Visitor<'_> for G2PointVisitor {
            type Value = G2Point;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A 96 byte hex encoded string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let point = hex::decode(strip_prefix(v))
                    .map_err(|e| de::Error::custom(format!("Failed to decode G2 point: {}", e)))?;
                if point.len() != BYTES_PER_G2_POINT {
                    return Err(de::Error::custom(format!(
                        "G2 point has invalid length. Expected {} got {}",
                        BYTES_PER_G2_POINT,
                        point.len()
                    )));
                }
                let mut res = [0; BYTES_PER_G2_POINT];
                res.copy_from_slice(&point);
                Ok(G2Point(res))
            }
        }

        deserializer.deserialize_str(G2PointVisitor)
    }
}

fn strip_prefix(s: &str) -> &str {
    if let Some(stripped) = s.strip_prefix("0x") {
        stripped
    } else {
        s
    }
}

//! KZG Type Definitions
//!
//! This crate contains type definitions related to KZG commitments and proofs,
//! separated from the main `kzg` crate to avoid a direct dependency on the `c_kzg` C library bindings.

use derivative::Derivative;
use ethereum_hashing::hash_fixed;
use serde::de::{self, Deserializer, Visitor}; // Keep trait imports for manual impls
use serde::ser::Serializer; // Keep trait imports for manual impls
use serde::{Deserialize, Serialize}; // Import derive macros
use ssz_derive::{Decode, Encode};
use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;
use tree_hash::{Hash256, PackedEncoding, TreeHash};

// Re-export types from rust-eth-kzg needed for PeerDAS and Cells
pub use rust_eth_kzg::{
    constants::{BYTES_PER_CELL, CELLS_PER_EXT_BLOB},
    Cell, CellIndex as CellID, CellRef, TrustedSetup as PeerDASTrustedSetup,
};

// Constants defined locally to avoid c_kzg dependency
pub const BYTES_PER_COMMITMENT: usize = 48;
pub const BYTES_PER_PROOF: usize = 48;
pub const BYTES_PER_G1_POINT: usize = 48;
pub const BYTES_PER_G2_POINT: usize = 96;
pub const BYTES_PER_BLOB: usize = 131072; // 4096 * 32
pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;

// Basic type definitions (fixed-size arrays)
pub type Bytes32 = [u8; 32];
pub type Bytes48 = [u8; BYTES_PER_COMMITMENT]; // Use local constant
pub type Blob = [u8; BYTES_PER_BLOB]; // Use local constant

// Type Aliases
pub type CellsAndKzgProofs = ([Cell; CELLS_PER_EXT_BLOB], [KzgProof; CELLS_PER_EXT_BLOB]);
pub type KzgBlobRef<'a> = &'a Blob; // Use local Blob type

// --- KzgCommitment ---
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

#[derive(Derivative, Clone, Copy, Encode, Decode)] // Removed #[ssz(...)] attribute
#[ssz(struct_behaviour = "transparent")]
#[derivative(PartialEq, Eq, Hash)]
pub struct KzgCommitment(pub [u8; BYTES_PER_COMMITMENT]); // Use local constant

impl KzgCommitment {
    pub fn calculate_versioned_hash(&self) -> Hash256 {
        let mut versioned_hash = hash_fixed(&self.0);
        versioned_hash[0] = VERSIONED_HASH_VERSION_KZG;
        Hash256::from_slice(versioned_hash.as_slice())
    }

    #[cfg(feature = "arbitrary")]
    pub fn empty_for_testing() -> Self {
        KzgCommitment([0; BYTES_PER_COMMITMENT]) // Use local constant
    }
}

impl Display for KzgCommitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for i in &self.0[0..2] {
            write!(f, "{:02x}", i)?;
        }
        write!(f, "…")?;
        for i in &self.0[BYTES_PER_COMMITMENT - 2..BYTES_PER_COMMITMENT] {
            // Use local constant
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

impl TreeHash for KzgCommitment {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <[u8; BYTES_PER_COMMITMENT] as TreeHash>::tree_hash_type() // Use local constant
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <[u8; BYTES_PER_COMMITMENT] as TreeHash>::tree_hash_packing_factor() // Use local constant
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl Serialize for KzgCommitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{:?}", self))
    }
}

impl<'de> Deserialize<'de> for KzgCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Self::from_str(&string).map_err(serde::de::Error::custom)
    }
}

impl FromStr for KzgCommitment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(stripped) = s.strip_prefix("0x") {
            let bytes = hex::decode(stripped).map_err(|e| e.to_string())?;
            if bytes.len() == BYTES_PER_COMMITMENT {
                // Use local constant
                let mut kzg_commitment_bytes = [0; BYTES_PER_COMMITMENT]; // Use local constant
                kzg_commitment_bytes[..].copy_from_slice(&bytes);
                Ok(Self(kzg_commitment_bytes))
            } else {
                Err(format!(
                    "InvalidByteLength: got {}, expected {}",
                    bytes.len(),
                    BYTES_PER_COMMITMENT // Use local constant
                ))
            }
        } else {
            Err("must start with 0x".to_string())
        }
    }
}

impl Debug for KzgCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0)) // Use hex crate directly
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for KzgCommitment {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut bytes = [0u8; BYTES_PER_COMMITMENT]; // Use local constant
        u.fill_buffer(&mut bytes)?;
        Ok(KzgCommitment(bytes))
    }
}

// --- KzgProof ---
#[derive(PartialEq, Eq, Hash, Clone, Copy, Encode, Decode)] // Added Eq, Removed #[ssz(...)] attribute
#[ssz(struct_behaviour = "transparent")]
pub struct KzgProof(pub [u8; BYTES_PER_PROOF]); // Use local constant

impl KzgProof {
    /// Creates a valid proof using `G1_POINT_AT_INFINITY`.
    pub fn empty() -> Self {
        let mut bytes = [0; BYTES_PER_PROOF]; // Use local constant
        bytes[0] = 0xc0;
        Self(bytes)
    }
}

impl fmt::Display for KzgProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl From<[u8; BYTES_PER_PROOF]> for KzgProof {
    // Use local constant
    fn from(bytes: [u8; BYTES_PER_PROOF]) -> Self {
        // Use local constant
        Self(bytes)
    }
}

impl From<KzgProof> for [u8; BYTES_PER_PROOF] {
    // Use local constant
    fn from(from: KzgProof) -> [u8; BYTES_PER_PROOF] {
        // Use local constant
        from.0
    }
}

impl TreeHash for KzgProof {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <[u8; BYTES_PER_PROOF]>::tree_hash_type() // Use local constant
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <[u8; BYTES_PER_PROOF]>::tree_hash_packing_factor() // Use local constant
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl Serialize for KzgProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for KzgProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Self::from_str(&string).map_err(serde::de::Error::custom)
    }
}

impl FromStr for KzgProof {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(stripped) = s.strip_prefix("0x") {
            let bytes = hex::decode(stripped).map_err(|e| e.to_string())?;
            if bytes.len() == BYTES_PER_PROOF {
                // Use local constant
                let mut kzg_proof_bytes = [0; BYTES_PER_PROOF]; // Use local constant
                kzg_proof_bytes[..].copy_from_slice(&bytes);
                Ok(Self(kzg_proof_bytes))
            } else {
                Err(format!(
                    "InvalidByteLength: got {}, expected {}",
                    bytes.len(),
                    BYTES_PER_PROOF // Use local constant
                ))
            }
        } else {
            Err("must start with 0x".to_string())
        }
    }
}

impl Debug for KzgProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0)) // Use hex crate directly
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for KzgProof {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut bytes = [0u8; BYTES_PER_PROOF]; // Use local constant
        u.fill_buffer(&mut bytes)?;
        Ok(KzgProof(bytes))
    }
}

// --- TrustedSetup ---

/// Wrapper over a BLS G1 point's byte representation.
#[derive(Debug, Clone, PartialEq, Eq)] // Added Eq
struct G1Point([u8; BYTES_PER_G1_POINT]); // Use local constant

/// Wrapper over a BLS G2 point's byte representation.
#[derive(Debug, Clone, PartialEq, Eq)] // Added Eq
struct G2Point([u8; BYTES_PER_G2_POINT]); // Use local constant

/// Contains the trusted setup parameters.
///
/// The serialize/deserialize implementations are written according to
/// the format specified in the the ethereum consensus specs trusted setup files.
///
/// See https://github.com/ethereum/consensus-specs/blob/dev/presets/mainnet/trusted_setups/trusted_setup_4096.json
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] // Added Eq
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
        // Use local constant
        self.g1_points.iter().map(|p| p.0).collect()
    }

    pub fn g2_points(&self) -> Vec<[u8; BYTES_PER_G2_POINT]> {
        // Use local constant
        self.g2_points.iter().map(|p| p.0).collect()
    }

    pub fn g1_len(&self) -> usize {
        self.g1_points.len()
    }
}

// This conversion now relies on rust_eth_kzg which is an allowed dependency
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
        // Serialize as "0x" prefixed hex string
        serializer.serialize_str(&format!("0x{}", hex::encode(self.0)))
    }
}

impl Serialize for G2Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as "0x" prefixed hex string
        serializer.serialize_str(&format!("0x{}", hex::encode(self.0)))
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
                formatter.write_str("A 48 byte hex encoded string, optionally 0x prefixed")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let point = hex::decode(strip_prefix(v))
                    .map_err(|e| de::Error::custom(format!("Failed to decode G1 point: {}", e)))?;
                if point.len() != BYTES_PER_G1_POINT {
                    // Use local constant
                    return Err(de::Error::custom(format!(
                        "G1 point has invalid length. Expected {} got {}",
                        BYTES_PER_G1_POINT, // Use local constant
                        point.len()
                    )));
                }
                let mut res = [0; BYTES_PER_G1_POINT]; // Use local constant
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
                formatter.write_str("A 96 byte hex encoded string, optionally 0x prefixed")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let point = hex::decode(strip_prefix(v))
                    .map_err(|e| de::Error::custom(format!("Failed to decode G2 point: {}", e)))?;
                if point.len() != BYTES_PER_G2_POINT {
                    // Use local constant
                    return Err(de::Error::custom(format!(
                        "G2 point has invalid length. Expected {} got {}",
                        BYTES_PER_G2_POINT, // Use local constant
                        point.len()
                    )));
                }
                let mut res = [0; BYTES_PER_G2_POINT]; // Use local constant
                res.copy_from_slice(&point);
                Ok(G2Point(res))
            }
        }

        deserializer.deserialize_str(G2PointVisitor)
    }
}

fn strip_prefix(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

// --- Tests (Optional, can be moved or kept) ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kzg_commitment_display() {
        let display_commitment_str = "0x53fa…adac";
        let commitment = KzgCommitment::from_str(
            "0x53fa09af35d1d1a9e76f65e16112a9064ce30d1e4e2df98583f0f5dc2e7dd13a4f421a9c89f518fafd952df76f23adac",
        )
        .unwrap();
        assert_eq!(commitment.to_string(), display_commitment_str);
    }

    #[test]
    fn kzg_commitment_debug() {
        let debug_commitment_str =
            "0x53fa09af35d1d1a9e76f65e16112a9064ce30d1e4e2df98583f0f5dc2e7dd13a4f421a9c89f518fafd952df76f23adac";
        let commitment = KzgCommitment::from_str(debug_commitment_str).unwrap();
        assert_eq!(
            format!("{:?}", commitment),
            format!("0x{}", debug_commitment_str.strip_prefix("0x").unwrap())
        );
    }

    #[test]
    fn kzg_proof_debug_and_display() {
        let proof_str =
            "0x8179056984a40733556afc0301e864e0661778a4147517707a8834693730bedc1456d13e7105e586494a746164e31bdb";
        let proof = KzgProof::from_str(proof_str).unwrap();
        assert_eq!(
            format!("{:?}", proof),
            format!("0x{}", proof_str.strip_prefix("0x").unwrap())
        );
        assert_eq!(
            proof.to_string(),
            format!("0x{}", proof_str.strip_prefix("0x").unwrap())
        );
    }

    #[test]
    fn trusted_setup_serde() {
        // A minimal example
        let json_str = r#"{
            "g1_monomial": ["0x0101...01", "0x0202...02"],
            "g1_lagrange": ["0x0303...03", "0x0404...04"],
            "g2_monomial": ["0x0505...05", "0x0606...06"]
        }"#;
        // Replace "..." with actual repeating bytes to match lengths
        let json_str = json_str.replace("01...01", &"01".repeat(BYTES_PER_G1_POINT));
        let json_str = json_str.replace("02...02", &"02".repeat(BYTES_PER_G1_POINT));
        let json_str = json_str.replace("03...03", &"03".repeat(BYTES_PER_G1_POINT));
        let json_str = json_str.replace("04...04", &"04".repeat(BYTES_PER_G1_POINT));
        let json_str = json_str.replace("05...05", &"05".repeat(BYTES_PER_G2_POINT));
        let json_str = json_str.replace("06...06", &"06".repeat(BYTES_PER_G2_POINT));

        let setup: TrustedSetup = serde_json::from_str(&json_str).unwrap();

        assert_eq!(setup.g1_monomial_points.len(), 2);
        assert_eq!(setup.g1_points.len(), 2);
        assert_eq!(setup.g2_points.len(), 2);

        assert_eq!(setup.g1_monomial_points[0].0[0], 0x01);
        assert_eq!(setup.g1_points[0].0[0], 0x03);
        assert_eq!(setup.g2_points[0].0[0], 0x05);

        let serialized = serde_json::to_string_pretty(&setup).unwrap();
        // Deserialize again to check consistency
        let setup2: TrustedSetup = serde_json::from_str(&serialized).unwrap();
        assert_eq!(setup, setup2);
    }
}

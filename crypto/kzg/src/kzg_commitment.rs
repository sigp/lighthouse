use c_kzg::BYTES_PER_COMMITMENT;
use derivative::Derivative;
use ethereum_hashing::hash_fixed;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use ssz_derive::{Decode, Encode};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use tree_hash::{Hash256, PackedEncoding, TreeHash};

pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

#[derive(Derivative, Clone, Copy, Encode, Decode)]
#[derivative(PartialEq, Eq, Hash)]
#[ssz(struct_behaviour = "transparent")]
pub struct KzgCommitment(pub [u8; c_kzg::BYTES_PER_COMMITMENT]);

impl KzgCommitment {
    pub fn calculate_versioned_hash(&self) -> Hash256 {
        let mut versioned_hash = hash_fixed(&self.0);
        versioned_hash[0] = VERSIONED_HASH_VERSION_KZG;
        Hash256::from_slice(versioned_hash.as_slice())
    }

    pub fn empty_for_testing() -> Self {
        KzgCommitment([0; c_kzg::BYTES_PER_COMMITMENT])
    }
}

impl From<KzgCommitment> for c_kzg::Bytes48 {
    fn from(value: KzgCommitment) -> Self {
        value.0.into()
    }
}

impl From<KzgCommitment> for c_kzg_min::Bytes48 {
    fn from(value: KzgCommitment) -> Self {
        value.0.into()
    }
}

impl Display for KzgCommitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_utils::hex::encode(self.0))
    }
}

impl TreeHash for KzgCommitment {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <[u8; BYTES_PER_COMMITMENT] as TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <[u8; BYTES_PER_COMMITMENT] as TreeHash>::tree_hash_packing_factor()
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
        serializer.serialize_str(&self.to_string())
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
                let mut kzg_commitment_bytes = [0; BYTES_PER_COMMITMENT];
                kzg_commitment_bytes[..].copy_from_slice(&bytes);
                Ok(Self(kzg_commitment_bytes))
            } else {
                Err(format!(
                    "InvalidByteLength: got {}, expected {}",
                    bytes.len(),
                    BYTES_PER_COMMITMENT
                ))
            }
        } else {
            Err("must start with 0x".to_string())
        }
    }
}

impl Debug for KzgCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", serde_utils::hex::encode(self.0))
    }
}

impl arbitrary::Arbitrary<'_> for KzgCommitment {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut bytes = [0u8; BYTES_PER_COMMITMENT];
        u.fill_buffer(&mut bytes)?;
        Ok(KzgCommitment(bytes))
    }
}

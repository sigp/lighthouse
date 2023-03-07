use derivative::Derivative;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use ssz_derive::{Decode, Encode};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use tree_hash::{PackedEncoding, TreeHash};

const KZG_COMMITMENT_BYTES_LEN: usize = 48;

#[derive(Derivative, Clone, Encode, Decode)]
#[derivative(PartialEq, Eq, Hash)]
#[ssz(struct_behaviour = "transparent")]
pub struct KzgCommitment(pub [u8; KZG_COMMITMENT_BYTES_LEN]);

impl Display for KzgCommitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", eth2_serde_utils::hex::encode(self.0))
    }
}

impl Default for KzgCommitment {
    fn default() -> Self {
        KzgCommitment([0; KZG_COMMITMENT_BYTES_LEN])
    }
}

impl TreeHash for KzgCommitment {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <[u8; KZG_COMMITMENT_BYTES_LEN] as TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <[u8; KZG_COMMITMENT_BYTES_LEN] as TreeHash>::tree_hash_packing_factor()
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
        pub struct StringVisitor;

        impl<'de> serde::de::Visitor<'de> for StringVisitor {
            type Value = String;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a hex string with 0x prefix")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(value.to_string())
            }
        }

        let string = deserializer.deserialize_str(StringVisitor)?;
        <Self as std::str::FromStr>::from_str(&string).map_err(serde::de::Error::custom)
    }
}

impl FromStr for KzgCommitment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(stripped) = s.strip_prefix("0x") {
            let bytes = hex::decode(stripped).map_err(|e| e.to_string())?;
            if bytes.len() == KZG_COMMITMENT_BYTES_LEN {
                let mut kzg_commitment_bytes = [0; KZG_COMMITMENT_BYTES_LEN];
                kzg_commitment_bytes[..].copy_from_slice(&bytes);
                Ok(Self(kzg_commitment_bytes))
            } else {
                Err(format!(
                    "InvalidByteLength: got {}, expected {}",
                    bytes.len(),
                    KZG_COMMITMENT_BYTES_LEN
                ))
            }
        } else {
            Err("must start with 0x".to_string())
        }
    }
}

impl Debug for KzgCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", eth2_serde_utils::hex::encode(self.0))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for KzgCommitment {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut bytes = [0u8; KZG_COMMITMENT_BYTES_LEN];
        u.fill_buffer(&mut bytes)?;
        Ok(KzgCommitment(bytes))
    }
}

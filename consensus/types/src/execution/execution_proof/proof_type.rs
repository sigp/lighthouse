use crate::Hash256;
use serde::{Deserialize, Serialize};
use ssz::{Decode as SszDecode, DecodeError, Encode as SszEncode};
use strum::{Display, FromRepr, VariantArray};
use tree_hash::{PackedEncoding, TreeHash as TreeHashTrait, TreeHashType};

/// Proof system that verifies an execution proof.
///
/// Each assigned [`ProofType`] names exactly one of these.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZkvmKind {
    /// OpenVM.
    Openvm,
    /// SP1.
    Sp1,
    /// Zisk.
    Zisk,
}

/// Identifier for an immutable proof-system, guest-program, and version tuple.
///
/// The discriminants are the assigned EIP-8025 wire encodings and are serialized as a `u8`. The
/// assignments are provisional while EIP-8025 is under development.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Display,
    FromRepr,
    VariantArray,
    Serialize,
    Deserialize,
)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
pub enum ProofType {
    /// ethrex stateless validator proven on OpenVM.
    EthrexOpenVM = 1,
    /// ethrex stateless validator proven on SP1.
    EthrexSP1 = 2,
    /// ethrex stateless validator proven on Zisk.
    EthrexZisk = 3,
    /// reth stateless validator proven on OpenVM.
    RethOpenVM = 4,
    /// reth stateless validator proven on SP1.
    RethSP1 = 5,
    /// reth stateless validator proven on Zisk.
    RethZisk = 6,
    /// Zesu stateless validator proven on Zisk.
    ZesuZisk = 7,
}

impl ProofType {
    /// Every proof type assigned by the current EIP-8025 specification.
    pub const fn all() -> &'static [Self] {
        Self::VARIANTS
    }

    /// The proof system this proof type is verified with.
    pub const fn zkvm(self) -> ZkvmKind {
        match self {
            Self::EthrexOpenVM | Self::RethOpenVM => ZkvmKind::Openvm,
            Self::EthrexSP1 | Self::RethSP1 => ZkvmKind::Sp1,
            Self::EthrexZisk | Self::RethZisk | Self::ZesuZisk => ZkvmKind::Zisk,
        }
    }

    /// The assigned EIP-8025 wire encoding.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// A `u8` encoding that no EIP-8025 proof type is assigned to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnassignedProofType(pub u8);

impl std::fmt::Display for UnassignedProofType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unassigned EIP-8025 proof type: {}", self.0)
    }
}

impl std::error::Error for UnassignedProofType {}

impl TryFrom<u8> for ProofType {
    type Error = UnassignedProofType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_repr(value).ok_or(UnassignedProofType(value))
    }
}

impl From<ProofType> for u8 {
    fn from(value: ProofType) -> Self {
        value.to_u8()
    }
}

// `ssz(enum_behaviour = "tag")` cannot be used here: it encodes the variant *index*, not the
// assigned discriminant, and rejects explicit selectors, so proof types would go on the wire as
// consecutive indices instead of their assigned discriminants.
impl SszEncode for ProofType {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        1
    }

    fn ssz_bytes_len(&self) -> usize {
        1
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.to_u8().ssz_append(buf);
    }
}

impl SszDecode for ProofType {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        1
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::try_from(u8::from_ssz_bytes(bytes)?)
            .map_err(|error| DecodeError::BytesInvalid(error.to_string()))
    }
}

impl TreeHashTrait for ProofType {
    fn tree_hash_type() -> TreeHashType {
        u8::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        self.to_u8().tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        u8::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> Hash256 {
        self.to_u8().tree_hash_root()
    }
}

/// Serialize a [`ProofType`] as a quoted decimal string, as the Beacon API requires.
pub(super) mod quoted_proof_type {
    use super::ProofType;
    use serde::{Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(value: &ProofType, serializer: S) -> Result<S::Ok, S::Error> {
        serde_utils::quoted_u8::serialize(&value.to_u8(), serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<ProofType, D::Error> {
        let value: u8 = serde_utils::quoted_u8::deserialize(deserializer)?;
        ProofType::try_from(value).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigned_proof_types_match_spec() {
        assert_eq!(
            ProofType::all(),
            [
                ProofType::EthrexOpenVM,
                ProofType::EthrexSP1,
                ProofType::EthrexZisk,
                ProofType::RethOpenVM,
                ProofType::RethSP1,
                ProofType::RethZisk,
                ProofType::ZesuZisk,
            ]
        );

        // The discriminants are the wire encoding, so `all()` and the assignments must agree.
        for (index, proof_type) in ProofType::all().iter().enumerate() {
            let encoding = u8::try_from(index + 1).expect("index within bound");
            assert_eq!(proof_type.to_u8(), encoding);
            assert_eq!(ProofType::try_from(encoding), Ok(*proof_type));
        }

        for unassigned in [0, 8, u8::MAX] {
            assert_eq!(
                ProofType::try_from(unassigned),
                Err(UnassignedProofType(unassigned))
            );
        }
    }

    #[test]
    fn proof_type_display_uses_variant_name() {
        assert_eq!(ProofType::EthrexOpenVM.to_string(), "EthrexOpenVM");
        assert_eq!(ProofType::EthrexSP1.to_string(), "EthrexSP1");
        assert_eq!(ProofType::EthrexZisk.to_string(), "EthrexZisk");
        assert_eq!(ProofType::RethOpenVM.to_string(), "RethOpenVM");
        assert_eq!(ProofType::RethSP1.to_string(), "RethSP1");
        assert_eq!(ProofType::RethZisk.to_string(), "RethZisk");
        assert_eq!(ProofType::ZesuZisk.to_string(), "ZesuZisk");
    }

    #[test]
    fn every_proof_type_names_its_proof_system() {
        let expected = [
            (ProofType::EthrexOpenVM, ZkvmKind::Openvm),
            (ProofType::EthrexSP1, ZkvmKind::Sp1),
            (ProofType::EthrexZisk, ZkvmKind::Zisk),
            (ProofType::RethOpenVM, ZkvmKind::Openvm),
            (ProofType::RethSP1, ZkvmKind::Sp1),
            (ProofType::RethZisk, ZkvmKind::Zisk),
            (ProofType::ZesuZisk, ZkvmKind::Zisk),
        ];
        for (proof_type, zkvm) in expected {
            assert_eq!(proof_type.zkvm(), zkvm);
        }
    }

    #[test]
    fn proof_type_ssz_round_trips_as_its_assigned_encoding() {
        for proof_type in ProofType::all() {
            let bytes = proof_type.as_ssz_bytes();
            assert_eq!(bytes, [proof_type.to_u8()]);
            assert_eq!(
                ProofType::from_ssz_bytes(&bytes).expect("assigned encoding decodes"),
                *proof_type
            );
        }

        // Unassigned encodings are rejected by the codec, and the tree hash matches the `u8`.
        for unassigned in [0u8, 8, u8::MAX] {
            assert!(ProofType::from_ssz_bytes(&[unassigned]).is_err());
        }
        assert_eq!(
            ProofType::RethSP1.tree_hash_root(),
            ProofType::RethSP1.to_u8().tree_hash_root()
        );
    }
}

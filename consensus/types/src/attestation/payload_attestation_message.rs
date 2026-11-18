use crate::ForkName;
use crate::attestation::payload_attestation_data::PayloadAttestationData;
use crate::{ForkVersionDecode, XmssSignature};
use bls::Signature;
use context_deserialize::{ContextDeserialize, context_deserialize};
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Gloas, Pq),
    variant_attributes(
        derive(
            TreeHash,
            Debug,
            Clone,
            PartialEq,
            Encode,
            Decode,
            Serialize,
            Deserialize
        ),
        context_deserialize(ForkName),
        cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary)),
    )
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(TreeHash, Debug, Clone, PartialEq, Encode, Decode, Serialize, Deserialize)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct PayloadAttestationMessage {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub data: PayloadAttestationData,
    #[superstruct(only(Gloas))]
    pub signature: Signature,
    #[superstruct(only(Pq), partial_getter(rename = "signature_pq"))]
    pub signature: XmssSignature,
}

impl ForkVersionDecode for PayloadAttestationMessage {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork {
            ForkName::Pq => PayloadAttestationMessagePq::from_ssz_bytes(bytes).map(Self::Pq),
            ForkName::Gloas | ForkName::Heze => {
                PayloadAttestationMessageGloas::from_ssz_bytes(bytes).map(Self::Gloas)
            }
            _ => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for PayloadAttestationMessage: {fork}"
            ))),
        }
    }
}

impl<'de> ContextDeserialize<'de, ForkName> for PayloadAttestationMessage {
    fn context_deserialize<D: Deserializer<'de>>(
        deserializer: D,
        fork: ForkName,
    ) -> Result<Self, D::Error> {
        match fork {
            ForkName::Pq => PayloadAttestationMessagePq::deserialize(deserializer).map(Self::Pq),
            ForkName::Gloas | ForkName::Heze => {
                PayloadAttestationMessageGloas::deserialize(deserializer).map(Self::Gloas)
            }
            _ => Err(serde::de::Error::custom(format!(
                "unsupported fork for PayloadAttestationMessage: {fork}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PayloadAttestationMessageGloas);
}

#[cfg(test)]
mod pq_tests {
    use super::*;

    ssz_and_tree_hash_tests!(PayloadAttestationMessagePq);
}

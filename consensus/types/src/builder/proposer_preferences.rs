use crate::{Address, ChainSpec, Domain, EthSpec, Fork, ForkName, Hash256, SignedRoot, Slot};
use crate::{ForkVersionDecode, XmssSignature};
use bls::{PublicKey, Signature};
use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

#[derive(Default, Debug, Clone, Serialize, Encode, Decode, Deserialize, TreeHash, Educe)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[educe(PartialEq, Hash)]
#[context_deserialize(ForkName)]
// https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/p2p-interface.md#new-proposerpreferences
pub struct ProposerPreferences {
    pub dependent_root: Hash256,
    pub proposal_slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub fee_recipient: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    pub target_gas_limit: u64,
}

impl SignedRoot for ProposerPreferences {}

// https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/p2p-interface.md#new-signedproposerpreferences
#[superstruct(
    variants(Gloas, Pq),
    variant_attributes(
        derive(TreeHash, Debug, Clone, Encode, Decode, Serialize, Deserialize, Educe),
        context_deserialize(ForkName),
        cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary)),
        educe(PartialEq, Hash),
    )
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(TreeHash, Debug, Clone, Encode, Decode, Serialize, Deserialize, Educe)]
#[educe(PartialEq, Hash)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct SignedProposerPreferences {
    pub message: ProposerPreferences,
    #[superstruct(only(Gloas))]
    pub signature: Signature,
    #[superstruct(only(Pq), partial_getter(rename = "signature_pq"))]
    pub signature: XmssSignature,
}

impl ForkVersionDecode for SignedProposerPreferences {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork {
            ForkName::Pq => SignedProposerPreferencesPq::from_ssz_bytes(bytes).map(Self::Pq),
            ForkName::Gloas | ForkName::Heze => {
                SignedProposerPreferencesGloas::from_ssz_bytes(bytes).map(Self::Gloas)
            }
            _ => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for SignedProposerPreferences: {fork}"
            ))),
        }
    }
}

impl<'de> ContextDeserialize<'de, ForkName> for SignedProposerPreferences {
    fn context_deserialize<D: Deserializer<'de>>(
        deserializer: D,
        fork: ForkName,
    ) -> Result<Self, D::Error> {
        match fork {
            ForkName::Pq => SignedProposerPreferencesPq::deserialize(deserializer).map(Self::Pq),
            ForkName::Gloas | ForkName::Heze => {
                SignedProposerPreferencesGloas::deserialize(deserializer).map(Self::Gloas)
            }
            _ => Err(serde::de::Error::custom(format!(
                "unsupported fork for SignedProposerPreferences: {fork}"
            ))),
        }
    }
}

impl SignedProposerPreferencesGloas {
    pub fn empty() -> Self {
        Self {
            message: ProposerPreferences::default(),
            signature: Signature::empty(),
        }
    }

    /// Verify `self.signature` against the given `pubkey`.
    pub fn verify_signature<E: EthSpec>(
        &self,
        pubkey: &PublicKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> bool {
        let proposal_epoch = self.message.proposal_slot.epoch(E::slots_per_epoch());
        let domain = spec.get_domain(
            proposal_epoch,
            Domain::ProposerPreferences,
            fork,
            genesis_validators_root,
        );
        let message = self.message.signing_root(domain);
        self.signature.verify(pubkey, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(ProposerPreferences);

    /// `validator_index` and `target_gas_limit` must serialize as quoted JSON strings (Beacon API
    /// convention) and round-trip back to their numeric values.
    #[test]
    fn quoted_u64_json_serde() {
        let preferences = ProposerPreferences {
            dependent_root: Hash256::ZERO,
            proposal_slot: Slot::new(7),
            validator_index: 42,
            fee_recipient: Address::ZERO,
            target_gas_limit: 30_000_000,
        };

        let value = serde_json::to_value(&preferences).unwrap();
        assert_eq!(value["validator_index"], serde_json::json!("42"));
        assert_eq!(value["target_gas_limit"], serde_json::json!("30000000"));

        let decoded: ProposerPreferences = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, preferences);
    }
}

#[cfg(test)]
mod pq_tests {
    use super::*;

    ssz_and_tree_hash_tests!(SignedProposerPreferencesPq);
}

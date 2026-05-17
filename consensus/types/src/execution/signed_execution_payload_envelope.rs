use crate::execution::{
    ExecutionPayloadEnvelopeGloas, ExecutionPayloadEnvelopeHeze, ExecutionPayloadEnvelopeRef,
};
use crate::fork::ForkVersionDecode;
use crate::state::BeaconStateError;
use crate::{
    BeaconState, ChainSpec, Domain, Epoch, EthSpec, ExecutionBlockHash, Fork, ForkName, Hash256,
    SignedRoot, Slot, consts::gloas::BUILDER_INDEX_SELF_BUILD,
};
use bls::{PublicKey, Signature};
use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Gloas, Heze),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            Educe,
        ),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        context_deserialize(ForkName),
        serde(bound = "E: EthSpec"),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
    ),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    map_ref_into(ExecutionPayloadEnvelopeRef)
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, TreeHash)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct SignedExecutionPayloadEnvelope<E: EthSpec> {
    #[superstruct(flatten)]
    pub message: ExecutionPayloadEnvelope<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedExecutionPayloadEnvelope<E> {
    pub fn message(&self) -> ExecutionPayloadEnvelopeRef<'_, E> {
        match self {
            Self::Gloas(inner) => ExecutionPayloadEnvelopeRef::Gloas(&inner.message),
            Self::Heze(inner) => ExecutionPayloadEnvelopeRef::Heze(&inner.message),
        }
    }

    pub fn min_size() -> usize {
        SignedExecutionPayloadEnvelopeGloas::<E>::empty()
            .as_ssz_bytes()
            .len()
    }

    #[allow(clippy::arithmetic_side_effects)]
    pub fn max_size() -> usize {
        Self::min_size() + ExecutionPayloadEnvelopeGloas::<E>::max_size()
            - ExecutionPayloadEnvelopeGloas::<E>::min_size()
    }

    pub fn slot(&self) -> Slot {
        match self {
            Self::Gloas(inner) => inner.message.payload.slot_number,
            Self::Heze(inner) => inner.message.payload.slot_number,
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.slot().epoch(E::slots_per_epoch())
    }

    pub fn beacon_block_root(&self) -> Hash256 {
        match self {
            Self::Gloas(inner) => inner.message.beacon_block_root,
            Self::Heze(inner) => inner.message.beacon_block_root,
        }
    }

    pub fn block_hash(&self) -> ExecutionBlockHash {
        match self {
            Self::Gloas(inner) => inner.message.payload.block_hash,
            Self::Heze(inner) => inner.message.payload.block_hash,
        }
    }

    pub fn builder_index(&self) -> u64 {
        match self {
            Self::Gloas(inner) => inner.message.builder_index,
            Self::Heze(inner) => inner.message.builder_index,
        }
    }

    /// Verify `self.signature`.
    pub fn verify_signature(
        &self,
        pubkey: &PublicKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> bool {
        let domain = spec.get_domain(
            self.epoch(),
            Domain::BeaconBuilder,
            fork,
            genesis_validators_root,
        );

        let message = self.message().signing_root(domain);
        self.signature().verify(pubkey, message)
    }

    /// Verify `self.signature` using keys drawn from the beacon state.
    pub fn verify_signature_with_state(
        &self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<bool, BeaconStateError> {
        let builder_index = self.builder_index();

        let pubkey_bytes = if builder_index == BUILDER_INDEX_SELF_BUILD {
            let validator_index = state.latest_block_header().proposer_index;
            state.get_validator(validator_index as usize)?.pubkey
        } else {
            state.get_builder(builder_index)?.pubkey
        };

        let pubkey = pubkey_bytes.decompress()?;

        if self.epoch() != state.current_epoch() {
            return Err(BeaconStateError::SignedEnvelopeIncorrectEpoch {
                state_epoch: state.current_epoch(),
                envelope_epoch: self.epoch(),
            });
        }

        Ok(self.verify_signature(
            &pubkey,
            &state.fork(),
            state.genesis_validators_root(),
            spec,
        ))
    }
}

impl<E: EthSpec> SignedExecutionPayloadEnvelopeGloas<E> {
    pub fn empty() -> Self {
        Self {
            message: ExecutionPayloadEnvelopeGloas::empty(),
            signature: Signature::empty(),
        }
    }
}

impl<E: EthSpec> SignedExecutionPayloadEnvelopeHeze<E> {
    pub fn empty() -> Self {
        Self {
            message: ExecutionPayloadEnvelopeHeze::empty(),
            signature: Signature::empty(),
        }
    }
}

impl<E: EthSpec> ForkVersionDecode for SignedExecutionPayloadEnvelope<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Gloas => {
                <SignedExecutionPayloadEnvelopeGloas<E> as ssz::Decode>::from_ssz_bytes(bytes)
                    .map(Self::Gloas)
            }
            ForkName::Heze => {
                <SignedExecutionPayloadEnvelopeHeze<E> as ssz::Decode>::from_ssz_bytes(bytes)
                    .map(Self::Heze)
            }
            _ => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for SignedExecutionPayloadEnvelope: {fork_name}",
            ))),
        }
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for SignedExecutionPayloadEnvelope<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err = |e| {
            serde::de::Error::custom(format!(
                "SignedExecutionPayloadEnvelope failed to deserialize: {:?}",
                e
            ))
        };
        match context {
            ForkName::Heze => Ok(Self::Heze(
                Deserialize::deserialize(deserializer).map_err(convert_err)?,
            )),
            ForkName::Gloas => Ok(Self::Gloas(
                Deserialize::deserialize(deserializer).map_err(convert_err)?,
            )),
            _ => Err(serde::de::Error::custom(format!(
                "SignedExecutionPayloadEnvelope failed to deserialize: unsupported fork '{}'",
                context
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    mod gloas {
        use super::*;
        ssz_and_tree_hash_tests!(SignedExecutionPayloadEnvelopeGloas<MainnetEthSpec>);
    }
    mod heze {
        use super::*;
        ssz_and_tree_hash_tests!(SignedExecutionPayloadEnvelopeHeze<MainnetEthSpec>);
    }
}

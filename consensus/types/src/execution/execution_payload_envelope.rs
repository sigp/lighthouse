use crate::execution::{ExecutionPayloadGloas, ExecutionRequestsGloas};
use crate::{
    BeaconStateError, ChainSpec, EthSpec, ForkName, ForkVersionDecode, Hash256, InconsistentFork,
    SignedRoot, Slot,
};
use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{BYTES_PER_LENGTH_OFFSET, Decode, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Gloas, Heze),
    variant_attributes(
        derive(
            Default,
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            Educe,
        ),
        context_deserialize(ForkName),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        serde(bound = "E: EthSpec"),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
    ),
    ref_attributes(derive(Debug, PartialEq, TreeHash), tree_hash(enum_behaviour = "transparent")),
    specific_variant_attributes(
        Gloas(tree_hash(
            struct_behaviour = "progressive_container",
            active_fields(1, 1, 1, 1, 1)
        )),
        // `beacon_block_root` is inactive, keeping the generalized indices of the other fields.
        Heze(tree_hash(
            struct_behaviour = "progressive_container",
            active_fields(1, 1, 1, 0, 1)
        ))
    ),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    )
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Encode, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec", untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ExecutionPayloadEnvelope<E: EthSpec> {
    pub payload: ExecutionPayloadGloas<E>,
    // [Modified in Gloas:EIP7688]
    pub execution_requests: ExecutionRequestsGloas<E>,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    // [Removed in Heze:EIP8411]
    #[superstruct(only(Gloas), partial_getter(copy))]
    pub beacon_block_root: Hash256,
    #[superstruct(getter(copy))]
    pub parent_beacon_block_root: Hash256,
}

impl<E: EthSpec> ExecutionPayloadEnvelope<E> {
    /// Returns the minimum SSZ-encoded size of any variant (all variable-length fields empty).
    pub fn min_size() -> usize {
        std::cmp::min(
            ExecutionPayloadEnvelopeGloas::<E>::default()
                .as_ssz_bytes()
                .len(),
            ExecutionPayloadEnvelopeHeze::<E>::default()
                .as_ssz_bytes()
                .len(),
        )
    }

    /// Returns the maximum SSZ-encoded size of any variant.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn max_size() -> usize {
        // The variants share their variable-length fields, so the largest fixed part bounds them.
        std::cmp::max(
            ExecutionPayloadEnvelopeGloas::<E>::default()
                .as_ssz_bytes()
                .len(),
            ExecutionPayloadEnvelopeHeze::<E>::default()
                .as_ssz_bytes()
                .len(),
        )
            // ExecutionPayloadGloas variable-length fields:
            + (E::max_extra_data_bytes() * <u8 as SszEncode>::ssz_fixed_len())
            + (E::max_transactions_per_payload()
                * (BYTES_PER_LENGTH_OFFSET + E::max_bytes_per_transaction()))
            + (E::max_withdrawals_per_payload()
                * <crate::Withdrawal as SszEncode>::ssz_fixed_len())
            // ExecutionRequests variable-length fields:
            + (E::max_deposit_requests_per_payload()
                * <crate::DepositRequest as SszEncode>::ssz_fixed_len())
            + (E::max_withdrawal_requests_per_payload()
                * <crate::WithdrawalRequest as SszEncode>::ssz_fixed_len())
            + (E::max_consolidation_requests_per_payload()
                * <crate::ConsolidationRequest as SszEncode>::ssz_fixed_len())
    }

    pub fn slot(&self) -> Slot {
        self.payload().slot_number
    }

    /// Consumes the envelope, returning its payload and execution requests.
    pub fn into_payload_and_requests(
        self,
    ) -> (ExecutionPayloadGloas<E>, ExecutionRequestsGloas<E>) {
        match self {
            Self::Gloas(envelope) => (envelope.payload, envelope.execution_requests),
            Self::Heze(envelope) => (envelope.payload, envelope.execution_requests),
        }
    }

    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        let fork_at_slot = spec.fork_name_at_slot::<E>(self.slot());
        let object_fork = self.fork_name_unchecked();

        if fork_at_slot == object_fork {
            Ok(object_fork)
        } else {
            Err(InconsistentFork {
                fork_at_slot,
                object_fork,
            })
        }
    }

    /// Returns the name of the fork pertaining to `self`.
    /// Does not check that the fork is consistent with the slot.
    pub fn fork_name_unchecked(&self) -> ForkName {
        match self {
            ExecutionPayloadEnvelope::Gloas(_) => ForkName::Gloas,
            ExecutionPayloadEnvelope::Heze(_) => ForkName::Heze,
        }
    }
}

impl<E: EthSpec> SignedRoot for ExecutionPayloadEnvelope<E> {}
impl<'a, E: EthSpec> SignedRoot for ExecutionPayloadEnvelopeRef<'a, E> {}

impl<E: EthSpec> ForkVersionDecode for ExecutionPayloadEnvelope<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for ExecutionPayloadEnvelope: {fork_name}"
            ))),
            ForkName::Gloas => {
                ExecutionPayloadEnvelopeGloas::from_ssz_bytes(bytes).map(Self::Gloas)
            }
            ForkName::Heze => ExecutionPayloadEnvelopeHeze::from_ssz_bytes(bytes).map(Self::Heze),
        }
    }
}

/// An execution payload envelope along with the root of its beacon block, as served by version 2 of
/// the envelope RPCs (EIP-8411). Heze envelopes don't contain the root of their block.
#[derive(Debug, Clone, PartialEq, Encode)]
pub struct ExecutionPayloadEnvelopeWithRoot<E: EthSpec> {
    pub beacon_block_root: Hash256,
    pub envelope: ExecutionPayloadEnvelope<E>,
}

impl<E: EthSpec> ExecutionPayloadEnvelopeWithRoot<E> {
    /// Returns the SSZ encoding of an `ExecutionPayloadEnvelopeWithRoot`, without cloning
    /// `envelope`.
    pub fn ssz_bytes(
        beacon_block_root: Hash256,
        envelope: &ExecutionPayloadEnvelope<E>,
    ) -> Vec<u8> {
        let offset = Self::fixed_len();
        let mut bytes = Vec::with_capacity(offset.saturating_add(envelope.ssz_bytes_len()));
        let mut encoder = ssz::SszEncoder::container(&mut bytes, offset);
        encoder.append(&beacon_block_root);
        encoder.append(envelope);
        encoder.finalize();
        bytes
    }

    /// Returns the minimum SSZ-encoded size of any variant.
    pub fn min_size() -> usize {
        Self::fixed_len().saturating_add(ExecutionPayloadEnvelope::<E>::min_size())
    }

    /// Returns the maximum SSZ-encoded size of any variant.
    pub fn max_size() -> usize {
        Self::fixed_len().saturating_add(ExecutionPayloadEnvelope::<E>::max_size())
    }

    /// The length of the fixed part: the root and the offset of the envelope.
    fn fixed_len() -> usize {
        <Hash256 as SszEncode>::ssz_fixed_len().saturating_add(BYTES_PER_LENGTH_OFFSET)
    }
}

impl<E: EthSpec> ForkVersionDecode for ExecutionPayloadEnvelopeWithRoot<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        // The envelope decoder needs the fork, which doesn't compose with `ssz_derive`.
        let mut builder = ssz::SszDecoderBuilder::new(bytes);

        builder.register_type::<Hash256>()?;
        builder.register_anonymous_variable_length_item()?;

        let mut decoder = builder.build()?;

        let beacon_block_root = decoder.decode_next()?;
        let envelope = decoder.decode_next_with(|bytes| {
            ExecutionPayloadEnvelope::from_ssz_bytes_by_fork(bytes, fork_name)
        })?;

        Ok(Self {
            beacon_block_root,
            envelope,
        })
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for ExecutionPayloadEnvelope<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err = |e| {
            serde::de::Error::custom(format!(
                "ExecutionPayloadEnvelope failed to deserialize: {:?}",
                e
            ))
        };
        Ok(match context {
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu => {
                return Err(serde::de::Error::custom(format!(
                    "ExecutionPayloadEnvelope failed to deserialize: unsupported fork '{}'",
                    context
                )));
            }
            ForkName::Gloas => {
                Self::Gloas(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Heze => {
                Self::Heze(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
        })
    }
}

#[cfg(test)]
mod gloas_tests {
    use super::*;
    use crate::Spec;

    ssz_and_tree_hash_tests!(ExecutionPayloadEnvelopeGloas<Spec>);
}

#[cfg(test)]
mod heze_tests {
    use super::*;
    use crate::Spec;

    ssz_and_tree_hash_tests!(ExecutionPayloadEnvelopeHeze<Spec>);

    #[test]
    fn heze_drops_beacon_block_root() {
        let gloas = ExecutionPayloadEnvelopeGloas::<Spec>::default();
        let heze = ExecutionPayloadEnvelopeHeze::<Spec>::default();
        assert_eq!(
            gloas.as_ssz_bytes().len(),
            heze.as_ssz_bytes().len() + 32,
            "the Heze envelope must not serialize `beacon_block_root`",
        );
        assert!(
            ExecutionPayloadEnvelope::Heze(heze)
                .beacon_block_root()
                .is_err()
        );
    }

    #[test]
    fn envelope_with_root_round_trip() {
        let with_root = ExecutionPayloadEnvelopeWithRoot::<Spec> {
            beacon_block_root: Hash256::repeat_byte(1),
            envelope: ExecutionPayloadEnvelope::Heze(ExecutionPayloadEnvelopeHeze {
                builder_index: 7,
                parent_beacon_block_root: Hash256::repeat_byte(2),
                ..Default::default()
            }),
        };
        let bytes = with_root.as_ssz_bytes();
        assert_eq!(
            ExecutionPayloadEnvelopeWithRoot::ssz_bytes(
                with_root.beacon_block_root,
                &with_root.envelope
            ),
            bytes
        );
        assert_eq!(
            ExecutionPayloadEnvelopeWithRoot::from_ssz_bytes_by_fork(&bytes, ForkName::Heze),
            Ok(with_root)
        );
    }
}

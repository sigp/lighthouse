use crate::execution::{
    ExecutionPayloadGloas, ExecutionPayloadRef, ExecutionRequestsGloas,
    verify_execution_payload_list_lengths_post_gloas,
    verify_execution_request_list_lengths_post_gloas,
};
use crate::{EthSpec, ForkName, Hash256, SignedRoot, Slot};
use context_deserialize::context_deserialize;
use educe::Educe;
use fixed_bytes::FixedBytesExtended;
use serde::{Deserialize, Serialize};
use ssz::{BYTES_PER_LENGTH_OFFSET, Decode, Encode as SszEncode};
use ssz_derive::Encode;
use tree_hash_derive::TreeHash;

#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Encode, Deserialize, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[context_deserialize(ForkName)]
#[serde(bound = "E: EthSpec")]
#[tree_hash(
    struct_behaviour = "progressive_container",
    active_fields(1, 1, 1, 1, 1)
)]
pub struct ExecutionPayloadEnvelope<E: EthSpec> {
    pub payload: ExecutionPayloadGloas<E>,
    // [Modified in Gloas:EIP7688]
    pub execution_requests: ExecutionRequestsGloas<E>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    pub beacon_block_root: Hash256,
    pub parent_beacon_block_root: Hash256,
}

impl<E: EthSpec> ExecutionPayloadEnvelope<E> {
    /// Returns an empty envelope with all fields zeroed. Used for SSZ size calculations.
    pub fn empty() -> Self {
        Self {
            payload: ExecutionPayloadGloas::default(),
            execution_requests: ExecutionRequestsGloas::default(),
            builder_index: 0,
            beacon_block_root: Hash256::zero(),
            parent_beacon_block_root: Hash256::zero(),
        }
    }

    /// Returns the minimum SSZ-encoded size (all variable-length fields empty).
    pub fn min_size() -> usize {
        Self::empty().as_ssz_bytes().len()
    }

    /// Returns the maximum SSZ-encoded size.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn max_size() -> usize {
        Self::min_size()
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
        self.payload.slot_number
    }
}

impl<E: EthSpec> SignedRoot for ExecutionPayloadEnvelope<E> {}

impl<E: EthSpec> Decode for ExecutionPayloadEnvelope<E> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_type::<ExecutionPayloadGloas<E>>()?;
        builder.register_type::<ExecutionRequestsGloas<E>>()?;
        builder.register_type::<u64>()?;
        builder.register_type::<Hash256>()?;
        builder.register_type::<Hash256>()?;

        let mut decoder = builder.build()?;
        let envelope = Self {
            payload: decoder.decode_next()?,
            execution_requests: decoder.decode_next()?,
            builder_index: decoder.decode_next()?,
            beacon_block_root: decoder.decode_next()?,
            parent_beacon_block_root: decoder.decode_next()?,
        };
        verify_execution_payload_list_lengths_post_gloas(ExecutionPayloadRef::Gloas(
            &envelope.payload,
        ))?;
        verify_execution_request_list_lengths_post_gloas(&envelope.execution_requests)?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ExecutionPayload, ForkVersionDecode, MainnetEthSpec, SignedExecutionPayloadEnvelope,
    };
    use bls::Signature;

    ssz_and_tree_hash_tests!(ExecutionPayloadEnvelope<MainnetEthSpec>);

    type E = MainnetEthSpec;

    fn assert_payload_decoding_result(
        payload: ExecutionPayloadGloas<E>,
        expected: Result<(), ssz::DecodeError>,
    ) {
        assert_eq!(
            verify_execution_payload_list_lengths_post_gloas(ExecutionPayloadRef::Gloas(&payload)),
            expected
        );
        let payload_bytes = payload.as_ssz_bytes();
        for fork in [ForkName::Gloas, ForkName::Heze] {
            assert_eq!(
                ExecutionPayload::<E>::from_ssz_bytes_by_fork(&payload_bytes, fork).map(
                    |decoded| {
                        assert_eq!(decoded.fork_name(), fork);
                        assert_eq!(decoded.as_ssz_bytes(), payload_bytes);
                    }
                ),
                expected
            );
        }

        let envelope = ExecutionPayloadEnvelope {
            payload,
            ..ExecutionPayloadEnvelope::empty()
        };
        assert_eq!(
            ExecutionPayloadEnvelope::<E>::from_ssz_bytes(&envelope.as_ssz_bytes())
                .map(|decoded| assert_eq!(decoded, envelope)),
            expected
        );
        let signed_envelope = SignedExecutionPayloadEnvelope {
            message: envelope,
            signature: Signature::empty(),
        };
        assert_eq!(
            SignedExecutionPayloadEnvelope::<E>::from_ssz_bytes(&signed_envelope.as_ssz_bytes())
                .map(|decoded| assert_eq!(decoded, signed_envelope)),
            expected
        );
    }

    #[test]
    fn payload_transaction_list_length() {
        let max = E::max_transactions_per_payload();
        let mut payload = ExecutionPayloadGloas {
            transactions: std::iter::repeat_n(Default::default(), max).collect(),
            ..ExecutionPayloadGloas::default()
        };
        assert_payload_decoding_result(payload.clone(), Ok(()));

        payload.transactions.push(Default::default());
        assert_payload_decoding_result(
            payload,
            Err(ssz::DecodeError::BytesInvalid(format!(
                "progressive list transactions has length {} > {max}",
                max + 1,
            ))),
        );
    }

    #[test]
    fn payload_withdrawal_list_length() {
        let max = E::max_withdrawals_per_payload();
        let mut payload = ExecutionPayloadGloas {
            withdrawals: std::iter::repeat_n(crate::test_utils::test_arbitrary_instance(), max)
                .collect(),
            ..ExecutionPayloadGloas::default()
        };
        assert_payload_decoding_result(payload.clone(), Ok(()));

        payload.withdrawals.push(payload.withdrawals[0].clone());
        assert_payload_decoding_result(
            payload,
            Err(ssz::DecodeError::BytesInvalid(format!(
                "progressive list withdrawals has length {} > {max}",
                max + 1,
            ))),
        );
    }
}

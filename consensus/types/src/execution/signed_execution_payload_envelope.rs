use crate::{
    Address, BeaconState, BeaconStateError, BlockAccessList, ChainSpec, Domain, Epoch, EthSpec,
    ExecutionBlockHash, ExecutionPayloadEnvelope, ExecutionPayloadGloas, ExecutionRequestsGloas,
    Fork, ForkName, Hash256, ProgressiveTransactions, ProgressiveWithdrawals, SignedRoot, Slot,
    Uint256, consts::gloas::BUILDER_INDEX_SELF_BUILD,
};
use bls::{PublicKey, Signature};
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use tree_hash_derive::TreeHash;

#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Encode, Decode, Deserialize, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec")]
#[context_deserialize(ForkName)]
pub struct SignedExecutionPayloadEnvelope<E: EthSpec> {
    pub message: ExecutionPayloadEnvelope<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedExecutionPayloadEnvelope<E> {
    /// Returns the minimum SSZ-encoded size (all variable-length fields empty).
    pub fn min_size() -> usize {
        Self {
            message: ExecutionPayloadEnvelope::empty(),
            signature: Signature::empty(),
        }
        .as_ssz_bytes()
        .len()
    }

    /// Returns the maximum SSZ-encoded size.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn max_size() -> usize {
        // Signature is fixed-size, so the variable-length delta is entirely from the envelope.
        Self::min_size() + ExecutionPayloadEnvelope::<E>::max_size()
            - ExecutionPayloadEnvelope::<E>::min_size()
    }

    pub fn slot(&self) -> Slot {
        self.message.slot()
    }

    pub fn epoch(&self) -> Epoch {
        self.slot().epoch(E::slots_per_epoch())
    }

    pub fn beacon_block_root(&self) -> Hash256 {
        self.message.beacon_block_root
    }

    pub fn block_hash(&self) -> ExecutionBlockHash {
        self.message.payload.block_hash
    }

    /// Verify `self.signature`.
    pub fn verify_signature(
        &self,
        pubkey: &PublicKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> bool {
        // Signed envelopes using the new BeaconBuilder domain per the spec:
        // https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#new-verify_execution_payload_envelope_signature
        let domain = spec.get_domain(
            self.epoch(),
            Domain::BeaconBuilder,
            fork,
            genesis_validators_root,
        );

        let message = self.message.signing_root(domain);

        self.signature.verify(pubkey, message)
    }

    /// Verify `self.signature` using keys drawn from the beacon state.
    pub fn verify_signature_with_state(
        &self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<bool, BeaconStateError> {
        let builder_index = self.message.builder_index;

        let pubkey_bytes = if builder_index == BUILDER_INDEX_SELF_BUILD {
            let validator_index = state.latest_block_header().proposer_index;
            state.get_validator(validator_index as usize)?.pubkey
        } else {
            state.get_builder(builder_index)?.pubkey
        };

        // TODO(gloas): Could use pubkey cache on state here, but it probably isn't worth
        // it because this function is rarely used. Almost always the envelope should be signature
        // verified prior to consensus code running.
        let pubkey = pubkey_bytes.decompress()?;

        // Ensure the state's epoch matches the message's epoch before determining the Fork.
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

/// The fixed fields of a Gloas execution payload.
///
/// Together with the body returned by `engine_getPayloadBodiesByHashV2`, these fields can be used
/// to reconstruct an `ExecutionPayloadGloas` without an additional execution-layer request.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
#[serde(bound = "E: EthSpec")]
pub struct ExecutionPayloadHeaderGloas<E: EthSpec> {
    pub parent_hash: ExecutionBlockHash,
    #[serde(with = "serde_utils::address_hex")]
    pub fee_recipient: Address,
    pub state_root: Hash256,
    pub receipts_root: Hash256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, E::BytesPerLogsBloom>,
    pub prev_randao: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub block_number: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, E::MaxExtraDataBytes>,
    #[serde(with = "serde_utils::quoted_u256")]
    pub base_fee_per_gas: Uint256,
    pub block_hash: ExecutionBlockHash,
    #[serde(with = "serde_utils::quoted_u64")]
    pub blob_gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub excess_blob_gas: u64,
    pub slot_number: Slot,
}

impl<E: EthSpec> From<&ExecutionPayloadGloas<E>> for ExecutionPayloadHeaderGloas<E> {
    fn from(payload: &ExecutionPayloadGloas<E>) -> Self {
        Self {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
            slot_number: payload.slot_number,
        }
    }
}

impl<E: EthSpec> ExecutionPayloadHeaderGloas<E> {
    pub fn into_payload(
        self,
        transactions: ProgressiveTransactions,
        withdrawals: ProgressiveWithdrawals,
        block_access_list: BlockAccessList,
    ) -> ExecutionPayloadGloas<E> {
        ExecutionPayloadGloas {
            parent_hash: self.parent_hash,
            fee_recipient: self.fee_recipient,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom,
            prev_randao: self.prev_randao,
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data,
            base_fee_per_gas: self.base_fee_per_gas,
            block_hash: self.block_hash,
            transactions,
            withdrawals,
            blob_gas_used: self.blob_gas_used,
            excess_blob_gas: self.excess_blob_gas,
            block_access_list,
            slot_number: self.slot_number,
        }
    }
}

/// The persistent fields of a signed execution payload envelope.
///
/// The execution payload body is stored separately and can be pruned after finalization. The
/// summary retains enough information to reconstruct the envelope from a body returned by the EL.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedExecutionPayloadEnvelopeSummary<E: EthSpec> {
    pub payload_header: ExecutionPayloadHeaderGloas<E>,
    pub execution_requests: ExecutionRequestsGloas<E>,
    pub builder_index: u64,
    pub beacon_block_root: Hash256,
    pub parent_beacon_block_root: Hash256,
    pub signature: Signature,
}

impl<E: EthSpec> From<SignedExecutionPayloadEnvelope<E>>
    for (
        SignedExecutionPayloadEnvelopeSummary<E>,
        ExecutionPayloadGloas<E>,
    )
{
    fn from(envelope: SignedExecutionPayloadEnvelope<E>) -> Self {
        let SignedExecutionPayloadEnvelope { message, signature } = envelope;

        let ExecutionPayloadEnvelope {
            payload,
            execution_requests,
            builder_index,
            beacon_block_root,
            parent_beacon_block_root,
        } = message;

        (
            SignedExecutionPayloadEnvelopeSummary {
                payload_header: (&payload).into(),
                execution_requests,
                builder_index,
                beacon_block_root,
                parent_beacon_block_root,
                signature,
            },
            payload,
        )
    }
}

impl<E: EthSpec> SignedExecutionPayloadEnvelopeSummary<E> {
    pub fn block_hash(&self) -> ExecutionBlockHash {
        self.payload_header.block_hash
    }

    pub fn slot(&self) -> Slot {
        self.payload_header.slot_number
    }

    pub fn into_envelope(
        self,
        payload: ExecutionPayloadGloas<E>,
    ) -> SignedExecutionPayloadEnvelope<E> {
        SignedExecutionPayloadEnvelope {
            message: ExecutionPayloadEnvelope {
                payload,
                execution_requests: self.execution_requests,
                builder_index: self.builder_index,
                beacon_block_root: self.beacon_block_root,
                parent_beacon_block_root: self.parent_beacon_block_root,
            },
            signature: self.signature,
        }
    }

    pub fn into_envelope_from_payload_body(
        self,
        transactions: ProgressiveTransactions,
        withdrawals: ProgressiveWithdrawals,
        block_access_list: BlockAccessList,
    ) -> SignedExecutionPayloadEnvelope<E> {
        let Self {
            payload_header,
            execution_requests,
            builder_index,
            beacon_block_root,
            parent_beacon_block_root,
            signature,
        } = self;
        let payload = payload_header.into_payload(transactions, withdrawals, block_access_list);

        SignedExecutionPayloadEnvelope {
            message: ExecutionPayloadEnvelope {
                payload,
                execution_requests,
                builder_index,
                beacon_block_root,
                parent_beacon_block_root,
            },
            signature,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(SignedExecutionPayloadEnvelope<MainnetEthSpec>);
}

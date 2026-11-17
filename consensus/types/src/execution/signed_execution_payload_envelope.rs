use crate::{
    Address, BeaconState, BeaconStateError, BlockAccessList, ChainSpec, Domain, Epoch, EthSpec,
    ExecutionBlockHash, ExecutionPayloadEnvelope, ExecutionPayloadEnvelopeGloas,
    ExecutionPayloadEnvelopeHeze, ExecutionPayloadGloas, ExecutionRequestsGloas, Fork, ForkName,
    ForkVersionDecode, Hash256, InconsistentFork, ProgressiveTransactions, ProgressiveWithdrawals,
    SignedRoot, Slot, Uint256, consts::gloas::BUILDER_INDEX_SELF_BUILD,
};
use bls::{PublicKey, Signature};
use context_deserialize::ContextDeserialize;
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{BYTES_PER_LENGTH_OFFSET, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use tree_hash_derive::TreeHash;

#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Encode, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec")]
pub struct SignedExecutionPayloadEnvelope<E: EthSpec> {
    pub message: ExecutionPayloadEnvelope<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedExecutionPayloadEnvelope<E> {
    /// Wraps an envelope without signing it, using the point at infinity as the signature.
    ///
    /// Heze envelopes are authenticated by the bid committing to their chunks rather than by a
    /// signature (EIP-8411).
    pub fn without_signature(message: ExecutionPayloadEnvelope<E>) -> Result<Self, bls::Error> {
        Ok(Self {
            message,
            signature: Signature::infinity()?,
        })
    }

    /// Returns the minimum SSZ-encoded size of any variant (all variable-length fields empty).
    #[allow(clippy::arithmetic_side_effects)]
    pub fn min_size() -> usize {
        BYTES_PER_LENGTH_OFFSET
            + <Signature as Encode>::ssz_fixed_len()
            + ExecutionPayloadEnvelope::<E>::min_size()
    }

    /// Returns the maximum SSZ-encoded size of any variant.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn max_size() -> usize {
        BYTES_PER_LENGTH_OFFSET
            + <Signature as Encode>::ssz_fixed_len()
            + ExecutionPayloadEnvelope::<E>::max_size()
    }

    pub fn slot(&self) -> Slot {
        self.message.slot()
    }

    pub fn epoch(&self) -> Epoch {
        self.slot().epoch(E::slots_per_epoch())
    }

    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        self.message.fork_name(spec)
    }

    /// Returns the name of the fork pertaining to `self`.
    /// Does not check that the fork is consistent with the slot.
    pub fn fork_name_unchecked(&self) -> ForkName {
        self.message.fork_name_unchecked()
    }

    /// Returns the root of the block the envelope reveals the payload for.
    ///
    /// Errors for Heze envelopes, which no longer contain the root (EIP-8411).
    pub fn beacon_block_root(&self) -> Result<Hash256, BeaconStateError> {
        self.message.beacon_block_root()
    }

    pub fn block_hash(&self) -> ExecutionBlockHash {
        self.message.payload().block_hash
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
        let builder_index = self.message.builder_index();

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

impl<E: EthSpec> ForkVersionDecode for SignedExecutionPayloadEnvelope<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        // The message decoder needs the fork, which doesn't compose with `ssz_derive`, so we
        // duplicate some parts of it here.
        let mut builder = ssz::SszDecoderBuilder::new(bytes);

        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<Signature>()?;

        let mut decoder = builder.build()?;

        let message = decoder.decode_next_with(|bytes| {
            ExecutionPayloadEnvelope::from_ssz_bytes_by_fork(bytes, fork_name)
        })?;
        let signature = decoder.decode_next()?;

        Ok(Self { message, signature })
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for SignedExecutionPayloadEnvelope<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper<M> {
            message: M,
            signature: Signature,
        }

        let convert_err = |e| {
            serde::de::Error::custom(format!(
                "SignedExecutionPayloadEnvelope failed to deserialize: {:?}",
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
                    "SignedExecutionPayloadEnvelope failed to deserialize: unsupported fork '{}'",
                    context
                )));
            }
            ForkName::Gloas => {
                let helper: Helper<ExecutionPayloadEnvelopeGloas<E>> =
                    Deserialize::deserialize(deserializer).map_err(convert_err)?;
                Self {
                    message: ExecutionPayloadEnvelope::Gloas(helper.message),
                    signature: helper.signature,
                }
            }
            ForkName::Heze => {
                let helper: Helper<ExecutionPayloadEnvelopeHeze<E>> =
                    Deserialize::deserialize(deserializer).map_err(convert_err)?;
                Self {
                    message: ExecutionPayloadEnvelope::Heze(helper.message),
                    signature: helper.signature,
                }
            }
        })
    }
}

/// The fixed fields of a Gloas execution payload.
///
/// Together with the body returned by `engine_getPayloadBodiesByHashV2`, these fields can be used
/// to reconstruct an `ExecutionPayloadGloas` without an additional execution-layer request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
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

/// The prunable fields of a Gloas execution payload.
///
/// The remaining payload fields are retained in [`ExecutionPayloadHeaderGloas`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct ExecutionPayloadBody<E: EthSpec> {
    pub transactions: ProgressiveTransactions,
    pub withdrawals: ProgressiveWithdrawals<E>,
    pub block_access_list: BlockAccessList,
}

impl<E: EthSpec> From<&ExecutionPayloadGloas<E>> for ExecutionPayloadBody<E> {
    fn from(payload: &ExecutionPayloadGloas<E>) -> Self {
        Self {
            transactions: payload.transactions.clone(),
            withdrawals: payload.withdrawals.clone(),
            block_access_list: payload.block_access_list.clone(),
        }
    }
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
        withdrawals: ProgressiveWithdrawals<E>,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct SignedExecutionPayloadEnvelopeSummary<E: EthSpec> {
    pub payload_header: ExecutionPayloadHeaderGloas<E>,
    pub execution_requests: ExecutionRequestsGloas<E>,
    pub builder_index: u64,
    pub beacon_block_root: Hash256,
    pub parent_beacon_block_root: Hash256,
    pub signature: Signature,
}

impl<E: EthSpec> SignedExecutionPayloadEnvelopeSummary<E> {
    /// Summarises `envelope` for the block with root `beacon_block_root`.
    ///
    /// The root is passed separately as Heze envelopes no longer contain it (EIP-8411).
    pub fn new(envelope: &SignedExecutionPayloadEnvelope<E>, beacon_block_root: Hash256) -> Self {
        Self {
            payload_header: envelope.message.payload().into(),
            execution_requests: envelope.message.execution_requests().clone(),
            builder_index: envelope.message.builder_index(),
            beacon_block_root,
            parent_beacon_block_root: envelope.message.parent_beacon_block_root(),
            signature: envelope.signature.clone(),
        }
    }

    pub fn block_hash(&self) -> ExecutionBlockHash {
        self.payload_header.block_hash
    }

    pub fn slot(&self) -> Slot {
        self.payload_header.slot_number
    }

    /// Reconstructs the envelope of fork `fork_name` from the summary and `payload_body`.
    pub fn into_envelope(
        self,
        payload_body: ExecutionPayloadBody<E>,
        fork_name: ForkName,
    ) -> SignedExecutionPayloadEnvelope<E> {
        let payload = self.payload_header.into_payload(
            payload_body.transactions,
            payload_body.withdrawals,
            payload_body.block_access_list,
        );
        let message = if fork_name.heze_enabled() {
            ExecutionPayloadEnvelope::Heze(ExecutionPayloadEnvelopeHeze {
                payload,
                execution_requests: self.execution_requests,
                builder_index: self.builder_index,
                parent_beacon_block_root: self.parent_beacon_block_root,
            })
        } else {
            ExecutionPayloadEnvelope::Gloas(ExecutionPayloadEnvelopeGloas {
                payload,
                execution_requests: self.execution_requests,
                builder_index: self.builder_index,
                beacon_block_root: self.beacon_block_root,
                parent_beacon_block_root: self.parent_beacon_block_root,
            })
        };
        SignedExecutionPayloadEnvelope {
            message,
            signature: self.signature,
        }
    }

    pub fn into_envelope_from_payload_body(
        self,
        transactions: ProgressiveTransactions,
        withdrawals: ProgressiveWithdrawals<E>,
        block_access_list: BlockAccessList,
        fork_name: ForkName,
    ) -> SignedExecutionPayloadEnvelope<E> {
        self.into_envelope(
            ExecutionPayloadBody {
                transactions,
                withdrawals,
                block_access_list,
            },
            fork_name,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Spec;
    use tree_hash::TreeHash;

    fn envelopes() -> Vec<SignedExecutionPayloadEnvelope<Spec>> {
        let gloas = ExecutionPayloadEnvelopeGloas {
            beacon_block_root: Hash256::repeat_byte(1),
            parent_beacon_block_root: Hash256::repeat_byte(2),
            builder_index: 3,
            ..Default::default()
        };
        let heze = ExecutionPayloadEnvelopeHeze {
            parent_beacon_block_root: Hash256::repeat_byte(2),
            builder_index: 3,
            ..Default::default()
        };
        vec![
            SignedExecutionPayloadEnvelope {
                message: gloas.into(),
                signature: Signature::empty(),
            },
            SignedExecutionPayloadEnvelope {
                message: heze.into(),
                signature: Signature::empty(),
            },
        ]
    }

    #[test]
    fn ssz_round_trip_by_fork() {
        for envelope in envelopes() {
            let fork_name = envelope.fork_name_unchecked();
            let bytes = envelope.as_ssz_bytes();
            assert_eq!(
                SignedExecutionPayloadEnvelope::from_ssz_bytes_by_fork(&bytes, fork_name).unwrap(),
                envelope
            );
        }
    }

    #[test]
    fn summary_round_trip() {
        for envelope in envelopes() {
            let fork_name = envelope.fork_name_unchecked();
            let body = ExecutionPayloadBody::from(envelope.message.payload());
            let summary =
                SignedExecutionPayloadEnvelopeSummary::new(&envelope, Hash256::repeat_byte(1));
            let reconstructed = summary.into_envelope(body, fork_name);
            assert_eq!(reconstructed, envelope);
            assert_eq!(
                reconstructed.message.tree_hash_root(),
                envelope.message.tree_hash_root()
            );
        }
    }

    #[test]
    fn size_bounds_cover_all_variants() {
        for envelope in envelopes() {
            let len = envelope.as_ssz_bytes().len();
            assert!(SignedExecutionPayloadEnvelope::<Spec>::min_size() <= len);
            assert!(len <= SignedExecutionPayloadEnvelope::<Spec>::max_size());
        }
    }
}

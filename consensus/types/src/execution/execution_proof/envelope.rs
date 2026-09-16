use super::{ProofData, ProofType, proof_type::quoted_proof_type};
use crate::{ForkName, Hash256, SignedRoot};
use bls::Signature;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

/// Gossip envelope binding opaque proof bytes to a beacon block.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct ExecutionProofEnvelope {
    pub proof_data: ProofData,
    #[serde(with = "quoted_proof_type")]
    pub proof_type: ProofType,
    pub beacon_block_root: Hash256,
}

impl SignedRoot for ExecutionProofEnvelope {}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct SignedExecutionProofEnvelope {
    pub message: ExecutionProofEnvelope,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub signature: Signature,
}

impl SignedExecutionProofEnvelope {
    pub fn beacon_block_root(&self) -> Hash256 {
        self.message.beacon_block_root
    }

    pub fn proof_type(&self) -> ProofType {
        self.message.proof_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::MaxProofSize;
    use fixed_bytes::FixedBytesExtended;
    use ssz::{BYTES_PER_LENGTH_OFFSET, Decode as _, Encode as _};
    use typenum::Unsigned;

    ssz_and_tree_hash_tests!(SignedExecutionProofEnvelope);

    fn signed_envelope(proof_type: ProofType) -> SignedExecutionProofEnvelope {
        SignedExecutionProofEnvelope {
            message: ExecutionProofEnvelope {
                proof_data: ProofData::new(vec![1]).expect("valid proof data"),
                proof_type,
                beacon_block_root: Hash256::zero(),
            },
            validator_index: 7,
            signature: Signature::empty(),
        }
    }

    #[test]
    fn signed_envelope_json_quotes_integers() {
        let envelope = signed_envelope(ProofType::RethSp1);

        let json = serde_json::to_value(&envelope).expect("serializes");
        assert_eq!(json["message"]["proof_type"], "2");
        assert_eq!(json["validator_index"], "7");

        let decoded: SignedExecutionProofEnvelope =
            serde_json::from_value(json).expect("deserializes");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn envelope_with_unassigned_proof_type_does_not_decode() {
        // EIP-8025 gossip validation says "[REJECT] The proof type is supported". That rule is
        // enforced here, by the codec, so an unassigned proof type never reaches validation.
        let envelope = signed_envelope(ProofType::RethSp1);
        let encoded = envelope.as_ssz_bytes();
        // The message is the only variable-size field, so its offset leads the encoding, and the
        // proof data offset leads the message.
        let message_offset = u32::from_le_bytes(
            encoded[..BYTES_PER_LENGTH_OFFSET]
                .try_into()
                .expect("the message offset is four bytes"),
        ) as usize;
        let offset = message_offset + BYTES_PER_LENGTH_OFFSET;
        assert_eq!(
            encoded[offset],
            ProofType::RethSp1.to_u8(),
            "located the proof type byte"
        );

        for unassigned in [0u8, 4, u8::MAX] {
            let mut corrupted = encoded.clone();
            corrupted[offset] = unassigned;
            assert!(
                SignedExecutionProofEnvelope::from_ssz_bytes(&corrupted).is_err(),
                "decoded an envelope carrying unassigned proof type {unassigned}"
            );
        }

        // The untouched encoding still decodes, so the corruption above is the only difference.
        assert_eq!(
            SignedExecutionProofEnvelope::from_ssz_bytes(&encoded).expect("valid envelope decodes"),
            envelope
        );
    }

    #[test]
    fn proof_data_and_signed_envelope_enforce_size_bound() {
        let max_proof_size = MaxProofSize::USIZE;

        assert!(ProofData::new(vec![0; max_proof_size + 1]).is_err());

        let proof_data = ProofData::new(vec![0; max_proof_size]).expect("valid proof data");
        let envelope = SignedExecutionProofEnvelope {
            message: ExecutionProofEnvelope {
                proof_data,
                proof_type: ProofType::RethOpenvm,
                beacon_block_root: Hash256::zero(),
            },
            validator_index: 0,
            signature: Signature::empty(),
        };

        let mut bytes = envelope.as_ssz_bytes();
        bytes.push(0);

        assert!(SignedExecutionProofEnvelope::from_ssz_bytes(&bytes).is_err());
    }
}

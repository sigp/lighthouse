//! Chunked propagation of execution payload envelopes (EIP-8411).
//!
//! The serialized `ExecutionPayloadEnvelope` is split into `TOTAL_EXECUTION_PAYLOAD_CHUNKS`
//! chunks. The bid commits to them with `payload_chunks_root`, so each chunk can be verified on
//! its own with an inclusion proof.

use crate::{EthSpec, ExecutionPayloadEnvelope, ForkName, ForkVersionDecode, Hash256, Slot};
use context_deserialize::context_deserialize;
use educe::Educe;
use ethereum_hashing::hash_fixed;
use merkle_proof::{MerkleTree, MerkleTreeError, verify_merkle_proof};
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use tree_hash_derive::TreeHash;

/// Index of a chunk, `0` through `TOTAL_EXECUTION_PAYLOAD_CHUNKS - 1`.
pub type ChunkIndex = u8;

/// Contiguous slice of a serialized `ExecutionPayloadEnvelope`.
pub type Chunk<E> = VariableList<u8, <E as EthSpec>::MaxPayloadChunkSize>;

/// All chunks of a serialized `ExecutionPayloadEnvelope`, in order.
pub type PayloadChunks<E> = FixedVector<Chunk<E>, <E as EthSpec>::TotalExecutionPayloadChunks>;

pub type ChunkBitmap<E> = ssz::BitVector<<E as EthSpec>::TotalExecutionPayloadChunks>;

#[derive(Debug, Clone, Encode, Decode)]
pub struct ChunkMetadata<E: EthSpec> {
    pub slot: Slot,
    pub have: ChunkBitmap<E>,
    pub request: ChunkBitmap<E>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PayloadChunkError {
    /// The serialized envelope doesn't fit into `TOTAL_EXECUTION_PAYLOAD_CHUNKS` chunks of at
    /// most `MAX_PAYLOAD_CHUNK_SIZE` bytes.
    EnvelopeTooLarge {
        envelope_size: usize,
    },
    SszTypes(ssz_types::Error),
    MerkleTree(MerkleTreeError),
    /// The chunks are not the ones a serialized envelope is split into: there are too few or too
    /// many of them, or their lengths differ from the ones `compute_payload_chunks` produces.
    NonCanonicalChunks,
    /// The chunks don't concatenate to a serialized envelope.
    Decode(ssz::DecodeError),
}

/// A chunk of an `ExecutionPayloadEnvelope`, as gossiped on `execution_payload_chunks`.
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, Educe)]
#[educe(PartialEq, Eq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec")]
#[context_deserialize(ForkName)]
pub struct PayloadChunk<E: EthSpec> {
    #[serde(with = "serde_utils::quoted_u8")]
    pub index: ChunkIndex,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub chunk: Chunk<E>,
    pub chunk_inclusion_proof: FixedVector<Hash256, E::ChunkInclusionProofDepth>,
}

impl<E: EthSpec> PayloadChunk<E> {
    /// Builds the `PayloadChunk` messages publishing `envelope`, one per chunk index, along with
    /// the `payload_chunks_root` their inclusion proofs verify against.
    pub fn build_payload_chunks(
        envelope: &ExecutionPayloadEnvelope<E>,
    ) -> Result<(Vec<Self>, Hash256), PayloadChunkError> {
        let chunks = envelope.compute_payload_chunks()?;
        let depth = E::chunk_inclusion_proof_depth();
        let tree = chunks_tree::<E>(&chunks);

        let chunks = chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| {
                let (_, proof) = tree
                    .generate_proof(index, depth)
                    .map_err(PayloadChunkError::MerkleTree)?;
                Ok(Self {
                    index: index as ChunkIndex,
                    chunk: chunk.clone(),
                    chunk_inclusion_proof: FixedVector::new(proof)
                        .map_err(PayloadChunkError::SszTypes)?,
                })
            })
            .collect::<Result<Vec<Self>, PayloadChunkError>>()?;
        Ok((chunks, tree.hash()))
    }

    /// Spec function `verify_payload_chunk_inclusion_proof`.
    ///
    /// Only the low `CHUNK_INCLUSION_PROOF_DEPTH` bits of `index` are checked, so the caller must
    /// ensure `index < TOTAL_EXECUTION_PAYLOAD_CHUNKS`.
    pub fn verify_inclusion_proof(&self, root: Hash256) -> bool {
        verify_merkle_proof(
            Hash256::from(hash_fixed(&self.chunk)),
            &self.chunk_inclusion_proof,
            E::chunk_inclusion_proof_depth(),
            self.index as usize,
            root,
        )
    }

    /// Returns the length of the SSZ encoding of a `PayloadChunk` with a chunk of
    /// `MAX_PAYLOAD_CHUNK_SIZE` bytes, the longest possible.
    pub fn max_ssz_len() -> usize {
        // The fixed length of the chunk is the length of its offset.
        <ChunkIndex as Decode>::ssz_fixed_len()
            .saturating_add(<Chunk<E> as Decode>::ssz_fixed_len())
            .saturating_add(
                <FixedVector<Hash256, E::ChunkInclusionProofDepth> as Decode>::ssz_fixed_len(),
            )
            .saturating_add(E::max_payload_chunk_size())
    }
}

impl<E: EthSpec> ExecutionPayloadEnvelope<E> {
    /// Spec function `compute_payload_chunks`.
    ///
    /// No padding is added: the last non-empty chunk can be shorter, and trailing chunks can be
    /// empty.
    pub fn compute_payload_chunks(&self) -> Result<PayloadChunks<E>, PayloadChunkError> {
        split_into_chunks::<E>(&self.as_ssz_bytes())
    }

    /// Spec function `compute_payload_chunks_root`.
    pub fn compute_payload_chunks_root(&self) -> Result<Hash256, PayloadChunkError> {
        Ok(payload_chunks_root::<E>(&self.compute_payload_chunks()?))
    }

    /// Returns whether this is the envelope a bid with `payload_chunks_root` commits to.
    ///
    /// Heze envelopes are authenticated by the bid committing to them rather than by a signature.
    pub fn matches_payload_chunks_root(&self, payload_chunks_root: Hash256) -> bool {
        self.compute_payload_chunks_root()
            .is_ok_and(|root| root == payload_chunks_root)
    }

    /// Reassembles the envelope of fork `fork_name` from all of its chunks, in order.
    ///
    /// Succeeds only if `chunks` are split like `compute_payload_chunks` splits the envelope. So
    /// if every chunk has a valid inclusion proof against a root, that root is the
    /// `compute_payload_chunks_root` of the envelope, and needs not be computed to know so.
    ///
    /// Valid inclusion proofs alone don't tell: a builder can commit to another split of the
    /// serialized envelope. This would make the envelope valid for the nodes reassembling it, and
    /// invalid for the ones computing the root from the envelope, e.g. after syncing it.
    ///
    /// This relies on SSZ decoding being strict: only the serialization of an envelope
    /// deserializes to it, so the chunks concatenate to what the envelope serializes to.
    pub fn from_payload_chunks<'a>(
        chunks: impl IntoIterator<Item = &'a Chunk<E>>,
        fork_name: ForkName,
    ) -> Result<Self, PayloadChunkError> {
        let chunks = chunks.into_iter().collect::<Vec<_>>();
        if chunks.len() != E::total_execution_payload_chunks() {
            return Err(PayloadChunkError::NonCanonicalChunks);
        }
        let data_len = chunks
            .iter()
            .fold(0usize, |len, chunk| len.saturating_add(chunk.len()));

        // The lengths `split_into_chunks` gives the chunks of `data_len` bytes.
        let chunk_size = data_len.div_ceil(E::total_execution_payload_chunks());
        let mut data = Vec::with_capacity(data_len);
        for chunk in chunks {
            let expected_len = chunk_size.min(data_len.saturating_sub(data.len()));
            if chunk.len() != expected_len {
                return Err(PayloadChunkError::NonCanonicalChunks);
            }
            data.extend_from_slice(chunk);
        }

        Self::from_ssz_bytes_by_fork(&data, fork_name).map_err(PayloadChunkError::Decode)
    }
}

/// Splits the serialized envelope `data` into `TOTAL_EXECUTION_PAYLOAD_CHUNKS` chunks of
/// `ceil(len(data) / TOTAL_EXECUTION_PAYLOAD_CHUNKS)` bytes.
fn split_into_chunks<E: EthSpec>(data: &[u8]) -> Result<PayloadChunks<E>, PayloadChunkError> {
    let chunk_size = data.len().div_ceil(E::total_execution_payload_chunks());
    if chunk_size > E::max_payload_chunk_size() {
        return Err(PayloadChunkError::EnvelopeTooLarge {
            envelope_size: data.len(),
        });
    }

    let chunks = (0..E::total_execution_payload_chunks())
        .map(|index| {
            let start = index.saturating_mul(chunk_size).min(data.len());
            let end = start.saturating_add(chunk_size).min(data.len());
            Chunk::<E>::new(data.get(start..end).unwrap_or_default().to_vec())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(PayloadChunkError::SszTypes)?;
    FixedVector::new(chunks).map_err(PayloadChunkError::SszTypes)
}

/// Returns the `payload_chunks_root` committing to `chunks`: the `hash_tree_root` of the
/// `Vector[Bytes32, TOTAL_EXECUTION_PAYLOAD_CHUNKS]` of the chunks' SHA-256 hashes.
pub fn payload_chunks_root<E: EthSpec>(chunks: &PayloadChunks<E>) -> Hash256 {
    chunks_tree::<E>(chunks).hash()
}

/// Returns the Merkle tree whose leaves are the SHA-256 hashes of `chunks`.
///
/// There are exactly `2 ** CHUNK_INCLUSION_PROOF_DEPTH` leaves, so its root is the
/// `hash_tree_root` of the leaves as a `Vector[Bytes32, TOTAL_EXECUTION_PAYLOAD_CHUNKS]`.
fn chunks_tree<E: EthSpec>(chunks: &PayloadChunks<E>) -> MerkleTree {
    let leaves = chunks
        .iter()
        .map(|chunk| Hash256::from(hash_fixed(chunk)))
        .collect::<Vec<_>>();
    MerkleTree::create(&leaves, E::chunk_inclusion_proof_depth())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ExecutionPayloadEnvelopeGloas, ExecutionPayloadEnvelopeHeze, ExecutionPayloadGloas,
        MainnetEthSpec, Spec,
    };
    use ssz_types::ProgressiveVariableList;
    use tree_hash::TreeHash;

    type E = MainnetEthSpec;

    ssz_and_tree_hash_tests!(PayloadChunk<Spec>);

    /// A Heze envelope whose serialization is about `transaction_bytes` longer than an empty one.
    ///
    /// The transaction bytes vary, so that no two chunks are equal.
    fn envelope(transaction_bytes: usize) -> ExecutionPayloadEnvelope<E> {
        let transaction =
            ProgressiveVariableList::new((0..transaction_bytes).map(|i| (i % 251) as u8).collect())
                .unwrap();
        ExecutionPayloadEnvelope::Heze(ExecutionPayloadEnvelopeHeze {
            payload: ExecutionPayloadGloas {
                transactions: ProgressiveVariableList::new(vec![transaction]).unwrap(),
                ..Default::default()
            },
            builder_index: 7,
            parent_beacon_block_root: Hash256::repeat_byte(1),
            ..Default::default()
        })
    }

    #[test]
    fn chunks_concatenate_to_the_serialized_envelope() {
        for transaction_bytes in [0, 1, 63, 64, 65, 100_000] {
            let envelope = envelope(transaction_bytes);
            let chunks = envelope.compute_payload_chunks().unwrap();
            let data = envelope.as_ssz_bytes();
            let chunk_size = data.len().div_ceil(E::total_execution_payload_chunks());

            assert_eq!(chunks.len(), E::total_execution_payload_chunks());
            assert!(chunks.iter().all(|chunk| chunk.len() <= chunk_size));
            assert_eq!(
                chunks
                    .iter()
                    .flat_map(|chunk| chunk.iter().copied())
                    .collect::<Vec<_>>(),
                data
            );
            assert_eq!(
                ExecutionPayloadEnvelope::from_payload_chunks(chunks.iter(), ForkName::Heze)
                    .unwrap(),
                envelope
            );
        }
    }

    #[test]
    fn only_canonical_chunks_reassemble() {
        let envelope = envelope(10_000);
        let chunks = envelope.compute_payload_chunks().unwrap().to_vec();
        let reassemble = |chunks: &[Chunk<E>]| {
            ExecutionPayloadEnvelope::<E>::from_payload_chunks(chunks, ForkName::Heze)
        };
        assert_eq!(reassemble(&chunks), Ok(envelope));

        // The same bytes, split differently: the first chunk gives its last byte to the second.
        let mut moved_byte = chunks.clone();
        let mut first = moved_byte[0].to_vec();
        let mut second = vec![first.pop().unwrap()];
        second.extend_from_slice(&moved_byte[1]);
        moved_byte[0] = Chunk::<E>::new(first).unwrap();
        moved_byte[1] = Chunk::<E>::new(second).unwrap();
        assert_eq!(
            reassemble(&moved_byte),
            Err(PayloadChunkError::NonCanonicalChunks)
        );

        // Not all of the chunks.
        assert_eq!(
            reassemble(&chunks[..chunks.len() - 1]),
            Err(PayloadChunkError::NonCanonicalChunks)
        );

        // Canonically split bytes that are no envelope.
        let garbage = split_into_chunks::<E>(&[0xff; 1000]).unwrap().to_vec();
        assert!(matches!(
            reassemble(&garbage),
            Err(PayloadChunkError::Decode(_))
        ));
    }

    #[test]
    fn chunks_are_unpadded() {
        let total = E::total_execution_payload_chunks();
        // (data length, chunk size, number of non-empty chunks)
        for (data_len, chunk_size, non_empty) in [
            (0, 0, 0),
            (1, 1, 1),
            (total - 1, 1, total - 1),
            (total, 1, total),
            // Two-byte chunks leave the trailing chunks empty.
            (total + 1, 2, total / 2 + 1),
            (10 * total + 3, 11, (10 * total + 3).div_ceil(11)),
        ] {
            let data = (0..data_len).map(|i| i as u8).collect::<Vec<_>>();
            let chunks = split_into_chunks::<E>(&data).unwrap();

            assert_eq!(chunks.len(), total);
            for (index, chunk) in chunks.iter().enumerate() {
                let start = (index * chunk_size).min(data_len);
                let end = (start + chunk_size).min(data_len);
                assert_eq!(chunk.to_vec(), data[start..end], "data length {data_len}");
                assert_eq!(
                    !chunk.is_empty(),
                    index < non_empty,
                    "data length {data_len}"
                );
            }
        }
    }

    #[test]
    fn oversized_envelope_is_rejected() {
        let max_size = E::max_payload_chunk_size() * E::total_execution_payload_chunks();
        let envelope = envelope(max_size);
        assert_eq!(
            envelope.compute_payload_chunks(),
            Err(PayloadChunkError::EnvelopeTooLarge {
                envelope_size: envelope.as_ssz_bytes().len()
            })
        );
    }

    #[test]
    fn root_is_hash_tree_root_of_chunk_hashes() {
        let chunks = envelope(10_000).compute_payload_chunks().unwrap();
        let leaves = FixedVector::<Hash256, <E as EthSpec>::TotalExecutionPayloadChunks>::new(
            chunks
                .iter()
                .map(|chunk| Hash256::from(hash_fixed(chunk)))
                .collect(),
        )
        .unwrap();
        assert_eq!(payload_chunks_root::<E>(&chunks), leaves.tree_hash_root());
    }

    #[test]
    fn root_commits_to_every_chunk() {
        let envelope = envelope(10_000);
        let root = envelope.compute_payload_chunks_root().unwrap();

        let ExecutionPayloadEnvelope::Heze(mut changed) = envelope else {
            panic!("envelope should be Heze");
        };
        changed.builder_index += 1;
        assert_ne!(
            ExecutionPayloadEnvelope::Heze(changed)
                .compute_payload_chunks_root()
                .unwrap(),
            root
        );
    }

    #[test]
    fn root_differs_between_envelope_variants() {
        let gloas = ExecutionPayloadEnvelope::<E>::Gloas(ExecutionPayloadEnvelopeGloas::default());
        let heze = ExecutionPayloadEnvelope::<E>::Heze(ExecutionPayloadEnvelopeHeze::default());
        assert_ne!(
            gloas.compute_payload_chunks_root().unwrap(),
            heze.compute_payload_chunks_root().unwrap()
        );
    }

    #[test]
    fn built_chunks_have_valid_inclusion_proofs() {
        let envelope = envelope(10_000);
        let (payload_chunks, root) = PayloadChunk::build_payload_chunks(&envelope).unwrap();
        let chunks = envelope.compute_payload_chunks().unwrap();

        assert_eq!(root, payload_chunks_root::<E>(&chunks));
        assert_eq!(payload_chunks.len(), E::total_execution_payload_chunks());
        for (index, payload_chunk) in payload_chunks.iter().enumerate() {
            assert_eq!(payload_chunk.index, index as ChunkIndex);
            assert_eq!(payload_chunk.chunk, chunks[index]);
            assert!(payload_chunk.verify_inclusion_proof(root));
        }
    }

    #[test]
    fn max_ssz_len_is_length_of_largest_payload_chunk() {
        let payload_chunk = PayloadChunk::<E> {
            index: 0,
            chunk: Chunk::<E>::new(vec![0; E::max_payload_chunk_size()]).unwrap(),
            chunk_inclusion_proof: FixedVector::default(),
        };
        assert_eq!(
            payload_chunk.as_ssz_bytes().len(),
            PayloadChunk::<E>::max_ssz_len()
        );
    }

    #[test]
    fn tampered_chunks_fail_inclusion_proof() {
        let envelope = envelope(10_000);
        let (payload_chunks, root) = PayloadChunk::build_payload_chunks(&envelope).unwrap();

        let mut wrong_chunk = payload_chunks[5].clone();
        wrong_chunk.chunk = payload_chunks[6].chunk.clone();
        assert!(!wrong_chunk.verify_inclusion_proof(root));

        let mut wrong_index = payload_chunks[5].clone();
        wrong_index.index = 6;
        assert!(!wrong_index.verify_inclusion_proof(root));

        assert!(!payload_chunks[5].verify_inclusion_proof(Hash256::repeat_byte(9)));
    }
}

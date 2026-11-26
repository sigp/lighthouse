use ssz_types::{BitVector, FixedVector, VariableList};

use crate::core::{EthSpec, Hash256};

/// `VRF_TREE_DEPTH + 1`: a secret followed by its committed leaf's Merkle branch.
///
/// `VRF_TREE_DEPTH` is a constant (not a preset value) in the spec, so this is not part of
/// `EthSpec`.
pub type VrfProofLength = typenum::U32;

/// A secret committed under a validator's VRF root, followed by the leaf's Merkle branch (the
/// spec's `VRFProof = Vector[Bytes32, VRF_TREE_DEPTH + 1]`).
pub type VrfProof = FixedVector<Hash256, VrfProofLength>;

/// A STARK proof of the XMSS signatures of attestations (the spec's
/// `AttestationProof = ByteList[MAX_STARK_PROOF_SIZE]`).
///
/// Fields of this type must use `#[serde(with = "ssz_types::serde_utils::hex_var_list")]` so
/// that the JSON encoding is a hex string.
pub type AttestationProof<E> = VariableList<u8, <E as EthSpec>::MaxStarkProofSize>;

/// Bits marking which committees of a slot participate in an attestation (the spec's
/// `CommitteeBits = Bitvector[MAX_COMMITTEES_PER_SLOT_PQ]` as modified in PQ).
pub type CommitteeBitsPq<E> = BitVector<<E as EthSpec>::MaxCommitteesPerSlotPq>;

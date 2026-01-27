use std::sync::Arc;

use bls::Signature;
use context_deserialize::context_deserialize;
use educe::Educe;
use kzg::{KzgCommitment, KzgProof};
use merkle_proof::verify_merkle_proof;
use safe_arith::ArithError;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::Error as SszError;
use ssz_types::{FixedVector, VariableList};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    block::{BLOB_KZG_COMMITMENTS_INDEX, BeaconBlockHeader, SignedBeaconBlockHeader},
    core::{Epoch, EthSpec, Hash256, Slot},
    fork::ForkName,
    kzg_ext::{KzgCommitments, KzgError},
    state::BeaconStateError,
    test_utils::TestRandom,
};

pub type ColumnIndex = u64;
pub type Cell<E> = FixedVector<u8, <E as EthSpec>::BytesPerCell>;
pub type DataColumn<E> = VariableList<Cell<E>, <E as EthSpec>::MaxBlobCommitmentsPerBlock>;

/// Identifies a set of data columns associated with a specific beacon block.
#[derive(Encode, Decode, Clone, Debug, PartialEq, TreeHash, Deserialize)]
#[context_deserialize(ForkName)]
pub struct DataColumnsByRootIdentifier<E: EthSpec> {
    pub block_root: Hash256,
    pub columns: VariableList<ColumnIndex, E::NumberOfColumns>,
}

pub type DataColumnSidecarList<E> = Vec<Arc<DataColumnSidecar<E>>>;

#[superstruct(
    variants(Fulu, Gloas),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Decode,
            Encode,
            TestRandom,
            Educe,
            TreeHash,
        ),
        context_deserialize(ForkName),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec")
        )
    ),
    ref_attributes(derive(TreeHash), tree_hash(enum_behaviour = "transparent")),
    cast_error(ty = "DataColumnSidecarError", expr = "DataColumnSidecarError::IncorrectStateVariant"),
    partial_getter_error(ty = "DataColumnSidecarError", expr = "DataColumnSidecarError::IncorrectStateVariant")
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, TreeHash, Encode, Decode, Educe, Deserialize)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct DataColumnSidecar<E: EthSpec> {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: ColumnIndex,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
    pub column: DataColumn<E>,
    /// All the KZG commitments and proofs associated with the block, used for verifying sample cells.
    pub kzg_commitments: KzgCommitments<E>,
    pub kzg_proofs: VariableList<KzgProof, E::MaxBlobCommitmentsPerBlock>,
    #[superstruct(only(Fulu))]
    pub signed_block_header: SignedBeaconBlockHeader,
    /// An inclusion proof, proving the inclusion of `blob_kzg_commitments` in `BeaconBlockBody`.
    #[superstruct(only(Fulu))]
    pub kzg_commitments_inclusion_proof: FixedVector<Hash256, E::KzgCommitmentsInclusionProofDepth>,
    #[superstruct(only(Gloas), partial_getter(rename = "slot_gloas"))]
    pub slot: Slot,
    #[superstruct(only(Gloas))]
    pub beacon_block_root: Hash256,
}

impl<E: EthSpec> DataColumnSidecar<E> {
    pub fn slot(&self) -> Slot {
        match self {
            DataColumnSidecar::Fulu(column) => column.slot(),
            DataColumnSidecar::Gloas(column) => column.slot,
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.slot().epoch(E::slots_per_epoch())
    }

    pub fn block_root(&self) -> Hash256 {
        match self {
            DataColumnSidecar::Fulu(column) => column.block_root(),
            DataColumnSidecar::Gloas(column) => column.beacon_block_root,
        }
    }

    /// Custom SSZ decoder that takes a `ForkName` as context.
    pub fn from_ssz_bytes_for_fork(
        bytes: &[u8],
        fork_name: ForkName,
    ) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra => Err(ssz::DecodeError::NoMatchingVariant),
            ForkName::Fulu => Ok(DataColumnSidecar::Gloas(
                DataColumnSidecarGloas::from_ssz_bytes(bytes)?,
            )),
            ForkName::Gloas => Ok(DataColumnSidecar::Fulu(
                DataColumnSidecarFulu::from_ssz_bytes(bytes)?,
            )),
        }
    }
}

impl<E: EthSpec> DataColumnSidecarFulu<E> {
    pub fn slot(&self) -> Slot {
        self.signed_block_header.message.slot
    }

    pub fn block_root(&self) -> Hash256 {
        self.signed_block_header.message.tree_hash_root()
    }

    pub fn block_parent_root(&self) -> Hash256 {
        self.signed_block_header.message.parent_root
    }

    pub fn block_proposer_index(&self) -> u64 {
        self.signed_block_header.message.proposer_index
    }

    /// Verifies the kzg commitment inclusion merkle proof.
    pub fn verify_inclusion_proof(&self) -> bool {
        let blob_kzg_commitments_root = self.kzg_commitments.tree_hash_root();

        verify_merkle_proof(
            blob_kzg_commitments_root,
            &self.kzg_commitments_inclusion_proof,
            E::kzg_commitments_inclusion_proof_depth(),
            BLOB_KZG_COMMITMENTS_INDEX,
            self.signed_block_header.message.body_root,
        )
    }

    pub fn min_size() -> usize {
        // min size is one cell
        Self {
            index: 0,
            column: VariableList::new(vec![Cell::<E>::default()]).unwrap(),
            kzg_commitments: VariableList::new(vec![KzgCommitment::empty_for_testing()]).unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty()]).unwrap(),
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader::empty(),
                signature: Signature::empty(),
            },
            kzg_commitments_inclusion_proof: Default::default(),
        }
        .as_ssz_bytes()
        .len()
    }

    pub fn max_size(max_blobs_per_block: usize) -> usize {
        Self {
            index: 0,
            column: VariableList::new(vec![Cell::<E>::default(); max_blobs_per_block]).unwrap(),
            kzg_commitments: VariableList::new(vec![
                KzgCommitment::empty_for_testing();
                max_blobs_per_block
            ])
            .unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty(); max_blobs_per_block]).unwrap(),
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader::empty(),
                signature: Signature::empty(),
            },
            kzg_commitments_inclusion_proof: Default::default(),
        }
        .as_ssz_bytes()
        .len()
    }
}

impl<E: EthSpec> DataColumnSidecarGloas<E> {
    pub fn min_size() -> usize {
        // min size is one cell
        Self {
            index: 0,
            column: VariableList::new(vec![Cell::<E>::default()]).unwrap(),
            kzg_commitments: VariableList::new(vec![KzgCommitment::empty_for_testing()]).unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty()]).unwrap(),
            slot: Slot::new(0),
            beacon_block_root: Hash256::ZERO,
        }
        .as_ssz_bytes()
        .len()
    }

    pub fn max_size(max_blobs_per_block: usize) -> usize {
        Self {
            index: 0,
            column: VariableList::new(vec![Cell::<E>::default(); max_blobs_per_block]).unwrap(),
            kzg_commitments: VariableList::new(vec![
                KzgCommitment::empty_for_testing();
                max_blobs_per_block
            ])
            .unwrap(),
            kzg_proofs: VariableList::new(vec![KzgProof::empty(); max_blobs_per_block]).unwrap(),
            slot: Slot::new(0),
            beacon_block_root: Hash256::ZERO,
        }
        .as_ssz_bytes()
        .len()
    }
}

#[derive(Debug)]
pub enum DataColumnSidecarError {
    ArithError(ArithError),
    BeaconStateError(BeaconStateError),
    DataColumnIndexOutOfBounds,
    KzgCommitmentInclusionProofOutOfBounds,
    KzgError(KzgError),
    KzgNotInitialized,
    MissingBlobSidecars,
    PreDeneb,
    SszError(SszError),
    BuildSidecarFailed(String),
    InvalidCellProofLength { expected: usize, actual: usize },
    IncorrectStateVariant,
}

impl From<ArithError> for DataColumnSidecarError {
    fn from(e: ArithError) -> Self {
        Self::ArithError(e)
    }
}

impl From<BeaconStateError> for DataColumnSidecarError {
    fn from(e: BeaconStateError) -> Self {
        Self::BeaconStateError(e)
    }
}

impl From<KzgError> for DataColumnSidecarError {
    fn from(e: KzgError) -> Self {
        Self::KzgError(e)
    }
}

impl From<SszError> for DataColumnSidecarError {
    fn from(e: SszError) -> Self {
        Self::SszError(e)
    }
}

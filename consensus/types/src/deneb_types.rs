use derivative::Derivative;
use serde::de::DeserializeOwned;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::sync::Arc;
use tree_hash_derive::TreeHash;

use kzg::{KzgCommitment, KzgProof};
use test_random_derive::TestRandom;

use crate::blob_sidecar::{BlobRoots, Blobs};
use crate::test_utils::TestRandom;
use crate::{BeaconBlock, BlindedPayload, BlobSidecar, EthSpec, Hash256, SignedBeaconBlock, Slot};

// TODO(jimmy): to be moved to respective type files.
// TODO(jimmy): cleanup unused types.

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    Default,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Eq, Hash)]
pub struct BlindedBlobSidecar {
    pub block_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    pub slot: Slot,
    pub block_parent_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub blob_root: Hash256,
    pub kzg_commitment: KzgCommitment,
    pub kzg_proof: KzgProof,
}

#[allow(unused)]
type BlindedBlobSidecarList<E> = VariableList<BlindedBlobSidecar, <E as EthSpec>::MaxBlobsPerBlock>;

#[allow(unused)]
struct BlindedBlockContents<E: EthSpec> {
    blinded_block: BeaconBlock<E, BlindedPayload<E>>,
    blinded_blob_sidecars: BlindedBlobSidecarList<E>,
}

#[allow(unused)]
struct SignedBlindedBlockContents<E: EthSpec> {
    signed_blinded_block: SignedBeaconBlock<E, BlindedPayload<E>>,
    signed_blinded_blob_sidecars: BlindedBlobSidecarList<E>,
}

pub trait AbstractSidecar<E: EthSpec>:
    serde::Serialize + DeserializeOwned + Encode + Decode
{
}

impl<E: EthSpec> AbstractSidecar<E> for BlobSidecar<E> {}
impl<E: EthSpec> AbstractSidecar<E> for BlindedBlobSidecar {}

pub type SidecarList<E, Sidecar> = VariableList<Arc<Sidecar>, <E as EthSpec>::MaxBlobsPerBlock>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(bound = "T: EthSpec")]
pub enum BlobsOrBlobRoots<T: EthSpec> {
    Blobs(Blobs<T>),
    BlobRoots(BlobRoots<T>),
}

impl<T: EthSpec> BlobsOrBlobRoots<T> {
    pub fn len(&self) -> usize {
        match self {
            Self::Blobs(blobs) => blobs.len(),
            Self::BlobRoots(blob_roots) => blob_roots.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Blobs(blobs) => blobs.is_empty(),
            Self::BlobRoots(blob_roots) => blob_roots.is_empty(),
        }
    }
}

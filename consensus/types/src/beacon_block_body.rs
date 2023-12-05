use crate::test_utils::TestRandom;
use crate::*;
use derivative::Derivative;
use merkle_proof::{MerkleTree, MerkleTreeError};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::marker::PhantomData;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash::{TreeHash, BYTES_PER_CHUNK};
use tree_hash_derive::TreeHash;

pub type KzgCommitments<T> =
    VariableList<KzgCommitment, <T as EthSpec>::MaxBlobCommitmentsPerBlock>;
pub type KzgCommitmentOpts<T> =
    FixedVector<Option<KzgCommitment>, <T as EthSpec>::MaxBlobsPerBlock>;

/// Index of the `blob_kzg_commitments` leaf in the `BeaconBlockBody` tree post-deneb.
pub const BLOB_KZG_COMMITMENTS_INDEX: usize = 11;

/// The body of a `BeaconChain` block, containing operations.
///
/// This *superstruct* abstracts over the hard-fork.
#[superstruct(
    variants(Base, Altair, Merge, Capella, Deneb),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            TestRandom,
            Derivative,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Hash(bound = "T: EthSpec, Payload: AbstractExecPayload<T>")),
        serde(
            bound = "T: EthSpec, Payload: AbstractExecPayload<T>",
            deny_unknown_fields
        ),
        arbitrary(bound = "T: EthSpec, Payload: AbstractExecPayload<T>"),
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Derivative, arbitrary::Arbitrary)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(untagged)]
#[serde(bound = "T: EthSpec, Payload: AbstractExecPayload<T>")]
#[arbitrary(bound = "T: EthSpec, Payload: AbstractExecPayload<T>")]
pub struct BeaconBlockBody<T: EthSpec, Payload: AbstractExecPayload<T> = FullPayload<T>> {
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    pub graffiti: Graffiti,
    pub proposer_slashings: VariableList<ProposerSlashing, T::MaxProposerSlashings>,
    pub attester_slashings: VariableList<AttesterSlashing<T>, T::MaxAttesterSlashings>,
    pub attestations: VariableList<Attestation<T>, T::MaxAttestations>,
    pub deposits: VariableList<Deposit, T::MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, T::MaxVoluntaryExits>,
    #[superstruct(only(Altair, Merge, Capella, Deneb))]
    pub sync_aggregate: SyncAggregate<T>,
    // We flatten the execution payload so that serde can use the name of the inner type,
    // either `execution_payload` for full payloads, or `execution_payload_header` for blinded
    // payloads.
    #[superstruct(only(Merge), partial_getter(rename = "execution_payload_merge"))]
    #[serde(flatten)]
    pub execution_payload: Payload::Merge,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    #[serde(flatten)]
    pub execution_payload: Payload::Capella,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    #[serde(flatten)]
    pub execution_payload: Payload::Deneb,
    #[superstruct(only(Capella, Deneb))]
    pub bls_to_execution_changes:
        VariableList<SignedBlsToExecutionChange, T::MaxBlsToExecutionChanges>,
    #[superstruct(only(Deneb))]
    pub blob_kzg_commitments: KzgCommitments<T>,
    #[superstruct(only(Base, Altair))]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[serde(skip)]
    #[arbitrary(default)]
    pub _phantom: PhantomData<Payload>,
}

impl<T: EthSpec, Payload: AbstractExecPayload<T>> BeaconBlockBody<T, Payload> {
    pub fn execution_payload(&self) -> Result<Payload::Ref<'_>, Error> {
        self.to_ref().execution_payload()
    }
}

impl<'a, T: EthSpec, Payload: AbstractExecPayload<T>> BeaconBlockBodyRef<'a, T, Payload> {
    pub fn execution_payload(&self) -> Result<Payload::Ref<'a>, Error> {
        match self {
            Self::Base(_) | Self::Altair(_) => Err(Error::IncorrectStateVariant),
            Self::Merge(body) => Ok(Payload::Ref::from(&body.execution_payload)),
            Self::Capella(body) => Ok(Payload::Ref::from(&body.execution_payload)),
            Self::Deneb(body) => Ok(Payload::Ref::from(&body.execution_payload)),
        }
    }

    /// Merkle tree branches for `BeaconBlockBody` container.
    ///
    /// This part of the proof is common for all commitment indices.
    fn kzg_commitments_body_proof(&self) -> Result<Vec<Hash256>, Error> {
        match self {
            Self::Base(_) | Self::Altair(_) | Self::Merge(_) | Self::Capella(_) => {
                Err(Error::IncorrectStateVariant)
            }
            Self::Deneb(body) => {
                let leaves = [
                    body.randao_reveal.tree_hash_root(),
                    body.eth1_data.tree_hash_root(),
                    body.graffiti.tree_hash_root(),
                    body.proposer_slashings.tree_hash_root(),
                    body.attester_slashings.tree_hash_root(),
                    body.attestations.tree_hash_root(),
                    body.deposits.tree_hash_root(),
                    body.voluntary_exits.tree_hash_root(),
                    body.sync_aggregate.tree_hash_root(),
                    body.execution_payload.tree_hash_root(),
                    body.bls_to_execution_changes.tree_hash_root(),
                    body.blob_kzg_commitments.tree_hash_root(),
                ];
                let beacon_block_body_depth = leaves.len().next_power_of_two().ilog2() as usize;
                let tree = MerkleTree::create(&leaves, beacon_block_body_depth);
                let (_, proof_body) = tree
                    .generate_proof(BLOB_KZG_COMMITMENTS_INDEX, beacon_block_body_depth)
                    .map_err(Error::MerkleTreeError)?;
                Ok(proof_body)
            }
        }
    }

    /// Produces the proof of inclusion for a `KzgCommitment` in `self.blob_kzg_commitments`
    /// for all indices.
    ///
    /// Note: For non-testing paths, we always require proofs for each index to be generated.
    /// Since the branches for the `BeaconBlockBody` ssz container are shared across inclusion proofs
    /// for each index, we can compute the more expensive top half branches just once.
    pub fn kzg_commitment_inclusion_proofs(
        &self,
    ) -> Result<Vec<FixedVector<Hash256, T::KzgCommitmentInclusionProofDepth>>, Error> {
        match self {
            Self::Base(_) | Self::Altair(_) | Self::Merge(_) | Self::Capella(_) => {
                Err(Error::IncorrectStateVariant)
            }
            Self::Deneb(body) => {
                let mut proofs = Vec::with_capacity(body.blob_kzg_commitments.len());
                // We compute the branches by generating 2 merkle trees:
                // 1. Merkle tree for the `BeaconBlockBody` container
                // 2. Merkle tree for the `blob_kzg_commitments` List object
                // We then merge the branches for both the trees all the way up to the root.

                // Part 1: Branches for the `BeaconBlockBody` container
                let proof_body = self.kzg_commitments_body_proof()?;

                let depth = T::max_blob_commitments_per_block()
                    .next_power_of_two()
                    .ilog2();
                let leaves: Vec<_> = body
                    .blob_kzg_commitments
                    .iter()
                    .map(|commitment| commitment.tree_hash_root())
                    .collect();
                let tree = MerkleTree::create(&leaves, depth as usize);
                // Add the branch corresponding to the length mix-in.
                let length = body.blob_kzg_commitments.len();
                let usize_len = std::mem::size_of::<usize>();
                let mut length_bytes = [0; BYTES_PER_CHUNK];
                length_bytes
                    .get_mut(0..usize_len)
                    .ok_or(Error::MerkleTreeError(MerkleTreeError::PleaseNotifyTheDevs))?
                    .copy_from_slice(&length.to_le_bytes());
                let length_root = Hash256::from_slice(length_bytes.as_slice());

                for index in 0..body.blob_kzg_commitments.len() {
                    // Part 2: Branches for the subtree rooted at `blob_kzg_commitments`
                    let (_, mut proof) = tree
                        .generate_proof(index, depth as usize)
                        .map_err(Error::MerkleTreeError)?;
                    proof.push(length_root);
                    // Join the proofs for the subtree and the main tree
                    proof.extend_from_slice(&proof_body);
                    debug_assert_eq!(proof.len(), T::kzg_proof_inclusion_proof_depth());
                    proofs.push(proof.into());
                }

                Ok(proofs)
            }
        }
    }
}

impl<'a, T: EthSpec, Payload: AbstractExecPayload<T>> BeaconBlockBodyRef<'a, T, Payload> {
    /// Get the fork_name of this object
    pub fn fork_name(self) -> ForkName {
        match self {
            BeaconBlockBodyRef::Base { .. } => ForkName::Base,
            BeaconBlockBodyRef::Altair { .. } => ForkName::Altair,
            BeaconBlockBodyRef::Merge { .. } => ForkName::Merge,
            BeaconBlockBodyRef::Capella { .. } => ForkName::Capella,
            BeaconBlockBodyRef::Deneb { .. } => ForkName::Deneb,
        }
    }
}

// We can convert pre-Bellatrix block bodies without payloads into block bodies "with" payloads.
impl<E: EthSpec> From<BeaconBlockBodyBase<E, BlindedPayload<E>>>
    for BeaconBlockBodyBase<E, FullPayload<E>>
{
    fn from(body: BeaconBlockBodyBase<E, BlindedPayload<E>>) -> Self {
        let BeaconBlockBodyBase {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            _phantom,
        } = body;

        BeaconBlockBodyBase {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> From<BeaconBlockBodyAltair<E, BlindedPayload<E>>>
    for BeaconBlockBodyAltair<E, FullPayload<E>>
{
    fn from(body: BeaconBlockBodyAltair<E, BlindedPayload<E>>) -> Self {
        let BeaconBlockBodyAltair {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            _phantom,
        } = body;

        BeaconBlockBodyAltair {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            _phantom: PhantomData,
        }
    }
}

// Likewise bodies with payloads can be transformed into bodies without.
impl<E: EthSpec> From<BeaconBlockBodyBase<E, FullPayload<E>>>
    for (
        BeaconBlockBodyBase<E, BlindedPayload<E>>,
        Option<ExecutionPayload<E>>,
    )
{
    fn from(body: BeaconBlockBodyBase<E, FullPayload<E>>) -> Self {
        let BeaconBlockBodyBase {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            _phantom,
        } = body;

        (
            BeaconBlockBodyBase {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                _phantom: PhantomData,
            },
            None,
        )
    }
}

impl<E: EthSpec> From<BeaconBlockBodyAltair<E, FullPayload<E>>>
    for (
        BeaconBlockBodyAltair<E, BlindedPayload<E>>,
        Option<ExecutionPayload<E>>,
    )
{
    fn from(body: BeaconBlockBodyAltair<E, FullPayload<E>>) -> Self {
        let BeaconBlockBodyAltair {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            _phantom,
        } = body;

        (
            BeaconBlockBodyAltair {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                _phantom: PhantomData,
            },
            None,
        )
    }
}

impl<E: EthSpec> From<BeaconBlockBodyMerge<E, FullPayload<E>>>
    for (
        BeaconBlockBodyMerge<E, BlindedPayload<E>>,
        Option<ExecutionPayloadMerge<E>>,
    )
{
    fn from(body: BeaconBlockBodyMerge<E, FullPayload<E>>) -> Self {
        let BeaconBlockBodyMerge {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayloadMerge { execution_payload },
        } = body;

        (
            BeaconBlockBodyMerge {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                execution_payload: BlindedPayloadMerge {
                    execution_payload_header: From::from(&execution_payload),
                },
            },
            Some(execution_payload),
        )
    }
}

impl<E: EthSpec> From<BeaconBlockBodyCapella<E, FullPayload<E>>>
    for (
        BeaconBlockBodyCapella<E, BlindedPayload<E>>,
        Option<ExecutionPayloadCapella<E>>,
    )
{
    fn from(body: BeaconBlockBodyCapella<E, FullPayload<E>>) -> Self {
        let BeaconBlockBodyCapella {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayloadCapella { execution_payload },
            bls_to_execution_changes,
        } = body;

        (
            BeaconBlockBodyCapella {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                execution_payload: BlindedPayloadCapella {
                    execution_payload_header: From::from(&execution_payload),
                },
                bls_to_execution_changes,
            },
            Some(execution_payload),
        )
    }
}

impl<E: EthSpec> From<BeaconBlockBodyDeneb<E, FullPayload<E>>>
    for (
        BeaconBlockBodyDeneb<E, BlindedPayload<E>>,
        Option<ExecutionPayloadDeneb<E>>,
    )
{
    fn from(body: BeaconBlockBodyDeneb<E, FullPayload<E>>) -> Self {
        let BeaconBlockBodyDeneb {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayloadDeneb { execution_payload },
            bls_to_execution_changes,
            blob_kzg_commitments,
        } = body;

        (
            BeaconBlockBodyDeneb {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                execution_payload: BlindedPayloadDeneb {
                    execution_payload_header: From::from(&execution_payload),
                },
                bls_to_execution_changes,
                blob_kzg_commitments,
            },
            Some(execution_payload),
        )
    }
}

// We can clone a full block into a blinded block, without cloning the payload.
impl<E: EthSpec> BeaconBlockBodyBase<E, FullPayload<E>> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyBase<E, BlindedPayload<E>> {
        let (block_body, _payload) = self.clone().into();
        block_body
    }
}

impl<E: EthSpec> BeaconBlockBodyAltair<E, FullPayload<E>> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyAltair<E, BlindedPayload<E>> {
        let (block_body, _payload) = self.clone().into();
        block_body
    }
}

impl<E: EthSpec> BeaconBlockBodyMerge<E, FullPayload<E>> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyMerge<E, BlindedPayload<E>> {
        let BeaconBlockBodyMerge {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayloadMerge { execution_payload },
        } = self;

        BeaconBlockBodyMerge {
            randao_reveal: randao_reveal.clone(),
            eth1_data: eth1_data.clone(),
            graffiti: *graffiti,
            proposer_slashings: proposer_slashings.clone(),
            attester_slashings: attester_slashings.clone(),
            attestations: attestations.clone(),
            deposits: deposits.clone(),
            voluntary_exits: voluntary_exits.clone(),
            sync_aggregate: sync_aggregate.clone(),
            execution_payload: BlindedPayloadMerge {
                execution_payload_header: execution_payload.into(),
            },
        }
    }
}

impl<E: EthSpec> BeaconBlockBodyCapella<E, FullPayload<E>> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyCapella<E, BlindedPayload<E>> {
        let BeaconBlockBodyCapella {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayloadCapella { execution_payload },
            bls_to_execution_changes,
        } = self;

        BeaconBlockBodyCapella {
            randao_reveal: randao_reveal.clone(),
            eth1_data: eth1_data.clone(),
            graffiti: *graffiti,
            proposer_slashings: proposer_slashings.clone(),
            attester_slashings: attester_slashings.clone(),
            attestations: attestations.clone(),
            deposits: deposits.clone(),
            voluntary_exits: voluntary_exits.clone(),
            sync_aggregate: sync_aggregate.clone(),
            execution_payload: BlindedPayloadCapella {
                execution_payload_header: execution_payload.into(),
            },
            bls_to_execution_changes: bls_to_execution_changes.clone(),
        }
    }
}

impl<E: EthSpec> BeaconBlockBodyDeneb<E, FullPayload<E>> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyDeneb<E, BlindedPayload<E>> {
        let BeaconBlockBodyDeneb {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayloadDeneb { execution_payload },
            bls_to_execution_changes,
            blob_kzg_commitments,
        } = self;

        BeaconBlockBodyDeneb {
            randao_reveal: randao_reveal.clone(),
            eth1_data: eth1_data.clone(),
            graffiti: *graffiti,
            proposer_slashings: proposer_slashings.clone(),
            attester_slashings: attester_slashings.clone(),
            attestations: attestations.clone(),
            deposits: deposits.clone(),
            voluntary_exits: voluntary_exits.clone(),
            sync_aggregate: sync_aggregate.clone(),
            execution_payload: BlindedPayloadDeneb {
                execution_payload_header: execution_payload.into(),
            },
            bls_to_execution_changes: bls_to_execution_changes.clone(),
            blob_kzg_commitments: blob_kzg_commitments.clone(),
        }
    }
}

impl<E: EthSpec> From<BeaconBlockBody<E, FullPayload<E>>>
    for (
        BeaconBlockBody<E, BlindedPayload<E>>,
        Option<ExecutionPayload<E>>,
    )
{
    fn from(body: BeaconBlockBody<E, FullPayload<E>>) -> Self {
        map_beacon_block_body!(body, |inner, cons| {
            let (block, payload) = inner.into();
            (cons(block), payload.map(Into::into))
        })
    }
}

/// Util method helpful for logging.
pub fn format_kzg_commitments(commitments: &[KzgCommitment]) -> String {
    let commitment_strings: Vec<String> = commitments.iter().map(|x| x.to_string()).collect();
    let commitments_joined = commitment_strings.join(", ");
    let surrounded_commitments = format!("[{}]", commitments_joined);
    surrounded_commitments
}

#[cfg(test)]
mod tests {
    mod base {
        use super::super::*;
        ssz_and_tree_hash_tests!(BeaconBlockBodyBase<MainnetEthSpec>);
    }
    mod altair {
        use super::super::*;
        ssz_and_tree_hash_tests!(BeaconBlockBodyAltair<MainnetEthSpec>);
    }
}

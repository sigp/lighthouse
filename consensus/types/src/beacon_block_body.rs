use crate::test_utils::TestRandom;
use crate::*;
use derivative::Derivative;
use merkle_proof::{MerkleTree, MerkleTreeError};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash::{TreeHash, BYTES_PER_CHUNK};
use tree_hash_derive::TreeHash;

pub type KzgCommitments<E> =
    VariableList<KzgCommitment, <E as EthSpec>::MaxBlobCommitmentsPerBlock>;
pub type KzgCommitmentOpts<E> =
    FixedVector<Option<KzgCommitment>, <E as EthSpec>::MaxBlobsPerBlock>;

/// The number of leaves (including padding) on the `BeaconBlockBody` Merkle tree.
///
/// ## Note
///
/// This constant is set with the assumption that there are `> 8` and `<= 16` fields on the
/// `BeaconBlockBody`. **Tree hashing will fail if this value is set incorrectly.**
pub const NUM_BEACON_BLOCK_BODY_HASH_TREE_ROOT_LEAVES: usize = 16;
/// Index of the `blob_kzg_commitments` leaf in the `BeaconBlockBody` tree post-deneb.
pub const BLOB_KZG_COMMITMENTS_INDEX: usize = 11;

/// The body of a `BeaconChain` block, containing operations.
///
/// This *superstruct* abstracts over the hard-fork.
#[superstruct(
    variants(Base, Altair, Bellatrix, Capella, Deneb, Electra),
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
        derivative(PartialEq, Hash(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")),
        serde(
            bound = "E: EthSpec, Payload: AbstractExecPayload<E>",
            deny_unknown_fields
        ),
        arbitrary(bound = "E: EthSpec, Payload: AbstractExecPayload<E>"),
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Derivative, arbitrary::Arbitrary)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(untagged)]
#[serde(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")]
#[arbitrary(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")]
pub struct BeaconBlockBody<E: EthSpec, Payload: AbstractExecPayload<E> = FullPayload<E>> {
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    pub graffiti: Graffiti,
    pub proposer_slashings: VariableList<ProposerSlashing, E::MaxProposerSlashings>,
    #[superstruct(
        only(Base, Altair, Bellatrix, Capella, Deneb),
        partial_getter(rename = "attester_slashings_base")
    )]
    pub attester_slashings: VariableList<AttesterSlashingBase<E>, E::MaxAttesterSlashings>,
    #[superstruct(only(Electra), partial_getter(rename = "attester_slashings_electra"))]
    pub attester_slashings:
        VariableList<AttesterSlashingElectra<E>, E::MaxAttesterSlashingsElectra>,
    #[superstruct(
        only(Base, Altair, Bellatrix, Capella, Deneb),
        partial_getter(rename = "attestations_base")
    )]
    pub attestations: VariableList<AttestationBase<E>, E::MaxAttestations>,
    #[superstruct(only(Electra), partial_getter(rename = "attestations_electra"))]
    pub attestations: VariableList<AttestationElectra<E>, E::MaxAttestationsElectra>,
    pub deposits: VariableList<Deposit, E::MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, E::MaxVoluntaryExits>,
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra))]
    pub sync_aggregate: SyncAggregate<E>,
    // We flatten the execution payload so that serde can use the name of the inner type,
    // either `execution_payload` for full payloads, or `execution_payload_header` for blinded
    // payloads.
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "execution_payload_bellatrix")
    )]
    #[serde(flatten)]
    pub execution_payload: Payload::Bellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    #[serde(flatten)]
    pub execution_payload: Payload::Capella,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    #[serde(flatten)]
    pub execution_payload: Payload::Deneb,
    #[superstruct(only(Electra), partial_getter(rename = "execution_payload_electra"))]
    #[serde(flatten)]
    pub execution_payload: Payload::Electra,
    #[superstruct(only(Capella, Deneb, Electra))]
    pub bls_to_execution_changes:
        VariableList<SignedBlsToExecutionChange, E::MaxBlsToExecutionChanges>,
    #[superstruct(only(Deneb, Electra))]
    pub blob_kzg_commitments: KzgCommitments<E>,
    #[superstruct(only(Electra))]
    pub consolidations: VariableList<SignedConsolidation, E::MaxConsolidations>,
    #[superstruct(only(Base, Altair))]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[serde(skip)]
    #[arbitrary(default)]
    pub _phantom: PhantomData<Payload>,
}

impl<E: EthSpec, Payload: AbstractExecPayload<E>> BeaconBlockBody<E, Payload> {
    pub fn execution_payload(&self) -> Result<Payload::Ref<'_>, Error> {
        self.to_ref().execution_payload()
    }
}

impl<'a, E: EthSpec, Payload: AbstractExecPayload<E>> BeaconBlockBodyRef<'a, E, Payload> {
    pub fn execution_payload(&self) -> Result<Payload::Ref<'a>, Error> {
        match self {
            Self::Base(_) | Self::Altair(_) => Err(Error::IncorrectStateVariant),
            Self::Bellatrix(body) => Ok(Payload::Ref::from(&body.execution_payload)),
            Self::Capella(body) => Ok(Payload::Ref::from(&body.execution_payload)),
            Self::Deneb(body) => Ok(Payload::Ref::from(&body.execution_payload)),
            Self::Electra(body) => Ok(Payload::Ref::from(&body.execution_payload)),
        }
    }

    /// Produces the proof of inclusion for a `KzgCommitment` in `self.blob_kzg_commitments`
    /// at `index`.
    pub fn kzg_commitment_merkle_proof(
        &self,
        index: usize,
    ) -> Result<FixedVector<Hash256, E::KzgCommitmentInclusionProofDepth>, Error> {
        match self {
            Self::Base(_) | Self::Altair(_) | Self::Bellatrix(_) | Self::Capella(_) => {
                Err(Error::IncorrectStateVariant)
            }
            Self::Deneb(body) => {
                // We compute the branches by generating 2 merkle trees:
                // 1. Merkle tree for the `blob_kzg_commitments` List object
                // 2. Merkle tree for the `BeaconBlockBody` container
                // We then merge the branches for both the trees all the way up to the root.

                // Part1 (Branches for the subtree rooted at `blob_kzg_commitments`)
                //
                // Branches for `blob_kzg_commitments` without length mix-in
                let depth = E::max_blob_commitments_per_block()
                    .next_power_of_two()
                    .ilog2();
                let leaves: Vec<_> = body
                    .blob_kzg_commitments
                    .iter()
                    .map(|commitment| commitment.tree_hash_root())
                    .collect();
                let tree = MerkleTree::create(&leaves, depth as usize);
                let (_, mut proof) = tree
                    .generate_proof(index, depth as usize)
                    .map_err(Error::MerkleTreeError)?;

                // Add the branch corresponding to the length mix-in.
                let length = body.blob_kzg_commitments.len();
                let usize_len = std::mem::size_of::<usize>();
                let mut length_bytes = [0; BYTES_PER_CHUNK];
                length_bytes
                    .get_mut(0..usize_len)
                    .ok_or(Error::MerkleTreeError(MerkleTreeError::PleaseNotifyTheDevs))?
                    .copy_from_slice(&length.to_le_bytes());
                let length_root = Hash256::from_slice(length_bytes.as_slice());
                proof.push(length_root);

                // Part 2
                // Branches for `BeaconBlockBody` container
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
                let (_, mut proof_body) = tree
                    .generate_proof(BLOB_KZG_COMMITMENTS_INDEX, beacon_block_body_depth)
                    .map_err(Error::MerkleTreeError)?;
                // Join the proofs for the subtree and the main tree
                proof.append(&mut proof_body);

                debug_assert_eq!(proof.len(), E::kzg_proof_inclusion_proof_depth());
                Ok(proof.into())
            }
            // TODO(electra): De-duplicate proof computation.
            Self::Electra(body) => {
                // We compute the branches by generating 2 merkle trees:
                // 1. Merkle tree for the `blob_kzg_commitments` List object
                // 2. Merkle tree for the `BeaconBlockBody` container
                // We then merge the branches for both the trees all the way up to the root.

                // Part1 (Branches for the subtree rooted at `blob_kzg_commitments`)
                //
                // Branches for `blob_kzg_commitments` without length mix-in
                let depth = E::max_blob_commitments_per_block()
                    .next_power_of_two()
                    .ilog2();
                let leaves: Vec<_> = body
                    .blob_kzg_commitments
                    .iter()
                    .map(|commitment| commitment.tree_hash_root())
                    .collect();
                let tree = MerkleTree::create(&leaves, depth as usize);
                let (_, mut proof) = tree
                    .generate_proof(index, depth as usize)
                    .map_err(Error::MerkleTreeError)?;

                // Add the branch corresponding to the length mix-in.
                let length = body.blob_kzg_commitments.len();
                let usize_len = std::mem::size_of::<usize>();
                let mut length_bytes = [0; BYTES_PER_CHUNK];
                length_bytes
                    .get_mut(0..usize_len)
                    .ok_or(Error::MerkleTreeError(MerkleTreeError::PleaseNotifyTheDevs))?
                    .copy_from_slice(&length.to_le_bytes());
                let length_root = Hash256::from_slice(length_bytes.as_slice());
                proof.push(length_root);

                // Part 2
                // Branches for `BeaconBlockBody` container
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
                let (_, mut proof_body) = tree
                    .generate_proof(BLOB_KZG_COMMITMENTS_INDEX, beacon_block_body_depth)
                    .map_err(Error::MerkleTreeError)?;
                // Join the proofs for the subtree and the main tree
                proof.append(&mut proof_body);

                debug_assert_eq!(proof.len(), E::kzg_proof_inclusion_proof_depth());
                Ok(proof.into())
            }
        }
    }

    /// Return `true` if this block body has a non-zero number of blobs.
    pub fn has_blobs(self) -> bool {
        self.blob_kzg_commitments()
            .map_or(false, |blobs| !blobs.is_empty())
    }

    pub fn attestations_len(&self) -> usize {
        match self {
            Self::Base(body) => body.attestations.len(),
            Self::Altair(body) => body.attestations.len(),
            Self::Bellatrix(body) => body.attestations.len(),
            Self::Capella(body) => body.attestations.len(),
            Self::Deneb(body) => body.attestations.len(),
            Self::Electra(body) => body.attestations.len(),
        }
    }

    pub fn attester_slashings_len(&self) -> usize {
        match self {
            Self::Base(body) => body.attester_slashings.len(),
            Self::Altair(body) => body.attester_slashings.len(),
            Self::Bellatrix(body) => body.attester_slashings.len(),
            Self::Capella(body) => body.attester_slashings.len(),
            Self::Deneb(body) => body.attester_slashings.len(),
            Self::Electra(body) => body.attester_slashings.len(),
        }
    }

    pub fn attestations(&self) -> Box<dyn Iterator<Item = AttestationRef<'a, E>> + 'a> {
        match self {
            Self::Base(body) => Box::new(body.attestations.iter().map(AttestationRef::Base)),
            Self::Altair(body) => Box::new(body.attestations.iter().map(AttestationRef::Base)),
            Self::Bellatrix(body) => Box::new(body.attestations.iter().map(AttestationRef::Base)),
            Self::Capella(body) => Box::new(body.attestations.iter().map(AttestationRef::Base)),
            Self::Deneb(body) => Box::new(body.attestations.iter().map(AttestationRef::Base)),
            Self::Electra(body) => Box::new(body.attestations.iter().map(AttestationRef::Electra)),
        }
    }

    pub fn attester_slashings(&self) -> Box<dyn Iterator<Item = AttesterSlashingRef<'a, E>> + 'a> {
        match self {
            Self::Base(body) => Box::new(
                body.attester_slashings
                    .iter()
                    .map(AttesterSlashingRef::Base),
            ),
            Self::Altair(body) => Box::new(
                body.attester_slashings
                    .iter()
                    .map(AttesterSlashingRef::Base),
            ),
            Self::Bellatrix(body) => Box::new(
                body.attester_slashings
                    .iter()
                    .map(AttesterSlashingRef::Base),
            ),
            Self::Capella(body) => Box::new(
                body.attester_slashings
                    .iter()
                    .map(AttesterSlashingRef::Base),
            ),
            Self::Deneb(body) => Box::new(
                body.attester_slashings
                    .iter()
                    .map(AttesterSlashingRef::Base),
            ),
            Self::Electra(body) => Box::new(
                body.attester_slashings
                    .iter()
                    .map(AttesterSlashingRef::Electra),
            ),
        }
    }
}

impl<'a, E: EthSpec, Payload: AbstractExecPayload<E>> BeaconBlockBodyRefMut<'a, E, Payload> {
    pub fn attestations_mut(
        &'a mut self,
    ) -> Box<dyn Iterator<Item = AttestationRefMut<'a, E>> + 'a> {
        match self {
            Self::Base(body) => Box::new(body.attestations.iter_mut().map(AttestationRefMut::Base)),
            Self::Altair(body) => {
                Box::new(body.attestations.iter_mut().map(AttestationRefMut::Base))
            }
            Self::Bellatrix(body) => {
                Box::new(body.attestations.iter_mut().map(AttestationRefMut::Base))
            }
            Self::Capella(body) => {
                Box::new(body.attestations.iter_mut().map(AttestationRefMut::Base))
            }
            Self::Deneb(body) => {
                Box::new(body.attestations.iter_mut().map(AttestationRefMut::Base))
            }
            Self::Electra(body) => {
                Box::new(body.attestations.iter_mut().map(AttestationRefMut::Electra))
            }
        }
    }
}

impl<'a, E: EthSpec, Payload: AbstractExecPayload<E>> BeaconBlockBodyRef<'a, E, Payload> {
    /// Get the fork_name of this object
    pub fn fork_name(self) -> ForkName {
        match self {
            BeaconBlockBodyRef::Base { .. } => ForkName::Base,
            BeaconBlockBodyRef::Altair { .. } => ForkName::Altair,
            BeaconBlockBodyRef::Bellatrix { .. } => ForkName::Bellatrix,
            BeaconBlockBodyRef::Capella { .. } => ForkName::Capella,
            BeaconBlockBodyRef::Deneb { .. } => ForkName::Deneb,
            BeaconBlockBodyRef::Electra { .. } => ForkName::Electra,
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

impl<E: EthSpec> From<BeaconBlockBodyBellatrix<E, FullPayload<E>>>
    for (
        BeaconBlockBodyBellatrix<E, BlindedPayload<E>>,
        Option<ExecutionPayloadBellatrix<E>>,
    )
{
    fn from(body: BeaconBlockBodyBellatrix<E, FullPayload<E>>) -> Self {
        let BeaconBlockBodyBellatrix {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayloadBellatrix { execution_payload },
        } = body;

        (
            BeaconBlockBodyBellatrix {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                execution_payload: BlindedPayloadBellatrix {
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

impl<E: EthSpec> From<BeaconBlockBodyElectra<E, FullPayload<E>>>
    for (
        BeaconBlockBodyElectra<E, BlindedPayload<E>>,
        Option<ExecutionPayloadElectra<E>>,
    )
{
    fn from(body: BeaconBlockBodyElectra<E, FullPayload<E>>) -> Self {
        let BeaconBlockBodyElectra {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayloadElectra { execution_payload },
            bls_to_execution_changes,
            blob_kzg_commitments,
            consolidations,
        } = body;

        (
            BeaconBlockBodyElectra {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                execution_payload: BlindedPayloadElectra {
                    execution_payload_header: From::from(&execution_payload),
                },
                bls_to_execution_changes,
                blob_kzg_commitments: blob_kzg_commitments.clone(),
                consolidations,
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

impl<E: EthSpec> BeaconBlockBodyBellatrix<E, FullPayload<E>> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyBellatrix<E, BlindedPayload<E>> {
        let BeaconBlockBodyBellatrix {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayloadBellatrix { execution_payload },
        } = self;

        BeaconBlockBodyBellatrix {
            randao_reveal: randao_reveal.clone(),
            eth1_data: eth1_data.clone(),
            graffiti: *graffiti,
            proposer_slashings: proposer_slashings.clone(),
            attester_slashings: attester_slashings.clone(),
            attestations: attestations.clone(),
            deposits: deposits.clone(),
            voluntary_exits: voluntary_exits.clone(),
            sync_aggregate: sync_aggregate.clone(),
            execution_payload: BlindedPayloadBellatrix {
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

impl<E: EthSpec> BeaconBlockBodyElectra<E, FullPayload<E>> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyElectra<E, BlindedPayload<E>> {
        let BeaconBlockBodyElectra {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayloadElectra { execution_payload },
            bls_to_execution_changes,
            blob_kzg_commitments,
            consolidations,
        } = self;

        BeaconBlockBodyElectra {
            randao_reveal: randao_reveal.clone(),
            eth1_data: eth1_data.clone(),
            graffiti: *graffiti,
            proposer_slashings: proposer_slashings.clone(),
            attester_slashings: attester_slashings.clone(),
            attestations: attestations.clone(),
            deposits: deposits.clone(),
            voluntary_exits: voluntary_exits.clone(),
            sync_aggregate: sync_aggregate.clone(),
            execution_payload: BlindedPayloadElectra {
                execution_payload_header: execution_payload.into(),
            },
            bls_to_execution_changes: bls_to_execution_changes.clone(),
            blob_kzg_commitments: blob_kzg_commitments.clone(),
            consolidations: consolidations.clone(),
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

impl<E: EthSpec> BeaconBlockBody<E> {
    pub fn block_body_merkle_proof(&self, generalized_index: usize) -> Result<Vec<Hash256>, Error> {
        let field_index = match generalized_index {
            light_client_update::EXECUTION_PAYLOAD_INDEX => {
                // Execution payload is a top-level field, subtract off the generalized indices
                // for the internal nodes. Result should be 9, the field offset of the execution
                // payload in the `BeaconBlockBody`:
                // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/beacon-chain.md#beaconblockbody
                generalized_index
                    .checked_sub(NUM_BEACON_BLOCK_BODY_HASH_TREE_ROOT_LEAVES)
                    .ok_or(Error::IndexNotSupported(generalized_index))?
            }
            _ => return Err(Error::IndexNotSupported(generalized_index)),
        };

        let attestations_root = match self {
            BeaconBlockBody::Base(_)
            | BeaconBlockBody::Altair(_)
            | BeaconBlockBody::Bellatrix(_)
            | BeaconBlockBody::Capella(_)
            | BeaconBlockBody::Deneb(_) => self.attestations_base()?.tree_hash_root(),
            BeaconBlockBody::Electra(_) => self.attestations_electra()?.tree_hash_root(),
        };

        let attester_slashings_root = match self {
            BeaconBlockBody::Base(_)
            | BeaconBlockBody::Altair(_)
            | BeaconBlockBody::Bellatrix(_)
            | BeaconBlockBody::Capella(_)
            | BeaconBlockBody::Deneb(_) => self.attester_slashings_base()?.tree_hash_root(),
            BeaconBlockBody::Electra(_) => self.attester_slashings_electra()?.tree_hash_root(),
        };

        let mut leaves = vec![
            self.randao_reveal().tree_hash_root(),
            self.eth1_data().tree_hash_root(),
            self.graffiti().tree_hash_root(),
            self.proposer_slashings().tree_hash_root(),
            attester_slashings_root,
            attestations_root,
            self.deposits().tree_hash_root(),
            self.voluntary_exits().tree_hash_root(),
        ];

        if let Ok(sync_aggregate) = self.sync_aggregate() {
            leaves.push(sync_aggregate.tree_hash_root())
        }

        if let Ok(execution_payload) = self.execution_payload() {
            leaves.push(execution_payload.tree_hash_root())
        }

        if let Ok(bls_to_execution_changes) = self.bls_to_execution_changes() {
            leaves.push(bls_to_execution_changes.tree_hash_root())
        }

        if let Ok(blob_kzg_commitments) = self.blob_kzg_commitments() {
            leaves.push(blob_kzg_commitments.tree_hash_root())
        }

        let depth = light_client_update::EXECUTION_PAYLOAD_PROOF_LEN;
        let tree = merkle_proof::MerkleTree::create(&leaves, depth);
        let (_, proof) = tree.generate_proof(field_index, depth)?;

        Ok(proof)
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

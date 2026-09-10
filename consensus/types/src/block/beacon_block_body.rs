use std::marker::PhantomData;

use bls::Signature;
use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use merkle_proof::MerkleTree;
use metastruct::metastruct;
use serde::{Deserialize, Deserializer, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, ProgressiveVariableList, VariableList};
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    ListRef, SignedExecutionPayloadBid,
    attestation::{
        AttestationBase, AttestationElectra, AttestationGloas, AttestationRef, AttestationRefMut,
        PayloadAttestation,
    },
    complete_kzg_commitment_merkle_proof,
    core::{EthSpec, Graffiti, Hash256},
    deposit::Deposit,
    execution::{
        AbstractExecPayload, BlindedPayload, BlindedPayloadBellatrix, BlindedPayloadCapella,
        BlindedPayloadDeneb, BlindedPayloadElectra, BlindedPayloadFulu, Eth1Data, ExecutionPayload,
        ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadDeneb,
        ExecutionPayloadElectra, ExecutionPayloadFulu, ExecutionPayloadGloas,
        ExecutionRequestsElectra, ExecutionRequestsGloas, FullPayload, FullPayloadBellatrix,
        FullPayloadCapella, FullPayloadDeneb, FullPayloadElectra, FullPayloadFulu,
        SignedBlsToExecutionChange,
    },
    exit::SignedVoluntaryExit,
    fork::{ForkName, map_fork_name},
    kzg_ext::KzgCommitments,
    light_client::consts::{EXECUTION_PAYLOAD_INDEX, EXECUTION_PAYLOAD_PROOF_LEN},
    slashing::{
        AttesterSlashingBase, AttesterSlashingElectra, AttesterSlashingGloas, AttesterSlashingRef,
        ProposerSlashing,
    },
    state::BeaconStateError,
    sync_committee::SyncAggregate,
};

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
    variants(Base, Altair, Bellatrix, Capella, Deneb, Electra, Fulu, Gloas, Heze),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            Educe,
        ),
        educe(PartialEq, Hash(bound(E: EthSpec, Payload: AbstractExecPayload<E>))),
        serde(
            bound = "E: EthSpec, Payload: AbstractExecPayload<E>",
            deny_unknown_fields
        ),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec, Payload: AbstractExecPayload<E>"),
        ),
        context_deserialize(ForkName),
    ),
    specific_variant_attributes(
        Base(metastruct(mappings(beacon_block_body_base_fields(groups(fields))))),
        Altair(metastruct(mappings(beacon_block_body_altair_fields(groups(fields))))),
        Bellatrix(metastruct(mappings(beacon_block_body_bellatrix_fields(groups(fields))))),
        Capella(metastruct(mappings(beacon_block_body_capella_fields(groups(fields))))),
        Deneb(metastruct(mappings(beacon_block_body_deneb_fields(groups(fields))))),
        Electra(metastruct(mappings(beacon_block_body_electra_fields(groups(fields))))),
        Fulu(metastruct(mappings(beacon_block_body_fulu_fields(groups(fields))))),
        Gloas(
            metastruct(mappings(beacon_block_body_gloas_fields(groups(fields)))),
            tree_hash(
                struct_behaviour = "progressive_container",
                active_fields(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
            )
        ),
        Heze(
            metastruct(mappings(beacon_block_body_heze_fields(groups(fields)))),
            tree_hash(
                struct_behaviour = "progressive_container",
                active_fields(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
            )
        ),
    ),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    )
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Educe, TreeHash)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(untagged)]
#[serde(bound = "E: EthSpec, Payload: AbstractExecPayload<E>")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct BeaconBlockBody<E: EthSpec, Payload: AbstractExecPayload<E> = FullPayload<E>> {
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    pub graffiti: Graffiti,
    #[superstruct(
        only(Base, Altair, Bellatrix, Capella, Deneb, Electra, Fulu),
        partial_getter(rename = "proposer_slashings_basic")
    )]
    pub proposer_slashings: VariableList<ProposerSlashing, E::MaxProposerSlashings>,
    #[superstruct(
        only(Gloas, Heze),
        partial_getter(rename = "proposer_slashings_progressive")
    )]
    pub proposer_slashings: ProgressiveVariableList<ProposerSlashing>,
    #[superstruct(
        only(Base, Altair, Bellatrix, Capella, Deneb),
        partial_getter(rename = "attester_slashings_base")
    )]
    pub attester_slashings: VariableList<AttesterSlashingBase<E>, E::MaxAttesterSlashings>,
    #[superstruct(
        only(Electra, Fulu),
        partial_getter(rename = "attester_slashings_electra")
    )]
    pub attester_slashings:
        VariableList<AttesterSlashingElectra<E>, E::MaxAttesterSlashingsElectra>,
    #[superstruct(only(Gloas, Heze), partial_getter(rename = "attester_slashings_gloas"))]
    pub attester_slashings: ProgressiveVariableList<AttesterSlashingGloas<E>>,
    #[superstruct(
        only(Base, Altair, Bellatrix, Capella, Deneb),
        partial_getter(rename = "attestations_base")
    )]
    pub attestations: VariableList<AttestationBase<E>, E::MaxAttestations>,
    #[superstruct(only(Electra, Fulu), partial_getter(rename = "attestations_electra"))]
    pub attestations: VariableList<AttestationElectra<E>, E::MaxAttestationsElectra>,
    #[superstruct(only(Gloas, Heze), partial_getter(rename = "attestations_gloas"))]
    pub attestations: ProgressiveVariableList<AttestationGloas<E>>,
    #[superstruct(
        only(Base, Altair, Bellatrix, Capella, Deneb, Electra, Fulu),
        partial_getter(rename = "deposits_basic")
    )]
    pub deposits: VariableList<Deposit, E::MaxDeposits>,
    #[superstruct(only(Gloas, Heze), partial_getter(rename = "deposits_progressive"))]
    pub deposits: ProgressiveVariableList<Deposit>,
    #[superstruct(
        only(Base, Altair, Bellatrix, Capella, Deneb, Electra, Fulu),
        partial_getter(rename = "voluntary_exits_basic")
    )]
    pub voluntary_exits: VariableList<SignedVoluntaryExit, E::MaxVoluntaryExits>,
    #[superstruct(
        only(Gloas, Heze),
        partial_getter(rename = "voluntary_exits_progressive")
    )]
    pub voluntary_exits: ProgressiveVariableList<SignedVoluntaryExit>,
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra, Fulu, Gloas, Heze))]
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
    #[superstruct(only(Fulu), partial_getter(rename = "execution_payload_fulu"))]
    #[serde(flatten)]
    pub execution_payload: Payload::Fulu,
    #[superstruct(
        only(Capella, Deneb, Electra, Fulu),
        partial_getter(rename = "bls_to_execution_changes_basic")
    )]
    pub bls_to_execution_changes:
        VariableList<SignedBlsToExecutionChange, E::MaxBlsToExecutionChanges>,
    #[superstruct(
        only(Gloas, Heze),
        partial_getter(rename = "bls_to_execution_changes_progressive")
    )]
    pub bls_to_execution_changes: ProgressiveVariableList<SignedBlsToExecutionChange>,
    #[superstruct(only(Deneb, Electra, Fulu))]
    pub blob_kzg_commitments: KzgCommitments<E>,
    #[superstruct(only(Electra, Fulu))]
    pub execution_requests: ExecutionRequestsElectra<E>,
    #[superstruct(only(Gloas, Heze))]
    pub signed_execution_payload_bid: SignedExecutionPayloadBid<E>,
    #[superstruct(only(Gloas, Heze))]
    pub payload_attestations: ProgressiveVariableList<PayloadAttestation<E>>,
    #[superstruct(only(Gloas, Heze))]
    pub parent_execution_requests: ExecutionRequestsGloas<E>,
    #[superstruct(only(Base, Altair, Gloas, Heze))]
    #[metastruct(exclude_from(fields))]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[serde(skip)]
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    pub _phantom: PhantomData<Payload>,
}

impl<E: EthSpec, Payload: AbstractExecPayload<E>> BeaconBlockBody<E, Payload> {
    pub fn execution_payload(&self) -> Result<Payload::Ref<'_>, BeaconStateError> {
        self.to_ref().execution_payload()
    }

    pub fn proposer_slashings(&self) -> ListRef<'_, ProposerSlashing, E::MaxProposerSlashings> {
        self.to_ref().proposer_slashings()
    }

    pub fn deposits(&self) -> ListRef<'_, Deposit, E::MaxDeposits> {
        self.to_ref().deposits()
    }

    pub fn voluntary_exits(&self) -> ListRef<'_, SignedVoluntaryExit, E::MaxVoluntaryExits> {
        self.to_ref().voluntary_exits()
    }

    pub fn bls_to_execution_changes(
        &self,
    ) -> Result<
        ListRef<'_, SignedBlsToExecutionChange, E::MaxBlsToExecutionChanges>,
        BeaconStateError,
    > {
        self.to_ref().bls_to_execution_changes()
    }

    /// Returns the name of the fork pertaining to `self`.
    pub fn fork_name(&self) -> ForkName {
        self.to_ref().fork_name()
    }
}

impl<'a, E: EthSpec, Payload: AbstractExecPayload<E>> BeaconBlockBodyRef<'a, E, Payload> {
    pub fn execution_payload(&self) -> Result<Payload::Ref<'a>, BeaconStateError> {
        match self {
            Self::Base(_) | Self::Altair(_) => Err(BeaconStateError::IncorrectStateVariant),
            Self::Bellatrix(body) => Ok(Payload::Ref::from(&body.execution_payload)),
            Self::Capella(body) => Ok(Payload::Ref::from(&body.execution_payload)),
            Self::Deneb(body) => Ok(Payload::Ref::from(&body.execution_payload)),
            Self::Electra(body) => Ok(Payload::Ref::from(&body.execution_payload)),
            Self::Fulu(body) => Ok(Payload::Ref::from(&body.execution_payload)),
            Self::Gloas(_) => Err(BeaconStateError::IncorrectStateVariant),
            Self::Heze(_) => Err(BeaconStateError::IncorrectStateVariant),
        }
    }

    pub fn body_merkle_leaves(&self) -> Vec<Hash256> {
        let mut leaves = vec![];
        match self {
            Self::Base(body) => {
                beacon_block_body_base_fields!(body, |_, field| leaves
                    .push(field.tree_hash_root()));
            }
            Self::Altair(body) => {
                beacon_block_body_altair_fields!(body, |_, field| leaves
                    .push(field.tree_hash_root()));
            }
            Self::Bellatrix(body) => {
                beacon_block_body_bellatrix_fields!(body, |_, field| leaves
                    .push(field.tree_hash_root()));
            }
            Self::Capella(body) => {
                beacon_block_body_capella_fields!(body, |_, field| leaves
                    .push(field.tree_hash_root()));
            }
            Self::Deneb(body) => {
                beacon_block_body_deneb_fields!(body, |_, field| leaves
                    .push(field.tree_hash_root()));
            }
            Self::Electra(body) => {
                beacon_block_body_electra_fields!(body, |_, field| leaves
                    .push(field.tree_hash_root()));
            }
            Self::Fulu(body) => {
                beacon_block_body_fulu_fields!(body, |_, field| leaves
                    .push(field.tree_hash_root()));
            }
            Self::Gloas(body) => {
                beacon_block_body_gloas_fields!(body, |_, field| leaves
                    .push(field.tree_hash_root()));
            }
            Self::Heze(body) => {
                beacon_block_body_heze_fields!(body, |_, field| leaves
                    .push(field.tree_hash_root()));
            }
        }
        leaves
    }

    /// Calculate a KZG commitment merkle proof.
    ///
    /// Prefer to use `complete_kzg_commitment_merkle_proof` with a reused proof for the
    /// `blob_kzg_commitments` field.
    pub fn kzg_commitment_merkle_proof(
        &self,
        index: usize,
    ) -> Result<FixedVector<Hash256, E::KzgCommitmentInclusionProofDepth>, BeaconStateError> {
        let kzg_commitments_proof = self.kzg_commitments_merkle_proof()?;
        let proof = self.complete_kzg_commitment_merkle_proof(index, &kzg_commitments_proof)?;
        Ok(proof)
    }

    /// Produces the proof of inclusion for a `KzgCommitment` in `self.blob_kzg_commitments`
    /// at `index` using an existing proof for the `blob_kzg_commitments` field.
    /// TODO(EIP7732) Investigate calling functions since this will no longer work for glas since no block_kzg_commitments in the body anymore
    pub fn complete_kzg_commitment_merkle_proof(
        &self,
        index: usize,
        kzg_commitments_proof: &[Hash256],
    ) -> Result<FixedVector<Hash256, E::KzgCommitmentInclusionProofDepth>, BeaconStateError> {
        match self {
            Self::Base(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Gloas(_)
            | Self::Heze(_) => Err(BeaconStateError::IncorrectStateVariant),
            Self::Deneb(_) | Self::Electra(_) | Self::Fulu(_) => {
                complete_kzg_commitment_merkle_proof::<E>(
                    self.blob_kzg_commitments()?,
                    index,
                    kzg_commitments_proof,
                )
            }
        }
    }

    /// Produces the proof of inclusion for `self.blob_kzg_commitments`.
    pub fn kzg_commitments_merkle_proof(
        &self,
    ) -> Result<FixedVector<Hash256, E::KzgCommitmentsInclusionProofDepth>, BeaconStateError> {
        // [Modified in Gloas:EIP7688] the body is a progressive container with different
        // generalized indices, which are not implemented yet. The body also no longer contains
        // `blob_kzg_commitments`, which moved to the execution payload bid (EIP-7732).
        if self.fork_name().gloas_enabled() {
            return Err(BeaconStateError::ProgressiveMerkleProofNotSupported);
        }
        let body_leaves = self.body_merkle_leaves();
        let beacon_block_body_depth = body_leaves.len().next_power_of_two().ilog2() as usize;
        let tree = MerkleTree::create(&body_leaves, beacon_block_body_depth);
        let (_, proof) = tree
            .generate_proof(BLOB_KZG_COMMITMENTS_INDEX, beacon_block_body_depth)
            .map_err(BeaconStateError::MerkleTreeError)?;
        Ok(FixedVector::new(proof)?)
    }

    pub fn block_body_merkle_proof(
        &self,
        generalized_index: usize,
    ) -> Result<Vec<Hash256>, BeaconStateError> {
        // [Modified in Gloas:EIP7688] the body is a progressive container with different
        // generalized indices, which are not implemented yet.
        if self.fork_name().gloas_enabled() {
            return Err(BeaconStateError::ProgressiveMerkleProofNotSupported);
        }
        let field_index = match generalized_index {
            EXECUTION_PAYLOAD_INDEX => {
                // Execution payload is a top-level field, subtract off the generalized indices
                // for the internal nodes. Result should be 9, the field offset of the execution
                // payload in the `BeaconBlockBody`:
                // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/beacon-chain.md#beaconblockbody
                generalized_index
                    .checked_sub(NUM_BEACON_BLOCK_BODY_HASH_TREE_ROOT_LEAVES)
                    .ok_or(BeaconStateError::GeneralizedIndexNotSupported(
                        generalized_index,
                    ))?
            }
            _ => {
                return Err(BeaconStateError::GeneralizedIndexNotSupported(
                    generalized_index,
                ));
            }
        };

        let leaves = self.body_merkle_leaves();
        let depth = EXECUTION_PAYLOAD_PROOF_LEN;
        let tree = merkle_proof::MerkleTree::create(&leaves, depth);
        let (_, proof) = tree.generate_proof(field_index, depth)?;

        Ok(proof)
    }

    /// Return `true` if this block body has a non-zero number of blobs.
    pub fn has_blobs(self) -> bool {
        self.blob_kzg_commitments()
            .is_ok_and(|blobs| !blobs.is_empty())
    }

    pub fn attestations_len(&self) -> usize {
        map_beacon_block_body_ref!(&'a _, self, |inner, cons| {
            cons(inner);
            inner.attestations.len()
        })
    }

    pub fn attester_slashings_len(&self) -> usize {
        map_beacon_block_body_ref!(&'a _, self, |inner, cons| {
            cons(inner);
            inner.attester_slashings.len()
        })
    }

    pub fn proposer_slashings(&self) -> ListRef<'a, ProposerSlashing, E::MaxProposerSlashings> {
        match self {
            Self::Base(body) => ListRef::Basic(&body.proposer_slashings),
            Self::Altair(body) => ListRef::Basic(&body.proposer_slashings),
            Self::Bellatrix(body) => ListRef::Basic(&body.proposer_slashings),
            Self::Capella(body) => ListRef::Basic(&body.proposer_slashings),
            Self::Deneb(body) => ListRef::Basic(&body.proposer_slashings),
            Self::Electra(body) => ListRef::Basic(&body.proposer_slashings),
            Self::Fulu(body) => ListRef::Basic(&body.proposer_slashings),
            Self::Gloas(body) => ListRef::Progressive(&body.proposer_slashings),
            Self::Heze(body) => ListRef::Progressive(&body.proposer_slashings),
        }
    }

    pub fn deposits(&self) -> ListRef<'a, Deposit, E::MaxDeposits> {
        match self {
            Self::Base(body) => ListRef::Basic(&body.deposits),
            Self::Altair(body) => ListRef::Basic(&body.deposits),
            Self::Bellatrix(body) => ListRef::Basic(&body.deposits),
            Self::Capella(body) => ListRef::Basic(&body.deposits),
            Self::Deneb(body) => ListRef::Basic(&body.deposits),
            Self::Electra(body) => ListRef::Basic(&body.deposits),
            Self::Fulu(body) => ListRef::Basic(&body.deposits),
            Self::Gloas(body) => ListRef::Progressive(&body.deposits),
            Self::Heze(body) => ListRef::Progressive(&body.deposits),
        }
    }

    pub fn voluntary_exits(&self) -> ListRef<'a, SignedVoluntaryExit, E::MaxVoluntaryExits> {
        match self {
            Self::Base(body) => ListRef::Basic(&body.voluntary_exits),
            Self::Altair(body) => ListRef::Basic(&body.voluntary_exits),
            Self::Bellatrix(body) => ListRef::Basic(&body.voluntary_exits),
            Self::Capella(body) => ListRef::Basic(&body.voluntary_exits),
            Self::Deneb(body) => ListRef::Basic(&body.voluntary_exits),
            Self::Electra(body) => ListRef::Basic(&body.voluntary_exits),
            Self::Fulu(body) => ListRef::Basic(&body.voluntary_exits),
            Self::Gloas(body) => ListRef::Progressive(&body.voluntary_exits),
            Self::Heze(body) => ListRef::Progressive(&body.voluntary_exits),
        }
    }

    pub fn bls_to_execution_changes(
        &self,
    ) -> Result<
        ListRef<'a, SignedBlsToExecutionChange, E::MaxBlsToExecutionChanges>,
        BeaconStateError,
    > {
        match self {
            Self::Base(_) | Self::Altair(_) | Self::Bellatrix(_) => {
                Err(BeaconStateError::IncorrectStateVariant)
            }
            Self::Capella(body) => Ok(ListRef::Basic(&body.bls_to_execution_changes)),
            Self::Deneb(body) => Ok(ListRef::Basic(&body.bls_to_execution_changes)),
            Self::Electra(body) => Ok(ListRef::Basic(&body.bls_to_execution_changes)),
            Self::Fulu(body) => Ok(ListRef::Basic(&body.bls_to_execution_changes)),
            Self::Gloas(body) => Ok(ListRef::Progressive(&body.bls_to_execution_changes)),
            Self::Heze(body) => Ok(ListRef::Progressive(&body.bls_to_execution_changes)),
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
            Self::Fulu(body) => Box::new(body.attestations.iter().map(AttestationRef::Electra)),
            Self::Gloas(body) => Box::new(body.attestations.iter().map(AttestationRef::Gloas)),
            Self::Heze(body) => Box::new(body.attestations.iter().map(AttestationRef::Gloas)),
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
            Self::Fulu(body) => Box::new(
                body.attester_slashings
                    .iter()
                    .map(AttesterSlashingRef::Electra),
            ),
            Self::Gloas(body) => Box::new(
                body.attester_slashings
                    .iter()
                    .map(AttesterSlashingRef::Gloas),
            ),
            Self::Heze(body) => Box::new(
                body.attester_slashings
                    .iter()
                    .map(AttesterSlashingRef::Gloas),
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
            Self::Fulu(body) => {
                Box::new(body.attestations.iter_mut().map(AttestationRefMut::Electra))
            }
            Self::Gloas(body) => {
                Box::new(body.attestations.iter_mut().map(AttestationRefMut::Gloas))
            }
            Self::Heze(body) => {
                Box::new(body.attestations.iter_mut().map(AttestationRefMut::Gloas))
            }
        }
    }

    /// Append a voluntary exit to the block body.
    pub fn voluntary_exits_push(
        &mut self,
        exit: SignedVoluntaryExit,
    ) -> Result<(), BeaconStateError> {
        match self {
            Self::Base(body) => body
                .voluntary_exits
                .push(exit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Altair(body) => body
                .voluntary_exits
                .push(exit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Bellatrix(body) => body
                .voluntary_exits
                .push(exit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Capella(body) => body
                .voluntary_exits
                .push(exit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Deneb(body) => body
                .voluntary_exits
                .push(exit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Electra(body) => body
                .voluntary_exits
                .push(exit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Fulu(body) => body
                .voluntary_exits
                .push(exit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Gloas(body) => {
                body.voluntary_exits.push(exit);
                Ok(())
            }
            Self::Heze(body) => {
                body.voluntary_exits.push(exit);
                Ok(())
            }
        }
    }

    /// Append a proposer slashing to the block body.
    pub fn proposer_slashings_push(
        &mut self,
        slashing: ProposerSlashing,
    ) -> Result<(), BeaconStateError> {
        match self {
            Self::Base(body) => body
                .proposer_slashings
                .push(slashing)
                .map_err(BeaconStateError::SszTypesError),
            Self::Altair(body) => body
                .proposer_slashings
                .push(slashing)
                .map_err(BeaconStateError::SszTypesError),
            Self::Bellatrix(body) => body
                .proposer_slashings
                .push(slashing)
                .map_err(BeaconStateError::SszTypesError),
            Self::Capella(body) => body
                .proposer_slashings
                .push(slashing)
                .map_err(BeaconStateError::SszTypesError),
            Self::Deneb(body) => body
                .proposer_slashings
                .push(slashing)
                .map_err(BeaconStateError::SszTypesError),
            Self::Electra(body) => body
                .proposer_slashings
                .push(slashing)
                .map_err(BeaconStateError::SszTypesError),
            Self::Fulu(body) => body
                .proposer_slashings
                .push(slashing)
                .map_err(BeaconStateError::SszTypesError),
            Self::Gloas(body) => {
                body.proposer_slashings.push(slashing);
                Ok(())
            }
            Self::Heze(body) => {
                body.proposer_slashings.push(slashing);
                Ok(())
            }
        }
    }

    /// Append a deposit to the block body.
    pub fn deposits_push(&mut self, deposit: Deposit) -> Result<(), BeaconStateError> {
        match self {
            Self::Base(body) => body
                .deposits
                .push(deposit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Altair(body) => body
                .deposits
                .push(deposit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Bellatrix(body) => body
                .deposits
                .push(deposit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Capella(body) => body
                .deposits
                .push(deposit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Deneb(body) => body
                .deposits
                .push(deposit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Electra(body) => body
                .deposits
                .push(deposit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Fulu(body) => body
                .deposits
                .push(deposit)
                .map_err(BeaconStateError::SszTypesError),
            Self::Gloas(body) => {
                body.deposits.push(deposit);
                Ok(())
            }
            Self::Heze(body) => {
                body.deposits.push(deposit);
                Ok(())
            }
        }
    }

    /// Replace the deposits list with the given deposits.
    pub fn set_deposits_from_iter(
        &mut self,
        deposits: impl IntoIterator<Item = Deposit>,
    ) -> Result<(), BeaconStateError> {
        match self {
            Self::Base(body) => {
                body.deposits = VariableList::new(deposits.into_iter().collect())
                    .map_err(BeaconStateError::SszTypesError)?;
            }
            Self::Altair(body) => {
                body.deposits = VariableList::new(deposits.into_iter().collect())
                    .map_err(BeaconStateError::SszTypesError)?;
            }
            Self::Bellatrix(body) => {
                body.deposits = VariableList::new(deposits.into_iter().collect())
                    .map_err(BeaconStateError::SszTypesError)?;
            }
            Self::Capella(body) => {
                body.deposits = VariableList::new(deposits.into_iter().collect())
                    .map_err(BeaconStateError::SszTypesError)?;
            }
            Self::Deneb(body) => {
                body.deposits = VariableList::new(deposits.into_iter().collect())
                    .map_err(BeaconStateError::SszTypesError)?;
            }
            Self::Electra(body) => {
                body.deposits = VariableList::new(deposits.into_iter().collect())
                    .map_err(BeaconStateError::SszTypesError)?;
            }
            Self::Fulu(body) => {
                body.deposits = VariableList::new(deposits.into_iter().collect())
                    .map_err(BeaconStateError::SszTypesError)?;
            }
            Self::Gloas(body) => {
                body.deposits = deposits.into_iter().collect();
            }
            Self::Heze(body) => {
                body.deposits = deposits.into_iter().collect();
            }
        }
        Ok(())
    }

    /// Mutable slice over the block body's voluntary exits.
    pub fn voluntary_exits_mut(&mut self) -> &mut [SignedVoluntaryExit] {
        match self {
            Self::Base(body) => &mut body.voluntary_exits,
            Self::Altair(body) => &mut body.voluntary_exits,
            Self::Bellatrix(body) => &mut body.voluntary_exits,
            Self::Capella(body) => &mut body.voluntary_exits,
            Self::Deneb(body) => &mut body.voluntary_exits,
            Self::Electra(body) => &mut body.voluntary_exits,
            Self::Fulu(body) => &mut body.voluntary_exits,
            Self::Gloas(body) => &mut body.voluntary_exits,
            Self::Heze(body) => &mut body.voluntary_exits,
        }
    }
}

impl<E: EthSpec, Payload: AbstractExecPayload<E>> BeaconBlockBodyRef<'_, E, Payload> {
    /// Get the fork_name of this object
    pub fn fork_name(self) -> ForkName {
        match self {
            BeaconBlockBodyRef::Base { .. } => ForkName::Base,
            BeaconBlockBodyRef::Altair { .. } => ForkName::Altair,
            BeaconBlockBodyRef::Bellatrix { .. } => ForkName::Bellatrix,
            BeaconBlockBodyRef::Capella { .. } => ForkName::Capella,
            BeaconBlockBodyRef::Deneb { .. } => ForkName::Deneb,
            BeaconBlockBodyRef::Electra { .. } => ForkName::Electra,
            BeaconBlockBodyRef::Fulu { .. } => ForkName::Fulu,
            BeaconBlockBodyRef::Gloas { .. } => ForkName::Gloas,
            BeaconBlockBodyRef::Heze { .. } => ForkName::Heze,
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

// Post-Fulu block bodies without payloads can be converted into block bodies with payloads
// TODO(EIP-7732) Look into whether we can remove this in the future since no blinded blocks post-gloas
impl<E: EthSpec> From<BeaconBlockBodyGloas<E, BlindedPayload<E>>>
    for BeaconBlockBodyGloas<E, FullPayload<E>>
{
    fn from(body: BeaconBlockBodyGloas<E, BlindedPayload<E>>) -> Self {
        let BeaconBlockBodyGloas {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            bls_to_execution_changes,
            parent_execution_requests,
            signed_execution_payload_bid,
            payload_attestations,
            _phantom,
        } = body;

        BeaconBlockBodyGloas {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            bls_to_execution_changes,
            parent_execution_requests,
            signed_execution_payload_bid,
            payload_attestations,
            _phantom: PhantomData,
        }
    }
}

// Post-Fulu block bodies without payloads can be converted into block bodies with payloads
// TODO(heze) Look into whether we can remove this in the future since no blinded blocks post-gloas
impl<E: EthSpec> From<BeaconBlockBodyHeze<E, BlindedPayload<E>>>
    for BeaconBlockBodyHeze<E, FullPayload<E>>
{
    fn from(body: BeaconBlockBodyHeze<E, BlindedPayload<E>>) -> Self {
        let BeaconBlockBodyHeze {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            bls_to_execution_changes,
            parent_execution_requests,
            signed_execution_payload_bid,
            payload_attestations,
            _phantom,
        } = body;

        BeaconBlockBodyHeze {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            bls_to_execution_changes,
            parent_execution_requests,
            signed_execution_payload_bid,
            payload_attestations,
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
            execution_requests,
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
                execution_requests,
            },
            Some(execution_payload),
        )
    }
}

impl<E: EthSpec> From<BeaconBlockBodyFulu<E, FullPayload<E>>>
    for (
        BeaconBlockBodyFulu<E, BlindedPayload<E>>,
        Option<ExecutionPayloadFulu<E>>,
    )
{
    fn from(body: BeaconBlockBodyFulu<E, FullPayload<E>>) -> Self {
        let BeaconBlockBodyFulu {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayloadFulu { execution_payload },
            bls_to_execution_changes,
            blob_kzg_commitments,
            execution_requests,
        } = body;

        (
            BeaconBlockBodyFulu {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                execution_payload: BlindedPayloadFulu {
                    execution_payload_header: From::from(&execution_payload),
                },
                bls_to_execution_changes,
                blob_kzg_commitments: blob_kzg_commitments.clone(),
                execution_requests,
            },
            Some(execution_payload),
        )
    }
}

impl<E: EthSpec> From<BeaconBlockBodyGloas<E, FullPayload<E>>>
    for (
        BeaconBlockBodyGloas<E, BlindedPayload<E>>,
        Option<ExecutionPayloadGloas<E>>,
    )
{
    fn from(body: BeaconBlockBodyGloas<E, FullPayload<E>>) -> Self {
        let BeaconBlockBodyGloas {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            bls_to_execution_changes,
            parent_execution_requests,
            signed_execution_payload_bid,
            payload_attestations,
            _phantom,
        } = body;

        (
            BeaconBlockBodyGloas {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                bls_to_execution_changes,
                parent_execution_requests,
                signed_execution_payload_bid,
                payload_attestations,
                _phantom: PhantomData,
            },
            None,
        )
    }
}

impl<E: EthSpec> From<BeaconBlockBodyHeze<E, FullPayload<E>>>
    for (
        BeaconBlockBodyHeze<E, BlindedPayload<E>>,
        Option<ExecutionPayloadGloas<E>>,
    )
{
    fn from(body: BeaconBlockBodyHeze<E, FullPayload<E>>) -> Self {
        let BeaconBlockBodyHeze {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            bls_to_execution_changes,
            parent_execution_requests,
            signed_execution_payload_bid,
            payload_attestations,
            _phantom,
        } = body;

        (
            BeaconBlockBodyHeze {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                bls_to_execution_changes,
                parent_execution_requests,
                signed_execution_payload_bid,
                payload_attestations,
                _phantom: PhantomData,
            },
            None,
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
            execution_requests,
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
            execution_requests: execution_requests.clone(),
        }
    }
}

impl<E: EthSpec> BeaconBlockBodyFulu<E, FullPayload<E>> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyFulu<E, BlindedPayload<E>> {
        let BeaconBlockBodyFulu {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: FullPayloadFulu { execution_payload },
            bls_to_execution_changes,
            blob_kzg_commitments,
            execution_requests,
        } = self;

        BeaconBlockBodyFulu {
            randao_reveal: randao_reveal.clone(),
            eth1_data: eth1_data.clone(),
            graffiti: *graffiti,
            proposer_slashings: proposer_slashings.clone(),
            attester_slashings: attester_slashings.clone(),
            attestations: attestations.clone(),
            deposits: deposits.clone(),
            voluntary_exits: voluntary_exits.clone(),
            sync_aggregate: sync_aggregate.clone(),
            execution_payload: BlindedPayloadFulu {
                execution_payload_header: execution_payload.into(),
            },
            bls_to_execution_changes: bls_to_execution_changes.clone(),
            blob_kzg_commitments: blob_kzg_commitments.clone(),
            execution_requests: execution_requests.clone(),
        }
    }
}

impl<E: EthSpec> BeaconBlockBodyGloas<E, FullPayload<E>> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyGloas<E, BlindedPayload<E>> {
        let (block_body, _payload) = self.clone().into();
        block_body
    }
}

impl<E: EthSpec> BeaconBlockBodyHeze<E, FullPayload<E>> {
    pub fn clone_as_blinded(&self) -> BeaconBlockBodyHeze<E, BlindedPayload<E>> {
        let (block_body, _payload) = self.clone().into();
        block_body
    }
}

impl<E: EthSpec> From<BeaconBlockBody<E, FullPayload<E>>>
    for (
        BeaconBlockBody<E, BlindedPayload<E>>,
        Option<ExecutionPayload<E>>,
    )
{
    #[allow(clippy::useless_conversion)] // Not a useless conversion
    fn from(body: BeaconBlockBody<E, FullPayload<E>>) -> Self {
        map_beacon_block_body!(body, |inner, cons| {
            let (block, payload) = inner.into();
            (cons(block), payload.map(Into::into))
        })
    }
}

impl<'de, E: EthSpec, Payload: AbstractExecPayload<E>> ContextDeserialize<'de, ForkName>
    for BeaconBlockBody<E, Payload>
{
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(map_fork_name!(
            context,
            Self,
            serde::Deserialize::deserialize(deserializer)?
        ))
    }
}

#[cfg(test)]
mod tests {
    mod base {
        use super::super::*;
        use crate::core::MainnetEthSpec;
        ssz_and_tree_hash_tests!(BeaconBlockBodyBase<MainnetEthSpec>);
    }
    mod altair {
        use super::super::*;
        use crate::core::MainnetEthSpec;
        ssz_and_tree_hash_tests!(BeaconBlockBodyAltair<MainnetEthSpec>);
    }
    mod gloas {
        use super::super::*;
        use crate::block::BeaconBlock;
        use crate::core::{ChainSpec, MainnetEthSpec};

        /// Check the derived Gloas body root against a manual computation from its 13 field
        /// roots, so an incorrect `active_fields` list would change the result (EIP-7688).
        #[test]
        fn gloas_body_progressive_container_root() {
            type E = MainnetEthSpec;
            let spec: ChainSpec = ForkName::Gloas.make_genesis_spec(E::default_spec());
            let block: BeaconBlock<E> = BeaconBlock::empty(&spec);
            let BeaconBlock::Gloas(block) = block else {
                panic!("expected a Gloas block");
            };
            let body = &block.body;

            // All 13 spec fields, in container order.
            let field_roots = [
                body.randao_reveal.tree_hash_root(),
                body.eth1_data.tree_hash_root(),
                body.graffiti.tree_hash_root(),
                body.proposer_slashings.tree_hash_root(),
                body.attester_slashings.tree_hash_root(),
                body.attestations.tree_hash_root(),
                body.deposits.tree_hash_root(),
                body.voluntary_exits.tree_hash_root(),
                body.sync_aggregate.tree_hash_root(),
                body.bls_to_execution_changes.tree_hash_root(),
                body.signed_execution_payload_bid.tree_hash_root(),
                body.payload_attestations.tree_hash_root(),
                body.parent_execution_requests.tree_hash_root(),
            ];

            let mut hasher = tree_hash::ProgressiveMerkleHasher::new();
            for root in &field_roots {
                hasher.write(root.as_slice()).unwrap();
            }
            let container_root = hasher.finish().unwrap();

            // `active_fields = [1] * 13`.
            let mut active_fields = [0u8; 32];
            active_fields[0] = 0xff;
            active_fields[1] = 0x1f;
            let expected = tree_hash::mix_in_active_fields(&container_root, active_fields);

            assert_eq!(body.tree_hash_root(), expected);
        }
    }
}

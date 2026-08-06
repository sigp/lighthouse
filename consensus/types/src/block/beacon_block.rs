use std::{fmt, marker::PhantomData};

use bls::{AggregateSignature, PublicKeyBytes, SecretKey, Signature, SignatureBytes};
use context_deserialize::ContextDeserialize;
use educe::Educe;
use fixed_bytes::FixedBytesExtended;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{Decode, DecodeError};
use ssz_derive::{Decode, Encode};
use ssz_types::{BitList, BitVector, FixedVector, ProgressiveVariableList, VariableList};
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    SignedExecutionPayloadBid, Spec,
    attestation::{AttestationBase, AttestationData, IndexedAttestationBase},
    block::{
        BeaconBlockBodyAltair, BeaconBlockBodyBase, BeaconBlockBodyBellatrix,
        BeaconBlockBodyCapella, BeaconBlockBodyDeneb, BeaconBlockBodyElectra, BeaconBlockBodyFulu,
        BeaconBlockBodyGloas, BeaconBlockBodyHeze, BeaconBlockBodyRef, BeaconBlockBodyRefMut,
        BeaconBlockHeader, SignedBeaconBlock, SignedBeaconBlockHeader,
    },
    core::{ChainSpec, Domain, Epoch, Graffiti, Hash256, SignedRoot, Slot},
    deposit::{Deposit, DepositData},
    execution::{
        AbstractExecPayload, BlindedPayload, Eth1Data, ExecutionPayload, ExecutionRequestsElectra,
        ExecutionRequestsGloas, FullPayload,
    },
    exit::{SignedVoluntaryExit, VoluntaryExit},
    fork::{Fork, ForkName, InconsistentFork, map_fork_name},
    slashing::{AttesterSlashingBase, ProposerSlashing},
    state::BeaconStateError,
    sync_committee::SyncAggregate,
};

/// A block of the `BeaconChain`.
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
        educe(PartialEq, Hash(bound(Payload: AbstractExecPayload))),
        serde(
            bound = "Payload: AbstractExecPayload",
            deny_unknown_fields
        ),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "Payload: AbstractExecPayload")
        )
    ),
    ref_attributes(
        derive(Debug, PartialEq, TreeHash),
        tree_hash(enum_behaviour = "transparent")
    ),
    map_ref_into(BeaconBlockBodyRef, BeaconBlock),
    map_ref_mut_into(BeaconBlockBodyRefMut)
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "Payload: AbstractExecPayload")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Educe)]
#[educe(PartialEq, Hash)]
#[serde(untagged)]
#[serde(bound = "Payload: AbstractExecPayload")]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct BeaconBlock<Payload: AbstractExecPayload = FullPayload> {
    #[superstruct(getter(copy))]
    pub slot: Slot,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[superstruct(getter(copy))]
    pub parent_root: Hash256,
    #[superstruct(getter(copy))]
    pub state_root: Hash256,
    #[superstruct(only(Base), partial_getter(rename = "body_base"))]
    pub body: BeaconBlockBodyBase<Payload>,
    #[superstruct(only(Altair), partial_getter(rename = "body_altair"))]
    pub body: BeaconBlockBodyAltair<Payload>,
    #[superstruct(only(Bellatrix), partial_getter(rename = "body_bellatrix"))]
    pub body: BeaconBlockBodyBellatrix<Payload>,
    #[superstruct(only(Capella), partial_getter(rename = "body_capella"))]
    pub body: BeaconBlockBodyCapella<Payload>,
    #[superstruct(only(Deneb), partial_getter(rename = "body_deneb"))]
    pub body: BeaconBlockBodyDeneb<Payload>,
    #[superstruct(only(Electra), partial_getter(rename = "body_electra"))]
    pub body: BeaconBlockBodyElectra<Payload>,
    #[superstruct(only(Fulu), partial_getter(rename = "body_fulu"))]
    pub body: BeaconBlockBodyFulu<Payload>,
    #[superstruct(only(Gloas), partial_getter(rename = "body_gloas"))]
    pub body: BeaconBlockBodyGloas<Payload>,
    #[superstruct(only(Heze), partial_getter(rename = "body_heze"))]
    pub body: BeaconBlockBodyHeze<Payload>,
}

pub type BlindedBeaconBlock = BeaconBlock<BlindedPayload>;

impl<Payload: AbstractExecPayload> SignedRoot for BeaconBlock<Payload> {}
impl<Payload: AbstractExecPayload> SignedRoot for BeaconBlockRef<'_, Payload> {}

/// Empty block trait for each block variant to implement.
pub trait EmptyBlock {
    /// Returns an empty block to be used during genesis.
    fn empty(spec: &ChainSpec) -> Self;
}

impl<Payload: AbstractExecPayload> BeaconBlock<Payload> {
    /// Returns an empty block to be used during genesis.
    pub fn empty(spec: &ChainSpec) -> Self {
        map_fork_name!(
            spec.fork_name_at_epoch(Epoch::new(Spec::genesis_epoch())),
            Self,
            EmptyBlock::empty(spec)
        )
    }

    /// Custom SSZ decoder that takes a `ChainSpec` as context.
    pub fn from_ssz_bytes(bytes: &[u8], spec: &ChainSpec) -> Result<Self, ssz::DecodeError> {
        let slot_len = <Slot as Decode>::ssz_fixed_len();
        let slot_bytes = bytes
            .get(0..slot_len)
            .ok_or(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: slot_len,
            })?;

        let slot = Slot::from_ssz_bytes(slot_bytes)?;
        let fork_at_slot = spec.fork_name_at_slot(slot);
        Self::from_ssz_bytes_for_fork(bytes, fork_at_slot)
    }

    /// Custom SSZ decoder that takes a `ForkName` as context.
    pub fn from_ssz_bytes_for_fork(
        bytes: &[u8],
        fork_name: ForkName,
    ) -> Result<Self, ssz::DecodeError> {
        Ok(map_fork_name!(fork_name, Self, <_>::from_ssz_bytes(bytes)?))
    }

    /// Try decoding each beacon block variant in sequence.
    ///
    /// This is *not* recommended unless you really have no idea what variant the block should be.
    /// Usually it's better to prefer `from_ssz_bytes` which will decode the correct variant based
    /// on the fork slot.
    pub fn any_from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        // TODO(heze): decode Heze here once it diverges from Gloas. While the two variants are
        // SSZ-identical, trying Heze first would mis-tag every Gloas block as Heze.
        BeaconBlockGloas::from_ssz_bytes(bytes)
            .map(BeaconBlock::Gloas)
            .or_else(|_| BeaconBlockFulu::from_ssz_bytes(bytes).map(BeaconBlock::Fulu))
            .or_else(|_| BeaconBlockElectra::from_ssz_bytes(bytes).map(BeaconBlock::Electra))
            .or_else(|_| BeaconBlockDeneb::from_ssz_bytes(bytes).map(BeaconBlock::Deneb))
            .or_else(|_| BeaconBlockCapella::from_ssz_bytes(bytes).map(BeaconBlock::Capella))
            .or_else(|_| BeaconBlockBellatrix::from_ssz_bytes(bytes).map(BeaconBlock::Bellatrix))
            .or_else(|_| BeaconBlockAltair::from_ssz_bytes(bytes).map(BeaconBlock::Altair))
            .or_else(|_| BeaconBlockBase::from_ssz_bytes(bytes).map(BeaconBlock::Base))
    }

    /// Convenience accessor for the `body` as a `BeaconBlockBodyRef`.
    pub fn body(&self) -> BeaconBlockBodyRef<'_, Payload> {
        self.to_ref().body()
    }

    /// Convenience accessor for the `body` as a `BeaconBlockBodyRefMut`.
    pub fn body_mut(&mut self) -> BeaconBlockBodyRefMut<'_, Payload> {
        self.to_mut().body_mut()
    }

    /// Returns the epoch corresponding to `self.slot()`.
    pub fn epoch(&self) -> Epoch {
        self.slot().epoch(Spec::slots_per_epoch())
    }

    /// Returns the `tree_hash_root` of the block.
    pub fn canonical_root(&self) -> Hash256 {
        self.tree_hash_root()
    }

    /// Returns a full `BeaconBlockHeader` of this block.
    ///
    /// Note: This method is used instead of an `Into` impl to avoid a `Clone` of an entire block
    /// when you want to have the block _and_ the header.
    ///
    /// Note: performs a full tree-hash of `self.body`.
    pub fn block_header(&self) -> BeaconBlockHeader {
        self.to_ref().block_header()
    }

    /// Returns a "temporary" header, where the `state_root` is `Hash256::zero()`.
    pub fn temporary_block_header(&self) -> BeaconBlockHeader {
        self.to_ref().temporary_block_header()
    }

    /// Return the tree hash root of the block's body.
    pub fn body_root(&self) -> Hash256 {
        self.to_ref().body_root()
    }

    /// Signs `self`, producing a `SignedBeaconBlock`.
    pub fn sign(
        self,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> SignedBeaconBlock<Payload> {
        let domain = spec.get_domain(
            self.epoch(),
            Domain::BeaconProposer,
            fork,
            genesis_validators_root,
        );
        let message = self.signing_root(domain);
        let signature = secret_key.sign(message);
        SignedBeaconBlock::from_block(self, signature)
    }
}

impl<'a, Payload: AbstractExecPayload> BeaconBlockRef<'a, Payload> {
    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        let fork_at_slot = spec.fork_name_at_slot(self.slot());
        let object_fork = self.fork_name_unchecked();

        if fork_at_slot == object_fork {
            Ok(object_fork)
        } else {
            Err(InconsistentFork {
                fork_at_slot,
                object_fork,
            })
        }
    }

    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Does not check that the fork is consistent with the slot.
    pub fn fork_name_unchecked(&self) -> ForkName {
        match self {
            BeaconBlockRef::Base { .. } => ForkName::Base,
            BeaconBlockRef::Altair { .. } => ForkName::Altair,
            BeaconBlockRef::Bellatrix { .. } => ForkName::Bellatrix,
            BeaconBlockRef::Capella { .. } => ForkName::Capella,
            BeaconBlockRef::Deneb { .. } => ForkName::Deneb,
            BeaconBlockRef::Electra { .. } => ForkName::Electra,
            BeaconBlockRef::Fulu { .. } => ForkName::Fulu,
            BeaconBlockRef::Gloas { .. } => ForkName::Gloas,
            BeaconBlockRef::Heze { .. } => ForkName::Heze,
        }
    }

    /// Convenience accessor for the `body` as a `BeaconBlockBodyRef`.
    pub fn body(&self) -> BeaconBlockBodyRef<'a, Payload> {
        map_beacon_block_ref_into_beacon_block_body_ref!(&'a _, *self, |block, cons| cons(
            &block.body
        ))
    }

    /// Return the tree hash root of the block's body.
    pub fn body_root(&self) -> Hash256 {
        map_beacon_block_ref!(&'a _, *self, |block, cons| {
            let _: Self = cons(block);
            block.body.tree_hash_root()
        })
    }

    /// Returns the epoch corresponding to `self.slot()`.
    pub fn epoch(&self) -> Epoch {
        self.slot().epoch(Spec::slots_per_epoch())
    }

    /// Returns a full `BeaconBlockHeader` of this block.
    pub fn block_header(&self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: self.slot(),
            proposer_index: self.proposer_index(),
            parent_root: self.parent_root(),
            state_root: self.state_root(),
            body_root: self.body_root(),
        }
    }

    /// Returns a "temporary" header, where the `state_root` is `Hash256::zero()`.
    pub fn temporary_block_header(self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            state_root: Hash256::zero(),
            ..self.block_header()
        }
    }

    /// Extracts a reference to an execution payload from a block, returning an error if the block
    /// is pre-merge.
    pub fn execution_payload(&self) -> Result<Payload::Ref<'a>, BeaconStateError> {
        self.body().execution_payload()
    }

    pub fn blob_kzg_commitments_len(&self) -> Option<usize> {
        match self {
            BeaconBlockRef::Base(_) => None,
            BeaconBlockRef::Altair(_) => None,
            BeaconBlockRef::Bellatrix(_) => None,
            BeaconBlockRef::Capella(_) => None,
            BeaconBlockRef::Deneb(block) => Some(block.body.blob_kzg_commitments.len()),
            BeaconBlockRef::Electra(block) => Some(block.body.blob_kzg_commitments.len()),
            BeaconBlockRef::Fulu(block) => Some(block.body.blob_kzg_commitments.len()),
            BeaconBlockRef::Gloas(block) => Some(
                block
                    .body
                    .signed_execution_payload_bid
                    .message
                    .blob_kzg_commitments
                    .len(),
            ),
            BeaconBlockRef::Heze(block) => Some(
                block
                    .body
                    .signed_execution_payload_bid
                    .message
                    .blob_kzg_commitments
                    .len(),
            ),
        }
    }
}

impl<'a, Payload: AbstractExecPayload> BeaconBlockRefMut<'a, Payload> {
    /// Convert a mutable reference to a beacon block to a mutable ref to its body.
    pub fn body_mut(self) -> BeaconBlockBodyRefMut<'a, Payload> {
        map_beacon_block_ref_mut_into_beacon_block_body_ref_mut!(&'a _, self, |block, cons| cons(
            &mut block.body
        ))
    }
}

impl<Payload: AbstractExecPayload> EmptyBlock for BeaconBlockBase<Payload> {
    fn empty(spec: &ChainSpec) -> Self {
        BeaconBlockBase {
            slot: spec.genesis_slot,
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: BeaconBlockBodyBase {
                randao_reveal: Signature::empty(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: Graffiti::default(),
                proposer_slashings: VariableList::empty(),
                attester_slashings: VariableList::empty(),
                attestations: VariableList::empty(),
                deposits: VariableList::empty(),
                voluntary_exits: VariableList::empty(),
                _phantom: PhantomData,
            },
        }
    }
}

impl<Payload: AbstractExecPayload> BeaconBlockBase<Payload> {
    /// Return a block where the block has maximum size.
    pub fn full(spec: &ChainSpec) -> Self {
        let header = BeaconBlockHeader {
            slot: Slot::new(1),
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body_root: Hash256::zero(),
        };

        let signed_header = SignedBeaconBlockHeader {
            message: header,
            signature: Signature::empty(),
        };
        let indexed_attestation = IndexedAttestationBase {
            attesting_indices: VariableList::new(vec![0_u64; Spec::MAX_VALIDATORS_PER_COMMITTEE])
                .unwrap(),
            data: AttestationData::default(),
            signature: AggregateSignature::empty(),
        };

        let deposit_data = DepositData {
            pubkey: PublicKeyBytes::empty(),
            withdrawal_credentials: Hash256::zero(),
            amount: 0,
            signature: SignatureBytes::empty(),
        };
        let proposer_slashing = ProposerSlashing {
            signed_header_1: signed_header.clone(),
            signed_header_2: signed_header,
        };

        let attester_slashing = AttesterSlashingBase {
            attestation_1: indexed_attestation.clone(),
            attestation_2: indexed_attestation,
        };

        let attestation = AttestationBase {
            aggregation_bits: BitList::with_capacity(Spec::MAX_VALIDATORS_PER_COMMITTEE).unwrap(),
            data: AttestationData::default(),
            signature: AggregateSignature::empty(),
        };

        let deposit = Deposit {
            proof: FixedVector::from_elem(Hash256::zero()),
            data: deposit_data,
        };

        let voluntary_exit = VoluntaryExit {
            epoch: Epoch::new(1),
            validator_index: 1,
        };

        let signed_voluntary_exit = SignedVoluntaryExit {
            message: voluntary_exit,
            signature: Signature::empty(),
        };

        let mut block = BeaconBlockBase::<Payload>::empty(spec);
        for _ in 0..Spec::MAX_PROPOSER_SLASHINGS {
            block
                .body
                .proposer_slashings
                .push(proposer_slashing.clone())
                .unwrap();
        }
        for _ in 0..Spec::MAX_DEPOSITS {
            block.body.deposits.push(deposit.clone()).unwrap();
        }
        for _ in 0..Spec::MAX_VOLUNTARY_EXITS {
            block
                .body
                .voluntary_exits
                .push(signed_voluntary_exit.clone())
                .unwrap();
        }
        for _ in 0..Spec::MAX_ATTESTER_SLASHINGS {
            block
                .body
                .attester_slashings
                .push(attester_slashing.clone())
                .unwrap();
        }

        for _ in 0..Spec::MAX_ATTESTATIONS {
            block.body.attestations.push(attestation.clone()).unwrap();
        }
        block
    }
}

impl<Payload: AbstractExecPayload> EmptyBlock for BeaconBlockAltair<Payload> {
    /// Returns an empty Altair block to be used during genesis.
    fn empty(spec: &ChainSpec) -> Self {
        BeaconBlockAltair {
            slot: spec
                .altair_fork_epoch
                .expect("altair enabled")
                .start_slot(Spec::slots_per_epoch()),
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: BeaconBlockBodyAltair {
                randao_reveal: Signature::empty(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: Graffiti::default(),
                proposer_slashings: VariableList::empty(),
                attester_slashings: VariableList::empty(),
                attestations: VariableList::empty(),
                deposits: VariableList::empty(),
                voluntary_exits: VariableList::empty(),
                sync_aggregate: SyncAggregate::empty(),
                _phantom: PhantomData,
            },
        }
    }
}

impl<Payload: AbstractExecPayload> BeaconBlockAltair<Payload> {
    /// Return an Altair block where the block has maximum size.
    pub fn full(spec: &ChainSpec) -> Self {
        let base_block: BeaconBlockBase<Payload> = BeaconBlockBase::<Payload>::full(spec);
        let sync_aggregate = SyncAggregate {
            sync_committee_signature: AggregateSignature::empty(),
            sync_committee_bits: BitVector::default(),
        };
        BeaconBlockAltair {
            slot: spec
                .altair_fork_epoch
                .expect("altair enabled")
                .start_slot(Spec::slots_per_epoch()),
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: BeaconBlockBodyAltair {
                proposer_slashings: base_block.body.proposer_slashings,
                attester_slashings: base_block.body.attester_slashings,
                attestations: base_block.body.attestations,
                deposits: base_block.body.deposits,
                voluntary_exits: base_block.body.voluntary_exits,
                sync_aggregate,
                randao_reveal: Signature::empty(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: Graffiti::default(),
                _phantom: PhantomData,
            },
        }
    }
}

impl<Payload: AbstractExecPayload> EmptyBlock for BeaconBlockBellatrix<Payload> {
    /// Returns an empty Bellatrix block to be used during genesis.
    fn empty(spec: &ChainSpec) -> Self {
        BeaconBlockBellatrix {
            slot: spec
                .bellatrix_fork_epoch
                .expect("bellatrix enabled")
                .start_slot(Spec::slots_per_epoch()),
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: BeaconBlockBodyBellatrix {
                randao_reveal: Signature::empty(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: Graffiti::default(),
                proposer_slashings: VariableList::empty(),
                attester_slashings: VariableList::empty(),
                attestations: VariableList::empty(),
                deposits: VariableList::empty(),
                voluntary_exits: VariableList::empty(),
                sync_aggregate: SyncAggregate::empty(),
                execution_payload: Payload::Bellatrix::default(),
            },
        }
    }
}

impl<Payload: AbstractExecPayload> EmptyBlock for BeaconBlockCapella<Payload> {
    /// Returns an empty Capella block to be used during genesis.
    fn empty(spec: &ChainSpec) -> Self {
        BeaconBlockCapella {
            slot: spec
                .capella_fork_epoch
                .expect("capella enabled")
                .start_slot(Spec::slots_per_epoch()),
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: BeaconBlockBodyCapella {
                randao_reveal: Signature::empty(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: Graffiti::default(),
                proposer_slashings: VariableList::empty(),
                attester_slashings: VariableList::empty(),
                attestations: VariableList::empty(),
                deposits: VariableList::empty(),
                voluntary_exits: VariableList::empty(),
                sync_aggregate: SyncAggregate::empty(),
                execution_payload: Payload::Capella::default(),
                bls_to_execution_changes: VariableList::empty(),
            },
        }
    }
}

impl<Payload: AbstractExecPayload> EmptyBlock for BeaconBlockDeneb<Payload> {
    /// Returns an empty Deneb block to be used during genesis.
    fn empty(spec: &ChainSpec) -> Self {
        BeaconBlockDeneb {
            slot: spec
                .deneb_fork_epoch
                .expect("deneb enabled")
                .start_slot(Spec::slots_per_epoch()),
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: BeaconBlockBodyDeneb {
                randao_reveal: Signature::empty(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: Graffiti::default(),
                proposer_slashings: VariableList::empty(),
                attester_slashings: VariableList::empty(),
                attestations: VariableList::empty(),
                deposits: VariableList::empty(),
                voluntary_exits: VariableList::empty(),
                sync_aggregate: SyncAggregate::empty(),
                execution_payload: Payload::Deneb::default(),
                bls_to_execution_changes: VariableList::empty(),
                blob_kzg_commitments: VariableList::empty(),
            },
        }
    }
}

impl<Payload: AbstractExecPayload> EmptyBlock for BeaconBlockElectra<Payload> {
    /// Returns an empty Electra block to be used during genesis.
    fn empty(spec: &ChainSpec) -> Self {
        BeaconBlockElectra {
            slot: spec
                .electra_fork_epoch
                .expect("electra enabled")
                .start_slot(Spec::slots_per_epoch()),
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: BeaconBlockBodyElectra {
                randao_reveal: Signature::empty(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: Graffiti::default(),
                proposer_slashings: VariableList::empty(),
                attester_slashings: VariableList::empty(),
                attestations: VariableList::empty(),
                deposits: VariableList::empty(),
                voluntary_exits: VariableList::empty(),
                sync_aggregate: SyncAggregate::empty(),
                execution_payload: Payload::Electra::default(),
                bls_to_execution_changes: VariableList::empty(),
                blob_kzg_commitments: VariableList::empty(),
                execution_requests: ExecutionRequestsElectra::default(),
            },
        }
    }
}

impl<Payload: AbstractExecPayload> EmptyBlock for BeaconBlockFulu<Payload> {
    /// Returns an empty Fulu block to be used during genesis.
    fn empty(spec: &ChainSpec) -> Self {
        BeaconBlockFulu {
            slot: spec
                .fulu_fork_epoch
                .expect("fulu enabled")
                .start_slot(Spec::slots_per_epoch()),
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: BeaconBlockBodyFulu {
                randao_reveal: Signature::empty(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: Graffiti::default(),
                proposer_slashings: VariableList::empty(),
                attester_slashings: VariableList::empty(),
                attestations: VariableList::empty(),
                deposits: VariableList::empty(),
                voluntary_exits: VariableList::empty(),
                sync_aggregate: SyncAggregate::empty(),
                execution_payload: Payload::Fulu::default(),
                bls_to_execution_changes: VariableList::empty(),
                blob_kzg_commitments: VariableList::empty(),
                execution_requests: ExecutionRequestsElectra::default(),
            },
        }
    }
}

impl<Payload: AbstractExecPayload> EmptyBlock for BeaconBlockGloas<Payload> {
    /// Returns an empty Gloas block to be used during genesis.
    fn empty(spec: &ChainSpec) -> Self {
        BeaconBlockGloas {
            slot: spec.genesis_slot,
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: BeaconBlockBodyGloas {
                randao_reveal: Signature::empty(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: Graffiti::default(),
                proposer_slashings: ProgressiveVariableList::empty(),
                attester_slashings: ProgressiveVariableList::empty(),
                attestations: ProgressiveVariableList::empty(),
                deposits: ProgressiveVariableList::empty(),
                voluntary_exits: ProgressiveVariableList::empty(),
                sync_aggregate: SyncAggregate::empty(),
                bls_to_execution_changes: ProgressiveVariableList::empty(),
                parent_execution_requests: ExecutionRequestsGloas::default(),
                signed_execution_payload_bid: SignedExecutionPayloadBid::empty(),
                payload_attestations: ProgressiveVariableList::empty(),
                _phantom: PhantomData,
            },
        }
    }
}

impl<Payload: AbstractExecPayload> EmptyBlock for BeaconBlockHeze<Payload> {
    /// Returns an empty Heze block to be used during genesis.
    fn empty(spec: &ChainSpec) -> Self {
        BeaconBlockHeze {
            slot: spec.genesis_slot,
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: BeaconBlockBodyHeze {
                randao_reveal: Signature::empty(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: Graffiti::default(),
                proposer_slashings: ProgressiveVariableList::empty(),
                attester_slashings: ProgressiveVariableList::empty(),
                attestations: ProgressiveVariableList::empty(),
                deposits: ProgressiveVariableList::empty(),
                voluntary_exits: ProgressiveVariableList::empty(),
                sync_aggregate: SyncAggregate::empty(),
                bls_to_execution_changes: ProgressiveVariableList::empty(),
                parent_execution_requests: ExecutionRequestsGloas::default(),
                signed_execution_payload_bid: SignedExecutionPayloadBid::empty(),
                payload_attestations: ProgressiveVariableList::empty(),
                _phantom: PhantomData,
            },
        }
    }
}

// TODO(EIP-7732) Mark's branch had the following implementation but not sure if it's needed so will just add header below for reference
// impl<Payload: AbstractExecPayload> BeaconBlockEIP7732<Payload> {

// TODO(EIP-7732) Look into whether we can remove this in the future since no blinded blocks post-gloas
impl From<BeaconBlockGloas<BlindedPayload>> for BeaconBlockGloas<FullPayload> {
    fn from(block: BeaconBlockGloas<BlindedPayload>) -> Self {
        let BeaconBlockGloas {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        } = block;

        BeaconBlockGloas {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body: body.into(),
        }
    }
}

// TODO(heze) Look into whether we can remove this in the future since no blinded blocks post-gloas
impl From<BeaconBlockHeze<BlindedPayload>> for BeaconBlockHeze<FullPayload> {
    fn from(block: BeaconBlockHeze<BlindedPayload>) -> Self {
        let BeaconBlockHeze {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        } = block;

        BeaconBlockHeze {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body: body.into(),
        }
    }
}

// We can convert pre-Bellatrix blocks without payloads into blocks "with" payloads.
impl From<BeaconBlockBase<BlindedPayload>> for BeaconBlockBase<FullPayload> {
    fn from(block: BeaconBlockBase<BlindedPayload>) -> Self {
        let BeaconBlockBase {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        } = block;

        BeaconBlockBase {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body: body.into(),
        }
    }
}

impl From<BeaconBlockAltair<BlindedPayload>> for BeaconBlockAltair<FullPayload> {
    fn from(block: BeaconBlockAltair<BlindedPayload>) -> Self {
        let BeaconBlockAltair {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        } = block;

        BeaconBlockAltair {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body: body.into(),
        }
    }
}

// We can convert blocks with payloads to blocks without payloads, and an optional payload.
macro_rules! impl_from {
    ($ty_name:ident, <$($from_params:ty),*>, <$($to_params:ty),*>, $body_expr:expr) => {
        impl From<$ty_name<$($from_params),*>>
            for ($ty_name<$($to_params),*>, Option<ExecutionPayload>)
        {
            #[allow(clippy::redundant_closure_call)]
            fn from(block: $ty_name<$($from_params),*>) -> Self {
                let $ty_name {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body,
                } = block;

                let (body, payload) = ($body_expr)(body);

                ($ty_name {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body,
                }, payload.map(Into::into))
            }
        }
    }
}

impl_from!(BeaconBlockBase, <FullPayload>, <BlindedPayload>, |body: BeaconBlockBodyBase<_>| body.into());
impl_from!(BeaconBlockAltair, <FullPayload>, <BlindedPayload>, |body: BeaconBlockBodyAltair<_>| body.into());
impl_from!(BeaconBlockBellatrix, <FullPayload>, <BlindedPayload>, |body: BeaconBlockBodyBellatrix<_>| body.into());
impl_from!(BeaconBlockCapella, <FullPayload>, <BlindedPayload>, |body: BeaconBlockBodyCapella<_>| body.into());
impl_from!(BeaconBlockDeneb, <FullPayload>, <BlindedPayload>, |body: BeaconBlockBodyDeneb<_>| body.into());
impl_from!(BeaconBlockElectra, <FullPayload>, <BlindedPayload>, |body: BeaconBlockBodyElectra<_>| body.into());
impl_from!(BeaconBlockFulu, <FullPayload>, <BlindedPayload>, |body: BeaconBlockBodyFulu<_>| body.into());
impl_from!(BeaconBlockGloas, <FullPayload>, <BlindedPayload>, |body: BeaconBlockBodyGloas<_>| body.into());
impl_from!(BeaconBlockHeze, <FullPayload>, <BlindedPayload>, |body: BeaconBlockBodyHeze<_>| body.into());

// We can clone blocks with payloads to blocks without payloads, without cloning the payload.
macro_rules! impl_clone_as_blinded {
    ($ty_name:ident, <$($from_params:ty),*>, <$($to_params:ty),*>) => {
        impl $ty_name<$($from_params),*>
        {
            pub fn clone_as_blinded(&self) -> $ty_name<$($to_params),*> {
                let $ty_name {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body,
                } = self;

                $ty_name {
                    slot: *slot,
                    proposer_index: *proposer_index,
                    parent_root: *parent_root,
                    state_root: *state_root,
                    body: body.clone_as_blinded(),
                }
            }
        }
    }
}

impl_clone_as_blinded!(BeaconBlockBase, <FullPayload>, <BlindedPayload>);
impl_clone_as_blinded!(BeaconBlockAltair, <FullPayload>, <BlindedPayload>);
impl_clone_as_blinded!(BeaconBlockBellatrix, <FullPayload>, <BlindedPayload>);
impl_clone_as_blinded!(BeaconBlockCapella, <FullPayload>, <BlindedPayload>);
impl_clone_as_blinded!(BeaconBlockDeneb, <FullPayload>, <BlindedPayload>);
impl_clone_as_blinded!(BeaconBlockElectra, <FullPayload>, <BlindedPayload>);
impl_clone_as_blinded!(BeaconBlockFulu, <FullPayload>, <BlindedPayload>);
impl_clone_as_blinded!(BeaconBlockGloas, <FullPayload>, <BlindedPayload>);
impl_clone_as_blinded!(BeaconBlockHeze, <FullPayload>, <BlindedPayload>);

// A reference to a full beacon block can be cloned into a blinded beacon block, without cloning the
// execution payload.
impl<'a> From<BeaconBlockRef<'a, FullPayload>> for BeaconBlock<BlindedPayload> {
    fn from(full_block: BeaconBlockRef<'a, FullPayload>) -> BeaconBlock<BlindedPayload> {
        map_beacon_block_ref_into_beacon_block!(&'a _, full_block, |inner, cons| {
            cons(inner.clone_as_blinded())
        })
    }
}

impl From<BeaconBlock<FullPayload>> for (BeaconBlock<BlindedPayload>, Option<ExecutionPayload>) {
    fn from(block: BeaconBlock<FullPayload>) -> Self {
        map_beacon_block!(block, |inner, cons| {
            let (block, payload): (_, Option<ExecutionPayload>) = inner.into();
            (cons(block), payload)
        })
    }
}

impl<'de, Payload: AbstractExecPayload> ContextDeserialize<'de, ForkName> for BeaconBlock<Payload> {
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

#[derive(Clone, Copy)]
pub enum BlockImportSource {
    Gossip,
    Lookup,
    RangeSync,
    HttpApi,
}

impl fmt::Display for BlockImportSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BlockImportSource::Gossip => write!(f, "gossip"),
            BlockImportSource::Lookup => write!(f, "lookup"),
            BlockImportSource::RangeSync => write!(f, "range_sync"),
            BlockImportSource::HttpApi => write!(f, "http_api"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_ssz_tree_hash_pair_with;
    use arbitrary::Arbitrary;
    use ssz::Encode;

    type BeaconBlock = super::BeaconBlock;
    type BeaconBlockBase = super::BeaconBlockBase;
    type BeaconBlockAltair = super::BeaconBlockAltair;

    #[test]
    fn roundtrip_base_block() {
        let mut u = crate::test_utils::test_unstructured();
        let spec = &ForkName::Base.make_genesis_spec(Spec::default_spec());

        let inner_block = BeaconBlockBase::arbitrary(&mut u).unwrap();
        let block = BeaconBlock::Base(inner_block.clone());

        test_ssz_tree_hash_pair_with(&block, &inner_block, |bytes| {
            BeaconBlock::from_ssz_bytes(bytes, spec)
        });
    }

    #[test]
    fn roundtrip_altair_block() {
        let mut u = crate::test_utils::test_unstructured();
        let spec = &ForkName::Altair.make_genesis_spec(Spec::default_spec());

        let inner_block = BeaconBlockAltair::arbitrary(&mut u).unwrap();
        let block = BeaconBlock::Altair(inner_block.clone());

        test_ssz_tree_hash_pair_with(&block, &inner_block, |bytes| {
            BeaconBlock::from_ssz_bytes(bytes, spec)
        });
    }

    #[test]
    fn roundtrip_capella_block() {
        let mut u = crate::test_utils::test_unstructured();
        let spec = &ForkName::Capella.make_genesis_spec(Spec::default_spec());

        let inner_block = BeaconBlockCapella::arbitrary(&mut u).unwrap();
        let block = BeaconBlock::Capella(inner_block.clone());

        test_ssz_tree_hash_pair_with(&block, &inner_block, |bytes| {
            BeaconBlock::from_ssz_bytes(bytes, spec)
        });
    }

    #[test]
    fn roundtrip_deneb_block() {
        let mut u = crate::test_utils::test_unstructured();
        let spec = &ForkName::Deneb.make_genesis_spec(Spec::default_spec());

        let inner_block = BeaconBlockDeneb::arbitrary(&mut u).unwrap();
        let block = BeaconBlock::Deneb(inner_block.clone());

        test_ssz_tree_hash_pair_with(&block, &inner_block, |bytes| {
            BeaconBlock::from_ssz_bytes(bytes, spec)
        });
    }

    #[test]
    fn roundtrip_electra_block() {
        let mut u = crate::test_utils::test_unstructured();
        let spec = &ForkName::Electra.make_genesis_spec(Spec::default_spec());

        let inner_block = BeaconBlockElectra::arbitrary(&mut u).unwrap();
        let block = BeaconBlock::Electra(inner_block.clone());

        test_ssz_tree_hash_pair_with(&block, &inner_block, |bytes| {
            BeaconBlock::from_ssz_bytes(bytes, spec)
        });
    }

    #[test]
    fn roundtrip_fulu_block() {
        let mut u = crate::test_utils::test_unstructured();
        let spec = &ForkName::Fulu.make_genesis_spec(Spec::default_spec());

        let inner_block = BeaconBlockFulu::arbitrary(&mut u).unwrap();
        let block = BeaconBlock::Fulu(inner_block.clone());

        test_ssz_tree_hash_pair_with(&block, &inner_block, |bytes| {
            BeaconBlock::from_ssz_bytes(bytes, spec)
        });
    }

    #[test]
    fn roundtrip_heze_block() {
        let mut u = crate::test_utils::test_unstructured();
        let spec = &ForkName::Heze.make_genesis_spec(Spec::default_spec());

        let inner_block = BeaconBlockHeze::arbitrary(&mut u).unwrap();
        let block = BeaconBlock::Heze(inner_block.clone());

        test_ssz_tree_hash_pair_with(&block, &inner_block, |bytes| {
            BeaconBlock::from_ssz_bytes(bytes, spec)
        });
    }

    #[test]
    fn roundtrip_gloas_block() {
        let mut u = crate::test_utils::test_unstructured();
        let spec = &ForkName::Gloas.make_genesis_spec(Spec::default_spec());

        let inner_block = BeaconBlockGloas::arbitrary(&mut u).unwrap();
        let block = BeaconBlock::Gloas(inner_block.clone());

        test_ssz_tree_hash_pair_with(&block, &inner_block, |bytes| {
            BeaconBlock::from_ssz_bytes(bytes, spec)
        });
    }

    #[test]
    fn decode_base_and_altair() {
        let mut spec = Spec::default_spec();
        spec.altair_fork_epoch = spec.altair_fork_epoch.or(Some(Epoch::new(1)));

        let mut u = crate::test_utils::test_unstructured();

        let altair_fork_epoch = spec.altair_fork_epoch.unwrap();

        let base_epoch = altair_fork_epoch.saturating_sub(1_u64);
        let base_slot = base_epoch.end_slot(Spec::slots_per_epoch());
        let altair_epoch = altair_fork_epoch;
        let altair_slot = altair_epoch.start_slot(Spec::slots_per_epoch());
        let capella_epoch = altair_fork_epoch + 1;
        let capella_slot = capella_epoch.start_slot(Spec::slots_per_epoch());
        let deneb_epoch = capella_epoch + 1;
        let deneb_slot = deneb_epoch.start_slot(Spec::slots_per_epoch());
        let electra_epoch = deneb_epoch + 1;
        let electra_slot = electra_epoch.start_slot(Spec::slots_per_epoch());
        let fulu_epoch = electra_epoch + 1;
        let fulu_slot = fulu_epoch.start_slot(Spec::slots_per_epoch());
        let gloas_epoch = fulu_epoch + 1;
        let gloas_slot = gloas_epoch.start_slot(Spec::slots_per_epoch());
        let heze_epoch = gloas_epoch + 1;
        let heze_slot = heze_epoch.start_slot(Spec::slots_per_epoch());

        spec.altair_fork_epoch = Some(altair_epoch);
        spec.capella_fork_epoch = Some(capella_epoch);
        spec.deneb_fork_epoch = Some(deneb_epoch);
        spec.electra_fork_epoch = Some(electra_epoch);
        spec.fulu_fork_epoch = Some(fulu_epoch);
        spec.gloas_fork_epoch = Some(gloas_epoch);
        spec.heze_fork_epoch = Some(heze_epoch);

        // BeaconBlockBase
        {
            let good_base_block = BeaconBlock::Base(BeaconBlockBase {
                slot: base_slot,
                ..<_>::arbitrary(&mut u).unwrap()
            });
            // It's invalid to have a base block with a slot higher than the fork epoch.
            let bad_base_block = {
                let mut bad = good_base_block.clone();
                *bad.slot_mut() = altair_slot;
                bad
            };

            assert_eq!(
                BeaconBlock::from_ssz_bytes(&good_base_block.as_ssz_bytes(), &spec)
                    .expect("good base block can be decoded"),
                good_base_block
            );
            BeaconBlock::from_ssz_bytes(&bad_base_block.as_ssz_bytes(), &spec)
                .expect_err("bad base block cannot be decoded");
        }

        // BeaconBlockAltair
        {
            let good_altair_block = BeaconBlock::Altair(BeaconBlockAltair {
                slot: altair_slot,
                ..<_>::arbitrary(&mut u).unwrap()
            });
            // It's invalid to have an Altair block with a epoch lower than the fork epoch.
            let bad_altair_block = {
                let mut bad = good_altair_block.clone();
                *bad.slot_mut() = base_slot;
                bad
            };

            assert_eq!(
                BeaconBlock::from_ssz_bytes(&good_altair_block.as_ssz_bytes(), &spec)
                    .expect("good altair block can be decoded"),
                good_altair_block
            );
            BeaconBlock::from_ssz_bytes(&bad_altair_block.as_ssz_bytes(), &spec)
                .expect_err("bad altair block cannot be decoded");
        }

        // BeaconBlockCapella
        {
            let good_block = BeaconBlock::Capella(BeaconBlockCapella {
                slot: capella_slot,
                ..<_>::arbitrary(&mut u).unwrap()
            });
            // It's invalid to have an Capella block with a epoch lower than the fork epoch.
            let bad_block = {
                let mut bad = good_block.clone();
                *bad.slot_mut() = altair_slot;
                bad
            };

            assert_eq!(
                BeaconBlock::from_ssz_bytes(&good_block.as_ssz_bytes(), &spec)
                    .expect("good capella block can be decoded"),
                good_block
            );
            BeaconBlock::from_ssz_bytes(&bad_block.as_ssz_bytes(), &spec)
                .expect_err("bad capella block cannot be decoded");
        }

        // BeaconBlockDeneb
        {
            let good_block = BeaconBlock::Deneb(BeaconBlockDeneb {
                slot: deneb_slot,
                ..<_>::arbitrary(&mut u).unwrap()
            });
            // It's invalid to have a Deneb block with a epoch lower than the fork epoch.
            let bad_block = {
                let mut bad = good_block.clone();
                *bad.slot_mut() = capella_slot;
                bad
            };

            assert_eq!(
                BeaconBlock::from_ssz_bytes(&good_block.as_ssz_bytes(), &spec)
                    .expect("good deneb block can be decoded"),
                good_block
            );
            BeaconBlock::from_ssz_bytes(&bad_block.as_ssz_bytes(), &spec)
                .expect_err("bad deneb block cannot be decoded");
        }

        // BeaconBlockElectra
        {
            let good_block = BeaconBlock::Electra(BeaconBlockElectra {
                slot: electra_slot,
                ..<_>::arbitrary(&mut u).unwrap()
            });
            // It's invalid to have an Electra block with a epoch lower than the fork epoch.
            let bad_block = {
                let mut bad = good_block.clone();
                *bad.slot_mut() = deneb_slot;
                bad
            };

            assert_eq!(
                BeaconBlock::from_ssz_bytes(&good_block.as_ssz_bytes(), &spec)
                    .expect("good electra block can be decoded"),
                good_block
            );
            BeaconBlock::from_ssz_bytes(&bad_block.as_ssz_bytes(), &spec)
                .expect_err("bad electra block cannot be decoded");
        }

        // BeaconBlockFulu
        {
            let good_block = BeaconBlock::Fulu(BeaconBlockFulu {
                slot: fulu_slot,
                ..<_>::arbitrary(&mut u).unwrap()
            });

            assert_eq!(
                BeaconBlock::from_ssz_bytes(&good_block.as_ssz_bytes(), &spec)
                    .expect("good fulu block can be decoded"),
                good_block
            );
        }

        // BeaconBlockGloas
        {
            let good_block = BeaconBlock::Gloas(BeaconBlockGloas {
                slot: gloas_slot,
                ..<_>::arbitrary(&mut u).unwrap()
            });
            // It's invalid to have a Fulu block with a epoch lower than the fork epoch.
            let _bad_block = {
                let mut bad = good_block.clone();
                *bad.slot_mut() = fulu_slot;
                bad
            };

            assert_eq!(
                BeaconBlock::from_ssz_bytes(&good_block.as_ssz_bytes(), &spec)
                    .expect("good gloas block can be decoded"),
                good_block
            );

            // TODO(gloas): Uncomment once Gloas has features since without features
            // and with a Fulu slot it decodes successfully to Fulu.
            //BeaconBlock::from_ssz_bytes(&bad_block.as_ssz_bytes(), &spec)
            //    .expect_err("bad gloas block cannot be decoded");
        }

        // BeaconBlockHeze
        {
            let good_block = BeaconBlock::Heze(BeaconBlockHeze {
                slot: heze_slot,
                ..<_>::arbitrary(&mut u).unwrap()
            });

            assert_eq!(
                BeaconBlock::from_ssz_bytes(&good_block.as_ssz_bytes(), &spec)
                    .expect("good heze block can be decoded"),
                good_block
            );
        }
    }
}

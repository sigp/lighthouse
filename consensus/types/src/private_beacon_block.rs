use crate::private_beacon_block_body::{
    PrivateBeaconBlockBodyAltair, PrivateBeaconBlockBodyBase, PrivateBeaconBlockBodyMerge,
    PrivateBeaconBlockBodyRef, PrivateBeaconBlockBodyRefMut,
};
use crate::signed_private_beacon_block::SignedPrivateBeaconBlock;
use crate::test_utils::TestRandom;
use crate::*;
use bls::Signature;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, DecodeError};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// A block of the `BeaconChain`.
#[superstruct(
    variants(Base, Altair, Merge),
    variant_attributes(
        derive(
            Debug,
            PartialEq,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            TestRandom
        ),
        serde(bound = "T: EthSpec", deny_unknown_fields),
        cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary)),
    ),
    ref_attributes(
        derive(Debug, PartialEq, TreeHash),
        tree_hash(enum_behaviour = "transparent")
    )
)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, TreeHash)]
#[serde(untagged)]
#[serde(bound = "T: EthSpec")]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct PrivateBeaconBlock<T: EthSpec> {
    #[superstruct(getter(copy))]
    pub slot: Slot,
    #[superstruct(getter(copy))]
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[superstruct(getter(copy))]
    pub parent_root: Hash256,
    #[superstruct(getter(copy))]
    pub state_root: Hash256,
    #[superstruct(only(Base), partial_getter(rename = "body_base"))]
    pub body: PrivateBeaconBlockBodyBase<T>,
    #[superstruct(only(Altair), partial_getter(rename = "body_altair"))]
    pub body: PrivateBeaconBlockBodyAltair<T>,
    #[superstruct(only(Merge), partial_getter(rename = "body_merge"))]
    pub body: PrivateBeaconBlockBodyMerge<T>,
}

impl<T: EthSpec> SignedRoot for PrivateBeaconBlock<T> {}
impl<'a, T: EthSpec> SignedRoot for PrivateBeaconBlockRef<'a, T> {}

impl<T: EthSpec> PrivateBeaconBlock<T> {
    /// Returns an empty block to be used during genesis.
    pub fn empty(spec: &ChainSpec) -> Self {
        if spec.merge_fork_epoch == Some(T::genesis_epoch()) {
            Self::Merge(PrivateBeaconBlockMerge::empty(spec))
        } else if spec.altair_fork_epoch == Some(T::genesis_epoch()) {
            Self::Altair(PrivateBeaconBlockAltair::empty(spec))
        } else {
            Self::Base(PrivateBeaconBlockBase::empty(spec))
        }
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
        let fork_at_slot = spec.fork_name_at_slot::<T>(slot);

        Ok(map_fork_name!(
            fork_at_slot,
            Self,
            <_>::from_ssz_bytes(bytes)?
        ))
    }

    /// Try decoding each beacon block variant in sequence.
    ///
    /// This is *not* recommended unless you really have no idea what variant the block should be.
    /// Usually it's better to prefer `from_ssz_bytes` which will decode the correct variant based
    /// on the fork slot.
    pub fn any_from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        PrivateBeaconBlockMerge::from_ssz_bytes(bytes)
            .map(PrivateBeaconBlock::Merge)
            .or_else(|_| {
                PrivateBeaconBlockAltair::from_ssz_bytes(bytes)
                    .map(PrivateBeaconBlock::Altair)
                    .or_else(|_| {
                        PrivateBeaconBlockBase::from_ssz_bytes(bytes).map(PrivateBeaconBlock::Base)
                    })
            })
    }

    /// Convenience accessor for the `body` as a `PrivateBeaconBlockBodyRef`.
    pub fn body(&self) -> PrivateBeaconBlockBodyRef<'_, T> {
        self.to_ref().body()
    }

    /// Convenience accessor for the `body` as a `PrivateBeaconBlockBodyRefMut`.
    pub fn body_mut(&mut self) -> PrivateBeaconBlockBodyRefMut<'_, T> {
        self.to_mut().body_mut()
    }

    /// Returns the epoch corresponding to `self.slot()`.
    pub fn epoch(&self) -> Epoch {
        self.slot().epoch(T::slots_per_epoch())
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

    /// Signs `self`, producing a `SignedPrivateBeaconBlock`.
    pub fn sign(
        self,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> SignedPrivateBeaconBlock<T> {
        let domain = spec.get_domain(
            self.epoch(),
            Domain::BeaconProposer,
            fork,
            genesis_validators_root,
        );
        let message = self.signing_root(domain);
        let signature = secret_key.sign(message);
        SignedPrivateBeaconBlock::from_block(self, signature)
    }
}

impl<'a, T: EthSpec> PrivateBeaconBlockRef<'a, T> {
    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        let fork_at_slot = spec.fork_name_at_slot::<T>(self.slot());
        let object_fork = match self {
            PrivateBeaconBlockRef::Base { .. } => ForkName::Base,
            PrivateBeaconBlockRef::Altair { .. } => ForkName::Altair,
            PrivateBeaconBlockRef::Merge { .. } => ForkName::Merge,
        };

        if fork_at_slot == object_fork {
            Ok(object_fork)
        } else {
            Err(InconsistentFork {
                fork_at_slot,
                object_fork,
            })
        }
    }

    /// Convenience accessor for the `body` as a `PrivateBeaconBlockBodyRef`.
    pub fn body(&self) -> PrivateBeaconBlockBodyRef<'a, T> {
        match self {
            PrivateBeaconBlockRef::Base(block) => PrivateBeaconBlockBodyRef::Base(&block.body),
            PrivateBeaconBlockRef::Altair(block) => PrivateBeaconBlockBodyRef::Altair(&block.body),
            PrivateBeaconBlockRef::Merge(block) => PrivateBeaconBlockBodyRef::Merge(&block.body),
        }
    }

    /// Return the tree hash root of the block's body.
    pub fn body_root(&self) -> Hash256 {
        match self {
            PrivateBeaconBlockRef::Base(block) => block.body.tree_hash_root(),
            PrivateBeaconBlockRef::Altair(block) => block.body.tree_hash_root(),
            PrivateBeaconBlockRef::Merge(block) => block.body.tree_hash_root(),
        }
    }

    /// Returns the epoch corresponding to `self.slot()`.
    pub fn epoch(&self) -> Epoch {
        self.slot().epoch(T::slots_per_epoch())
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
}

impl<'a, T: EthSpec> PrivateBeaconBlockRefMut<'a, T> {
    /// Convert a mutable reference to a beacon block to a mutable ref to its body.
    pub fn body_mut(self) -> PrivateBeaconBlockBodyRefMut<'a, T> {
        match self {
            PrivateBeaconBlockRefMut::Base(block) => {
                PrivateBeaconBlockBodyRefMut::Base(&mut block.body)
            }
            PrivateBeaconBlockRefMut::Altair(block) => {
                PrivateBeaconBlockBodyRefMut::Altair(&mut block.body)
            }
            PrivateBeaconBlockRefMut::Merge(block) => {
                PrivateBeaconBlockBodyRefMut::Merge(&mut block.body)
            }
        }
    }
}

impl<T: EthSpec> PrivateBeaconBlockBase<T> {
    /// Returns an empty block to be used during genesis.
    pub fn empty(spec: &ChainSpec) -> Self {
        PrivateBeaconBlockBase {
            slot: spec.genesis_slot,
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: PrivateBeaconBlockBodyBase {
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
            },
        }
    }

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
        let indexed_attestation: IndexedAttestation<T> = IndexedAttestation {
            attesting_indices: VariableList::new(vec![
                0_u64;
                T::MaxValidatorsPerCommittee::to_usize()
            ])
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

        let attester_slashing = AttesterSlashing {
            attestation_1: indexed_attestation.clone(),
            attestation_2: indexed_attestation,
        };

        let attestation: Attestation<T> = Attestation {
            aggregation_bits: BitList::with_capacity(T::MaxValidatorsPerCommittee::to_usize())
                .unwrap(),
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

        let mut block = PrivateBeaconBlockBase::<T>::empty(spec);
        for _ in 0..T::MaxProposerSlashings::to_usize() {
            block
                .body
                .proposer_slashings
                .push(proposer_slashing.clone())
                .unwrap();
        }
        for _ in 0..T::MaxDeposits::to_usize() {
            block.body.deposits.push(deposit.clone()).unwrap();
        }
        for _ in 0..T::MaxVoluntaryExits::to_usize() {
            block
                .body
                .voluntary_exits
                .push(signed_voluntary_exit.clone())
                .unwrap();
        }
        for _ in 0..T::MaxAttesterSlashings::to_usize() {
            block
                .body
                .attester_slashings
                .push(attester_slashing.clone())
                .unwrap();
        }

        for _ in 0..T::MaxAttestations::to_usize() {
            block.body.attestations.push(attestation.clone()).unwrap();
        }
        block
    }
}

impl<T: EthSpec> PrivateBeaconBlockAltair<T> {
    /// Returns an empty Altair block to be used during genesis.
    pub fn empty(spec: &ChainSpec) -> Self {
        PrivateBeaconBlockAltair {
            slot: spec.genesis_slot,
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: PrivateBeaconBlockBodyAltair {
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
            },
        }
    }

    /// Return an Altair block where the block has maximum size.
    pub fn full(spec: &ChainSpec) -> Self {
        let base_block = PrivateBeaconBlockBase::full(spec);
        let sync_aggregate = SyncAggregate {
            sync_committee_signature: AggregateSignature::empty(),
            sync_committee_bits: BitVector::default(),
        };
        PrivateBeaconBlockAltair {
            slot: spec.genesis_slot,
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: PrivateBeaconBlockBodyAltair {
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
            },
        }
    }
}

impl<T: EthSpec> PrivateBeaconBlockMerge<T> {
    /// Returns an empty Merge block to be used during genesis.
    pub fn empty(spec: &ChainSpec) -> Self {
        PrivateBeaconBlockMerge {
            slot: spec.genesis_slot,
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: PrivateBeaconBlockBodyMerge {
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
                execution_payload_header: ExecutionPayloadHeader::empty(),
            },
        }
    }

    /// Return an Merge block where the block has maximum size.
    pub fn full(spec: &ChainSpec) -> Self {
        let altair_block = PrivateBeaconBlockAltair::full(spec);
        PrivateBeaconBlockMerge {
            slot: spec.genesis_slot,
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: PrivateBeaconBlockBodyMerge {
                proposer_slashings: altair_block.body.proposer_slashings,
                attester_slashings: altair_block.body.attester_slashings,
                attestations: altair_block.body.attestations,
                deposits: altair_block.body.deposits,
                voluntary_exits: altair_block.body.voluntary_exits,
                sync_aggregate: altair_block.body.sync_aggregate,
                randao_reveal: Signature::empty(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: Graffiti::default(),
                execution_payload_header: ExecutionPayloadHeader::default(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{test_ssz_tree_hash_pair_with, SeedableRng, TestRandom, XorShiftRng};
    use crate::{ForkName, MainnetEthSpec};
    use ssz::Encode;

    type PrivateBeaconBlock = super::PrivateBeaconBlock<MainnetEthSpec>;
    type PrivateBeaconBlockBase = super::PrivateBeaconBlockBase<MainnetEthSpec>;
    type PrivateBeaconBlockAltair = super::PrivateBeaconBlockAltair<MainnetEthSpec>;

    #[test]
    fn roundtrip_base_block() {
        let rng = &mut XorShiftRng::from_seed([42; 16]);
        let spec = &ForkName::Base.make_genesis_spec(MainnetEthSpec::default_spec());

        let inner_block = PrivateBeaconBlockBase {
            slot: Slot::random_for_test(rng),
            proposer_index: u64::random_for_test(rng),
            parent_root: Hash256::random_for_test(rng),
            state_root: Hash256::random_for_test(rng),
            body: PrivateBeaconBlockBodyBase::random_for_test(rng),
        };
        let block = PrivateBeaconBlock::Base(inner_block.clone());

        test_ssz_tree_hash_pair_with(&block, &inner_block, |bytes| {
            PrivateBeaconBlock::from_ssz_bytes(bytes, spec)
        });
    }

    #[test]
    fn roundtrip_altair_block() {
        let rng = &mut XorShiftRng::from_seed([42; 16]);
        let spec = &ForkName::Altair.make_genesis_spec(MainnetEthSpec::default_spec());

        let inner_block = PrivateBeaconBlockAltair {
            slot: Slot::random_for_test(rng),
            proposer_index: u64::random_for_test(rng),
            parent_root: Hash256::random_for_test(rng),
            state_root: Hash256::random_for_test(rng),
            body: PrivateBeaconBlockBodyAltair::random_for_test(rng),
        };
        let block = PrivateBeaconBlock::Altair(inner_block.clone());

        test_ssz_tree_hash_pair_with(&block, &inner_block, |bytes| {
            PrivateBeaconBlock::from_ssz_bytes(bytes, spec)
        });
    }

    #[test]
    fn decode_base_and_altair() {
        type E = MainnetEthSpec;

        let rng = &mut XorShiftRng::from_seed([42; 16]);

        let fork_epoch = Epoch::from_ssz_bytes(&[7, 6, 5, 4, 3, 2, 1, 0]).unwrap();

        let base_epoch = fork_epoch.saturating_sub(1_u64);
        let base_slot = base_epoch.end_slot(E::slots_per_epoch());
        let altair_epoch = fork_epoch;
        let altair_slot = altair_epoch.start_slot(E::slots_per_epoch());

        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(fork_epoch);

        // PrivateBeaconBlockBase
        {
            let good_base_block = PrivateBeaconBlock::Base(PrivateBeaconBlockBase {
                slot: base_slot,
                ..<_>::random_for_test(rng)
            });
            // It's invalid to have a base block with a slot higher than the fork epoch.
            let bad_base_block = {
                let mut bad = good_base_block.clone();
                *bad.slot_mut() = altair_slot;
                bad
            };

            assert_eq!(
                PrivateBeaconBlock::from_ssz_bytes(&good_base_block.as_ssz_bytes(), &spec)
                    .expect("good base block can be decoded"),
                good_base_block
            );
            PrivateBeaconBlock::from_ssz_bytes(&bad_base_block.as_ssz_bytes(), &spec)
                .expect_err("bad base block cannot be decoded");
        }

        // PrivateBeaconBlockAltair
        {
            let good_altair_block = PrivateBeaconBlock::Altair(PrivateBeaconBlockAltair {
                slot: altair_slot,
                ..<_>::random_for_test(rng)
            });
            // It's invalid to have an Altair block with a epoch lower than the fork epoch.
            let bad_altair_block = {
                let mut bad = good_altair_block.clone();
                *bad.slot_mut() = base_slot;
                bad
            };

            assert_eq!(
                PrivateBeaconBlock::from_ssz_bytes(&good_altair_block.as_ssz_bytes(), &spec)
                    .expect("good altair block can be decoded"),
                good_altair_block
            );
            PrivateBeaconBlock::from_ssz_bytes(&bad_altair_block.as_ssz_bytes(), &spec)
                .expect_err("bad altair block cannot be decoded");
        }
    }
}

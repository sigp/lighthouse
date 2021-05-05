use crate::beacon_block_body::{
    BeaconBlockBodyAltair, BeaconBlockBodyBase, BeaconBlockBodyRef, BeaconBlockBodyRefMut,
};
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
    variants(Base, Altair),
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
        cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))
    ),
    ref_attributes(derive(Debug, PartialEq, TreeHash))
)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, TreeHash)]
#[serde(untagged)]
#[serde(bound = "T: EthSpec")]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
pub struct BeaconBlock<T: EthSpec> {
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
    pub body: BeaconBlockBodyBase<T>,
    #[superstruct(only(Altair), partial_getter(rename = "body_altair"))]
    pub body: BeaconBlockBodyAltair<T>,
}

impl<T: EthSpec> SignedRoot for BeaconBlock<T> {}
impl<'a, T: EthSpec> SignedRoot for BeaconBlockRef<'a, T> {}

impl<T: EthSpec> BeaconBlock<T> {
    /// Returns an empty block to be used during genesis.
    pub fn empty(spec: &ChainSpec) -> Self {
        if spec.altair_fork_slot == Some(spec.genesis_slot) {
            Self::Altair(BeaconBlockAltair::empty(spec))
        } else {
            Self::Base(BeaconBlockBase::empty(spec))
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

        if spec
            .altair_fork_slot
            .map_or(true, |altair_slot| slot < altair_slot)
        {
            BeaconBlockBase::from_ssz_bytes(bytes).map(Self::Base)
        } else {
            BeaconBlockAltair::from_ssz_bytes(bytes).map(Self::Altair)
        }
    }

    /// Convenience accessor for the `body` as a `BeaconBlockBodyRef`.
    pub fn body(&self) -> BeaconBlockBodyRef<'_, T> {
        self.to_ref().body()
    }

    /// Convenience accessor for the `body` as a `BeaconBlockBodyRefMut`.
    pub fn body_mut(&mut self) -> BeaconBlockBodyRefMut<'_, T> {
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

    /// Signs `self`, producing a `SignedBeaconBlock`.
    pub fn sign(
        self,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> SignedBeaconBlock<T> {
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

impl<'a, T: EthSpec> BeaconBlockRef<'a, T> {
    /// Convenience accessor for the `body` as a `BeaconBlockBodyRef`.
    pub fn body(&self) -> BeaconBlockBodyRef<'a, T> {
        match self {
            BeaconBlockRef::Base(block) => BeaconBlockBodyRef::Base(&block.body),
            BeaconBlockRef::Altair(block) => BeaconBlockBodyRef::Altair(&block.body),
        }
    }

    /// Return the tree hash root of the block's body.
    pub fn body_root(&self) -> Hash256 {
        match self {
            BeaconBlockRef::Base(block) => block.body.tree_hash_root(),
            BeaconBlockRef::Altair(block) => block.body.tree_hash_root(),
        }
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

impl<'a, T: EthSpec> BeaconBlockRefMut<'a, T> {
    /// Convert a mutable reference to a beacon block to a mutable ref to its body.
    pub fn body_mut(self) -> BeaconBlockBodyRefMut<'a, T> {
        match self {
            BeaconBlockRefMut::Base(block) => BeaconBlockBodyRefMut::Base(&mut block.body),
            BeaconBlockRefMut::Altair(block) => BeaconBlockBodyRefMut::Altair(&mut block.body),
        }
    }
}

impl<T: EthSpec> BeaconBlockBase<T> {
    /// Returns an empty block to be used during genesis.
    pub fn empty(spec: &ChainSpec) -> Self {
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

        let mut block = BeaconBlockBase::<T>::empty(spec);
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

impl<T: EthSpec> BeaconBlockAltair<T> {
    /// Returns an empty Altair block to be used during genesis.
    pub fn empty(spec: &ChainSpec) -> Self {
        BeaconBlockAltair {
            slot: spec.genesis_slot,
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
            },
        }
    }

    /// Return an Altair block where the block has maximum size.
    pub fn full(spec: &ChainSpec) -> Self {
        let base_block = BeaconBlockBase::full(spec);
        let sync_aggregate = SyncAggregate {
            sync_committee_signature: AggregateSignature::empty(),
            sync_committee_bits: BitVector::default(),
        };
        BeaconBlockAltair {
            slot: spec.genesis_slot,
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
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{test_ssz_tree_hash_pair_with, SeedableRng, TestRandom, XorShiftRng};
    use crate::{ForkName, MainnetEthSpec};

    type BeaconBlock = super::BeaconBlock<MainnetEthSpec>;
    type BeaconBlockBase = super::BeaconBlockBase<MainnetEthSpec>;
    type BeaconBlockAltair = super::BeaconBlockAltair<MainnetEthSpec>;

    #[test]
    fn roundtrip_base_block() {
        let rng = &mut XorShiftRng::from_seed([42; 16]);
        let spec = &ForkName::Base.make_genesis_spec(MainnetEthSpec::default_spec());

        let inner_block = BeaconBlockBase {
            slot: Slot::random_for_test(rng),
            proposer_index: u64::random_for_test(rng),
            parent_root: Hash256::random_for_test(rng),
            state_root: Hash256::random_for_test(rng),
            body: BeaconBlockBodyBase::random_for_test(rng),
        };
        let block = BeaconBlock::Base(inner_block.clone());

        test_ssz_tree_hash_pair_with(&block, &inner_block, |bytes| {
            BeaconBlock::from_ssz_bytes(bytes, spec)
        });
    }

    #[test]
    fn roundtrip_altair_block() {
        let rng = &mut XorShiftRng::from_seed([42; 16]);
        let spec = &ForkName::Altair.make_genesis_spec(MainnetEthSpec::default_spec());

        let inner_block = BeaconBlockAltair {
            slot: Slot::random_for_test(rng),
            proposer_index: u64::random_for_test(rng),
            parent_root: Hash256::random_for_test(rng),
            state_root: Hash256::random_for_test(rng),
            body: BeaconBlockBodyAltair::random_for_test(rng),
        };
        let block = BeaconBlock::Altair(inner_block.clone());

        test_ssz_tree_hash_pair_with(&block, &inner_block, |bytes| {
            BeaconBlock::from_ssz_bytes(bytes, spec)
        });
    }
}

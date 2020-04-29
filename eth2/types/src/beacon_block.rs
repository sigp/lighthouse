use crate::test_utils::TestRandom;
use crate::*;
use bls::Signature;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// A block of the `BeaconChain`.
///
/// Spec v0.11.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
#[serde(bound = "T: EthSpec")]
pub struct BeaconBlock<T: EthSpec> {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub body: BeaconBlockBody<T>,
}

impl<T: EthSpec> SignedRoot for BeaconBlock<T> {}

impl<T: EthSpec> BeaconBlock<T> {
    /// Returns an empty block to be used during genesis.
    ///
    /// Spec v0.11.1
    pub fn empty(spec: &ChainSpec) -> Self {
        BeaconBlock {
            slot: spec.genesis_slot,
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: BeaconBlockBody {
                randao_reveal: Signature::empty_signature(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: [0; 32],
                proposer_slashings: VariableList::empty(),
                attester_slashings: VariableList::empty(),
                attestations: VariableList::empty(),
                deposits: VariableList::empty(),
                voluntary_exits: VariableList::empty(),
            },
        }
    }

    /// Return a block where the block has the max possible operations.
    pub fn full(spec: &ChainSpec) -> BeaconBlock<T> {
        let header = BeaconBlockHeader {
            slot: Slot::new(1),
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body_root: Hash256::zero(),
        };

        let signed_header = SignedBeaconBlockHeader {
            message: header,
            signature: Signature::empty_signature(),
        };
        let indexed_attestation: IndexedAttestation<T> = IndexedAttestation {
            attesting_indices: VariableList::new(vec![
                0 as u64;
                T::MaxValidatorsPerCommittee::to_usize()
            ])
            .unwrap(),
            data: AttestationData::default(),
            signature: AggregateSignature::new(),
        };

        let deposit_data = DepositData {
            pubkey: PublicKeyBytes::empty(),
            withdrawal_credentials: Hash256::zero(),
            amount: 0,
            signature: SignatureBytes::empty(),
        };
        let proposer_slashing = ProposerSlashing {
            signed_header_1: signed_header.clone(),
            signed_header_2: signed_header.clone(),
        };

        let attester_slashing = AttesterSlashing {
            attestation_1: indexed_attestation.clone(),
            attestation_2: indexed_attestation.clone(),
        };

        let attestation: Attestation<T> = Attestation {
            aggregation_bits: BitList::with_capacity(T::MaxValidatorsPerCommittee::to_usize())
                .unwrap(),
            data: AttestationData::default(),
            signature: AggregateSignature::new(),
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
            signature: Signature::empty_signature(),
        };

        let mut block: BeaconBlock<T> = BeaconBlock::empty(spec);
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

    /// Returns the epoch corresponding to `self.slot`.
    pub fn epoch(&self) -> Epoch {
        self.slot.epoch(T::slots_per_epoch())
    }

    /// Returns the `tree_hash_root` of the block.
    ///
    /// Spec v0.11.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.tree_hash_root()[..])
    }

    /// Returns a full `BeaconBlockHeader` of this block.
    ///
    /// Note: This method is used instead of an `Into` impl to avoid a `Clone` of an entire block
    /// when you want to have the block _and_ the header.
    ///
    /// Note: performs a full tree-hash of `self.body`.
    ///
    /// Spec v0.11.1
    pub fn block_header(&self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body_root: Hash256::from_slice(&self.body.tree_hash_root()[..]),
        }
    }

    /// Returns a "temporary" header, where the `state_root` is `Hash256::zero()`.
    ///
    /// Spec v0.11.1
    pub fn temporary_block_header(&self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            state_root: Hash256::zero(),
            ..self.block_header()
        }
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
        let signature = Signature::new(message.as_bytes(), secret_key);
        SignedBeaconBlock {
            message: self,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BeaconBlock<MainnetEthSpec>);
}

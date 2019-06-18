use crate::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use lmd_ghost::LmdGhost;
use slot_clock::SlotClock;
use slot_clock::TestingSlotClock;
use std::marker::PhantomData;
use std::sync::Arc;
use store::MemoryStore;
use tree_hash::{SignedRoot, TreeHash};
use types::{
    test_utils::TestingBeaconStateBuilder, AggregateSignature, Attestation,
    AttestationDataAndCustodyBit, BeaconBlock, Bitfield, ChainSpec, Domain, EthSpec, Hash256,
    Keypair, SecretKey, Signature,
};

pub struct CommonTypes<L, E>
where
    L: LmdGhost<MemoryStore, E>,
    E: EthSpec,
{
    _phantom_l: PhantomData<L>,
    _phantom_e: PhantomData<E>,
}

impl<L, E> BeaconChainTypes for CommonTypes<L, E>
where
    L: LmdGhost<MemoryStore, E>,
    E: EthSpec,
{
    type Store = MemoryStore;
    type SlotClock = TestingSlotClock;
    type LmdGhost = L;
    type EthSpec = E;
}

pub struct BeaconChainHarness<L, E>
where
    L: LmdGhost<MemoryStore, E>,
    E: EthSpec,
{
    chain: BeaconChain<CommonTypes<L, E>>,
    keypairs: Vec<Keypair>,
    spec: ChainSpec,
}

impl<L, E> BeaconChainHarness<L, E>
where
    L: LmdGhost<MemoryStore, E>,
    E: EthSpec,
{
    pub fn new(validator_count: usize) -> Self {
        let spec = E::default_spec();

        let store = Arc::new(MemoryStore::open());

        let state_builder =
            TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(validator_count, &spec);
        let (genesis_state, keypairs) = state_builder.build();

        let mut genesis_block = BeaconBlock::empty(&spec);
        genesis_block.state_root = Hash256::from_slice(&genesis_state.tree_hash_root());

        // Slot clock
        let slot_clock = TestingSlotClock::new(
            spec.genesis_slot,
            genesis_state.genesis_time,
            spec.seconds_per_slot,
        );

        let chain = BeaconChain::from_genesis(
            store,
            slot_clock,
            genesis_state,
            genesis_block,
            spec.clone(),
        )
        .expect("Terminate if beacon chain generation fails");

        Self {
            chain,
            keypairs,
            spec,
        }
    }

    pub fn extend_canonical_chain(&self) {
        self.chain.slot_clock.advance_slot();
        self.chain.catchup_state().expect("should catchup state");

        let block = self.build_block();
        let outcome = self
            .chain
            .process_block(block)
            .expect("should process block");
        assert_eq!(outcome, BlockProcessingOutcome::Processed);

        self.add_attestations_to_op_pool();
    }

    fn build_block(&self) -> BeaconBlock {
        let slot = self.chain.read_slot_clock().unwrap();

        let sk = {
            let proposer = self
                .chain
                .block_proposer(slot)
                .expect("should get block propoer");
            &self.keypairs[proposer].sk
        };

        let fork = &self.chain.head().beacon_state.fork;

        let randao_reveal = {
            let epoch = slot.epoch(E::slots_per_epoch());
            let message = epoch.tree_hash_root();
            let domain = self.spec.get_domain(epoch, Domain::Randao, fork);
            Signature::new(&message, domain, sk)
        };

        let (mut block, _state) = self
            .chain
            .produce_block(randao_reveal)
            .expect("should producer block");

        block.signature = {
            let message = block.signed_root();
            let epoch = block.slot.epoch(E::slots_per_epoch());
            let domain = self.spec.get_domain(epoch, Domain::BeaconProposer, fork);
            Signature::new(&message, domain, sk)
        };

        block
    }

    fn add_attestations_to_op_pool(&self) {
        let state = &self.chain.current_state();
        let spec = &self.spec;
        let fork = &state.fork;

        state
            .get_crosslink_committees_at_slot(state.slot)
            .expect("should get committees")
            .iter()
            .for_each(|cc| {
                let committee_size = cc.committee.len();

                for (i, validator_index) in cc.committee.iter().enumerate() {
                    let data = self
                        .chain
                        .produce_attestation_data(cc.shard)
                        .expect("should produce attestation data");

                    let mut aggregation_bitfield = Bitfield::new();
                    aggregation_bitfield.set(i, true);
                    aggregation_bitfield.set(committee_size, false);

                    let mut custody_bitfield = Bitfield::new();
                    custody_bitfield.set(committee_size, false);

                    let signature = {
                        let message = AttestationDataAndCustodyBit {
                            data: data.clone(),
                            custody_bit: false,
                        }
                        .tree_hash_root();

                        let domain = spec.get_domain(data.target_epoch, Domain::Attestation, fork);

                        let mut agg_sig = AggregateSignature::new();
                        agg_sig.add(&Signature::new(
                            &message,
                            domain,
                            self.get_sk(*validator_index),
                        ));

                        agg_sig
                    };

                    let attestation = Attestation {
                        aggregation_bitfield,
                        data,
                        custody_bitfield,
                        signature,
                    };

                    self.chain
                        .process_attestation(attestation)
                        .expect("should process attestation");
                }
            });
    }

    fn get_sk(&self, validator_index: usize) -> &SecretKey {
        &self.keypairs[validator_index].sk
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))]
mod test {
    use super::*;
    use lmd_ghost::ThreadSafeReducedTree;
    use types::MinimalEthSpec;

    pub const VALIDATOR_COUNT: usize = 16;

    #[test]
    fn build_two_epochs_on_genesis() {
        let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

        let harness: BeaconChainHarness<
            ThreadSafeReducedTree<MemoryStore, MinimalEthSpec>,
            MinimalEthSpec,
        > = BeaconChainHarness::new(VALIDATOR_COUNT);

        for _ in 0..num_blocks_produced {
            harness.extend_canonical_chain();
        }

        let state = &harness.chain.head().beacon_state;

        assert_eq!(
            state.slot, num_blocks_produced,
            "head should be at the current slot"
        );
        assert_eq!(
            state.current_epoch(),
            num_blocks_produced / MinimalEthSpec::slots_per_epoch(),
            "head should be at the expected epoch"
        );
        assert_eq!(
            state.current_justified_epoch,
            state.current_epoch() - 1,
            "the head should be justified one behind the current epoch"
        );
        assert_eq!(
            state.finalized_epoch,
            state.current_epoch() - 1,
            "the head should be finalized one behind the current epoch"
        );
    }
}

#![cfg(not(feature = "fake_crypto"))]

use state_processing::{
    per_block_processing, test_utils::BlockBuilder, BlockProcessingError, BlockSignatureStrategy,
};
use types::{
    AggregateSignature, BeaconBlock, BeaconState, ChainSpec, EthSpec, Keypair, MinimalEthSpec,
    Signature, Slot,
};

const VALIDATOR_COUNT: usize = 64;

fn get_block<T, F>(mut mutate_builder: F) -> (BeaconBlock<T>, BeaconState<T>)
where
    T: EthSpec,
    F: FnMut(&mut BlockBuilder<T>),
{
    let spec = T::default_spec();
    let mut builder: BlockBuilder<T> = BlockBuilder::new(VALIDATOR_COUNT, &spec);
    builder.set_slot(Slot::from(T::slots_per_epoch() * 3 - 2));
    builder.build_caches(&spec);
    mutate_builder(&mut builder);
    builder.build(&spec)
}

fn test_scenario<T: EthSpec, F, G>(mutate_builder: F, mut invalidate_block: G, spec: &ChainSpec)
where
    T: EthSpec,
    F: FnMut(&mut BlockBuilder<T>),
    G: FnMut(&mut BeaconBlock<T>),
{
    let (mut block, state) = get_block::<T, _>(mutate_builder);

    /*
     * Control check to ensure the valid block should pass verification.
     */

    assert_eq!(
        per_block_processing(
            &mut state.clone(),
            &block,
            None,
            BlockSignatureStrategy::VerifyIndividual,
            spec
        ),
        Ok(()),
        "valid block should pass with verify individual"
    );

    assert_eq!(
        per_block_processing(
            &mut state.clone(),
            &block,
            None,
            BlockSignatureStrategy::VerifyBulk,
            spec
        ),
        Ok(()),
        "valid block should pass with verify bulk"
    );

    invalidate_block(&mut block);

    /*
     * Check to ensure the invalid block fails.
     */

    assert!(
        per_block_processing(
            &mut state.clone(),
            &block,
            None,
            BlockSignatureStrategy::VerifyIndividual,
            spec
        )
        .is_err(),
        "invalid block should fail with verify individual"
    );

    assert_eq!(
        per_block_processing(
            &mut state.clone(),
            &block,
            None,
            BlockSignatureStrategy::VerifyBulk,
            spec
        ),
        Err(BlockProcessingError::BulkSignatureVerificationFailed),
        "invalid block should fail with verify bulk"
    );
}

// TODO: use lazy static
fn agg_sig() -> AggregateSignature {
    let mut agg_sig = AggregateSignature::new();
    agg_sig.add(&sig());
    agg_sig
}

// TODO: use lazy static
fn sig() -> Signature {
    let keypair = Keypair::random();
    Signature::new(&[42, 42], 12, &keypair.sk)
}

type TestEthSpec = MinimalEthSpec;

mod signatures_minimal {
    use super::*;

    #[test]
    fn block_proposal() {
        let spec = &TestEthSpec::default_spec();

        test_scenario::<TestEthSpec, _, _>(|_| {}, |block| block.signature = sig(), spec);
    }

    #[test]
    fn randao() {
        let spec = &TestEthSpec::default_spec();

        test_scenario::<TestEthSpec, _, _>(|_| {}, |block| block.body.randao_reveal = sig(), spec);
    }

    #[test]
    fn proposer_slashing() {
        let spec = &TestEthSpec::default_spec();

        test_scenario::<TestEthSpec, _, _>(
            |mut builder| {
                builder.num_proposer_slashings = 1;
            },
            |block| block.body.proposer_slashings[0].header_1.signature = sig(),
            spec,
        );
        test_scenario::<TestEthSpec, _, _>(
            |mut builder| {
                builder.num_proposer_slashings = 1;
            },
            |block| block.body.proposer_slashings[0].header_2.signature = sig(),
            spec,
        );
    }

    #[test]
    fn attester_slashing() {
        let spec = &TestEthSpec::default_spec();

        test_scenario::<TestEthSpec, _, _>(
            |mut builder| {
                builder.num_attester_slashings = 1;
            },
            |block| block.body.attester_slashings[0].attestation_1.signature = agg_sig(),
            spec,
        );
        test_scenario::<TestEthSpec, _, _>(
            |mut builder| {
                builder.num_attester_slashings = 1;
            },
            |block| block.body.attester_slashings[0].attestation_2.signature = agg_sig(),
            spec,
        );
    }

    #[test]
    fn attestation() {
        let spec = &TestEthSpec::default_spec();

        test_scenario::<TestEthSpec, _, _>(
            |mut builder| {
                builder.num_attestations = 1;
            },
            |block| block.body.attestations[0].signature = agg_sig(),
            spec,
        );
    }

    #[test]
    // TODO: fix fail by making valid merkle proofs.
    #[should_panic]
    fn deposit() {
        let spec = &TestEthSpec::default_spec();

        test_scenario::<TestEthSpec, _, _>(
            |mut builder| {
                builder.num_deposits = 1;
            },
            |block| block.body.deposits[0].data.signature = sig().into(),
            spec,
        );
    }

    #[test]
    fn exit() {
        let mut spec = &mut TestEthSpec::default_spec();

        // Allows the test to pass.
        spec.persistent_committee_period = 0;

        test_scenario::<TestEthSpec, _, _>(
            |mut builder| {
                builder.num_exits = 1;
            },
            |block| block.body.voluntary_exits[0].signature = sig(),
            spec,
        );
    }

    // Cannot test transfers because their length is zero.
}

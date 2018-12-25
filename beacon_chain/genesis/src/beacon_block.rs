use bls::Signature;
use spec::ChainSpec;
use types::{BeaconBlock, BeaconBlockBody};

/// Generate a genesis BeaconBlock.
pub fn genesis_beacon_block(spec: &ChainSpec) -> BeaconBlock {
    BeaconBlock {
        slot: spec.initial_slot_number,
        parent_root: spec.zero_hash,
        state_root: spec.zero_hash,
        randao_reveal: spec.zero_hash,
        candidate_pow_receipt_root: spec.zero_hash,
        signature: Signature::default(),
        body: BeaconBlockBody {
            proposer_slashings: vec![],
            casper_slashings: vec![],
            attestations: vec![],
            deposits: vec![],
            exits: vec![],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: enhance these tests.
    // https://github.com/sigp/lighthouse/issues/117

    #[test]
    fn test_genesis() {
        let spec = ChainSpec::foundation();

        // This only checks that the function runs without panic.
        genesis_beacon_block(&spec);
    }
}

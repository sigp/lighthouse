use spec::ChainSpec;
use types::{BeaconBlock, BeaconBlockBody, Eth1Data, Hash256};

/// Generate a genesis BeaconBlock.
pub fn genesis_beacon_block(state_root: Hash256, spec: &ChainSpec) -> BeaconBlock {
    BeaconBlock {
        slot: spec.genesis_slot_number,
        parent_root: spec.zero_hash,
        state_root,
        randao_reveal: spec.zero_hash,
        eth1_data: Eth1Data {
            deposit_root: Hash256::zero(),
            block_hash: Hash256::zero(),
        },
        signature: spec.empty_signature.clone(),
        body: BeaconBlockBody {
            proposer_slashings: vec![],
            casper_slashings: vec![],
            attestations: vec![],
            custody_reseeds: vec![],
            custody_challenges: vec![],
            custody_responses: vec![],
            deposits: vec![],
            exits: vec![],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::Signature;

    #[test]
    fn test_genesis() {
        let spec = ChainSpec::foundation();
        let state_root = Hash256::from("cats".as_bytes());

        // This only checks that the function runs without panic.
        genesis_beacon_block(state_root, &spec);
    }

    #[test]
    fn test_zero_items() {
        let spec = ChainSpec::foundation();

        let state_root = Hash256::zero();

        let genesis_block = genesis_beacon_block(state_root, &spec);

        assert!(genesis_block.slot == 0);
        assert!(genesis_block.parent_root.is_zero());
        assert!(genesis_block.randao_reveal.is_zero());
        assert!(genesis_block.eth1_data.deposit_root.is_zero());
        assert!(genesis_block.eth1_data.block_hash.is_zero());
    }

    #[test]
    fn test_beacon_body() {
        let spec = ChainSpec::foundation();

        let state_root = Hash256::zero();

        let genesis_block = genesis_beacon_block(state_root, &spec);

        // Custody items are not being implemented until phase 1 so tests to be added later

        assert!(genesis_block.body.proposer_slashings.is_empty());
        assert!(genesis_block.body.casper_slashings.is_empty());
        assert!(genesis_block.body.attestations.is_empty());
        assert!(genesis_block.body.deposits.is_empty());
        assert!(genesis_block.body.exits.is_empty());
    }

    #[test]
    fn test_signature() {
        let spec = ChainSpec::foundation();

        let state_root = Hash256::zero();

        let genesis_block = genesis_beacon_block(state_root, &spec);

        // Signature should consist of [bytes48(0), bytes48(0)]
        // Note this is implemented using Apache Milagro BLS which requires one extra byte -> 97bytes
        let raw_sig = genesis_block.signature.as_raw();
        let raw_sig_bytes = raw_sig.as_bytes();

        for item in raw_sig_bytes.iter() {
            assert!(*item == 0);
        }
        assert_eq!(genesis_block.signature, Signature::empty_signature());
    }
}

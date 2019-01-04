use bls::{Signature, BLS_AGG_SIG_BYTE_SIZE};
use spec::ChainSpec;
use ssz::{encode::encode_length, Decodable, LENGTH_BYTES};
use types::{BeaconBlock, BeaconBlockBody, Hash256};

/// Generate a genesis BeaconBlock.
pub fn genesis_beacon_block(state_root: Hash256, spec: &ChainSpec) -> BeaconBlock {
    BeaconBlock {
        slot: spec.initial_slot_number,
        parent_root: spec.zero_hash,
        state_root,
        randao_reveal: spec.zero_hash,
        candidate_pow_receipt_root: spec.zero_hash,
        signature: genesis_signature(),
        body: BeaconBlockBody {
            proposer_slashings: vec![],
            casper_slashings: vec![],
            attestations: vec![],
            deposits: vec![],
            exits: vec![],
        },
    }
}

fn genesis_signature() -> Signature {
    let mut bytes = encode_length(BLS_AGG_SIG_BYTE_SIZE, LENGTH_BYTES);
    bytes.append(&mut vec![0; BLS_AGG_SIG_BYTE_SIZE]);
    let (signature, _) = match Signature::ssz_decode(&bytes, 0) {
        Ok(sig) => sig,
        Err(_) => unreachable!(),
    };
    signature
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: enhance these tests.
    // https://github.com/sigp/lighthouse/issues/117

    #[test]
    fn test_genesis() {
        let spec = ChainSpec::foundation();
        let state_root = Hash256::from("cats".as_bytes());

        // This only checks that the function runs without panic.
        genesis_beacon_block(state_root, &spec);
    }
}

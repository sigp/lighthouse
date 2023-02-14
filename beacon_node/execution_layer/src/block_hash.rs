use crate::{
    keccak::{keccak256, KeccakHasher},
    metrics, Error, ExecutionLayer,
};
use ethers_core::utils::rlp::RlpStream;
use keccak_hash::KECCAK_EMPTY_LIST_RLP;
use triehash::ordered_trie_root;
use types::{
    map_execution_block_header_fields, Address, EthSpec, ExecutionBlockHash, ExecutionBlockHeader,
    ExecutionPayload, Hash256, Hash64, Uint256,
};

impl<T: EthSpec> ExecutionLayer<T> {
    /// Verify `payload.block_hash` locally within Lighthouse.
    ///
    /// No remote calls to the execution client will be made, so this is quite a cheap check.
    pub fn verify_payload_block_hash(&self, payload: &ExecutionPayload<T>) -> Result<(), Error> {
        let _timer = metrics::start_timer(&metrics::EXECUTION_LAYER_VERIFY_BLOCK_HASH);

        // Calculate the transactions root.
        // We're currently using a deprecated Parity library for this. We should move to a
        // better alternative when one appears, possibly following Reth.
        let rlp_transactions_root = ordered_trie_root::<KeccakHasher, _>(
            payload.transactions.iter().map(|txn_bytes| &**txn_bytes),
        );

        // Construct the block header.
        let exec_block_header = ExecutionBlockHeader::from_payload(
            payload,
            KECCAK_EMPTY_LIST_RLP.as_fixed_bytes().into(),
            rlp_transactions_root,
        );

        // Hash the RLP encoding of the block header.
        let rlp_block_header = rlp_encode_block_header(&exec_block_header);
        let header_hash = ExecutionBlockHash::from_root(keccak256(&rlp_block_header));

        if header_hash != payload.block_hash {
            return Err(Error::BlockHashMismatch {
                computed: header_hash,
                payload: payload.block_hash,
                transactions_root: rlp_transactions_root,
            });
        }

        Ok(())
    }
}

/// RLP encode an execution block header.
pub fn rlp_encode_block_header(header: &ExecutionBlockHeader) -> Vec<u8> {
    let mut rlp_header_stream = RlpStream::new();
    rlp_header_stream.begin_unbounded_list();
    map_execution_block_header_fields!(&header, |_, field| {
        rlp_header_stream.append(field);
    });
    rlp_header_stream.finalize_unbounded_list();
    rlp_header_stream.out().into()
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::FromHex;
    use std::str::FromStr;

    fn test_rlp_encoding(
        header: &ExecutionBlockHeader,
        expected_rlp: Option<&str>,
        expected_hash: Hash256,
    ) {
        let rlp_encoding = rlp_encode_block_header(header);

        if let Some(expected_rlp) = expected_rlp {
            let computed_rlp = hex::encode(&rlp_encoding);
            assert_eq!(expected_rlp, computed_rlp);
        }

        let computed_hash = keccak256(&rlp_encoding);
        assert_eq!(expected_hash, computed_hash);
    }

    #[test]
    fn test_rlp_encode_eip1559_block() {
        let header = ExecutionBlockHeader {
            parent_hash: Hash256::from_str("e0a94a7a3c9617401586b1a27025d2d9671332d22d540e0af72b069170380f2a").unwrap(),
            ommers_hash: Hash256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap(),
            beneficiary: Address::from_str("ba5e000000000000000000000000000000000000").unwrap(),
            state_root: Hash256::from_str("ec3c94b18b8a1cff7d60f8d258ec723312932928626b4c9355eb4ab3568ec7f7").unwrap(),
            transactions_root: Hash256::from_str("50f738580ed699f0469702c7ccc63ed2e51bc034be9479b7bff4e68dee84accf").unwrap(),
            receipts_root: Hash256::from_str("29b0562f7140574dd0d50dee8a271b22e1a0a7b78fca58f7c60370d8317ba2a9").unwrap(),
            logs_bloom: <[u8; 256]>::from_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().into(),
            difficulty: 0x020000.into(),
            number: 0x01_u64.into(),
            gas_limit: 0x016345785d8a0000_u64.into(),
            gas_used: 0x015534_u64.into(),
            timestamp: 0x079e,
            extra_data: vec![0x42],
            mix_hash: Hash256::from_str("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            nonce: Hash64::zero(),
            base_fee_per_gas: 0x036b_u64.into(),
        };
        let expected_rlp = "f90200a0e0a94a7a3c9617401586b1a27025d2d9671332d22d540e0af72b069170380f2aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ba5e000000000000000000000000000000000000a0ec3c94b18b8a1cff7d60f8d258ec723312932928626b4c9355eb4ab3568ec7f7a050f738580ed699f0469702c7ccc63ed2e51bc034be9479b7bff4e68dee84accfa029b0562f7140574dd0d50dee8a271b22e1a0a7b78fca58f7c60370d8317ba2a9b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000830200000188016345785d8a00008301553482079e42a0000000000000000000000000000000000000000000000000000000000000000088000000000000000082036b";
        let expected_hash =
            Hash256::from_str("6a251c7c3c5dca7b42407a3752ff48f3bbca1fab7f9868371d9918daf1988d1f")
                .unwrap();
        test_rlp_encoding(&header, Some(expected_rlp), expected_hash);
    }

    #[test]
    fn test_rlp_encode_merge_block() {
        let header = ExecutionBlockHeader {
            parent_hash: Hash256::from_str("927ca537f06c783a3a2635b8805eef1c8c2124f7444ad4a3389898dd832f2dbe").unwrap(),
            ommers_hash: Hash256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap(),
            beneficiary: Address::from_str("ba5e000000000000000000000000000000000000").unwrap(),
            state_root: Hash256::from_str("0xe97859b065bd8dbbb4519c7cb935024de2484c2b7f881181b4360492f0b06b82").unwrap(),
            transactions_root: Hash256::from_str("50f738580ed699f0469702c7ccc63ed2e51bc034be9479b7bff4e68dee84accf").unwrap(),
            receipts_root: Hash256::from_str("29b0562f7140574dd0d50dee8a271b22e1a0a7b78fca58f7c60370d8317ba2a9").unwrap(),
            logs_bloom: <[u8; 256]>::from_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().into(),
            difficulty: 0x00.into(),
            number: 0x01_u64.into(),
            gas_limit: 0x016345785d8a0000_u64.into(),
            gas_used: 0x015534_u64.into(),
            timestamp: 0x079e,
            extra_data: vec![0x42],
            mix_hash: Hash256::from_str("0000000000000000000000000000000000000000000000000000000000020000").unwrap(),
            nonce: Hash64::zero(),
            base_fee_per_gas: 0x036b_u64.into(),
        };
        let expected_rlp = "f901fda0927ca537f06c783a3a2635b8805eef1c8c2124f7444ad4a3389898dd832f2dbea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ba5e000000000000000000000000000000000000a0e97859b065bd8dbbb4519c7cb935024de2484c2b7f881181b4360492f0b06b82a050f738580ed699f0469702c7ccc63ed2e51bc034be9479b7bff4e68dee84accfa029b0562f7140574dd0d50dee8a271b22e1a0a7b78fca58f7c60370d8317ba2a9b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800188016345785d8a00008301553482079e42a0000000000000000000000000000000000000000000000000000000000002000088000000000000000082036b";
        let expected_hash =
            Hash256::from_str("0x5b1f0f2efdaa19e996b4aea59eeb67620259f09732732a339a10dac311333684")
                .unwrap();
        test_rlp_encoding(&header, Some(expected_rlp), expected_hash);
    }

    // Test a real payload from mainnet.
    #[test]
    fn test_rlp_encode_block_16182891() {
        let header = ExecutionBlockHeader {
            parent_hash: Hash256::from_str("3e9c7b3f403947f110f68c4564a004b73dd8ebf73b143e46cc637926eec01a6d").unwrap(),
            ommers_hash: Hash256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap(),
            beneficiary: Address::from_str("dafea492d9c6733ae3d56b7ed1adb60692c98bc5").unwrap(),
            state_root: Hash256::from_str("5a8183d230818a167477420ce3a393ca3ef8706a7d596694ab6059894ed6fda9").unwrap(),
            transactions_root: Hash256::from_str("0223f0cb35f184d2ac409e89dc0768ad738f777bd1c85d3302ca50f307180c94").unwrap(),
            receipts_root: Hash256::from_str("371c76821b1cc21232574604eac5349d51647eb530e2a45d4f6fe2c501351aa5").unwrap(),
            logs_bloom: <[u8; 256]>::from_hex("1a2c559955848d2662a0634cb40c7a6192a1524f11061203689bcbcdec901b054084d4f4d688009d24c10918e0089b48e72fe2d7abafb903889d10c3827c6901096612d259801b1b7ba1663a4201f5f88f416a9997c55bcc2c54785280143b057a008764c606182e324216822a2d5913e797a05c16cc1468d001acf3783b18e00e0203033e43106178db554029e83ca46402dc49d929d7882a04a0e7215041bdabf7430bd10ef4bb658a40f064c63c4816660241c2480862f26742fdf9ca41637731350301c344e439428182a03e384484e6d65d0c8a10117c6739ca201b60974519a1ae6b0c3966c0f650b449d10eae065dab2c83ab4edbab5efdea50bbc801").unwrap().into(),
            difficulty: 0.into(),
            number: 16182891.into(),
            gas_limit: 0x1c9c380.into(),
            gas_used: 0xe9b752.into(),
            timestamp: 0x6399bf63,
            extra_data: hex::decode("496c6c756d696e61746520446d6f63726174697a6520447374726962757465").unwrap(),
            mix_hash: Hash256::from_str("bf5289894b2ceab3549f92f063febbac896b280ddb18129a57cff13113c11b13").unwrap(),
            nonce: Hash64::zero(),
            base_fee_per_gas: 0x34187b238_u64.into(),
        };
        let expected_hash =
            Hash256::from_str("6da69709cd5a34079b6604d29cd78fc01dacd7c6268980057ad92a2bede87351")
                .unwrap();
        test_rlp_encoding(&header, None, expected_hash);
    }
}

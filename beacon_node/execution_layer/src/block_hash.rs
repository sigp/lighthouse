use crate::{Error, ExecutionLayer};
use ethers_core::utils::rlp::RlpStream;
use hash256_std_hasher::Hash256StdHasher;
use hash_db::Hasher;
use keccak_hash::KECCAK_EMPTY_LIST_RLP;
use slog::debug;
use tiny_keccak::{Hasher as _, Keccak};
use triehash::ordered_trie_root;
use types::{
    map_execution_block_header_fields, Address, EthSpec, ExecutionBlockHash, ExecutionBlockHeader,
    ExecutionPayload, Hash256, Hash64, Uint256,
};

fn keccak256(bytes: &[u8]) -> Hash256 {
    let mut keccak = Keccak::v256();
    keccak.update(bytes);
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);
    Hash256::from(out)
}

// Keccak hasher
//
// Based on:
// https://github.com/paritytech/trie/blob/b76c9db35c2bb1b00e60c74a25f386c32ea1933d/test-support/keccak-hasher/src/lib.rs#L24-L41
#[derive(Default, Debug, Clone, PartialEq)]
pub struct KeccakHasher;

impl Hasher for KeccakHasher {
    type Out = Hash256;
    type StdHasher = Hash256StdHasher;

    const LENGTH: usize = 32;

    fn hash(x: &[u8]) -> Self::Out {
        keccak256(x)
    }
}

pub fn rlp_encode_block_header(header: &ExecutionBlockHeader) -> Vec<u8> {
    let mut rlp_header_stream = RlpStream::new();
    rlp_header_stream.begin_unbounded_list();
    map_execution_block_header_fields!(&header, |_, field| {
        rlp_header_stream.append(field);
    });
    rlp_header_stream.finalize_unbounded_list();
    assert!(rlp_header_stream.is_finished());
    rlp_header_stream.out().into()
}

impl<T: EthSpec> ExecutionLayer<T> {
    pub fn verify_payload_block_hash(&self, payload: &ExecutionPayload<T>) -> Result<(), Error> {
        // Calculate the transactions root.
        // FIXME(sproul): use non-deprecated library
        let rlp_transactions_root = Hash256::from(ordered_trie_root::<KeccakHasher, _>(
            payload.transactions.iter().map(|txn_bytes| {
                let bytes_slice: &[u8] = &*txn_bytes;
                bytes_slice
            }),
        ));

        debug!(
            self.log(),
            "Computed RLP transactions root";
            "block_number" => payload.block_number,
            "transactions_root" => ?rlp_transactions_root,
        );
        debug!(
            self.log(),
            "Full payload";
            "payload" => format!("{:#?}", payload),
        );

        let exec_block_header = ExecutionBlockHeader::from_payload(
            &payload,
            KECCAK_EMPTY_LIST_RLP.as_fixed_bytes().into(),
            rlp_transactions_root,
        );

        // Hash it.
        let rlp_block_header = rlp_encode_block_header(&exec_block_header);
        let header_hash = ExecutionBlockHash::from_root(keccak256(&rlp_block_header));

        if header_hash != payload.block_hash {
            return Err(Error::BlockHashMismatch {
                computed: header_hash,
                payload: payload.block_hash,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::FromHex;
    use std::str::FromStr;

    fn test_rlp_encoding(
        header: &ExecutionBlockHeader,
        expected_rlp: &str,
        expected_hash: Hash256,
    ) {
        let rlp_encoding = rlp_encode_block_header(&header);

        let computed_rlp = hex::encode(&rlp_encoding);
        assert_eq!(expected_rlp, computed_rlp);

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
        test_rlp_encoding(&header, expected_rlp, expected_hash);
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
        test_rlp_encoding(&header, expected_rlp, expected_hash);
    }
}

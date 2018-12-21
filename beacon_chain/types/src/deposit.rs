use super::ssz::{decode_ssz_list, Decodable, DecodeError, Encodable, SszStream};
use super::{DepositData, Hash256};

#[derive(Debug, PartialEq, Clone)]
pub struct Deposit {
    pub merkle_branch: Vec<Hash256>,
    pub merkle_tree_index: u64,
    pub deposit_data: DepositData,
}

impl Encodable for Deposit {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.merkle_branch);
        s.append(&self.merkle_tree_index);
        s.append(&self.deposit_data);
    }
}

impl Decodable for Deposit {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (merkle_branch, i) = decode_ssz_list(bytes, i)?;
        let (merkle_tree_index, i) = <_>::ssz_decode(bytes, i)?;
        let (deposit_data, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                merkle_branch,
                merkle_tree_index,
                deposit_data,
            },
            i,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::super::{DepositInput, Hash256};
    use super::*;
    use bls::{Keypair, Signature};

    #[test]
    pub fn test_ssz_round_trip() {
        let keypair = Keypair::random();

        let original = Deposit {
            merkle_branch: vec![
                Hash256::from("one".as_bytes()),
                Hash256::from("two".as_bytes()),
            ],
            merkle_tree_index: 19,
            deposit_data: DepositData {
                deposit_input: DepositInput {
                    pubkey: keypair.pk,
                    withdrawal_credentials: Hash256::from("cats".as_bytes()),
                    randao_commitment: Hash256::from("dogs".as_bytes()),
                    proof_of_possession: Signature::new(&[42, 42], &keypair.sk),
                },
                value: 12,
                timestamp: 100,
            },
        };

        let bytes = ssz_encode(&original);
        let (decoded, _) = Deposit::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}

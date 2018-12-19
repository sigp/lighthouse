use super::ssz::{decode_ssz_list, Decodable, DecodeError, Encodable, SszStream};
use super::Hash256;
use bls::{AggregateSignature, PublicKey};

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
        let (merkle_tree_index, i) = u64::ssz_decode(bytes, i)?;
        let (deposit_data, i) = DepositData::ssz_decode(bytes, i)?;

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

#[derive(Debug, PartialEq, Clone)]
pub struct DepositData {
    pub deposit_input: DepositInput,
    pub value: u64,
    pub timestamp: u64,
}

impl Encodable for DepositData {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.deposit_input);
        s.append(&self.value);
        s.append(&self.timestamp);
    }
}

impl Decodable for DepositData {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (deposit_input, i) = DepositInput::ssz_decode(bytes, i)?;
        let (value, i) = u64::ssz_decode(bytes, i)?;
        let (timestamp, i) = u64::ssz_decode(bytes, i)?;

        Ok((
            Self {
                deposit_input,
                value,
                timestamp,
            },
            i,
        ))
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DepositInput {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: Hash256,
    pub randao_commitment: Hash256,
    pub proof_of_possession: AggregateSignature,
}

impl Encodable for DepositInput {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.pubkey.as_bytes());
        s.append(&self.withdrawal_credentials);
        s.append(&self.randao_commitment);
        s.append(&self.proof_of_possession);
    }
}

impl Decodable for DepositInput {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (pubkey_bytes, i) = decode_ssz_list(bytes, i)?;
        let pubkey = PublicKey::from_bytes(&pubkey_bytes).map_err(|_| DecodeError::TooShort)?;
        let (withdrawal_credentials, i) = Hash256::ssz_decode(bytes, i)?;
        let (randao_commitment, i) = Hash256::ssz_decode(bytes, i)?;
        let (proof_of_possession, i) = AggregateSignature::ssz_decode(bytes, i)?;

        Ok((
            Self {
                pubkey,
                withdrawal_credentials,
                randao_commitment,
                proof_of_possession,
            },
            i,
        ))
    }
}

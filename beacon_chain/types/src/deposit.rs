use super::Hash256;
use bls::{AggregateSignature, PublicKey};

#[derive(Debug, PartialEq, Clone)]
pub struct Deposit {
    pub merkle_branch: Vec<Hash256>,
    pub merkle_tree_index: u64,
    pub deposit_data: DepositData,
}

#[derive(Debug, PartialEq, Clone)]
pub struct DepositData {
    pub deposit_input: DepositInput,
    pub value: u64,
    pub timestamp: u64,
}

#[derive(Debug, PartialEq, Clone)]
pub struct DepositInput {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: Hash256,
    pub randao_commitment: Hash256,
    pub proof_of_possession: AggregateSignature,
}

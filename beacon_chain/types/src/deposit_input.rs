use super::bls::{PublicKey, Signature};
use super::{Hash256};

pub struct DepositInput {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: Hash256,
    pub randao_commitment: Hash256,
    pub proof_of_possession: Signature
}

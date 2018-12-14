use super::bls::{Keypair, PublicKey, AggregateSignature};
use super::{Hash256};

pub struct DepositParameters {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: Hash256,
    pub randao_commitment: Hash256,
    pub proof_of_possession: AggregateSignature
}

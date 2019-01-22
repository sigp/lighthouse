use super::{Address, Hash256};
use bls::{PublicKey, Signature};

/// The information gathered from the PoW chain validator registration function.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatorRegistration {
    pub pubkey: PublicKey,
    pub withdrawal_shard: u64,
    pub withdrawal_address: Address,
    pub randao_commitment: Hash256,
    pub proof_of_possession: Signature,
}

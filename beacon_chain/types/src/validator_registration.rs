use bls::{
    create_proof_of_possession,
    Keypair,
    PublicKey,
    Signature,
};
use super::{
    Address,
    Hash256,
};


/// The information gathered from the PoW chain validator registration function.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatorRegistration {
    pub pubkey: PublicKey,
    pub withdrawal_shard: u16,
    pub withdrawal_address: Address,
    pub randao_commitment: Hash256,
    pub proof_of_possession: Signature,
}

impl ValidatorRegistration {
    pub fn random() -> Self {
        let keypair = Keypair::random();

        Self {
            pubkey: keypair.pk.clone(),
            withdrawal_shard: 0,
            withdrawal_address: Address::random(),
            randao_commitment: Hash256::random(),
            proof_of_possession: create_proof_of_possession(&keypair),
        }
    }
}

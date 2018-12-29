use super::{PublicKey, SecretKey};

#[derive(Debug, Clone, PartialEq)]
pub struct Keypair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

impl Keypair {
    /// Instantiate a Keypair using SecretKey::random().
    pub fn random() -> Self {
        let sk = SecretKey::random();
        let pk = PublicKey::from_secret_key(&sk);
        Keypair { sk, pk }
    }
}

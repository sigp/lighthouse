use super::{PublicKey, SecretKey};
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

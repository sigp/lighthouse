use crate::consts::{BLS_WITHDRAWAL_PREFIX, ETH1_ADDRESS_WITHDRAWAL_PREFIX};
use crate::*;
use bls::get_withdrawal_credentials;

pub struct WithdrawalCredentials(Hash256);

impl WithdrawalCredentials {
    pub fn bls(withdrawal_public_key: &PublicKey) -> Self {
        let withdrawal_credentials =
            get_withdrawal_credentials(withdrawal_public_key, BLS_WITHDRAWAL_PREFIX);
        Self(Hash256::from_slice(&withdrawal_credentials))
    }

    pub fn eth1(withdrawal_address: Address) -> Self {
        let mut withdrawal_credentials = [0; 32];
        withdrawal_credentials[0] = ETH1_ADDRESS_WITHDRAWAL_PREFIX;
        withdrawal_credentials[12..].copy_from_slice(withdrawal_address.as_bytes());
        Self(Hash256::from_slice(&withdrawal_credentials))
    }
}

impl From<WithdrawalCredentials> for Hash256 {
    fn from(withdrawal_credentials: WithdrawalCredentials) -> Self {
        withdrawal_credentials.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::generate_deterministic_keypair;
    use std::str::FromStr;

    #[test]
    fn bls_withdrawal_credentials() {
        let keypair = generate_deterministic_keypair(0);
        let credentials = WithdrawalCredentials::bls(&keypair.pk);
        let manually_generated_credentials =
            get_withdrawal_credentials(&keypair.pk, BLS_WITHDRAWAL_PREFIX);
        let hash: Hash256 = credentials.into();
        assert_eq!(hash[0], BLS_WITHDRAWAL_PREFIX);
        assert_eq!(hash.as_bytes(), &manually_generated_credentials);
    }

    #[test]
    fn eth1_withdrawal_credentials() {
        let address = Address::from_str("0x25c4a76E7d118705e7Ea2e9b7d8C59930d8aCD3b").unwrap();
        let credentials = WithdrawalCredentials::eth1(address);
        let hash: Hash256 = credentials.into();
        assert_eq!(
            hash,
            Hash256::from_str("0x01000000000000000000000025c4a76E7d118705e7Ea2e9b7d8C59930d8aCD3b")
                .unwrap()
        )
    }
}

use bls::{PublicKey, get_withdrawal_credentials};

use crate::core::{Address, ChainSpec, Hash256};

pub struct WithdrawalCredentials(Hash256);

impl WithdrawalCredentials {
    /// Append the 0x00 prefix to the withdrawal credentials, signalling that it
    /// is a BLS-type. BLS withdrawal credentials were used for the Beacon Chain
    /// launch, they do not support withdrawals.
    pub fn type_0x00(withdrawal_public_key: &PublicKey, spec: &ChainSpec) -> Self {
        let withdrawal_credentials =
            get_withdrawal_credentials(withdrawal_public_key, spec.bls_withdrawal_prefix_byte);
        Self(Hash256::from_slice(&withdrawal_credentials))
    }

    /// Append the 0x01 prefix to the withdrawal credentials, signalling that it
    /// is a non-compounding validator that receives rewards for to an
    /// ETH1 execution address.
    pub fn type_0x01(withdrawal_address: Address, spec: &ChainSpec) -> Self {
        let mut withdrawal_credentials = [0; 32];
        withdrawal_credentials[0] = spec.eth1_address_withdrawal_prefix_byte;
        withdrawal_credentials[12..].copy_from_slice(withdrawal_address.as_slice());
        Self(Hash256::from_slice(&withdrawal_credentials))
    }

    /// Append the 0x02 prefix to the withdrawal credentials, signalling that it
    /// is a compounding validator.
    pub fn type_0x02(withdrawal_address: Address, spec: &ChainSpec) -> Self {
        let mut withdrawal_credentials = [0; 32];
        withdrawal_credentials[0] = spec.compounding_withdrawal_prefix_byte;
        withdrawal_credentials[12..].copy_from_slice(withdrawal_address.as_slice());
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
    use crate::{EthSpec, MainnetEthSpec, test_utils::generate_deterministic_keypair};
    use std::str::FromStr;

    const ADDRESS: &str = "0x25c4a76E7d118705e7Ea2e9b7d8C59930d8aCD3b";

    #[test]
    fn bls_withdrawal_credentials() {
        let spec = &MainnetEthSpec::default_spec();
        let keypair = generate_deterministic_keypair(0);
        let credentials = WithdrawalCredentials::type_0x00(&keypair.pk, spec);
        let manually_generated_credentials =
            get_withdrawal_credentials(&keypair.pk, spec.bls_withdrawal_prefix_byte);
        let hash: Hash256 = credentials.into();
        assert_eq!(hash[0], spec.bls_withdrawal_prefix_byte);
        assert_eq!(hash.as_slice(), &manually_generated_credentials);
    }

    #[test]
    fn non_compounding_withdrawal_credentials() {
        let spec = &MainnetEthSpec::default_spec();
        let address = Address::from_str(ADDRESS).unwrap();
        let credentials = WithdrawalCredentials::type_0x01(address, spec);
        let hash: Hash256 = credentials.into();
        assert_eq!(
            hash,
            Hash256::from_str("0x01000000000000000000000025c4a76E7d118705e7Ea2e9b7d8C59930d8aCD3b")
                .unwrap()
        )
    }

    #[test]
    fn compounding_withdrawal_credentials() {
        let spec = &MainnetEthSpec::default_spec();
        let address = Address::from_str(ADDRESS).unwrap();
        let credentials = WithdrawalCredentials::type_0x02(address, spec);
        let hash: Hash256 = credentials.into();
        assert_eq!(
            hash,
            Hash256::from_str("0x02000000000000000000000025c4a76E7d118705e7Ea2e9b7d8C59930d8aCD3b")
                .unwrap()
        )
    }
}

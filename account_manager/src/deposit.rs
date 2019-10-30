use bls::{get_withdrawal_credentials, Keypair, Signature};
use types::{ChainSpec, DepositData, Hash256};

/// Generate deposit parameters given validator and withdrawal keypairs and deposit amount.
pub fn generate_deposit_params(
    validator_key: Keypair,
    withdrawal_key: &Keypair,
    amount: u64,
    spec: &ChainSpec,
) -> DepositData {
    let withdrawal_credentials = Hash256::from_slice(&get_withdrawal_credentials(
        &withdrawal_key.pk,
        spec.bls_withdrawal_prefix_byte,
    ));
    let mut deposit = DepositData {
        pubkey: validator_key.pk.into(),
        withdrawal_credentials,
        amount,
        signature: Signature::empty_signature().into(),
    };
    deposit.signature = deposit.create_signature(&validator_key.sk, spec);
    deposit
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::PublicKeyBytes;
    use ssz::{ssz_encode, Decode};
    use tree_hash::SignedRoot;

    #[test]
    fn test_deposit_params() {
        let vkp = Keypair::random();
        let wkp = Keypair::random();
        let amount: u64 = 0;
        let spec = ChainSpec::default();
        let deposit_data = generate_deposit_params(vkp.clone(), &wkp, amount, &spec);

        assert_eq!(
            deposit_data.pubkey,
            PublicKeyBytes::from_ssz_bytes(&ssz_encode(&vkp.pk)).unwrap()
        );

        assert_eq!(
            deposit_data.withdrawal_credentials,
            Hash256::from_slice(&get_withdrawal_credentials(
                &wkp.pk,
                spec.bls_withdrawal_prefix_byte,
            ))
        );

        assert_eq!(deposit_data.amount, amount);

        let signature = Signature::from_bytes(&deposit_data.signature.as_bytes()).unwrap();
        let hashed_root = deposit_data.signed_root();
        assert!(signature.verify(&hashed_root, spec.get_deposit_domain(), &vkp.pk));
    }
}

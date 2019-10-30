use bls::{get_withdrawal_credentials, Keypair, PublicKeyBytes, SignatureBytes, BLS_SIG_BYTE_SIZE};
use ssz::{ssz_encode, Decode};
use types::{ChainSpec, DepositData, Hash256};

pub fn generate_deposit_params(
    validator_key: Keypair,
    withdrawal_key: Keypair,
    deposit_amount: u64,
    spec: ChainSpec,
) -> Result<DepositData, String> {
    let pubkey = PublicKeyBytes::from_ssz_bytes(&ssz_encode(&validator_key.pk))
        .map_err(|e| format!("Invalid validator pubkey ssz: {:?}", e))?;
    let withdrawal_credentials = Hash256::from_slice(&get_withdrawal_credentials(
        &withdrawal_key.pk,
        spec.bls_withdrawal_prefix_byte,
    ));
    // Creating a fake signature to construct the deposit struct
    let fake_signature = SignatureBytes::from_ssz_bytes(&[0; BLS_SIG_BYTE_SIZE])
        .map_err(|e| format!("Invalid signature ssz: {:?}", e))?;
    let mut deposit = DepositData {
        pubkey,
        withdrawal_credentials,
        amount: deposit_amount,
        signature: fake_signature,
    };
    let signature = deposit.create_signature(&validator_key.sk, &spec);
    deposit.signature = signature;
    Ok(deposit)
}

use crate::*;
use crate::test_utils::{DepositTestTask};
use bls::{get_withdrawal_credentials, PublicKeyBytes, SignatureBytes};


/// Builds an deposit to be used for testing purposes.
///
/// This struct should **never be used for production purposes.**
pub struct TestingDepositBuilder {
    deposit: Deposit,
}

impl TestingDepositBuilder {
    /// Instantiates a new builder.
    pub fn new(pubkey: PublicKey, amount: u64) -> Self {
        let deposit = Deposit {
            proof: vec![].into(),
            data: DepositData {
                pubkey: PublicKeyBytes::from(pubkey),
                withdrawal_credentials: Hash256::zero(),
                amount,
                signature: SignatureBytes::empty(),
            },
        };

        Self { deposit }
    }

    /// Signs the deposit, also setting the following values:
    ///
    /// - `pubkey` to the signing pubkey.
    /// - `withdrawal_credentials` to the signing pubkey.
    /// - `proof_of_possession`
    pub fn sign(&mut self, test_task: &DepositTestTask, keypair: &Keypair, epoch: Epoch, fork: &Fork, spec: &ChainSpec) {
        let new_key = Keypair::random();
        let mut withdraw_cred = &keypair.pk;
        let mut pubkey = keypair.pk.clone();
        let mut sig_key  = &keypair.sk;

        match test_task {
            DepositTestTask::BadPubKey => pubkey = new_key.pk,
            DepositTestTask::BadWithdrawCred => withdraw_cred = &new_key.pk,
            DepositTestTask::BadSig => sig_key = &new_key.sk,
            _ => (),
        }

        let withdrawal_credentials = Hash256::from_slice(
            &get_withdrawal_credentials(withdraw_cred, spec.bls_withdrawal_prefix_byte)[..],
        );

        // Building the data and signing it
        self.deposit.data.pubkey = PublicKeyBytes::from(pubkey);
        self.deposit.data.withdrawal_credentials = withdrawal_credentials;
        self.deposit.data.signature =
            self.deposit
                .data
                .create_signature(sig_key, epoch, fork, spec);
    }

    /// Builds the deposit, consuming the builder.
    pub fn build(self) -> Deposit {
        self.deposit
    }
}

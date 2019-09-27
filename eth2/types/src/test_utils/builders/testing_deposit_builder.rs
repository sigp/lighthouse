use crate::*;
use crate::test_utils::{DepositTestTask};
use ssz::{Decode, Encode};
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
        let mut pubkey = keypair.pk.clone();
        let mut secret_key = keypair.sk.clone();

        match test_task {
            DepositTestTask::BadPubKey => pubkey = new_key.pk,
            DepositTestTask::InvalidPubKey => {
                let mut public_key_bytes: Vec<u8> = vec![0; 48];
                public_key_bytes[0] = 255;
                let ssz_bytes: Vec<u8> = public_key_bytes.as_ssz_bytes();
                pubkey = PublicKey::from_ssz_bytes(&ssz_bytes).unwrap();
            },
            DepositTestTask::BadSig => secret_key = new_key.sk,
            _ => (),
        }

        let withdrawal_credentials = Hash256::from_slice(
            &get_withdrawal_credentials(&keypair.pk, spec.bls_withdrawal_prefix_byte)[..],
        );

        // Building the data and signing it
        self.deposit.data.pubkey = PublicKeyBytes::from(pubkey);
        self.deposit.data.withdrawal_credentials = withdrawal_credentials;
        self.deposit.data.signature =
            self.deposit
                .data
                .create_signature(&secret_key, epoch, fork, spec);
    }

    /// Builds the deposit, consuming the builder.
    pub fn build(self) -> Deposit {
        self.deposit
    }
}

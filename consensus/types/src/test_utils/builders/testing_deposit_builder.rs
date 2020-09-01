use crate::test_utils::DepositTestTask;
use crate::*;
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
    pub fn sign(&mut self, test_task: DepositTestTask, keypair: &Keypair, spec: &ChainSpec) {
        let new_key = Keypair::random();
        let mut pubkeybytes = PublicKeyBytes::from(keypair.pk.clone());
        let mut secret_key = keypair.sk.clone();

        match test_task {
            DepositTestTask::BadPubKey => pubkeybytes = PublicKeyBytes::from(new_key.pk),
            DepositTestTask::InvalidPubKey => {
                // Creating invalid public key bytes
                let mut public_key_bytes: Vec<u8> = vec![0; 48];
                public_key_bytes[0] = 255;
                pubkeybytes = PublicKeyBytes::deserialize(&public_key_bytes).unwrap();
            }
            DepositTestTask::BadSig => secret_key = new_key.sk,
            _ => (),
        }

        let withdrawal_credentials = Hash256::from_slice(
            &get_withdrawal_credentials(&keypair.pk, spec.bls_withdrawal_prefix_byte)[..],
        );

        // Building the data and signing it
        self.deposit.data.pubkey = pubkeybytes;
        self.deposit.data.withdrawal_credentials = withdrawal_credentials;
        self.deposit.data.signature = self.deposit.data.create_signature(&secret_key, spec);
    }

    /// Builds the deposit, consuming the builder.
    pub fn build(self) -> Deposit {
        self.deposit
    }
}

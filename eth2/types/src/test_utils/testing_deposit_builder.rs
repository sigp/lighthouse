use crate::*;
use bls::get_withdrawal_credentials;

pub struct TestingDepositBuilder {
    deposit: Deposit,
}

impl TestingDepositBuilder {
    pub fn new(amount: u64) -> Self {
        let keypair = Keypair::random();

        let deposit = Deposit {
            branch: vec![],
            index: 0,
            deposit_data: DepositData {
                amount,
                timestamp: 1,
                deposit_input: DepositInput {
                    pubkey: keypair.pk,
                    withdrawal_credentials: Hash256::zero(),
                    proof_of_possession: Signature::empty_signature(),
                },
            },
        };

        Self { deposit }
    }

    pub fn set_index(&mut self, index: u64) {
        self.deposit.index = index;
    }

    pub fn sign(&mut self, keypair: &Keypair, domain: u64, spec: &ChainSpec) {
        let withdrawal_credentials = Hash256::from_slice(
            &get_withdrawal_credentials(&keypair.pk, spec.bls_withdrawal_prefix_byte)[..],
        );
        self.deposit.deposit_data.deposit_input.pubkey = keypair.pk.clone();
        self.deposit
            .deposit_data
            .deposit_input
            .withdrawal_credentials = withdrawal_credentials.clone();
        self.deposit.deposit_data.deposit_input.proof_of_possession =
            DepositInput::create_proof_of_possession(&keypair, &withdrawal_credentials, domain);
    }

    pub fn build(self) -> Deposit {
        self.deposit
    }
}

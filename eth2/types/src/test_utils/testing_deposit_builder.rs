use crate::*;
use bls::{create_proof_of_possession, get_withdrawal_credentials};

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

    pub fn sign(&mut self, keypair: &Keypair, spec: &ChainSpec) {
        self.deposit.deposit_data.deposit_input.pubkey = keypair.pk.clone();
        self.deposit.deposit_data.deposit_input.proof_of_possession =
            create_proof_of_possession(&keypair);
        self.deposit
            .deposit_data
            .deposit_input
            .withdrawal_credentials = Hash256::from_slice(
            &get_withdrawal_credentials(&keypair.pk, spec.bls_withdrawal_prefix_byte)[..],
        );
    }

    pub fn build(self) -> Deposit {
        self.deposit
    }
}

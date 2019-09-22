use crate::*;
use merkle_proof::MerkleTree;
use int_to_bytes::int_to_bytes32;
use bls::{get_withdrawal_credentials, PublicKeyBytes, SignatureBytes};
use tree_hash::{TreeHash};


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
    pub fn sign(&mut self, keypair: &Keypair, epoch: Epoch, fork: &Fork, spec: &ChainSpec) {
        let withdrawal_credentials = Hash256::from_slice(
            &get_withdrawal_credentials(&keypair.pk, spec.bls_withdrawal_prefix_byte)[..],
        );

        // Building the data and signing it
        self.deposit.data.pubkey = PublicKeyBytes::from(keypair.pk.clone());
        self.deposit.data.withdrawal_credentials = withdrawal_credentials;
        self.deposit.data.signature =
            self.deposit
                .data
                .create_signature(&keypair.sk, epoch, fork, spec);
        
        // Now building the proofs
        // Inspired fmor beacon_chain_builder.rs
        // Vector implementation for simplicity. Will be removed.
        let datas = vec![self.deposit.data.clone()];

        let deposit_root_leaves = datas
            .iter()
            .map(|data| Hash256::from_slice(&data.tree_hash_root()))
            .collect::<Vec<_>>();

        // Iterating on object of length == 1. Will remove later
        for i in 1..=deposit_root_leaves.len() {
            let tree = MerkleTree::create(
                &deposit_root_leaves[0..i],
                spec.deposit_contract_tree_depth as usize,
            );

            let (_, mut proof) = tree.generate_proof(i - 1, spec.deposit_contract_tree_depth as usize);
            proof.push(Hash256::from_slice(&int_to_bytes32(i as u64)));

            assert_eq!(
                proof.len(),
                spec.deposit_contract_tree_depth as usize + 1,
                "Deposit proof should be correct len",
            );
            // Since this loop only runs once, taking a short-cut here.
            self.deposit = Deposit {
                proof: proof.into(),
                data: self.deposit.data.clone(),
            }
        }
    }

    /// Builds the deposit, consuming the builder.
    pub fn build(self) -> Deposit {
        self.deposit
    }
}

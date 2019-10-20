/*
/// Represents an eth1 deposit contract merkle tree.
///
/// Each `deposit` is included with a proof into the `deposit_root`. The index for a deposit in the
/// merkle tree is equal to it's index in `deposits`.
pub struct DepositSet {
    pub deposit_root: Hash256,
    pub deposits: Vec<Deposit>,
}

impl DepositSet {
    pub fn from_logs(tree_depth: usize, logs: Vec<DepositLog>) -> Self {
        let roots = logs
            .iter()
            .map(|log| Hash256::from_slice(&log.deposit_data.tree_hash_root()))
            .collect::<Vec<_>>();

        let tree = DepositDataTree::create(&roots, roots.len(), tree_depth);

        let deposits = logs
            .into_iter()
            .enumerate()
            .map(|(i, deposit_log)| {
                let (_leaf, proof) = tree.generate_proof(i);

                Deposit {
                    proof: proof.into(),
                    data: deposit_log.deposit_data,
                }
            })
            .collect();

        DepositSet {
            deposit_root: tree.root(),
            deposits,
        }
    }
}
*/

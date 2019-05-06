use ethereum_types::H256 as Hash256;
use tree_hash::TreeHash;

fn main() {
    let n = 2048;

    let vec: Vec<Hash256> = (0..n).map(|_| Hash256::random()).collect();

    vec.tree_hash_root();
}

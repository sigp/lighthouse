use cached_tree_hash::TreeHashCache;
use ethereum_types::H256 as Hash256;

fn run(vec: &Vec<Hash256>, modified_vec: &Vec<Hash256>) {
    let mut cache = TreeHashCache::new(vec, 0).unwrap();

    cache.update(modified_vec).unwrap();
}

fn main() {
    let n = 2048;

    let vec: Vec<Hash256> = (0..n).map(|_| Hash256::random()).collect();

    let mut modified_vec = vec.clone();
    modified_vec[n - 1] = Hash256::random();

    for _ in 0..10_000 {
        run(&vec, &modified_vec);
    }
}

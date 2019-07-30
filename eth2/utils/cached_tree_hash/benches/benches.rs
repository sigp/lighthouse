#[macro_use]
extern crate criterion;

use cached_tree_hash::TreeHashCache;
use criterion::black_box;
use criterion::{Benchmark, Criterion};
use eth2_hashing::hash;
use ethereum_types::H256 as Hash256;
use tree_hash::TreeHash;

fn criterion_benchmark(c: &mut Criterion) {
    let n = 1024;

    let source_vec: Vec<Hash256> = (0..n).map(|_| Hash256::random()).collect();

    let mut source_modified_vec = source_vec.clone();
    source_modified_vec[n - 1] = Hash256::random();

    let modified_vec = source_modified_vec.clone();
    c.bench(
        &format!("vec_of_{}_hashes", n),
        Benchmark::new("standard", move |b| {
            b.iter_with_setup(
                || modified_vec.clone(),
                |modified_vec| black_box(modified_vec.tree_hash_root()),
            )
        })
        .sample_size(100),
    );

    let modified_vec = source_modified_vec.clone();
    c.bench(
        &format!("vec_of_{}_hashes", n),
        Benchmark::new("build_cache", move |b| {
            b.iter_with_setup(
                || modified_vec.clone(),
                |vec| black_box(TreeHashCache::new(&vec, 0)),
            )
        })
        .sample_size(100),
    );

    let vec = source_vec.clone();
    let modified_vec = source_modified_vec.clone();
    c.bench(
        &format!("vec_of_{}_hashes", n),
        Benchmark::new("cache_update", move |b| {
            b.iter_with_setup(
                || {
                    let cache = TreeHashCache::new(&vec, 0).unwrap();
                    (cache, modified_vec.clone())
                },
                |(mut cache, modified_vec)| black_box(cache.update(&modified_vec)),
            )
        })
        .sample_size(100),
    );

    c.bench(
        &format!("{}_hashes", n),
        Benchmark::new("hash_64_bytes", move |b| {
            b.iter(|| {
                for _ in 0..n {
                    let _digest = hash(&[42; 64]);
                }
            })
        })
        .sample_size(100),
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

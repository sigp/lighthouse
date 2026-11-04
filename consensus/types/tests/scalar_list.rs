//! `ScalarList` hash roots must equal milhouse's for the same values: fixed
//! lists against `milhouse::List`, progressive lists against
//! `milhouse::ProgressiveList`.

use silver_hashing::HashFormat;
use tree_hash::TreeHash;
use typenum::{U64, U1099511627776};
use types::scalar_list::ScalarList;

type Limit = U1099511627776;

fn milhouse_root_u64(vals: &[u64]) -> tree_hash::Hash256 {
    milhouse::List::<u64, Limit>::new(vals.to_vec())
        .unwrap()
        .tree_hash_root()
}

fn milhouse_root_u8(vals: &[u8]) -> tree_hash::Hash256 {
    milhouse::List::<u8, Limit>::new(vals.to_vec())
        .unwrap()
        .tree_hash_root()
}

const SIZES: &[usize] = &[0, 1, 3, 4, 5, 31, 32, 33, 127, 128, 1000, 4096, 10_000];

#[test]
fn build_roots_match_milhouse() {
    for &n in SIZES {
        let vals: Vec<u64> = (0..n as u64).map(|i| i * 7 + 1).collect();
        let ours = ScalarList::<u64, Limit>::new(vals.clone(), HashFormat::Fixed).unwrap();
        assert_eq!(ours.tree_hash_root(), milhouse_root_u64(&vals), "u64 n={n}");

        let vals: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let ours = ScalarList::<u8, Limit>::new(vals.clone(), HashFormat::Fixed).unwrap();
        assert_eq!(ours.tree_hash_root(), milhouse_root_u8(&vals), "u8 n={n}");
    }
}

#[test]
fn sparse_writes_match_milhouse() {
    let mut vals: Vec<u64> = (0..10_000).collect();
    let mut ours = ScalarList::<u64, Limit>::new(vals.clone(), HashFormat::Fixed).unwrap();
    for i in [0usize, 1, 500, 501, 502, 9998, 9999] {
        vals[i] = 1_000_000 + i as u64;
        ours.set(i, vals[i]).unwrap();
    }
    assert!(!ours.is_committed());
    ours.commit();
    assert_eq!(ours.tree_hash_root(), milhouse_root_u64(&vals));
}

#[test]
fn dense_writes_match_milhouse() {
    let mut ours = ScalarList::<u64, Limit>::new((0..10_000).collect(), HashFormat::Fixed).unwrap();
    for i in (0..ours.len()).step_by(3) {
        ours.set(i, i as u64 * 2).unwrap();
    }
    ours.commit();
    let expect: Vec<u64> = (0..10_000)
        .map(|i| if i % 3 == 0 { i * 2 } else { i })
        .collect();
    assert_eq!(ours.tree_hash_root(), milhouse_root_u64(&expect));
}

#[test]
fn push_grows_across_pow2_boundaries() {
    let mut ours = ScalarList::<u64, Limit>::default();
    let mut vals = Vec::new();
    for i in 0..600u64 {
        ours.push(i * 3).unwrap();
        vals.push(i * 3);
        if [0, 1, 3, 4, 127, 128, 129, 511, 512, 599].contains(&i) {
            ours.commit();
            assert_eq!(
                ours.tree_hash_root(),
                milhouse_root_u64(&vals),
                "after push {i}"
            );
        }
    }
}

#[test]
fn capacity_is_enforced() {
    assert!(ScalarList::<u64, U64>::new(vec![0; 65], HashFormat::Fixed).is_err());
    let mut full = ScalarList::<u64, U64>::new(vec![0; 64], HashFormat::Fixed).unwrap();
    assert!(full.push(1).is_err());
}

#[test]
fn ssz_round_trip() {
    use ssz::{Decode, Encode};
    let ours =
        ScalarList::<u64, Limit>::new((0..1000).map(|i| i * 13).collect(), HashFormat::Fixed)
            .unwrap();
    let bytes = ours.as_ssz_bytes();
    let back = ScalarList::<u64, Limit>::from_ssz_bytes(&bytes).unwrap();
    assert_eq!(back, ours);
    assert_eq!(back.tree_hash_root(), ours.tree_hash_root());
}

fn progressive_root_u64(vals: &[u64]) -> tree_hash::Hash256 {
    milhouse::ProgressiveList::<u64>::new(vals.to_vec())
        .unwrap()
        .tree_hash_root()
}

fn progressive_root_u8(vals: &[u8]) -> tree_hash::Hash256 {
    milhouse::ProgressiveList::<u8>::new(vals.to_vec())
        .unwrap()
        .tree_hash_root()
}

/// Sizes either side of each progressive subtree start: subtree `k` starts
/// at chunk `(4^k - 1) / 3`.
fn around_subtree_starts(vals_per_chunk: usize) -> Vec<usize> {
    let mut sizes = vec![0, 1];
    for k in 1..=7 {
        let start = (4usize.pow(k) - 1) / 3 * vals_per_chunk;
        sizes.extend([start - 1, start, start + 1]);
    }
    sizes
}

#[test]
fn progressive_roots_match_milhouse() {
    for n in around_subtree_starts(4) {
        let vals: Vec<u64> = (0..n as u64).map(|i| i * 7 + 1).collect();
        let ours = ScalarList::<u64, Limit>::new(vals.clone(), HashFormat::Progressive).unwrap();
        assert_eq!(
            ours.tree_hash_root(),
            progressive_root_u64(&vals),
            "u64 n={n}"
        );
    }
    for n in around_subtree_starts(32) {
        let vals: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let ours = ScalarList::<u8, Limit>::new(vals.clone(), HashFormat::Progressive).unwrap();
        assert_eq!(
            ours.tree_hash_root(),
            progressive_root_u8(&vals),
            "u8 n={n}"
        );
    }
}

#[test]
fn writes_across_segments_match_milhouse() {
    let mut vals: Vec<u64> = (0..30_000).collect();
    let mut ours = ScalarList::<u64, Limit>::new(vals.clone(), HashFormat::Progressive).unwrap();
    for i in around_subtree_starts(4) {
        vals[i] = 1_000_000 + i as u64;
        ours.set(i, vals[i]).unwrap();
    }
    ours.commit();
    assert_eq!(ours.tree_hash_root(), progressive_root_u64(&vals));
}

#[test]
fn rewrite_all_matches_milhouse() {
    let mut ours =
        ScalarList::<u64, Limit>::new((0..50_000u64).collect(), HashFormat::Progressive).unwrap();
    for i in 0..ours.len() {
        ours.set(i, i as u64 * 2).unwrap();
    }
    ours.commit();
    let expect: Vec<u64> = (0..50_000).map(|i| i * 2).collect();
    assert_eq!(ours.tree_hash_root(), progressive_root_u64(&expect));
}

#[test]
fn push_grows_across_segment_boundaries() {
    let mut ours = ScalarList::<u64, Limit>::new(Vec::new(), HashFormat::Progressive).unwrap();
    let mut vals = Vec::new();
    let checked = around_subtree_starts(4);
    for i in 0..22_000u64 {
        ours.push(i * 3).unwrap();
        vals.push(i * 3);
        if checked.contains(&vals.len()) {
            ours.commit();
            assert_eq!(
                ours.tree_hash_root(),
                progressive_root_u64(&vals),
                "after push {i}"
            );
        }
    }
}

#[test]
fn progressive_ssz_round_trip() {
    use ssz::Encode;
    let ours = ScalarList::<u64, Limit>::new(
        (0..1000u64).map(|i| i * 13).collect(),
        HashFormat::Progressive,
    )
    .unwrap();
    let bytes = ours.as_ssz_bytes();
    // Decode is representation-blind (fixed by default); clients migrate
    // Gloas-fork fields right after, which is what we model here.
    let back: ScalarList<u64, Limit> =
        types::scalar_list::progressive::decode::from_ssz_bytes(&bytes).unwrap();
    assert_eq!(back, ours);
    assert_eq!(back.tree_hash_root(), ours.tree_hash_root());
}

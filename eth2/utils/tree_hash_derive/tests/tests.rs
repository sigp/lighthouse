use tree_hash::{CachedTreeHashSubTree, SignedRoot, TreeHash};
use tree_hash_derive::{CachedTreeHashSubTree, SignedRoot, TreeHash};

#[derive(Clone, Debug, TreeHash, CachedTreeHashSubTree)]
pub struct Inner {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
}

fn test_standard_and_cached<T>(original: &T, modified: &T)
where
    T: CachedTreeHashSubTree<T>,
{
    let mut cache = original.new_tree_hash_cache().unwrap();

    let standard_root = original.tree_hash_root();
    let cached_root = cache.root().unwrap().to_vec();
    assert_eq!(standard_root, cached_root);

    // Test after a modification
    modified
        .update_tree_hash_cache(&original, &mut cache, 0)
        .unwrap();
    let standard_root = modified.tree_hash_root();
    let cached_root = cache.root().unwrap().to_vec();
    assert_eq!(standard_root, cached_root);
}

#[test]
fn inner_standard_vs_cached() {
    let original = Inner {
        a: 1,
        b: 2,
        c: 3,
        d: 4,
    };
    let modified = Inner {
        b: 42,
        ..original.clone()
    };

    test_standard_and_cached(&original, &modified);
}

#[derive(Clone, Debug, TreeHash, CachedTreeHashSubTree)]
pub struct Uneven {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
    pub e: u64,
}

#[test]
fn uneven_standard_vs_cached() {
    let original = Uneven {
        a: 1,
        b: 2,
        c: 3,
        d: 4,
        e: 5,
    };
    let modified = Uneven {
        e: 42,
        ..original.clone()
    };

    test_standard_and_cached(&original, &modified);
}

#[derive(Clone, Debug, TreeHash, SignedRoot)]
pub struct SignedInner {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
    #[signed_root(skip_hashing)]
    pub e: u64,
}

#[test]
fn signed_root() {
    let unsigned = Inner {
        a: 1,
        b: 2,
        c: 3,
        d: 4,
    };
    let signed = SignedInner {
        a: 1,
        b: 2,
        c: 3,
        d: 4,
        e: 5,
    };

    assert_eq!(unsigned.tree_hash_root(), signed.signed_root());
}

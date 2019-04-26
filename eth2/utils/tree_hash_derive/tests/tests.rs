use cached_tree_hash::{CachedTreeHash, CachedTreeHasher};
use tree_hash::{merkleize::merkle_root, SignedRoot, TreeHash};
use tree_hash_derive::{CachedTreeHash, SignedRoot, TreeHash};

#[derive(Clone, Debug, TreeHash, CachedTreeHash)]
pub struct Inner {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
}

fn test_standard_and_cached<T>(original: &T, modified: &T)
where
    T: CachedTreeHash<T>,
{
    // let mut cache = original.new_tree_hash_cache().unwrap();
    let mut hasher = CachedTreeHasher::new(original).unwrap();

    let standard_root = original.tree_hash_root();
    let cached_root = hasher.tree_hash_root().unwrap();
    assert_eq!(standard_root, cached_root);

    // Test after a modification
    hasher.update(modified).unwrap();
    let standard_root = modified.tree_hash_root();
    let cached_root = hasher.tree_hash_root().unwrap();
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

#[derive(Clone, Debug, TreeHash, CachedTreeHash)]
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

#[derive(TreeHash, SignedRoot)]
struct CryptoKitties {
    best_kitty: u64,
    worst_kitty: u8,
    kitties: Vec<u32>,
}

impl CryptoKitties {
    fn new() -> Self {
        CryptoKitties {
            best_kitty: 9999,
            worst_kitty: 1,
            kitties: vec![2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43],
        }
    }

    fn hash(&self) -> Vec<u8> {
        let mut leaves = vec![];
        leaves.append(&mut self.best_kitty.tree_hash_root());
        leaves.append(&mut self.worst_kitty.tree_hash_root());
        leaves.append(&mut self.kitties.tree_hash_root());
        merkle_root(&leaves)
    }
}

#[test]
fn test_simple_tree_hash_derive() {
    let kitties = CryptoKitties::new();
    assert_eq!(kitties.tree_hash_root(), kitties.hash());
}

#[test]
fn test_simple_signed_root_derive() {
    let kitties = CryptoKitties::new();
    assert_eq!(kitties.signed_root(), kitties.hash());
}

#[derive(TreeHash, SignedRoot)]
struct Casper {
    friendly: bool,
    #[tree_hash(skip_hashing)]
    friends: Vec<u32>,
    #[signed_root(skip_hashing)]
    dead: bool,
}

impl Casper {
    fn new() -> Self {
        Casper {
            friendly: true,
            friends: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            dead: true,
        }
    }

    fn expected_signed_hash(&self) -> Vec<u8> {
        let mut list = Vec::new();
        list.append(&mut self.friendly.tree_hash_root());
        list.append(&mut self.friends.tree_hash_root());
        merkle_root(&list)
    }

    fn expected_tree_hash(&self) -> Vec<u8> {
        let mut list = Vec::new();
        list.append(&mut self.friendly.tree_hash_root());
        list.append(&mut self.dead.tree_hash_root());
        merkle_root(&list)
    }
}

#[test]
fn test_annotated_tree_hash_derive() {
    let casper = Casper::new();
    assert_eq!(casper.tree_hash_root(), casper.expected_tree_hash());
}

#[test]
fn test_annotated_signed_root_derive() {
    let casper = Casper::new();
    assert_eq!(casper.signed_root(), casper.expected_signed_hash());
}

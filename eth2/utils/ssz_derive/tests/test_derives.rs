use ssz::{SignedRoot, TreeHash};
use ssz_derive::{SignedRoot, TreeHash};

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
        let mut list: Vec<Vec<u8>> = Vec::new();
        list.push(self.best_kitty.hash_tree_root());
        list.push(self.worst_kitty.hash_tree_root());
        list.push(self.kitties.hash_tree_root());
        ssz::merkle_hash(&mut list)
    }
}

#[test]
fn test_cryptokitties_hash() {
    let kitties = CryptoKitties::new();
    let expected_hash = vec![
        201, 9, 139, 14, 24, 247, 21, 55, 132, 211, 51, 125, 183, 186, 177, 33, 147, 210, 42, 108,
        174, 162, 221, 227, 157, 179, 15, 7, 97, 239, 82, 220,
    ];
    assert_eq!(kitties.hash(), expected_hash);
}

#[test]
fn test_simple_tree_hash_derive() {
    let kitties = CryptoKitties::new();
    assert_eq!(kitties.hash_tree_root(), kitties.hash());
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
        list.push(self.friendly.hash_tree_root());
        list.push(self.friends.hash_tree_root());
        ssz::merkle_hash(&mut list)
    }

    fn expected_tree_hash(&self) -> Vec<u8> {
        let mut list = Vec::new();
        list.push(self.friendly.hash_tree_root());
        list.push(self.dead.hash_tree_root());
        ssz::merkle_hash(&mut list)
    }
}

#[test]
fn test_annotated_tree_hash_derive() {
    let casper = Casper::new();
    assert_eq!(casper.hash_tree_root(), casper.expected_tree_hash());
}

#[test]
fn test_annotated_signed_root_derive() {
    let casper = Casper::new();
    assert_eq!(casper.signed_root(), casper.expected_signed_hash());
}

use ssz_types::{typenum::U1, VariableList};
use tree_hash::{Hash256, TreeHash};
use tree_hash_derive::TreeHash;

fn mix_in_selector(a: Hash256, selector: u8) -> Hash256 {
    let mut b = [0; 32];
    b[0] = selector;

    Hash256::from_slice(&eth2_hashing::hash32_concat(a.as_bytes(), &b))
}

fn u8_hash_concat(v1: u8, v2: u8) -> Hash256 {
    let mut a = [0; 32];
    let mut b = [0; 32];

    a[0] = v1;
    b[0] = v2;

    Hash256::from_slice(&eth2_hashing::hash32_concat(&a, &b))
}

fn u8_hash(x: u8) -> Hash256 {
    let mut a = [0; 32];
    a[0] = x;
    Hash256::from_slice(&a)
}

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "transparent")]
enum FixedTrans {
    A(u8),
    B(u8),
}

#[test]
fn fixed_trans() {
    assert_eq!(FixedTrans::A(2).tree_hash_root(), u8_hash(2));
    assert_eq!(FixedTrans::B(2).tree_hash_root(), u8_hash(2));
}

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "union")]
enum FixedUnion {
    A(u8),
    B(u8),
}

#[test]
fn fixed_union() {
    assert_eq!(FixedUnion::A(2).tree_hash_root(), u8_hash_concat(2, 0));
    assert_eq!(FixedUnion::B(2).tree_hash_root(), u8_hash_concat(2, 1));
}

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "transparent")]
enum VariableTrans {
    A(VariableList<u8, U1>),
    B(VariableList<u8, U1>),
}

#[test]
fn variable_trans() {
    assert_eq!(
        VariableTrans::A(VariableList::from(vec![2])).tree_hash_root(),
        u8_hash_concat(2, 1)
    );
    assert_eq!(
        VariableTrans::B(VariableList::from(vec![2])).tree_hash_root(),
        u8_hash_concat(2, 1)
    );
}

#[derive(TreeHash)]
#[tree_hash(enum_behaviour = "union")]
enum VariableUnion {
    A(VariableList<u8, U1>),
    B(VariableList<u8, U1>),
}

#[test]
fn variable_union() {
    assert_eq!(
        VariableUnion::A(VariableList::from(vec![2])).tree_hash_root(),
        mix_in_selector(u8_hash_concat(2, 1), 0)
    );
    assert_eq!(
        VariableUnion::B(VariableList::from(vec![2])).tree_hash_root(),
        mix_in_selector(u8_hash_concat(2, 1), 1)
    );
}

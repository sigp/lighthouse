#![allow(unused)]

use ethereum_types::U256;
use merkle_partial::cache::hash_children;
use merkle_partial::field::{Composite, Node, Primitive};
use merkle_partial::{Error, MerkleTreeOverlay, Partial, Path, SerializedPartial};
use merkle_partial_derive;
use ssz_types::{FixedVector, VariableList};
use typenum::{U32, U8};

#[derive(Debug, Default, merkle_partial_derive::Partial)]
pub struct A {
    a: U256,
    b: U256,
    c: u128,
    d: u128,
}

#[test]
fn basic_overlay() {
    assert_eq!(
        A::get_node(vec![Path::Ident("a".to_string())]),
        Ok(Node::Primitive(vec![Primitive {
            index: 3,
            ident: "a".to_string(),
            size: 32,
            offset: 0,
        }]))
    );

    assert_eq!(
        A::get_node(vec![Path::Ident("b".to_string())]),
        Ok(Node::Primitive(vec![Primitive {
            index: 4,
            ident: "b".to_string(),
            size: 32,
            offset: 0,
        }]))
    );

    assert_eq!(
        A::get_node(vec![Path::Ident("c".to_string())]),
        Ok(Node::Primitive(vec![
            Primitive {
                index: 5,
                ident: "c".to_string(),
                size: 16,
                offset: 0,
            },
            Primitive {
                index: 5,
                ident: "d".to_string(),
                size: 16,
                offset: 16,
            }
        ]))
    );
}

#[test]
fn basic_partial() {
    let one = U256::from(1);
    let two = U256::from(2);

    let mut arr = [0_u8; 128];

    one.to_little_endian(&mut arr[0..32]);
    two.to_little_endian(&mut arr[32..64]);
    arr[64] = 3;
    arr[80] = 4;

    let partial = SerializedPartial {
        indices: vec![3, 4, 5, 6],
        chunks: arr.to_vec(),
    };

    let mut p = Partial::<A>::new(partial.clone());

    assert_eq!(
        p.get_bytes(vec![Path::Ident("a".to_string())]),
        Ok(arr[0..32].to_vec())
    );

    assert_eq!(
        p.get_bytes(vec![Path::Ident("b".to_string())]),
        Ok(arr[32..64].to_vec())
    );

    assert_eq!(
        p.get_bytes(vec![Path::Ident("c".to_string())]),
        Ok(arr[64..80].to_vec())
    );

    assert_eq!(
        p.get_bytes(vec![Path::Ident("d".to_string())]),
        Ok(arr[80..96].to_vec())
    );

    assert_eq!(
        p.get_bytes(vec![Path::Ident("e".to_string())]),
        Err(Error::InvalidPath(Path::Ident("e".to_string())))
    );
}

#[derive(merkle_partial_derive::Partial)]
struct B {
    a: u64,
    b: FixedVector<u128, U8>,
}

#[test]
fn simple_fixed_vector() {
    assert_eq!(B::height(), 1);
    assert_eq!(B::first_leaf(), 1);
    assert_eq!(B::last_leaf(), 2);

    assert_eq!(
        B::get_node(vec![Path::Ident("a".to_string())]),
        Ok(Node::Primitive(vec![Primitive {
            ident: "a".to_string(),
            index: 1,
            size: 8,
            offset: 0,
        }]))
    );

    for i in 0..4 {
        assert_eq!(
            B::get_node(vec![Path::Ident("b".to_string()), Path::Index(2 * i)]),
            Ok(Node::Primitive(vec![
                Primitive {
                    ident: (2 * i).to_string(),
                    index: 11 + i,
                    size: 16,
                    offset: 0,
                },
                Primitive {
                    ident: (2 * i + 1).to_string(),
                    index: 11 + i,
                    size: 16,
                    offset: 16,
                }
            ]))
        );
    }
}

#[derive(merkle_partial_derive::Partial)]
struct C {
    a: u8,
    b: u16,
    c: u32,
}

#[test]
fn single_node() {
    assert_eq!(
        C::get_node(vec![Path::Ident("a".to_string())]),
        Ok(Node::Primitive(vec![
            Primitive {
                ident: "a".to_string(),
                index: 0,
                size: 1,
                offset: 0,
            },
            Primitive {
                ident: "b".to_string(),
                index: 0,
                size: 2,
                offset: 1,
            },
            Primitive {
                ident: "c".to_string(),
                index: 0,
                size: 4,
                offset: 3,
            }
        ]))
    );
}

#[derive(Debug, Default, merkle_partial_derive::Partial)]
struct Message {
    timestamp: u64,
    message: FixedVector<u8, U32>,
}

#[derive(Debug, Default, merkle_partial_derive::Partial)]
struct State {
    messages: VariableList<Message, U8>,
}

fn zero_hash(depth: u8) -> Vec<u8> {
    if depth == 0 {
        vec![0; 32]
    } else if depth == 1 {
        hash_children(&[0; 32], &[0; 32])
    } else {
        let last = zero_hash(depth - 1);
        hash_children(&last, &last)
    }
}

// NOTE: copied from `nested_structure2.rs`
#[test]
fn roundtrip_partial() {
    let mut arr = vec![0; 224];

    // 31 `message[0].timestamp`
    arr[0] = 1;

    // 32 `message[0].message`
    arr[32..64].copy_from_slice(&vec![1_u8; 32]);

    // 33 `message[1].timestamp`
    arr[64] = 2;

    // 34 `message[1].message`
    arr[96..128].copy_from_slice(&vec![42_u8; 32]);

    // 8 `hash of message[2] and message[3]`
    arr[128..160].copy_from_slice(&zero_hash(2));

    // 4 `hash of message[4..7]`
    arr[160..192].copy_from_slice(&zero_hash(3));

    // 2 length mixin
    arr[223] = 2;

    let sp = SerializedPartial {
        indices: vec![31, 32, 33, 34, 8, 4, 2],
        chunks: arr.clone(),
    };

    let mut partial = Partial::<State>::new(sp);
    assert_eq!(partial.fill(), Ok(()));

    // TESTING TIMESTAMPS
    assert_eq!(
        partial.get_bytes(vec![
            Path::Ident("messages".to_string()),
            Path::Index(0),
            Path::Ident("timestamp".to_string())
        ]),
        Ok(vec![1, 0, 0, 0, 0, 0, 0, 0])
    );

    assert_eq!(
        partial.get_bytes(vec![
            Path::Ident("messages".to_string()),
            Path::Index(1),
            Path::Ident("timestamp".to_string())
        ]),
        Ok(vec![2, 0, 0, 0, 0, 0, 0, 0])
    );

    // TESTING MESSAGES
    assert_eq!(
        partial.get_bytes(vec![
            Path::Ident("messages".to_string()),
            Path::Index(0),
            Path::Ident("message".to_string()),
            Path::Index(1),
        ]),
        Ok(vec![1])
    );

    assert_eq!(
        partial.get_bytes(vec![
            Path::Ident("messages".to_string()),
            Path::Index(1),
            Path::Ident("message".to_string()),
            Path::Index(31),
        ]),
        Ok(vec![42])
    );
}

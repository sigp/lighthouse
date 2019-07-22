use ethereum_types::U256;
use merkle_partial::field::{Composite, Leaf, Node, Primitive};
use merkle_partial::{Error, MerkleTreeOverlay, Partial, Path, SerializedPartial};
use merkle_partial_derive;
use ssz_types::FixedVector;
use typenum::U8;

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
        A::get_node(0),
        Node::Composite(Composite {
            ident: "".to_owned(),
            index: 0,
            height: A::height(),
        })
    );

    assert_eq!(A::get_node(1), Node::Intermediate(1));
    assert_eq!(A::get_node(2), Node::Intermediate(2));

    assert_eq!(
        A::get_node(3),
        Node::Leaf(Leaf::Primitive(vec![Primitive {
            index: 3,
            ident: "a".to_string(),
            size: 32,
            offset: 0,
        }]))
    );

    assert_eq!(
        A::get_node(4),
        Node::Leaf(Leaf::Primitive(vec![Primitive {
            index: 4,
            ident: "b".to_string(),
            size: 32,
            offset: 0,
        }]))
    );

    assert_eq!(
        A::get_node(5),
        Node::Leaf(Leaf::Primitive(vec![
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

    let mut p = Partial::<A>::default();

    assert_eq!(p.load_partial(partial.clone()), Ok(()));

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
        B::get_node(0),
        Node::Composite(Composite {
            ident: "".to_string(),
            index: 0,
            height: 1,
        })
    );

    assert_eq!(B::get_node(5), Node::Intermediate(5));
    assert_eq!(B::get_node(6), Node::Intermediate(6));

    for i in 11..=14 {
        assert_eq!(
            B::get_node(i),
            Node::Leaf(Leaf::Primitive(vec![
                Primitive {
                    ident: (2 * (i - 11)).to_string(),
                    index: i,
                    size: 16,
                    offset: 0,
                },
                Primitive {
                    ident: (2 * (i - 11) + 1).to_string(),
                    index: i,
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
        C::get_node(0),
        Node::Leaf(Leaf::Primitive(vec![
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

    assert_eq!(C::get_node(1), Node::Unattached(1));
    assert_eq!(C::get_node(1000), Node::Unattached(1000));
}

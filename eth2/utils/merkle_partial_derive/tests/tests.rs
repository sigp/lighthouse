use ethereum_types::U256;
use merkle_partial::field::{Composite, Leaf, Node, Primitive};
use merkle_partial::{Error, MerkleTreeOverlay, Partial, Path, SerializedPartial};
use merkle_partial_derive;

#[derive(Debug, Default, merkle_partial_derive::Partial)]
pub struct A {
    a: U256,
    b: U256,
    c: u128,
    d: u128,
}

#[test]
fn overlay() {
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
fn partial() {
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

    assert_eq!(p.is_path_loaded(vec![Path::Ident("a".to_string())]), true);
    assert_eq!(
        p.bytes_at_path(vec![Path::Ident("a".to_string())]),
        Ok(arr[0..32].to_vec())
    );

    assert_eq!(p.is_path_loaded(vec![Path::Ident("b".to_string())]), true);
    assert_eq!(
        p.bytes_at_path(vec![Path::Ident("b".to_string())]),
        Ok(arr[32..64].to_vec())
    );

    assert_eq!(p.is_path_loaded(vec![Path::Ident("c".to_string())]), true);
    assert_eq!(
        p.bytes_at_path(vec![Path::Ident("c".to_string())]),
        Ok(arr[64..80].to_vec())
    );

    assert_eq!(p.is_path_loaded(vec![Path::Ident("d".to_string())]), true);
    assert_eq!(
        p.bytes_at_path(vec![Path::Ident("d".to_string())]),
        Ok(arr[80..96].to_vec())
    );

    assert_eq!(p.is_path_loaded(vec![Path::Ident("e".to_string())]), false);
    assert_eq!(
        p.bytes_at_path(vec![Path::Ident("e".to_string())]),
        Err(Error::InvalidPath(Path::Ident("e".to_string())))
    );
}

use ethereum_types::U256;
use merkle_partial::cache::hash_children;
use merkle_partial::field::{Composite, Leaf, Node, Primitive};
use merkle_partial::impls::replace_index;
use merkle_partial::tree_arithmetic::zeroed::{
    general_index_to_subtree, relative_depth, root_from_depth, subtree_index_to_general,
};
use merkle_partial::{Error, MerkleTreeOverlay, NodeIndex, Partial, Path, SerializedPartial};
use ssz_types::VariableList;
use typenum::U8;

// A's merkle tree
//
//        a_root(0)
//       /         \
//      a(1)      b(2)
//                 /   \
//           data(5) len(6)
//           /      \
//      i(11)        i(12)
//      /   \       /     \
//  b0(23) b2(24) b4(26) b6(27)
#[derive(Debug, Default)]
struct S {
    a: U256,
    b: VariableList<u128, U8>,
}

// Implemented by derive macro
impl MerkleTreeOverlay for S {
    fn height() -> u8 {
        1
    }

    fn first_leaf() -> NodeIndex {
        1
    }

    fn last_leaf() -> NodeIndex {
        2
    }

    fn get_node(index: NodeIndex) -> Node {
        match index {
            0 => Node::Composite(Composite {
                ident: "".to_owned(),
                index: 0,
                height: Self::height().into(),
            }),
            1 => Node::Leaf(Leaf::Primitive(vec![Primitive {
                ident: "a".to_owned(),
                index: 1,
                size: 32,
                offset: 0,
            }])),
            2 => Node::Composite(Composite {
                ident: "b".to_owned(),
                index: 2,
                height: 3,
            }),
            _ => {
                let subtree_root =
                    root_from_depth(index, relative_depth(Self::first_leaf(), index));
                let subtree_index = general_index_to_subtree(subtree_root, index);

                if subtree_root == 2 {
                    replace_index(<VariableList<u128, U8>>::get_node(subtree_index), index)
                } else {
                    Node::Unattached(index)
                }
            }
        }
    }

    fn get_node_from_path(path: Vec<Path>) -> merkle_partial::Result<Node> {
        if Some(&Path::Ident("a".to_string())) == path.first() {
            if path.len() == 1 {
                Ok(Self::get_node(1))
            } else {
                match U256::get_node_from_path(path[1..].to_vec()) {
                    Ok(n) => Ok(replace_index(
                        n.clone(),
                        subtree_index_to_general(1, n.get_index()),
                    )),
                    e => e,
                }
            }
        } else if Some(&Path::Ident("b".to_string())) == path.first() {
            if path.len() == 1 {
                Ok(Self::get_node(2))
            } else {
                match VariableList::<u128, U8>::get_node_from_path(path[1..].to_vec()) {
                    Ok(n) => Ok(replace_index(
                        n.clone(),
                        subtree_index_to_general(2, n.get_index()),
                    )),
                    e => e,
                }
            }
        } else if let Some(p) = path.first() {
            Err(merkle_partial::Error::InvalidPath(p.clone()))
        } else {
            Err(merkle_partial::Error::EmptyPath())
        }
    }
}

#[test]
fn roundtrip_partial() {
    let mut arr = [0_u8; 160];
    arr[15] = 0;
    arr[31] = 1;
    arr[47] = 2;
    arr[63] = 3;
    arr[127] = 3; // length

    let twelve: &[u8] = &hash_children(&arr[64..96], &arr[64..96]);

    arr[64..96].copy_from_slice(twelve);

    let sp = SerializedPartial {
        indices: vec![23, 24, 12, 6, 1],
        chunks: arr.to_vec(),
    };

    let mut p = Partial::<S>::default();

    assert_eq!(p.load_partial(sp.clone()), Ok(()));
    assert_eq!(p.fill(), Ok(()));
    assert_eq!(
        p.extract_partial(vec![Path::Ident("b".to_string()), Path::Index(2)]),
        Ok(sp)
    );

    assert_eq!(
        p.get_bytes(vec![Path::Ident("b".to_string()), Path::Index(2)]),
        Ok(arr[32..48].to_vec())
    );
}

#[test]
fn get_paths() {
    let mut arr = [0_u8; 160];

    arr[31] = 1;
    arr[47] = 0;
    arr[63] = 1;
    arr[79] = 2;
    arr[95] = 3;
    arr[111] = 4;
    arr[127] = 5;
    arr[143] = 6;
    arr[159] = 7;

    let sp = SerializedPartial {
        indices: vec![1, 23, 24, 25, 26],
        chunks: arr.to_vec(),
    };

    let mut p = Partial::<S>::default();

    assert_eq!(p.load_partial(sp.clone()), Ok(()));

    assert_eq!(
        p.get_bytes(vec![Path::Ident("a".to_string())]),
        Ok(arr[0..32].to_vec())
    );

    for i in 0_usize..8_usize {
        assert_eq!(
            p.get_bytes(vec![Path::Ident("b".to_string()), Path::Index(i as u64)]),
            Ok(arr[(32 + i * 16)..(32 + ((i + 1) * 16))].to_vec())
        );
    }

    assert_eq!(
        p.get_bytes(vec![Path::Ident("b".to_string()), Path::Index(8)]),
        Err(Error::InvalidPath(Path::Index(8))),
    );

    assert_eq!(
        p.get_bytes(vec![Path::Ident("b".to_string()), Path::Index(8000)]),
        Err(Error::InvalidPath(Path::Index(8000))),
    );

    assert_eq!(
        p.get_bytes(vec![Path::Ident("c".to_string())]),
        Err(Error::InvalidPath(Path::Ident("c".to_string()))),
    );
}

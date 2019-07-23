use merkle_partial::cache::hash_children;
use merkle_partial::field::{Composite, Leaf, Node, Primitive};
use merkle_partial::impls::replace_index;
use merkle_partial::tree_arithmetic::zeroed::{
    general_index_to_subtree, relative_depth, root_from_depth, subtree_index_to_general,
};
use merkle_partial::{MerkleTreeOverlay, NodeIndex, Partial, Path, SerializedPartial};
use ssz_types::{FixedVector, VariableList};
use typenum::{U32, U8};

// S's merkle tree
//
//           root(0)
//          /       \
//    data_root(1) len(2)
//      /     \
// a[0,1](3) a[2,3](4)
#[derive(Debug, Default)]
struct Message {
    timestamp: u64,
    message: FixedVector<u8, U32>,
}

#[derive(Debug, Default)]
struct State {
    messages: VariableList<Message, U8>,
}

impl MerkleTreeOverlay for Message {
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
                height: Self::height(),
            }),
            1 => Node::Leaf(Leaf::Primitive(vec![Primitive {
                ident: "timestamp".to_string(),
                index: 1,
                size: 8,
                offset: 0,
            }])),
            2 => Node::Composite(Composite {
                ident: "message".to_string(),
                index: 2,
                height: FixedVector::<u8, U32>::height(),
            }),
            _ => {
                let subtree_root =
                    root_from_depth(index, relative_depth(Self::first_leaf(), index));
                let subtree_index = general_index_to_subtree(subtree_root, index);

                if subtree_root == 2 {
                    replace_index(FixedVector::<u8, U32>::get_node(subtree_index), index)
                } else {
                    Node::Unattached(index)
                }
            }
        }
    }

    fn get_node_from_path(path: Vec<Path>) -> merkle_partial::Result<Node> {
        if Some(&Path::Ident("timestamp".to_string())) == path.first() {
            Ok(Self::get_node(1))
        } else if Some(&Path::Ident("message".to_string())) == path.first() {
            match FixedVector::<u8, U32>::get_node_from_path(path[1..].to_vec()) {
                Ok(n) => Ok(replace_index(
                    n.clone(),
                    subtree_index_to_general(2, n.get_index()),
                )),
                e => e,
            }
        } else if let Some(p) = path.first() {
            Err(merkle_partial::Error::InvalidPath(p.clone()))
        } else {
            Err(merkle_partial::Error::EmptyPath())
        }
    }
}

// Implemented by derive macro
impl MerkleTreeOverlay for State {
    fn height() -> u8 {
        0
    }

    fn first_leaf() -> NodeIndex {
        0
    }

    fn last_leaf() -> NodeIndex {
        0
    }

    fn get_node(index: NodeIndex) -> Node {
        if index == 0 {
            Node::Composite(Composite {
                ident: "messages".to_owned(),
                index: 0,
                height: VariableList::<Message, U8>::height().into(),
            })
        } else {
            VariableList::<Message, U8>::get_node(index)
        }
    }

    fn get_node_from_path(path: Vec<Path>) -> merkle_partial::Result<Node> {
        if Some(&Path::Ident("messages".to_string())) == path.first() {
            if path.len() == 1 {
                Ok(Self::get_node(0))
            } else {
                VariableList::<Message, U8>::get_node_from_path(path[1..].to_vec())
            }
        } else if let Some(p) = path.first() {
            Err(merkle_partial::Error::InvalidPath(p.clone()))
        } else {
            Err(merkle_partial::Error::EmptyPath())
        }
    }
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

    let mut partial = Partial::<State>::default();

    assert_eq!(partial.load_partial(sp), Ok(()));
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

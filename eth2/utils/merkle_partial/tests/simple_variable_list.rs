use hashing::hash;
use merkle_partial::field::{Composite, Node};
use merkle_partial::{Error, MerkleTreeOverlay, NodeIndex, Partial, Path, SerializedPartial};
use ssz_types::VariableList;
use typenum::U4;

// S's merkle tree
//
//           root(0)
//          /       \
//    data_root(1) len(2)
//      /     \
// a[0,1](3) a[2,3](4)
#[derive(Debug, Default)]
struct S {
    a: VariableList<u128, U4>,
}

impl MerkleTreeOverlay for S {
    fn height() -> u8 {
        0
    }

    fn first_leaf() -> NodeIndex {
        0
    }

    fn last_leaf() -> NodeIndex {
        0
    }

    fn get_node(path: Vec<Path>) -> Result<Node, Error> {
        if Some(&Path::Ident("a".to_string())) == path.first() {
            if path.len() == 1 {
                Ok(Node::Composite(Composite {
                    ident: "a".to_owned(),
                    index: 0,
                    height: VariableList::<u128, U4>::height().into(),
                }))
            } else {
                VariableList::<u128, U4>::get_node(path[1..].to_vec())
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
    let mut chunk = [0_u8; 96];
    chunk[15] = 1;
    chunk[31] = 2;
    chunk[47] = 3;
    chunk[63] = 4;
    chunk[64..96].copy_from_slice(&hash(&[0; 64]));

    let partial = SerializedPartial {
        indices: vec![3, 4, 2],
        chunks: chunk.to_vec(),
    };

    let mut p = Partial::<S>::new(partial.clone());
    assert_eq!(p.fill(), Ok(()));

    assert_eq!(
        Ok(partial),
        p.extract_partial(vec![Path::Ident("a".to_string()), Path::Index(0)])
    );
}

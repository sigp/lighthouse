use ethereum_types::U256;
use hashing::hash;
use merkle_partial::field::{Composite, Node};
use merkle_partial::{MerkleTreeOverlay, NodeIndex, Partial, Path, SerializedPartial};
use ssz_types::FixedVector;
use typenum::U4;

// S's merkle tree
//
//        c_root(0)
//       /         \
//     i(1)       i(2)
//     /  \       /  \
//   a[0] a[1]  a[2] a[3]
#[derive(Debug, Default)]
struct S {
    a: FixedVector<U256, U4>,
}

// Implemented by derive macro
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

    fn get_node(index: NodeIndex) -> Node {
        if index == 0 {
            Node::Composite(Composite {
                ident: "a".to_owned(),
                index: 0,
                height: FixedVector::<U256, U4>::height().into(),
            })
        } else {
            FixedVector::<U256, U4>::get_node(index)
        }
    }

    fn get_node_from_path(path: Vec<Path>) -> merkle_partial::Result<Node> {
        if Some(&Path::Ident("a".to_string())) == path.first() {
            if path.len() == 1 {
                Ok(Self::get_node(0))
            } else {
                FixedVector::<U256, U4>::get_node_from_path(path[1..].to_vec())
            }
        } else if let Some(p) = path.first() {
            Err(merkle_partial::Error::InvalidPath(p.clone()))
        } else {
            Err(merkle_partial::Error::EmptyPath())
        }
    }
}

#[test]
fn get_partial_vector() {
    let mut chunk = [0_u8; 96];
    chunk[31] = 1;
    chunk[64..96].copy_from_slice(&hash(&[0; 64]));

    let partial = SerializedPartial {
        indices: vec![5, 6, 1],
        chunks: chunk.to_vec(),
    };

    let mut p = Partial::<S>::default();

    assert_eq!(p.load_partial(partial.clone()), Ok(()));
    assert_eq!(p.fill(), Ok(()));
    assert_eq!(
        Ok(partial),
        p.extract_partial(vec![Path::Ident("a".to_string()), Path::Index(2)])
    );
}

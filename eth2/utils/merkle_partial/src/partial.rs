use super::{NodeIndex, SerializedPartial};
use crate::cache::Cache;
use crate::error::{Error, Result};
use crate::merkle_tree_overlay::path_matcher::match_path;
use crate::merkle_tree_overlay::MerkleTreeOverlay;
use crate::path::Path;
use crate::tree_arithmetic::zeroed::{expand_tree_index, sibling_index};
use hashing::hash;
use std::marker::PhantomData;
use tree_hash::BYTES_PER_CHUNK;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Partial<T: MerkleTreeOverlay> {
    cache: Cache,
    _phantom: PhantomData<T>,
}

/// The `Partial` trait allows for `SerializedPartial`s to be generated and verified for a struct.
impl<T: MerkleTreeOverlay> Partial<T> {
    /// Populates the struct's cache with a `SerializedPartial`.
    pub fn load_partial(&mut self, partial: SerializedPartial) -> Result<()> {
        for (i, index) in partial.indices.iter().enumerate() {
            let chunk = partial.chunks[i * BYTES_PER_CHUNK..(i + 1) * BYTES_PER_CHUNK].to_vec();
            self.cache.insert(*index, chunk.clone());
        }

        Ok(())
    }

    /// Generates a `SerializedPartial` proving that `path` is a part of the current merkle tree.
    pub fn extract_partial(&self, path: Vec<Path>) -> Result<SerializedPartial> {
        let (indices, chunks) = extract_partial_helper::<T>(
            &self.cache,
            0,
            T::height(),
            path,
            &mut vec![],
            &mut vec![],
        )?;

        Ok(SerializedPartial { indices, chunks })
    }

    /// Returns the bytes representation of the object associated with `path`
    pub fn bytes_at_path(&self, path: Vec<Path>) -> Result<Vec<u8>> {
        if path.len() == 0 {
            return Err(Error::EmptyPath());
        }

        let (index, begin, end) = bytes_at_path_helper::<T>(path, 0, T::height())?;

        Ok(self.cache.get(index).ok_or(Error::MissingNode(index))?[begin..end].to_vec())
    }

    /// Return whether a path has been loade into the partial.
    pub fn is_path_loaded(&self, path: Vec<Path>) -> bool {
        if let Ok(_) = self.bytes_at_path(path) {
            true
        } else {
            false
        }
    }

    /// Determines if the current merkle tree is valid.
    pub fn is_valid(&self) -> bool {
        for node in self.cache.nodes() {
            let (left, right, parent) = expand_tree_index(node);

            if node > 1 {
                let left = self.cache.get(left);
                let right = self.cache.get(right);
                let parent = self.cache.get(parent);

                if let (Some(left), Some(right), Some(parent)) = (left, right, parent) {
                    if hash_children(&left, &right) != *parent {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Inserts missing nodes into the merkle tree that can be generated from existing nodes.
    pub fn fill(&mut self) -> Result<()> {
        let mut nodes: Vec<u64> = self.cache.nodes();
        nodes.sort_by(|a, b| b.cmp(a));

        let mut position = 0;
        while position < nodes.len() {
            let (left, right, parent) = expand_tree_index(nodes[position]);

            if self.cache.contains_node(left)
                && self.cache.contains_node(right)
                && !self.cache.contains_node(parent)
            {
                let h = hash_children(
                    &self.cache.get(left).ok_or(Error::MissingNode(left))?,
                    &self.cache.get(right).ok_or(Error::MissingNode(right))?,
                );

                self.cache.insert(parent, h);
                nodes.push(parent);
            }

            position += 1;
        }

        Ok(())
    }
}

/// Recursively traverse the tree structure, matching the appropriate `path` element with its index,
/// eventually returning the `indicies` and `chunks` needed to generate the partial for the path.
fn extract_partial_helper<T: MerkleTreeOverlay + ?Sized>(
    cache: &Cache,
    root: NodeIndex,
    height: u8,
    path: Vec<Path>,
    indices: &mut Vec<NodeIndex>,
    chunks: &mut Vec<u8>,
) -> Result<(Vec<NodeIndex>, Vec<u8>)> {
    if path.len() == 0 {
        return Ok((indices.clone(), chunks.clone()));
    }

    let (index, height, _, _) = match_path::<T>(path[0].clone(), root, height)?;

    // When the height is 0, the node is a basic value
    if height == 0 {
        indices.push(index);
        chunks.extend(cache.get(index).ok_or(Error::MissingNode(index))?);
    }

    let mut visitor = index;
    while visitor > root {
        let sibling = sibling_index(visitor);
        let left = 2 * sibling + 1;
        let right = 2 * sibling + 2;

        if !(indices.contains(&left) && indices.contains(&right)) {
            indices.push(sibling);
            chunks.extend(cache.get(sibling).ok_or(Error::MissingNode(sibling))?);
        }

        visitor /= 2;
    }

    extract_partial_helper::<T>(cache, index, height, path[1..].to_vec(), indices, chunks)
}

/// Recursively traverse the tree structure, matching the appropriate `path` element with its index,
/// eventually returning the chunk index, beginning offset, and end offset of the associated value.
fn bytes_at_path_helper<T: MerkleTreeOverlay + ?Sized>(
    path: Vec<Path>,
    root: NodeIndex,
    height: u8,
) -> Result<(NodeIndex, usize, usize)> {
    if path.len() == 0 {
        return Err(Error::EmptyPath());
    }

    if let Ok((index, height, offset, size)) = match_path::<T>(path[0].clone(), root, height) {
        if path.len() == 1 {
            let begin: usize = offset as usize;
            let end: usize = begin + size as usize;

            return Ok((index, begin, end));
        } else {
            return bytes_at_path_helper::<T>(path[1..].to_vec(), index, height);
        }
    }

    Err(Error::InvalidPath(path[0].clone()))
}

/// Helper function that appends `right` to `left` and hashes the result.
fn hash_children(left: &[u8], right: &[u8]) -> Vec<u8> {
    let children: Vec<u8> = left.iter().cloned().chain(right.iter().cloned()).collect();
    hash(&children)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{Composite, Leaf, Node, Primitive};
    use ethereum_types::U256;
    use ssz_types::{FixedVector, VariableList};
    use typenum::U4;

    #[derive(Debug, Default)]
    struct A {
        a: U256,
        b: U256,
        c: u128,
        d: u128,
        // Should be added by derive macro
        cache: Cache,
    }

    // A's merkle tree
    //
    //        a_root(0)
    //       /         \
    //     i(1)       i(2)
    //    /   \       /   \
    //  a(3) b(4)  c,d(5) p(6)
    //
    // n(i) => n = node type, i = general index
    // i = intermediate, p = padding

    // Should be implemented by derive macro
    impl MerkleTreeOverlay for A {
        fn height() -> u8 {
            2
        }

        fn first_leaf() -> NodeIndex {
            3
        }

        fn last_leaf() -> NodeIndex {
            4
        }

        fn get_node(index: NodeIndex) -> Node {
            match index {
                0 => Node::Composite(Composite {
                    ident: "".to_owned(),
                    index: 1,
                    height: Self::height().into(),
                }),
                1 => Node::Intermediate(2),
                2 => Node::Intermediate(3),
                3 => Node::Leaf(Leaf::Primitive(vec![Primitive {
                    ident: "a".to_owned(),
                    index: index,
                    size: 32,
                    offset: 0,
                }])),
                4 => Node::Leaf(Leaf::Primitive(vec![Primitive {
                    ident: "b".to_owned(),
                    index: index,
                    size: 32,
                    offset: 0,
                }])),
                5 => Node::Leaf(Leaf::Primitive(vec![
                    Primitive {
                        ident: "c".to_owned(),
                        index: index,
                        size: 16,
                        offset: 0,
                    },
                    Primitive {
                        ident: "d".to_owned(),
                        index: index,
                        size: 16,
                        offset: 16,
                    },
                ])),
                6 => Node::Leaf(Leaf::Padding()),
                n => unimplemented!("get node: {:?}", n),
            }
        }
    }

    #[derive(Debug, Default)]
    struct B {
        a: VariableList<u128, U4>,
        cache: Cache,
    }

    // B's merkle tree
    //
    //        b_root(0)
    //       /         \
    // b_data_root(1) b_len(2)
    //    /   \
    //  . . . . .
    //

    // Should be implemented by derive macro
    impl MerkleTreeOverlay for B {
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
                    height: VariableList::<u128, U4>::height().into(),
                })
            } else {
                VariableList::<u128, U4>::get_node(index)
            }
        }
    }

    #[derive(Debug, Default)]
    struct C {
        a: VariableList<U256, U4>,
        cache: Cache,
    }

    // C's merkle tree
    //
    //        c_root(0)
    //       /         \
    //     i(1)       i(2)
    //     /  \       /  \
    //   a[0] a[1]  a[2] a[3]

    // Should be implemented by derive macro
    impl MerkleTreeOverlay for C {
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
    }

    #[test]
    fn is_valid_partial() {
        let mut cache: Cache = Cache::default();

        // leaf nodes
        cache.insert(6, vec![6; BYTES_PER_CHUNK]);
        cache.insert(5, vec![5; BYTES_PER_CHUNK]);
        cache.insert(4, vec![4; BYTES_PER_CHUNK]);
        cache.insert(3, vec![3; BYTES_PER_CHUNK]);

        // intermediate nodes
        cache.insert(2, hash_children(&cache[5], &cache[6]));
        cache.insert(1, hash_children(&cache[3], &cache[4]));

        // root node
        cache.insert(0, hash_children(&cache[1], &cache[2]));

        let p = Partial::<A>::default();

        assert_eq!(p.is_valid(), true);
    }

    #[test]
    fn can_fill_cache() {
        let mut p = Partial::<A>::default();

        // leaf nodes
        p.cache.insert(7, vec![7; BYTES_PER_CHUNK]);
        p.cache.insert(6, vec![6; BYTES_PER_CHUNK]);
        p.cache.insert(5, vec![5; BYTES_PER_CHUNK]);
        p.cache.insert(4, vec![4; BYTES_PER_CHUNK]);

        assert_eq!(p.fill(), Ok(()));
        assert_eq!(p.is_valid(), true);
    }

    #[test]
    fn load_partial_basic_container() {
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

    #[test]
    fn get_partial_basic_container() {
        let three = U256::from(1);
        let four = U256::from(2);

        let mut arr = [0_u8; 96];

        four.to_little_endian(&mut arr[0..32]);
        three.to_little_endian(&mut arr[32..64]);

        let two: &[u8] = &hash_children(&arr[64..96], &arr[64..96]);

        arr[64..96].copy_from_slice(two);

        let partial = SerializedPartial {
            indices: vec![4, 3, 2],
            chunks: arr.to_vec(),
        };

        let mut p = Partial::<A>::default();

        assert_eq!(p.load_partial(partial.clone()), Ok(()));
        assert_eq!(p.fill(), Ok(()));
        assert_eq!(
            Ok(partial),
            p.extract_partial(vec![Path::Ident("a".to_string())])
        );
    }

    #[test]
    fn get_partial_list() {
        let mut chunk = [0_u8; 128];
        chunk[15] = 1;
        chunk[31] = 2;
        chunk[32..64].copy_from_slice(&hash(&[0; 64]));
        chunk[127] = 2;

        let partial = SerializedPartial {
            indices: vec![7, 8, 4, 2],
            chunks: chunk.to_vec(),
        };

        let mut p = Partial::<B>::default();

        assert_eq!(p.load_partial(partial.clone()), Ok(()));
        assert_eq!(p.fill(), Ok(()));

        assert_eq!(
            Ok(partial),
            p.extract_partial(vec![Path::Ident("a".to_string()), Path::Index(0)])
        );
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

        let mut p = Partial::<C>::default();
        assert_eq!(p.load_partial(partial.clone()), Ok(()));
        assert_eq!(p.fill(), Ok(()));

        assert_eq!(
            Ok(partial),
            p.extract_partial(vec![Path::Ident("a".to_string()), Path::Index(2)])
        );
    }
}

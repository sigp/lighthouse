use super::{NodeIndex, SerializedPartial};
use crate::cache::Cache;
use crate::error::{Error, Result};
use crate::field::{Leaf, Node};
use crate::merkle_tree_overlay::path_matcher::match_path;
use crate::merkle_tree_overlay::MerkleTreeOverlay;
use crate::path::Path;
use crate::tree_arithmetic::zeroed::{expand_tree_index, sibling_index};
use hashing::hash;
use tree_hash::BYTES_PER_CHUNK;

/// The `Partial` trait allows for `SerializedPartial`s to be generated and verified for a struct.
pub trait Partial: MerkleTreeOverlay + Sized {
    /// Gets a reference to the struct's `Cache` which stores known nodes.
    fn get_cache(&self) -> &Cache;

    /// Gets a mutable reference to the struct's `Cache` which stores known nodes.
    fn get_cache_mut(&mut self) -> &mut Cache;

    /// Generates a `SerializedPartial` proving that `path` is a part of the current merkle tree.
    fn extract_partial(&self, path: Vec<Path>) -> Result<SerializedPartial> {
        let (indices, chunks) = extract_partial_helper::<Self>(
            self.get_cache(),
            0,
            Self::height(),
            path,
            &mut vec![],
            &mut vec![],
        )?;

        Ok(SerializedPartial { indices, chunks })
    }

    /// Populates the struct's cache with a `SerializedPartial`.
    fn load_partial(&mut self, partial: SerializedPartial) -> Result<()> {
        for (i, index) in partial.indices.iter().enumerate() {
            let chunk = partial.chunks[i * BYTES_PER_CHUNK..(i + 1) * BYTES_PER_CHUNK].to_vec();
            self.get_cache_mut().insert(*index, chunk.clone());
        }

        Ok(())
    }

    /// Returns the bytes representation of the object associated with `path`
    fn bytes_at_path(&self, path: Vec<Path>, root: NodeIndex) -> Result<Vec<u8>> {
        if path.len() == 0 {
            return Err(Error::EmptyPath());
        }

        let (index, begin, end) = bytes_at_path_helper::<Self>(path, root, Self::height())?;

        Ok(self
            .get_cache()
            .get(index)
            .ok_or(Error::MissingNode(index))?[begin..end]
            .to_vec())
    }

    /// Return whether a path has been loade into the partial.
    fn is_path_loaded(&self, path: Vec<&str>) -> bool {
        let height = Self::height();

        let mut leaves: Vec<Node> = vec![];
        for i in 2_u64.pow(height as u32)..(2_u64.pow(height as u32 + 1) - 1) {
            leaves.push(Self::get_node(i as NodeIndex - 1));
        }

        for leaf in leaves {
            if let Node::Leaf(Leaf::Basic(chunk_fields)) = leaf {
                for field in chunk_fields {
                    if path[0] == field.ident {
                        if let Some(_) = self.get_cache().get(field.index) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Determines if the current merkle tree is valid.
    fn is_valid(&self) -> bool {
        let cache = self.get_cache();
        for node in cache.nodes() {
            let (left, right, parent) = expand_tree_index(node);

            if node > 1 {
                let left = cache.get(left);
                let right = cache.get(right);
                let parent = cache.get(parent);

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
    fn fill(&mut self) -> Result<()> {
        let cache = self.get_cache_mut();

        let mut nodes: Vec<u64> = cache.nodes();
        nodes.sort_by(|a, b| b.cmp(a));

        let mut position = 0;
        while position < nodes.len() {
            let (left, right, parent) = expand_tree_index(nodes[position]);

            if cache.contains_node(left)
                && cache.contains_node(right)
                && !cache.contains_node(parent)
            {
                let h = hash_children(
                    &cache.get(left).ok_or(Error::MissingNode(left))?,
                    &cache.get(right).ok_or(Error::MissingNode(right))?,
                );

                cache.insert(parent, h);
                nodes.push(parent);
            }

            position += 1;
        }

        Ok(())
    }
}

/// Recursively traverse the tree structure, matching the appropriate `path` element with its index,
/// eventually returning the `indicies` and `chunks` needed to generate the partial for the path.
fn extract_partial_helper<T: MerkleTreeOverlay>(
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
fn bytes_at_path_helper<T: MerkleTreeOverlay>(
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
    use crate::field::{Basic, Composite, Leaf, Node};
    use ethereum_types::U256;
    use ssz_types::VariableList;
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
                3 => Node::Leaf(Leaf::Basic(vec![Basic {
                    ident: "a".to_owned(),
                    index: index,
                    size: 32,
                    offset: 0,
                }])),
                4 => Node::Leaf(Leaf::Basic(vec![Basic {
                    ident: "b".to_owned(),
                    index: index,
                    size: 32,
                    offset: 0,
                }])),
                5 => Node::Leaf(Leaf::Basic(vec![
                    Basic {
                        ident: "c".to_owned(),
                        index: index,
                        size: 16,
                        offset: 0,
                    },
                    Basic {
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

    impl Partial for A {
        fn get_cache(&self) -> &Cache {
            &self.cache
        }

        fn get_cache_mut(&mut self) -> &mut Cache {
            &mut self.cache
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

    impl Partial for B {
        fn get_cache(&self) -> &Cache {
            &self.cache
        }

        fn get_cache_mut(&mut self) -> &mut Cache {
            &mut self.cache
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

        let mut a = A::default();
        a.cache = cache;

        assert_eq!(a.is_valid(), true);
    }

    #[test]
    fn can_fill_cache() {
        let mut cache = Cache::default();

        // leaf nodes
        cache.insert(7, vec![7; BYTES_PER_CHUNK]);
        cache.insert(6, vec![6; BYTES_PER_CHUNK]);
        cache.insert(5, vec![5; BYTES_PER_CHUNK]);
        cache.insert(4, vec![4; BYTES_PER_CHUNK]);

        let mut a = A {
            a: 1.into(),
            b: 2.into(),
            c: 3,
            d: 4,
            cache,
        };

        assert_eq!(a.fill(), Ok(()));
        assert_eq!(a.is_valid(), true);
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

        let mut a = A::default();

        assert_eq!(a.load_partial(partial.clone()), Ok(()));

        assert_eq!(a.is_path_loaded(vec!["a"]), true);
        assert_eq!(
            a.bytes_at_path(vec![Path::Ident("a".to_string())], 0),
            Ok(arr[0..32].to_vec())
        );

        assert_eq!(a.is_path_loaded(vec!["b"]), true);
        assert_eq!(
            a.bytes_at_path(vec![Path::Ident("b".to_string())], 0),
            Ok(arr[32..64].to_vec())
        );

        assert_eq!(a.is_path_loaded(vec!["c"]), true);
        assert_eq!(
            a.bytes_at_path(vec![Path::Ident("c".to_string())], 0),
            Ok(arr[64..80].to_vec())
        );

        assert_eq!(a.is_path_loaded(vec!["d"]), true);
        assert_eq!(
            a.bytes_at_path(vec![Path::Ident("d".to_string())], 0),
            Ok(arr[80..96].to_vec())
        );

        assert_eq!(a.is_path_loaded(vec!["e"]), false);
        assert_eq!(
            a.bytes_at_path(vec![Path::Ident("e".to_string())], 0),
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

        let mut a = A::default();

        assert_eq!(a.load_partial(partial.clone()), Ok(()));
        assert_eq!(a.fill(), Ok(()));
        assert_eq!(
            Ok(partial),
            a.extract_partial(vec![Path::Ident("a".to_string())])
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

        let mut b = B::default();

        assert_eq!(b.load_partial(partial.clone()), Ok(()));
        assert_eq!(b.fill(), Ok(()));

        assert_eq!(
            Ok(partial),
            b.extract_partial(vec![Path::Ident("a".to_string()), Path::Index(0)])
        );
    }

}

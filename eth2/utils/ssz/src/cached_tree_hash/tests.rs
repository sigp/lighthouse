use super::*;
use int_to_bytes::int_to_bytes32;

#[derive(Clone)]
pub struct Inner {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
}

impl CachedTreeHash for Inner {
    type Item = Self;

    fn leaves_and_subtrees(&self) -> Vec<u8> {
        let mut leaves_and_subtrees = vec![];

        leaves_and_subtrees.append(&mut self.a.leaves_and_subtrees());
        leaves_and_subtrees.append(&mut self.b.leaves_and_subtrees());
        leaves_and_subtrees.append(&mut self.c.leaves_and_subtrees());
        leaves_and_subtrees.append(&mut self.d.leaves_and_subtrees());

        leaves_and_subtrees
    }

    fn num_bytes(&self) -> usize {
        let mut bytes = 0;

        bytes += self.a.num_bytes();
        bytes += self.b.num_bytes();
        bytes += self.c.num_bytes();
        bytes += self.d.num_bytes();

        bytes
    }

    fn offsets(&self) -> Result<Vec<usize>, Error> {
        let mut offsets = vec![];

        offsets.push(self.a.num_child_nodes() + 1);
        offsets.push(self.b.num_child_nodes() + 1);
        offsets.push(self.c.num_child_nodes() + 1);
        offsets.push(self.d.num_child_nodes() + 1);

        Ok(offsets)
    }

    fn num_child_nodes(&self) -> usize {
        let mut children = 0;
        let leaves = 4;

        children += self.a.num_child_nodes();
        children += self.b.num_child_nodes();
        children += self.c.num_child_nodes();
        children += self.d.num_child_nodes();

        num_nodes(leaves) + children - 1
    }

    fn cached_hash_tree_root(
        &self,
        other: &Self,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Result<usize, Error> {
        let offset_handler = OffsetHandler::new(self, chunk)?;

        // Skip past the internal nodes and update any changed leaf nodes.
        {
            let chunk = offset_handler.first_leaf_node()?;
            let chunk = self.a.cached_hash_tree_root(&other.a, cache, chunk)?;
            let chunk = self.b.cached_hash_tree_root(&other.b, cache, chunk)?;
            let chunk = self.c.cached_hash_tree_root(&other.c, cache, chunk)?;
            let _chunk = self.d.cached_hash_tree_root(&other.d, cache, chunk)?;
        }

        for (&parent, children) in offset_handler.iter_internal_nodes().rev() {
            if cache.either_modified(children)? {
                cache.modify_chunk(parent, &cache.hash_children(children)?)?;
            }
        }

        Ok(offset_handler.next_node())
    }
}

#[derive(Clone)]
pub struct Outer {
    pub a: u64,
    pub b: Inner,
    pub c: u64,
}

impl CachedTreeHash for Outer {
    type Item = Self;

    fn leaves_and_subtrees(&self) -> Vec<u8> {
        let mut leaves_and_subtrees = vec![];

        leaves_and_subtrees.append(&mut self.a.leaves_and_subtrees());
        leaves_and_subtrees.append(&mut self.b.leaves_and_subtrees());
        leaves_and_subtrees.append(&mut self.c.leaves_and_subtrees());

        leaves_and_subtrees
    }

    fn num_bytes(&self) -> usize {
        let mut bytes = 0;
        bytes += self.a.num_bytes();
        bytes += self.b.num_bytes();
        bytes += self.c.num_bytes();
        bytes
    }

    fn num_child_nodes(&self) -> usize {
        let mut children = 0;
        let leaves = 3;

        children += self.a.num_child_nodes();
        children += self.b.num_child_nodes();
        children += self.c.num_child_nodes();

        num_nodes(leaves) + children - 1
    }

    fn offsets(&self) -> Result<Vec<usize>, Error> {
        let mut offsets = vec![];

        offsets.push(self.a.num_child_nodes() + 1);
        offsets.push(self.b.num_child_nodes() + 1);
        offsets.push(self.c.num_child_nodes() + 1);

        Ok(offsets)
    }

    fn cached_hash_tree_root(
        &self,
        other: &Self,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Result<usize, Error> {
        let offset_handler = OffsetHandler::new(self, chunk)?;

        // Skip past the internal nodes and update any changed leaf nodes.
        {
            let chunk = offset_handler.first_leaf_node()?;
            let chunk = self.a.cached_hash_tree_root(&other.a, cache, chunk)?;
            let chunk = self.b.cached_hash_tree_root(&other.b, cache, chunk)?;
            let _chunk = self.c.cached_hash_tree_root(&other.c, cache, chunk)?;
        }

        for (&parent, children) in offset_handler.iter_internal_nodes().rev() {
            if cache.either_modified(children)? {
                cache.modify_chunk(parent, &cache.hash_children(children)?)?;
            }
        }

        Ok(offset_handler.next_node())
    }
}

fn join(many: Vec<Vec<u8>>) -> Vec<u8> {
    let mut all = vec![];
    for one in many {
        all.extend_from_slice(&mut one.clone())
    }
    all
}

#[test]
fn partial_modification_to_inner_struct() {
    let original_inner = Inner {
        a: 1,
        b: 2,
        c: 3,
        d: 4,
    };

    let original_outer = Outer {
        a: 0,
        b: original_inner.clone(),
        c: 5,
    };

    let modified_inner = Inner {
        a: 42,
        ..original_inner.clone()
    };

    // Modify outer
    let modified_outer = Outer {
        b: modified_inner.clone(),
        ..original_outer.clone()
    };

    println!("AAAAAAAAA");
    // Perform a differential hash
    let mut cache_struct = TreeHashCache::new(&original_outer).unwrap();
    println!("BBBBBBBBBB");

    modified_outer
        .cached_hash_tree_root(&original_outer, &mut cache_struct, 0)
        .unwrap();

    let modified_cache: Vec<u8> = cache_struct.into();

    // Generate reference data.
    let mut data = vec![];
    data.append(&mut int_to_bytes32(0));
    let inner_bytes: Vec<u8> = TreeHashCache::new(&modified_inner).unwrap().into();
    data.append(&mut int_to_bytes32(5));

    let leaves = vec![
        int_to_bytes32(0),
        inner_bytes[0..32].to_vec(),
        int_to_bytes32(5),
        vec![0; 32], // padding
    ];
    let mut merkle = merkleize(join(leaves));
    merkle.splice(4 * 32..5 * 32, inner_bytes);

    assert_eq!(merkle.len() / HASHSIZE, 13);
    assert_eq!(modified_cache.len() / HASHSIZE, 13);

    assert_eq!(merkle, modified_cache);
}

#[test]
fn partial_modification_to_outer() {
    let inner = Inner {
        a: 1,
        b: 2,
        c: 3,
        d: 4,
    };

    let original_outer = Outer {
        a: 0,
        b: inner.clone(),
        c: 5,
    };

    // Build the initial cache.
    // let original_cache = original_outer.build_cache_bytes();

    // Modify outer
    let modified_outer = Outer {
        c: 42,
        ..original_outer.clone()
    };

    // Perform a differential hash
    let mut cache_struct = TreeHashCache::new(&original_outer).unwrap();

    modified_outer
        .cached_hash_tree_root(&original_outer, &mut cache_struct, 0)
        .unwrap();

    let modified_cache: Vec<u8> = cache_struct.into();

    // Generate reference data.
    let mut data = vec![];
    data.append(&mut int_to_bytes32(0));
    let inner_bytes: Vec<u8> = TreeHashCache::new(&inner).unwrap().into();
    data.append(&mut int_to_bytes32(5));

    let leaves = vec![
        int_to_bytes32(0),
        inner_bytes[0..32].to_vec(),
        int_to_bytes32(42),
        vec![0; 32], // padding
    ];
    let mut merkle = merkleize(join(leaves));
    merkle.splice(4 * 32..5 * 32, inner_bytes);

    assert_eq!(merkle.len() / HASHSIZE, 13);
    assert_eq!(modified_cache.len() / HASHSIZE, 13);

    assert_eq!(merkle, modified_cache);
}

#[test]
fn outer_builds() {
    let inner = Inner {
        a: 1,
        b: 2,
        c: 3,
        d: 4,
    };

    let outer = Outer {
        a: 0,
        b: inner.clone(),
        c: 5,
    };

    // Build the function output.
    let cache: Vec<u8> = TreeHashCache::new(&outer).unwrap().into();

    // Generate reference data.
    let mut data = vec![];
    data.append(&mut int_to_bytes32(0));
    let inner_bytes: Vec<u8> = TreeHashCache::new(&inner).unwrap().into();
    data.append(&mut int_to_bytes32(5));

    let leaves = vec![
        int_to_bytes32(0),
        inner_bytes[0..32].to_vec(),
        int_to_bytes32(5),
        vec![0; 32], // padding
    ];
    let mut merkle = merkleize(join(leaves));
    merkle.splice(4 * 32..5 * 32, inner_bytes);

    assert_eq!(merkle.len() / HASHSIZE, 13);
    assert_eq!(cache.len() / HASHSIZE, 13);

    assert_eq!(merkle, cache);
}

/*
#[test]
fn partial_modification_u64_vec() {
    let n: u64 = 50;

    let original_vec: Vec<u64> = (0..n).collect();

    // Generate initial cache.
    let original_cache = original_vec.build_cache_bytes();

    // Modify the vec
    let mut modified_vec = original_vec.clone();
    modified_vec[n as usize - 1] = 42;

    // Perform a differential hash
    let mut cache_struct = TreeHashCache::from_bytes(original_cache.clone()).unwrap();
    modified_vec.cached_hash_tree_root(&original_vec, &mut cache_struct, 0);
    let modified_cache: Vec<u8> = cache_struct.into();

    // Generate reference data.
    let mut data = vec![];
    for i in &modified_vec {
        data.append(&mut int_to_bytes8(*i));
    }
    let data = sanitise_bytes(data);
    let expected = merkleize(data);

    assert_eq!(expected, modified_cache);
}

#[test]
fn large_vec_of_u64_builds() {
    let n: u64 = 50;

    let my_vec: Vec<u64> = (0..n).collect();

    // Generate function output.
    let cache = my_vec.build_cache_bytes();

    // Generate reference data.
    let mut data = vec![];
    for i in &my_vec {
        data.append(&mut int_to_bytes8(*i));
    }
    let data = sanitise_bytes(data);
    let expected = merkleize(data);

    assert_eq!(expected, cache);
}

#[test]
fn vec_of_u64_builds() {
    let data = join(vec![
        int_to_bytes8(1),
        int_to_bytes8(2),
        int_to_bytes8(3),
        int_to_bytes8(4),
        int_to_bytes8(5),
        vec![0; 32 - 8], // padding
    ]);

    let expected = merkleize(data);

    let my_vec = vec![1, 2, 3, 4, 5];

    let cache = my_vec.build_cache_bytes();

    assert_eq!(expected, cache);
}
*/

#[test]
fn merkleize_odd() {
    let data = join(vec![
        int_to_bytes32(1),
        int_to_bytes32(2),
        int_to_bytes32(3),
        int_to_bytes32(4),
        int_to_bytes32(5),
    ]);

    let merkle = merkleize(sanitise_bytes(data));

    let expected_len = num_nodes(8) * BYTES_PER_CHUNK;

    assert_eq!(merkle.len(), expected_len);
}

fn generic_test(index: usize) {
    let inner = Inner {
        a: 1,
        b: 2,
        c: 3,
        d: 4,
    };

    let cache: Vec<u8> = TreeHashCache::new(&inner).unwrap().into();

    let changed_inner = match index {
        0 => Inner {
            a: 42,
            ..inner.clone()
        },
        1 => Inner {
            b: 42,
            ..inner.clone()
        },
        2 => Inner {
            c: 42,
            ..inner.clone()
        },
        3 => Inner {
            d: 42,
            ..inner.clone()
        },
        _ => panic!("bad index"),
    };

    let mut cache_struct = TreeHashCache::from_bytes(cache.clone()).unwrap();

    changed_inner
        .cached_hash_tree_root(&inner, &mut cache_struct, 0)
        .unwrap();

    // assert_eq!(*cache_struct.hash_count, 3);

    let new_cache: Vec<u8> = cache_struct.into();

    let data1 = int_to_bytes32(1);
    let data2 = int_to_bytes32(2);
    let data3 = int_to_bytes32(3);
    let data4 = int_to_bytes32(4);

    let mut data = vec![data1, data2, data3, data4];

    data[index] = int_to_bytes32(42);

    let expected = merkleize(join(data));

    assert_eq!(expected, new_cache);
}

#[test]
fn cached_hash_on_inner() {
    generic_test(0);
    generic_test(1);
    generic_test(2);
    generic_test(3);
}

#[test]
fn inner_builds() {
    let data1 = int_to_bytes32(1);
    let data2 = int_to_bytes32(2);
    let data3 = int_to_bytes32(3);
    let data4 = int_to_bytes32(4);

    let data = join(vec![data1, data2, data3, data4]);
    let expected = merkleize(data);

    let inner = Inner {
        a: 1,
        b: 2,
        c: 3,
        d: 4,
    };

    let cache: Vec<u8> = TreeHashCache::new(&inner).unwrap().into();

    assert_eq!(expected, cache);
}

#[test]
fn merkleize_4_leaves() {
    let data1 = hash(&int_to_bytes32(1));
    let data2 = hash(&int_to_bytes32(2));
    let data3 = hash(&int_to_bytes32(3));
    let data4 = hash(&int_to_bytes32(4));

    let data = join(vec![
        data1.clone(),
        data2.clone(),
        data3.clone(),
        data4.clone(),
    ]);

    let cache = merkleize(data);

    let hash_12 = {
        let mut joined = vec![];
        joined.append(&mut data1.clone());
        joined.append(&mut data2.clone());
        hash(&joined)
    };
    let hash_34 = {
        let mut joined = vec![];
        joined.append(&mut data3.clone());
        joined.append(&mut data4.clone());
        hash(&joined)
    };
    let hash_hash12_hash_34 = {
        let mut joined = vec![];
        joined.append(&mut hash_12.clone());
        joined.append(&mut hash_34.clone());
        hash(&joined)
    };

    for (i, chunk) in cache.chunks(HASHSIZE).enumerate().rev() {
        let expected = match i {
            0 => hash_hash12_hash_34.clone(),
            1 => hash_12.clone(),
            2 => hash_34.clone(),
            3 => data1.clone(),
            4 => data2.clone(),
            5 => data3.clone(),
            6 => data4.clone(),
            _ => vec![],
        };

        assert_eq!(chunk, &expected[..], "failed at {}", i);
    }
}

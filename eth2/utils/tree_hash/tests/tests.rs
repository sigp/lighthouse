use hashing::hash;
use int_to_bytes::{int_to_bytes32, int_to_bytes8};
use tree_hash::cached_tree_hash::*;
use tree_hash::standard_tree_hash::*;
use tree_hash::*;

#[derive(Clone, Debug)]
pub struct InternalCache {
    pub a: u64,
    pub b: u64,
    pub cache: Option<TreeHashCache>,
}

impl TreeHash for InternalCache {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Composite
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        let mut leaves = Vec::with_capacity(4 * HASHSIZE);

        leaves.append(&mut self.a.tree_hash_root());
        leaves.append(&mut self.b.tree_hash_root());

        efficient_merkleize(&leaves)[0..32].to_vec()
    }
}

impl CachedTreeHash<InternalCache> for InternalCache {
    fn update_internal_tree_hash_cache(mut self, mut old: Self) -> Result<(Self, Self), Error> {
        let mut local_cache = old.cache;
        old.cache = None;

        if let Some(ref mut local_cache) = local_cache {
            self.update_cache(&old, local_cache, 0)?;
        } else {
            local_cache = Some(self.new_cache()?)
        }

        self.cache = local_cache;

        Ok((old, self))
    }

    fn cached_tree_hash_root(&self) -> Option<Vec<u8>> {
        match &self.cache {
            None => None,
            Some(c) => Some(c.root()?.to_vec()),
        }
    }

    fn clone_without_tree_hash_cache(&self) -> Self {
        Self {
            a: self.a,
            b: self.b,
            cache: None,
        }
    }
}

#[test]
fn works_when_embedded() {
    let old = InternalCache {
        a: 99,
        b: 99,
        cache: None,
    };

    let mut new = old.clone_without_tree_hash_cache();
    new.a = 1;
    new.b = 2;

    let (_old, new) = new.update_internal_tree_hash_cache(old).unwrap();

    let root = new.cached_tree_hash_root().unwrap();

    let leaves = vec![int_to_bytes32(1), int_to_bytes32(2)];
    let merkle = merkleize(join(leaves));

    assert_eq!(&merkle[0..32], &root[..]);
}

impl CachedTreeHashSubTree<InternalCache> for InternalCache {
    fn new_cache(&self) -> Result<TreeHashCache, Error> {
        let tree = TreeHashCache::from_leaves_and_subtrees(
            self,
            vec![self.a.new_cache()?, self.b.new_cache()?],
        )?;

        Ok(tree)
    }

    fn btree_overlay(&self, chunk_offset: usize) -> Result<BTreeOverlay, Error> {
        let mut lengths = vec![];

        lengths.push(BTreeOverlay::new(&self.a, 0)?.total_nodes());
        lengths.push(BTreeOverlay::new(&self.b, 0)?.total_nodes());

        BTreeOverlay::from_lengths(chunk_offset, lengths)
    }

    fn update_cache(
        &self,
        other: &Self,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Result<usize, Error> {
        let offset_handler = BTreeOverlay::new(self, chunk)?;

        // Skip past the internal nodes and update any changed leaf nodes.
        {
            let chunk = offset_handler.first_leaf_node()?;
            let chunk = self.a.update_cache(&other.a, cache, chunk)?;
            let _chunk = self.b.update_cache(&other.b, cache, chunk)?;
        }

        for (&parent, children) in offset_handler.iter_internal_nodes().rev() {
            if cache.either_modified(children)? {
                cache.modify_chunk(parent, &cache.hash_children(children)?)?;
            }
        }

        Ok(offset_handler.next_node)
    }
}

fn num_nodes(num_leaves: usize) -> usize {
    2 * num_leaves - 1
}

#[derive(Clone, Debug)]
pub struct Inner {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
}

impl TreeHash for Inner {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Composite
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        let mut leaves = Vec::with_capacity(4 * HASHSIZE);

        leaves.append(&mut self.a.tree_hash_root());
        leaves.append(&mut self.b.tree_hash_root());
        leaves.append(&mut self.c.tree_hash_root());
        leaves.append(&mut self.d.tree_hash_root());

        efficient_merkleize(&leaves)[0..32].to_vec()
    }
}

impl CachedTreeHashSubTree<Inner> for Inner {
    fn new_cache(&self) -> Result<TreeHashCache, Error> {
        let tree = TreeHashCache::from_leaves_and_subtrees(
            self,
            vec![
                self.a.new_cache()?,
                self.b.new_cache()?,
                self.c.new_cache()?,
                self.d.new_cache()?,
            ],
        )?;

        Ok(tree)
    }

    fn btree_overlay(&self, chunk_offset: usize) -> Result<BTreeOverlay, Error> {
        let mut lengths = vec![];

        lengths.push(BTreeOverlay::new(&self.a, 0)?.total_nodes());
        lengths.push(BTreeOverlay::new(&self.b, 0)?.total_nodes());
        lengths.push(BTreeOverlay::new(&self.c, 0)?.total_nodes());
        lengths.push(BTreeOverlay::new(&self.d, 0)?.total_nodes());

        BTreeOverlay::from_lengths(chunk_offset, lengths)
    }

    fn update_cache(
        &self,
        other: &Self,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Result<usize, Error> {
        let offset_handler = BTreeOverlay::new(self, chunk)?;

        // Skip past the internal nodes and update any changed leaf nodes.
        {
            let chunk = offset_handler.first_leaf_node()?;
            let chunk = self.a.update_cache(&other.a, cache, chunk)?;
            let chunk = self.b.update_cache(&other.b, cache, chunk)?;
            let chunk = self.c.update_cache(&other.c, cache, chunk)?;
            let _chunk = self.d.update_cache(&other.d, cache, chunk)?;
        }

        for (&parent, children) in offset_handler.iter_internal_nodes().rev() {
            if cache.either_modified(children)? {
                cache.modify_chunk(parent, &cache.hash_children(children)?)?;
            }
        }

        Ok(offset_handler.next_node)
    }
}

#[derive(Clone, Debug)]
pub struct Outer {
    pub a: u64,
    pub b: Inner,
    pub c: u64,
}

impl TreeHash for Outer {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Composite
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Struct should never be packed.")
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        let mut leaves = Vec::with_capacity(4 * HASHSIZE);

        leaves.append(&mut self.a.tree_hash_root());
        leaves.append(&mut self.b.tree_hash_root());
        leaves.append(&mut self.c.tree_hash_root());

        efficient_merkleize(&leaves)[0..32].to_vec()
    }
}

impl CachedTreeHashSubTree<Outer> for Outer {
    fn new_cache(&self) -> Result<TreeHashCache, Error> {
        let tree = TreeHashCache::from_leaves_and_subtrees(
            self,
            vec![
                self.a.new_cache()?,
                self.b.new_cache()?,
                self.c.new_cache()?,
            ],
        )?;

        Ok(tree)
    }

    fn btree_overlay(&self, chunk_offset: usize) -> Result<BTreeOverlay, Error> {
        let mut lengths = vec![];

        lengths.push(BTreeOverlay::new(&self.a, 0)?.total_nodes());
        lengths.push(BTreeOverlay::new(&self.b, 0)?.total_nodes());
        lengths.push(BTreeOverlay::new(&self.c, 0)?.total_nodes());

        BTreeOverlay::from_lengths(chunk_offset, lengths)
    }

    fn update_cache(
        &self,
        other: &Self,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Result<usize, Error> {
        let offset_handler = BTreeOverlay::new(self, chunk)?;

        // Skip past the internal nodes and update any changed leaf nodes.
        {
            let chunk = offset_handler.first_leaf_node()?;
            let chunk = self.a.update_cache(&other.a, cache, chunk)?;
            let chunk = self.b.update_cache(&other.b, cache, chunk)?;
            let _chunk = self.c.update_cache(&other.c, cache, chunk)?;
        }

        for (&parent, children) in offset_handler.iter_internal_nodes().rev() {
            if cache.either_modified(children)? {
                cache.modify_chunk(parent, &cache.hash_children(children)?)?;
            }
        }

        Ok(offset_handler.next_node)
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

    // Perform a differential hash
    let mut cache_struct = TreeHashCache::new(&original_outer).unwrap();

    modified_outer
        .update_cache(&original_outer, &mut cache_struct, 0)
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
        .update_cache(&original_outer, &mut cache_struct, 0)
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

fn mix_in_length(root: &mut [u8], len: usize) {
    let mut bytes = root.to_vec();
    bytes.append(&mut int_to_bytes32(len as u64));

    root.copy_from_slice(&hash(&bytes));
}

/// Generic test that covers:
///
/// 1. Produce a new cache from `original`.
/// 2. Do a differential hash between `original` and `modified`.
/// 3. Test that the cache generated matches the one we generate manually.
///
/// In effect it ensures that we can do a differential hash between two `Vec<u64>`.
fn test_u64_vec_modifications(original: Vec<u64>, modified: Vec<u64>) {
    // Generate initial cache.
    let original_cache: Vec<u8> = TreeHashCache::new(&original).unwrap().into();

    // Perform a differential hash
    let mut cache_struct = TreeHashCache::from_bytes(original_cache.clone(), false).unwrap();
    modified
        .update_cache(&original, &mut cache_struct, 0)
        .unwrap();
    let modified_cache: Vec<u8> = cache_struct.into();

    // Generate reference data.
    let mut data = vec![];
    for i in &modified {
        data.append(&mut int_to_bytes8(*i));
    }
    let data = sanitise_bytes(data);
    let mut expected = merkleize(data);

    mix_in_length(&mut expected[0..HASHSIZE], modified.len());

    assert_eq!(expected, modified_cache);
    assert_eq!(&expected[0..32], &modified.tree_hash_root()[..]);
}

#[test]
fn partial_modification_u64_vec() {
    let n: u64 = 2_u64.pow(5);

    let original_vec: Vec<u64> = (0..n).collect();

    let mut modified_vec = original_vec.clone();
    modified_vec[n as usize - 1] = 42;

    test_u64_vec_modifications(original_vec, modified_vec);
}

#[test]
fn shortened_u64_vec_len_within_pow_2_boundary() {
    let n: u64 = 2_u64.pow(5) - 1;

    let original_vec: Vec<u64> = (0..n).collect();

    let mut modified_vec = original_vec.clone();
    modified_vec.pop();

    test_u64_vec_modifications(original_vec, modified_vec);
}

#[test]
fn shortened_u64_vec_len_outside_pow_2_boundary() {
    let original_vec: Vec<u64> = (0..2_u64.pow(6)).collect();

    let modified_vec: Vec<u64> = (0..2_u64.pow(5)).collect();

    test_u64_vec_modifications(original_vec, modified_vec);
}

#[test]
fn extended_u64_vec_len_within_pow_2_boundary() {
    let n: u64 = 2_u64.pow(5) - 2;

    let original_vec: Vec<u64> = (0..n).collect();

    let mut modified_vec = original_vec.clone();
    modified_vec.push(42);

    test_u64_vec_modifications(original_vec, modified_vec);
}

#[test]
fn extended_u64_vec_len_outside_pow_2_boundary() {
    let original_vec: Vec<u64> = (0..2_u64.pow(5)).collect();

    let modified_vec: Vec<u64> = (0..2_u64.pow(6)).collect();

    test_u64_vec_modifications(original_vec, modified_vec);
}

#[test]
fn large_vec_of_u64_builds() {
    let n: u64 = 50;

    let my_vec: Vec<u64> = (0..n).collect();

    // Generate function output.
    let cache: Vec<u8> = TreeHashCache::new(&my_vec).unwrap().into();

    // Generate reference data.
    let mut data = vec![];
    for i in &my_vec {
        data.append(&mut int_to_bytes8(*i));
    }
    let data = sanitise_bytes(data);
    let expected = merkleize(data);

    assert_eq!(expected, cache);
}

/// Generic test that covers:
///
/// 1. Produce a new cache from `original`.
/// 2. Do a differential hash between `original` and `modified`.
/// 3. Test that the cache generated matches the one we generate manually.
///
/// The `reference` vec is used to build the tree hash cache manually. `Inner` is just 4x `u64`, so
/// you can represent 2x `Inner` with a `reference` vec of len 8.
///
/// In effect it ensures that we can do a differential hash between two `Vec<Inner>`.
fn test_inner_vec_modifications(original: Vec<Inner>, modified: Vec<Inner>, reference: Vec<u64>) {
    let mut cache = TreeHashCache::new(&original).unwrap();

    modified.update_cache(&original, &mut cache, 0).unwrap();
    let modified_cache: Vec<u8> = cache.into();

    // Build the reference vec.

    let mut leaves = vec![];
    let mut full_bytes = vec![];

    for n in reference.chunks(4) {
        let mut merkle = merkleize(join(vec![
            int_to_bytes32(n[0]),
            int_to_bytes32(n[1]),
            int_to_bytes32(n[2]),
            int_to_bytes32(n[3]),
        ]));
        leaves.append(&mut merkle[0..HASHSIZE].to_vec());
        full_bytes.append(&mut merkle);
    }

    let num_leaves = leaves.len() / HASHSIZE;
    let mut expected = merkleize(leaves);

    let num_internal_nodes = num_leaves.next_power_of_two() - 1;
    expected.splice(num_internal_nodes * HASHSIZE.., full_bytes);

    for _ in num_leaves..num_leaves.next_power_of_two() {
        expected.append(&mut vec![0; HASHSIZE]);
    }

    mix_in_length(&mut expected[0..HASHSIZE], modified.len());

    // Compare the cached tree to the reference tree.
    assert_trees_eq(&expected, &modified_cache);
    assert_eq!(&expected[0..32], &modified.tree_hash_root()[..]);
}

#[test]
fn partial_modification_of_vec_of_inner() {
    let original = vec![
        Inner {
            a: 0,
            b: 1,
            c: 2,
            d: 3,
        },
        Inner {
            a: 4,
            b: 5,
            c: 6,
            d: 7,
        },
        Inner {
            a: 8,
            b: 9,
            c: 10,
            d: 11,
        },
    ];

    let mut modified = original.clone();
    modified[1].a = 42;

    let mut reference_vec: Vec<u64> = (0..12).collect();
    reference_vec[4] = 42;

    test_inner_vec_modifications(original, modified, reference_vec);
}

#[test]
fn shortened_vec_of_inner_within_power_of_two_boundary() {
    let original = vec![
        Inner {
            a: 0,
            b: 1,
            c: 2,
            d: 3,
        },
        Inner {
            a: 4,
            b: 5,
            c: 6,
            d: 7,
        },
        Inner {
            a: 8,
            b: 9,
            c: 10,
            d: 11,
        },
        Inner {
            a: 12,
            b: 13,
            c: 14,
            d: 15,
        },
    ];

    let mut modified = original.clone();
    modified.pop(); // remove the last element from the list.

    let reference_vec: Vec<u64> = (0..12).collect();

    test_inner_vec_modifications(original, modified, reference_vec);
}

#[test]
fn shortened_vec_of_inner_outside_power_of_two_boundary() {
    let original = vec![
        Inner {
            a: 0,
            b: 1,
            c: 2,
            d: 3,
        },
        Inner {
            a: 4,
            b: 5,
            c: 6,
            d: 7,
        },
        Inner {
            a: 8,
            b: 9,
            c: 10,
            d: 11,
        },
        Inner {
            a: 12,
            b: 13,
            c: 14,
            d: 15,
        },
        Inner {
            a: 16,
            b: 17,
            c: 18,
            d: 19,
        },
    ];

    let mut modified = original.clone();
    modified.pop(); // remove the last element from the list.

    let reference_vec: Vec<u64> = (0..16).collect();

    test_inner_vec_modifications(original, modified, reference_vec);
}

#[test]
fn lengthened_vec_of_inner_within_power_of_two_boundary() {
    let original = vec![
        Inner {
            a: 0,
            b: 1,
            c: 2,
            d: 3,
        },
        Inner {
            a: 4,
            b: 5,
            c: 6,
            d: 7,
        },
        Inner {
            a: 8,
            b: 9,
            c: 10,
            d: 11,
        },
    ];

    let mut modified = original.clone();
    modified.push(Inner {
        a: 12,
        b: 13,
        c: 14,
        d: 15,
    });

    let reference_vec: Vec<u64> = (0..16).collect();

    test_inner_vec_modifications(original, modified, reference_vec);
}

#[test]
fn lengthened_vec_of_inner_outside_power_of_two_boundary() {
    let original = vec![
        Inner {
            a: 0,
            b: 1,
            c: 2,
            d: 3,
        },
        Inner {
            a: 4,
            b: 5,
            c: 6,
            d: 7,
        },
        Inner {
            a: 8,
            b: 9,
            c: 10,
            d: 11,
        },
        Inner {
            a: 12,
            b: 13,
            c: 14,
            d: 15,
        },
    ];

    let mut modified = original.clone();
    modified.push(Inner {
        a: 16,
        b: 17,
        c: 18,
        d: 19,
    });

    let reference_vec: Vec<u64> = (0..20).collect();

    test_inner_vec_modifications(original, modified, reference_vec);
}

#[test]
fn vec_of_inner_builds() {
    let numbers: Vec<u64> = (0..12).collect();

    let mut leaves = vec![];
    let mut full_bytes = vec![];

    for n in numbers.chunks(4) {
        let mut merkle = merkleize(join(vec![
            int_to_bytes32(n[0]),
            int_to_bytes32(n[1]),
            int_to_bytes32(n[2]),
            int_to_bytes32(n[3]),
        ]));
        leaves.append(&mut merkle[0..HASHSIZE].to_vec());
        full_bytes.append(&mut merkle);
    }

    let mut expected = merkleize(leaves);
    expected.splice(3 * HASHSIZE.., full_bytes);
    expected.append(&mut vec![0; HASHSIZE]);

    let my_vec = vec![
        Inner {
            a: 0,
            b: 1,
            c: 2,
            d: 3,
        },
        Inner {
            a: 4,
            b: 5,
            c: 6,
            d: 7,
        },
        Inner {
            a: 8,
            b: 9,
            c: 10,
            d: 11,
        },
    ];

    let cache: Vec<u8> = TreeHashCache::new(&my_vec).unwrap().into();

    assert_trees_eq(&expected, &cache);
}

/// Provides detailed assertions when comparing merkle trees.
fn assert_trees_eq(a: &[u8], b: &[u8]) {
    assert_eq!(a.len(), b.len(), "Byte lens different");
    for i in (0..a.len() / HASHSIZE).rev() {
        let range = i * HASHSIZE..(i + 1) * HASHSIZE;
        assert_eq!(
            a[range.clone()],
            b[range],
            "Chunk {}/{} different \n\n a: {:?} \n\n b: {:?}",
            i,
            a.len() / HASHSIZE,
            a,
            b,
        );
    }
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

    let cache: Vec<u8> = TreeHashCache::new(&my_vec).unwrap().into();

    assert_eq!(expected, cache);
}

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

    let mut cache_struct = TreeHashCache::from_bytes(cache.clone(), false).unwrap();

    changed_inner
        .update_cache(&inner, &mut cache_struct, 0)
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

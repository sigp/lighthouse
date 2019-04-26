use cached_tree_hash::{merkleize::merkleize, *};
use int_to_bytes::int_to_bytes32;
use tree_hash_derive::{CachedTreeHash, TreeHash};

#[derive(Clone, Debug, TreeHash, CachedTreeHash)]
pub struct NestedStruct {
    pub a: u64,
    pub b: Inner,
}

fn test_routine<T>(original: T, modified: Vec<T>)
where
    T: CachedTreeHash<T>,
{
    let mut hasher = CachedTreeHasher::new(&original).unwrap();

    let standard_root = original.tree_hash_root();
    let cached_root = hasher.tree_hash_root().unwrap();
    assert_eq!(standard_root, cached_root, "Initial cache build failed.");

    for (i, modified) in modified.iter().enumerate() {
        println!("-- Start of modification {} --", i);
        // Test after a modification
        hasher
            .update(modified)
            .expect(&format!("Modification {}", i));
        let standard_root = modified.tree_hash_root();
        let cached_root = hasher
            .tree_hash_root()
            .expect(&format!("Modification {}", i));
        assert_eq!(
            standard_root, cached_root,
            "Modification {} failed. \n Cache: {:?}",
            i, hasher
        );
    }
}

#[test]
fn test_nested_struct() {
    let original = NestedStruct {
        a: 42,
        b: Inner {
            a: 12,
            b: 13,
            c: 14,
            d: 15,
        },
    };
    let modified = vec![NestedStruct {
        a: 99,
        ..original.clone()
    }];

    test_routine(original, modified);
}

#[test]
fn test_inner() {
    let original = Inner {
        a: 12,
        b: 13,
        c: 14,
        d: 15,
    };

    let modified = vec![Inner {
        a: 99,
        ..original.clone()
    }];

    test_routine(original, modified);
}

#[test]
fn test_vec() {
    let original: Vec<u64> = vec![1, 2, 3, 4, 5];

    let modified: Vec<Vec<u64>> = vec![
        vec![1, 2, 3, 4, 42],
        vec![1, 2, 3, 4],
        vec![],
        vec![42; 2_usize.pow(4)],
        vec![],
        vec![],
        vec![1, 2, 3, 4, 42],
        vec![1, 2, 3],
        vec![1],
    ];

    test_routine(original, modified);
}

#[test]
fn test_nested_list_of_u64() {
    let original: Vec<Vec<u64>> = vec![vec![42]];

    let modified = vec![
        vec![vec![1]],
        vec![vec![1], vec![2]],
        vec![vec![1], vec![3], vec![4]],
        vec![],
        vec![vec![1], vec![3], vec![4]],
        vec![],
        vec![vec![1, 2], vec![3], vec![4, 5, 6, 7, 8]],
        vec![],
        vec![vec![1], vec![2], vec![3]],
        vec![vec![1, 2, 3, 4, 5, 6], vec![1, 2, 3, 4, 5, 6, 7]],
        vec![vec![], vec![], vec![]],
        vec![vec![0, 0, 0], vec![0], vec![0]],
    ];

    test_routine(original, modified);
}

#[derive(Clone, Debug, TreeHash, CachedTreeHash)]
pub struct StructWithVec {
    pub a: u64,
    pub b: Inner,
    pub c: Vec<u64>,
}

#[test]
fn test_struct_with_vec() {
    let original = StructWithVec {
        a: 42,
        b: Inner {
            a: 12,
            b: 13,
            c: 14,
            d: 15,
        },
        c: vec![1, 2, 3, 4, 5],
    };

    let modified = vec![
        StructWithVec {
            a: 99,
            ..original.clone()
        },
        StructWithVec {
            a: 100,
            ..original.clone()
        },
        StructWithVec {
            c: vec![1, 2, 3, 4, 5],
            ..original.clone()
        },
        StructWithVec {
            c: vec![1, 3, 4, 5, 6],
            ..original.clone()
        },
        StructWithVec {
            c: vec![1, 3, 4, 5, 6, 7, 8, 9],
            ..original.clone()
        },
        StructWithVec {
            c: vec![1, 3, 4, 5],
            ..original.clone()
        },
        StructWithVec {
            b: Inner {
                a: u64::max_value(),
                b: u64::max_value(),
                c: u64::max_value(),
                d: u64::max_value(),
            },
            c: vec![],
            ..original.clone()
        },
        StructWithVec {
            b: Inner {
                a: 0,
                b: 1,
                c: 2,
                d: 3,
            },
            ..original.clone()
        },
    ];

    test_routine(original, modified);
}

#[test]
fn test_vec_of_struct_with_vec() {
    let a = StructWithVec {
        a: 42,
        b: Inner {
            a: 12,
            b: 13,
            c: 14,
            d: 15,
        },
        c: vec![1, 2, 3, 4, 5],
    };
    let b = StructWithVec {
        c: vec![],
        ..a.clone()
    };
    let c = StructWithVec {
        b: Inner {
            a: 99,
            b: 100,
            c: 101,
            d: 102,
        },
        ..a.clone()
    };
    let d = StructWithVec { a: 0, ..a.clone() };

    // let original: Vec<StructWithVec> = vec![a.clone(), c.clone()];
    let original: Vec<StructWithVec> = vec![a.clone()];

    let modified = vec![
        vec![a.clone(), c.clone()],
        vec![a.clone(), b.clone(), c.clone(), d.clone()],
        vec![b.clone(), a.clone(), c.clone(), d.clone()],
        vec![],
        vec![a.clone()],
        vec![a.clone(), b.clone(), c.clone(), d.clone()],
    ];

    test_routine(original, modified);
}

#[derive(Clone, Debug, TreeHash, CachedTreeHash)]
pub struct StructWithVecOfStructs {
    pub a: u64,
    pub b: Inner,
    pub c: Vec<Inner>,
}

fn get_inners() -> Vec<Inner> {
    vec![
        Inner {
            a: 12,
            b: 13,
            c: 14,
            d: 15,
        },
        Inner {
            a: 99,
            b: 100,
            c: 101,
            d: 102,
        },
        Inner {
            a: 255,
            b: 256,
            c: 257,
            d: 0,
        },
        Inner {
            a: 1000,
            b: 2000,
            c: 3000,
            d: 0,
        },
        Inner {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
        },
    ]
}

fn get_struct_with_vec_of_structs() -> Vec<StructWithVecOfStructs> {
    let inner_a = Inner {
        a: 12,
        b: 13,
        c: 14,
        d: 15,
    };

    let inner_b = Inner {
        a: 99,
        b: 100,
        c: 101,
        d: 102,
    };

    let inner_c = Inner {
        a: 255,
        b: 256,
        c: 257,
        d: 0,
    };

    let a = StructWithVecOfStructs {
        a: 42,
        b: inner_a.clone(),
        c: vec![inner_a.clone(), inner_b.clone(), inner_c.clone()],
    };

    let b = StructWithVecOfStructs {
        c: vec![],
        ..a.clone()
    };

    let c = StructWithVecOfStructs {
        a: 800,
        ..a.clone()
    };

    let d = StructWithVecOfStructs {
        b: inner_c.clone(),
        ..a.clone()
    };

    let e = StructWithVecOfStructs {
        c: vec![inner_a.clone(), inner_b.clone()],
        ..a.clone()
    };

    let f = StructWithVecOfStructs {
        c: vec![inner_a.clone()],
        ..a.clone()
    };

    vec![a, b, c, d, e, f]
}

#[test]
fn test_struct_with_vec_of_structs() {
    let variants = get_struct_with_vec_of_structs();

    test_routine(variants[0].clone(), variants.clone());
    test_routine(variants[1].clone(), variants.clone());
    test_routine(variants[2].clone(), variants.clone());
    test_routine(variants[3].clone(), variants.clone());
    test_routine(variants[4].clone(), variants.clone());
    test_routine(variants[5].clone(), variants.clone());
}

#[derive(Clone, Debug, TreeHash, CachedTreeHash)]
pub struct StructWithVecOfStructWithVecOfStructs {
    pub a: Vec<StructWithVecOfStructs>,
    pub b: u64,
}

#[test]
fn test_struct_with_vec_of_struct_with_vec_of_structs() {
    let structs = get_struct_with_vec_of_structs();

    let variants = vec![
        StructWithVecOfStructWithVecOfStructs {
            a: structs[..].to_vec(),
            b: 99,
        },
        StructWithVecOfStructWithVecOfStructs { a: vec![], b: 99 },
        StructWithVecOfStructWithVecOfStructs {
            a: structs[0..2].to_vec(),
            b: 99,
        },
        StructWithVecOfStructWithVecOfStructs {
            a: structs[0..2].to_vec(),
            b: 100,
        },
        StructWithVecOfStructWithVecOfStructs {
            a: structs[0..1].to_vec(),
            b: 100,
        },
        StructWithVecOfStructWithVecOfStructs {
            a: structs[0..4].to_vec(),
            b: 100,
        },
        StructWithVecOfStructWithVecOfStructs {
            a: structs[0..5].to_vec(),
            b: 8,
        },
    ];

    for v in &variants {
        test_routine(v.clone(), variants.clone());
    }
}

#[derive(Clone, Debug, TreeHash, CachedTreeHash)]
pub struct StructWithTwoVecs {
    pub a: Vec<Inner>,
    pub b: Vec<Inner>,
}

#[test]
fn test_struct_with_two_vecs() {
    let inners = get_inners();

    let variants = vec![
        StructWithTwoVecs {
            a: inners[..].to_vec(),
            b: inners[..].to_vec(),
        },
        StructWithTwoVecs {
            a: inners[0..1].to_vec(),
            b: inners[..].to_vec(),
        },
        StructWithTwoVecs {
            a: inners[0..1].to_vec(),
            b: inners[0..2].to_vec(),
        },
        StructWithTwoVecs {
            a: inners[0..4].to_vec(),
            b: inners[0..2].to_vec(),
        },
        StructWithTwoVecs {
            a: vec![],
            b: inners[..].to_vec(),
        },
        StructWithTwoVecs {
            a: inners[..].to_vec(),
            b: vec![],
        },
        StructWithTwoVecs {
            a: inners[0..3].to_vec(),
            b: inners[0..1].to_vec(),
        },
    ];

    for v in &variants {
        test_routine(v.clone(), variants.clone());
    }
}

#[derive(Clone, Debug, TreeHash, CachedTreeHash)]
pub struct U64AndTwoStructs {
    pub a: u64,
    pub b: Inner,
    pub c: Inner,
}

#[test]
fn test_u64_and_two_structs() {
    let inners = get_inners();

    let variants = vec![
        U64AndTwoStructs {
            a: 99,
            b: inners[0].clone(),
            c: inners[1].clone(),
        },
        U64AndTwoStructs {
            a: 10,
            b: inners[2].clone(),
            c: inners[3].clone(),
        },
        U64AndTwoStructs {
            a: 0,
            b: inners[1].clone(),
            c: inners[1].clone(),
        },
        U64AndTwoStructs {
            a: 0,
            b: inners[1].clone(),
            c: inners[1].clone(),
        },
    ];

    for v in &variants {
        test_routine(v.clone(), variants.clone());
    }
}

#[derive(Clone, Debug, TreeHash, CachedTreeHash)]
pub struct Inner {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
}

fn generic_test(index: usize) {
    let inner = Inner {
        a: 1,
        b: 2,
        c: 3,
        d: 4,
    };

    let mut cache = TreeHashCache::new(&inner, 0).unwrap();

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

    changed_inner.update_tree_hash_cache(&mut cache).unwrap();

    let data1 = int_to_bytes32(1);
    let data2 = int_to_bytes32(2);
    let data3 = int_to_bytes32(3);
    let data4 = int_to_bytes32(4);

    let mut data = vec![data1, data2, data3, data4];

    data[index] = int_to_bytes32(42);

    let expected = merkleize(join(data));

    let cache_bytes: Vec<u8> = cache.into();

    assert_eq!(expected, cache_bytes);
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

    let cache: Vec<u8> = TreeHashCache::new(&inner, 0).unwrap().into();

    assert_eq!(expected, cache);
}

fn join(many: Vec<Vec<u8>>) -> Vec<u8> {
    let mut all = vec![];
    for one in many {
        all.extend_from_slice(&mut one.clone())
    }
    all
}

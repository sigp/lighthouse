use super::BYTES_PER_CHUNK;
use hashing::hash;

const MAX_TREE_DEPTH: usize = 32;

lazy_static! {
    /// Cached zero hashes where `ZERO_HASHES[i]` is the hash of a Merkle tree with 2^i zero leaves.
    static ref ZERO_HASHES: Vec<Vec<u8>> = {
        let mut hashes = vec![vec![0; 32]; MAX_TREE_DEPTH + 1];

        for i in 0..MAX_TREE_DEPTH {
            hashes[i + 1] = hash_concat(&hashes[i], &hashes[i]);
        }

        hashes
    };
}

struct ChunkStore(Vec<u8>);

impl ChunkStore {
    fn with_capacity(chunks: usize) -> Self {
        Self(vec![0; chunks * BYTES_PER_CHUNK])
    }

    fn set(&mut self, i: usize, value: &[u8]) -> Result<(), ()> {
        if i < self.len() && value.len() == BYTES_PER_CHUNK {
            let slice = &mut self.0[i * BYTES_PER_CHUNK..i * BYTES_PER_CHUNK + BYTES_PER_CHUNK];
            slice.copy_from_slice(value);
            Ok(())
        } else {
            Err(())
        }
    }

    fn get(&self, i: usize) -> Result<&[u8], ()> {
        if i < self.len() {
            Ok(&self.0[i * BYTES_PER_CHUNK..i * BYTES_PER_CHUNK + BYTES_PER_CHUNK])
        } else {
            Err(())
        }
    }

    fn len(&self) -> usize {
        self.0.len() / BYTES_PER_CHUNK
    }

    fn truncate(&mut self, num_chunks: usize) {
        self.0.truncate(num_chunks * BYTES_PER_CHUNK)
    }

    fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

fn get_zero_hash(i: usize) -> &'static [u8] {
    if i < MAX_TREE_DEPTH {
        &ZERO_HASHES[i]
    } else {
        panic!("Tree exceeeds MAX_TREE_DEPTH of {}")
    }
}

/// Concatenate two vectors.
fn concat(mut vec1: Vec<u8>, mut vec2: Vec<u8>) -> Vec<u8> {
    vec1.append(&mut vec2);
    vec1
}

/// Compute the hash of two other hashes concatenated.
fn hash_concat(h1: &[u8], h2: &[u8]) -> Vec<u8> {
    hash(&concat(h1.to_vec(), h2.to_vec()))
}

/// Merklizes bytes and returns the root, using a minimal amount of memory.
///
/// If `bytes.len() <= BYTES_PER_CHUNK`, no hashing is done and bytes is returned, potentially
/// padded out to `BYTES_PER_CHUNK` length with `0`.
pub fn padded_merklize(bytes: &[u8], min_leaves: usize) -> Vec<u8> {
    // If the bytes are just one chunk (or less than one chunk) just return them padded to a chunk.
    if bytes.len() <= BYTES_PER_CHUNK {
        let mut o = bytes.to_vec();
        o.resize(BYTES_PER_CHUNK, 0);
        return o;
    }

    // The number of leaves that can be made directly from `bytes`.
    let leaves_with_values = (bytes.len() + (BYTES_PER_CHUNK - 1)) / BYTES_PER_CHUNK;

    // The number of parents that will appear leaves with values.
    //
    // I.e., the number of nodes one height above the leaves where one it's children has a value
    // from `bytes`.
    let initial_parents_with_values = (leaves_with_values + leaves_with_values % 2) / 2;

    // The number of leaves in the full tree (including padding nodes).
    let num_leaves = std::cmp::max(
        leaves_with_values.next_power_of_two(),
        min_leaves.next_power_of_two(),
    );

    // The height of the full tree.
    let height = num_leaves.trailing_zeros() as usize;

    /*
    let min_leaves = min_leaves.next_power_of_two();
    let real_leaves = (bytes.len() + (BYTES_PER_CHUNK - 1)) / BYTES_PER_CHUNK;
    let total_leaves = std::cmp::max(real_leaves.next_power_of_two(), min_leaves);
    let height = total_leaves.trailing_zeros() as usize;
    let initial_parent_nodes = {
        let even_real_leaves = real_leaves + real_leaves % 2;
        even_real_leaves / 2
    };
    */

    // A buffer/scratch-space used for storing each round of hashing at each height.
    //
    // This buffer is kept as small as possible; it will never store a padding node.
    let mut chunks = ChunkStore::with_capacity(initial_parents_with_values);

    // TODO: remove this.
    let empty_chunk_hash = hash(&[0; BYTES_PER_CHUNK]);

    for i in 0..initial_parents_with_values {
        let start = i * BYTES_PER_CHUNK;

        let hash = match bytes.get(start..start + BYTES_PER_CHUNK * 2) {
            // All bytes are available, hash as ususal.
            Some(slice) => hash(slice),
            // Unable to get all the bytes.
            None => {
                match bytes.get(start..) {
                    // Able to get some of the bytes, pad them out.
                    Some(slice) => {
                        let mut bytes = slice.to_vec();
                        bytes.resize(BYTES_PER_CHUNK, 0);
                        hash(&bytes)
                    }
                    // Unable to get any bytes, use the empty-chunk hash.
                    None => empty_chunk_hash.clone(),
                }
            }
        };

        assert_eq!(
            hash.len(),
            BYTES_PER_CHUNK,
            "Hashes should be exactly one chunk"
        );

        chunks
            .set(i, &hash)
            .expect("buf is adequate size for parents of leaves")
    }

    dbg!(num_leaves);

    for height in 1..height {
        let child_nodes = chunks.len();
        let parent_nodes = (child_nodes + child_nodes % 2) / 2;

        for i in 0..parent_nodes {
            let (left, right) = match (chunks.get(i * 2), chunks.get(i * 2 + 1)) {
                (Ok(left), Ok(right)) => (left, right),
                (Ok(left), Err(_)) => (left, get_zero_hash(height)),
                (Err(_), Err(_)) => unreachable!("Parent must have one child"),
                (Err(_), Ok(_)) => unreachable!("Parent must have a left child"),
            };

            assert_eq!(
                left.len(),
                BYTES_PER_CHUNK,
                "Left child should be correct length."
            );
            assert_eq!(
                right.len(),
                BYTES_PER_CHUNK,
                "Right child should be correct length."
            );

            let mut preimage = left.to_vec();
            preimage.append(&mut right.to_vec());

            chunks
                .set(i, &hash(&preimage))
                .expect("Buf is adequate size for parent");
        }

        chunks.truncate(parent_nodes);
    }

    let root = chunks.into_vec();

    assert_eq!(root.len(), 32, "Only one chunk should remain");

    root
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::merkleize::merkle_root as reference_root;

    macro_rules! common_tests {
        ($fn: ident) => {
            #[test]
            fn zero_value_0_nodes() {
                test_against_reference(&zero_nodes(0));
            }

            #[test]
            fn zero_value_1_nodes() {
                test_against_reference(&zero_nodes(1));
            }

            #[test]
            fn zero_value_2_nodes() {
                test_against_reference(&zero_nodes(2));
            }

            #[test]
            fn zero_value_3_nodes() {
                test_against_reference(&zero_nodes(3));
            }

            #[test]
            fn zero_value_4_nodes() {
                test_against_reference(&zero_nodes(4));
            }

            #[test]
            fn zero_value_8_nodes() {
                test_against_reference(&zero_nodes(8));
            }

            #[test]
            fn zero_value_9_nodes() {
                test_against_reference(&zero_nodes(9));
            }

            #[test]
            fn zero_value_range_of_nodes() {
                for i in 0..1 << 5 {
                    test_against_reference(&zero_nodes(i));
                }
            }
        };
    }

    mod zero_value {
        use super::*;

        fn zero_nodes(n: usize) -> Vec<u8> {
            vec![0; BYTES_PER_CHUNK * n]
        }

        common_tests!(zero_nodes);
    }

    mod random_value {
        use super::*;
        use rand::RngCore;

        fn zero_nodes(n: usize) -> Vec<u8> {
            let mut nodes = vec![];

            for _ in 0..n {
                let mut random_data = [0; BYTES_PER_CHUNK];
                rand::thread_rng().fill_bytes(&mut random_data);

                nodes.append(&mut random_data.to_vec())
            }

            nodes
        }

        common_tests!(zero_nodes);
    }

    fn test_against_reference(input: &[u8]) {
        assert_eq!(
            reference_root(&input),
            padded_merklize(&input, 0),
            "input.len(): {:?}",
            input
        );
    }
}

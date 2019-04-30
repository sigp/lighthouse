use hashing::hash;
use tree_hash::{BYTES_PER_CHUNK, HASHSIZE, MERKLE_HASH_CHUNK};

/// Split `values` into a power-of-two, identical-length chunks (padding with `0`) and merkleize
/// them, returning the entire merkle tree.
///
/// The root hash is `merkleize(values)[0..BYTES_PER_CHUNK]`.
pub fn merkleize(values: Vec<u8>) -> Vec<u8> {
    let values = sanitise_bytes(values);

    let leaves = values.len() / HASHSIZE;

    if leaves == 0 {
        panic!("No full leaves");
    }

    if !leaves.is_power_of_two() {
        panic!("leaves is not power of two");
    }

    let mut o: Vec<u8> = vec![0; (num_nodes(leaves) - leaves) * HASHSIZE];
    o.append(&mut values.to_vec());

    let mut i = o.len();
    let mut j = o.len() - values.len();

    while i >= MERKLE_HASH_CHUNK {
        i -= MERKLE_HASH_CHUNK;
        let hash = hash(&o[i..i + MERKLE_HASH_CHUNK]);

        j -= HASHSIZE;
        o[j..j + HASHSIZE].copy_from_slice(&hash);
    }

    o
}

/// Ensures that the given `bytes` are a power-of-two chunks, padding with zero if not.
pub fn sanitise_bytes(mut bytes: Vec<u8>) -> Vec<u8> {
    let present_leaves = num_unsanitized_leaves(bytes.len());
    let required_leaves = present_leaves.next_power_of_two();

    if (present_leaves != required_leaves) | last_leaf_needs_padding(bytes.len()) {
        bytes.resize(num_bytes(required_leaves), 0);
    }

    bytes
}

/// Pads out `bytes` to ensure it is a clean `num_leaves` chunks.
pub fn pad_for_leaf_count(num_leaves: usize, bytes: &mut Vec<u8>) {
    let required_leaves = num_leaves.next_power_of_two();

    bytes.resize(
        bytes.len() + (required_leaves - num_leaves) * BYTES_PER_CHUNK,
        0,
    );
}

fn last_leaf_needs_padding(num_bytes: usize) -> bool {
    num_bytes % HASHSIZE != 0
}

/// Returns the number of leaves for a given `bytes_len` number of bytes, rounding up if
/// `num_bytes` is not a client multiple of chunk size.
pub fn num_unsanitized_leaves(bytes_len: usize) -> usize {
    (bytes_len + HASHSIZE - 1) / HASHSIZE
}

fn num_bytes(num_leaves: usize) -> usize {
    num_leaves * HASHSIZE
}

fn num_nodes(num_leaves: usize) -> usize {
    2 * num_leaves - 1
}

/// Returns the power-of-two number of leaves that would result from the given `bytes_len` number
/// of bytes.
pub fn num_sanitized_leaves(bytes_len: usize) -> usize {
    let leaves = (bytes_len + HASHSIZE - 1) / HASHSIZE;
    leaves.next_power_of_two()
}

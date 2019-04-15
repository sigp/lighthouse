pub mod cached_tree_hash;
pub mod standard_tree_hash;

pub const BYTES_PER_CHUNK: usize = 32;
pub const HASHSIZE: usize = 32;
pub const MERKLE_HASH_CHUNCK: usize = 2 * BYTES_PER_CHUNK;

#[derive(Debug, PartialEq, Clone)]
pub enum ItemType {
    Basic,
    List,
    Composite,
}

fn num_sanitized_leaves(num_bytes: usize) -> usize {
    let leaves = (num_bytes + HASHSIZE - 1) / HASHSIZE;
    leaves.next_power_of_two()
}

fn num_nodes(num_leaves: usize) -> usize {
    2 * num_leaves - 1
}

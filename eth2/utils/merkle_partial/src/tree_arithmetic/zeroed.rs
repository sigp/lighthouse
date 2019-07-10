use crate::tree_arithmetic;

pub const fn subtree_index_to_general(root: u64, index: u64) -> u64 {
    tree_arithmetic::subtree_index_to_general(root + 1, index + 1) - 1
}

pub const fn general_index_to_subtree(root: u64, index: u64) -> u64 {
    tree_arithmetic::general_index_to_subtree(root + 1, index + 1) - 1
}

pub fn expand_tree_index(index: u64) -> (u64, u64, u64) {
    let (left, right, parent) = tree_arithmetic::expand_tree_index(index + 1);
    (left - 1, right - 1, parent - 1)
}

pub const fn sibling_index(index: u64) -> u64 {
    tree_arithmetic::sibling_index(index + 1) - 1
}

pub const fn left_most_leaf(root: u64, depth: u64) -> u64 {
    tree_arithmetic::left_most_leaf(root + 1, depth + 1) - 1
}

pub const fn right_most_leaf(root: u64, depth: u64) -> u64 {
    tree_arithmetic::right_most_leaf(root + 1, depth + 1) - 1
}

pub const fn is_in_subtree(root: u64, index: u64) -> bool {
    tree_arithmetic::is_in_subtree(root + 1, index + 1)
}

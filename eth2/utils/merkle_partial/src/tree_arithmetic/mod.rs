pub mod zeroed;

/// Returns a node's family. `index` is zero indexed.
pub fn expand_tree_index(index: u64) -> (u64, u64, u64) {
    let left = index - (index & 1) + (index == 1) as u64;
    let right = index + (index & 1 ^ 1) + (index == 1) as u64;
    let parent = left / 2 + (index == 1) as u64;

    (left, right, parent)
}

/// Returns the index of a node's sibling. `index` is zero indexed.
pub const fn sibling_index(index: u64) -> u64 {
    index - (index & 1) + (index & 1 ^ 1) + (index == 1) as u64
}

pub const fn left_most_leaf(root: u64, depth: u64) -> u64 {
    let pow = 1 << depth;
    root * pow
}

pub const fn right_most_leaf(root: u64, depth: u64) -> u64 {
    let pow = 1 << depth;
    root * pow + pow - 1
}

pub const fn is_in_subtree(root: u64, index: u64) -> bool {
    let diff = relative_depth(root, index);
    let left_most = left_most_leaf(root, diff);
    let right_most = right_most_leaf(root, diff);

    (left_most <= index) & (index <= right_most)
}

pub const fn relative_depth(a: u64, b: u64) -> u64 {
    let a = log_base_two(last_power_of_two(a));
    let b = log_base_two(last_power_of_two(b));

    b - a
}

// https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
pub const fn next_power_of_two(n: u64) -> u64 {
    let mut ret: u128 = (n - 1) as u128;

    ret = ret | ret >> 1;
    ret = ret | ret >> 2;
    ret = ret | ret >> 4;
    ret = ret | ret >> 8;
    ret = ret | ret >> 16;
    ret = ret | ret >> 32;

    (ret + 1) as u64
}

pub const fn last_power_of_two(n: u64) -> u64 {
    let mut ret: u128 = n as u128;

    ret = ret | ret >> 1;
    ret = ret | ret >> 2;
    ret = ret | ret >> 4;
    ret = ret | ret >> 8;
    ret = ret | ret >> 16;
    ret = ret | ret >> 32;

    ((ret + 1) >> 1) as u64
}

pub const fn root_from_depth(index: u64, depth: u64) -> u64 {
    index / (1 << depth)
}

pub const fn log_base_two(n: u64) -> u64 {
    const DE_BRUIJN_BIT_POSITION: &'static [u64] = &[
        63, 0, 58, 1, 59, 47, 53, 2, 60, 39, 48, 27, 54, 33, 42, 3, 61, 51, 37, 40, 49, 18, 28, 20,
        55, 30, 34, 11, 43, 14, 22, 4, 62, 57, 46, 52, 38, 26, 32, 41, 50, 36, 17, 19, 29, 10, 13,
        21, 56, 45, 25, 31, 35, 16, 9, 12, 44, 24, 15, 8, 23, 7, 6, 5,
    ];

    DE_BRUIJN_BIT_POSITION[(n.wrapping_mul(0x07EDD5E59A4E28C2) >> 58) as usize]
}

pub const fn subtree_index_to_general(root: u64, index: u64) -> u64 {
    (root * index) - (root - 1) * (index - last_power_of_two(index))
}

pub const fn general_index_to_subtree(root: u64, index: u64) -> u64 {
    let depth_diff = log_base_two(last_power_of_two(index)) - log_base_two(last_power_of_two(root));
    let left_most = left_most_leaf(root, depth_diff);
    let n = index % left_most;

    index / root + (n / root) % root + n % root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_depth_difference() {
        assert_eq!(relative_depth(1, 1), 0);
        assert_eq!(relative_depth(1, 2), 1);
        assert_eq!(relative_depth(1, 5), 2);
        assert_eq!(relative_depth(1, 13), 3);
        assert_eq!(relative_depth(1, 30), 4);

        assert_eq!(relative_depth(2, 30), 3);
        assert_eq!(relative_depth(7, 30), 2);
        assert_eq!(relative_depth(11, 30), 1);
        assert_eq!(relative_depth(28, 30), 0);

        assert_eq!(relative_depth(1, 2_u64.pow(63)), 63);
    }

    #[test]
    fn compute_root_from_depth() {
        assert_eq!(root_from_depth(2, 1), 1);
        assert_eq!(root_from_depth(3, 1), 1);

        assert_eq!(root_from_depth(16, 4), 1);
        assert_eq!(root_from_depth(16, 3), 2);
        assert_eq!(root_from_depth(16, 2), 4);
        assert_eq!(root_from_depth(16, 1), 8);
        assert_eq!(root_from_depth(16, 0), 16);

        assert_eq!(root_from_depth(31, 4), 1);
        assert_eq!(root_from_depth(31, 3), 3);
        assert_eq!(root_from_depth(31, 2), 7);
        assert_eq!(root_from_depth(31, 1), 15);
        assert_eq!(root_from_depth(31, 0), 31);

        assert_eq!(root_from_depth(22, 4), 1);
        assert_eq!(root_from_depth(22, 3), 2);
        assert_eq!(root_from_depth(22, 2), 5);
        assert_eq!(root_from_depth(22, 1), 11);
        assert_eq!(root_from_depth(22, 0), 22);

        assert_eq!(root_from_depth(25, 4), 1);
        assert_eq!(root_from_depth(25, 3), 3);
        assert_eq!(root_from_depth(25, 2), 6);
        assert_eq!(root_from_depth(25, 1), 12);
        assert_eq!(root_from_depth(25, 0), 25);
    }

    #[test]
    fn compute_expanded_tree_indexes() {
        assert_eq!(expand_tree_index(2), (2, 3, 1));
        assert_eq!(expand_tree_index(3), (2, 3, 1));
        assert_eq!(expand_tree_index(14), (14, 15, 7));
        assert_eq!(expand_tree_index(15), (14, 15, 7));
    }

    #[test]
    fn compute_sibling_index() {
        assert_eq!(sibling_index(2), 3);
        assert_eq!(sibling_index(3), 2);
        assert_eq!(sibling_index(6), 7);
        assert_eq!(sibling_index(7), 6);
        assert_eq!(sibling_index(100), 101);
        assert_eq!(sibling_index(101), 100);
    }

    #[test]
    fn next_and_last_power_of_two() {
        assert_eq!(last_power_of_two(1), 1);
        assert_eq!(last_power_of_two(2), 2);
        assert_eq!(last_power_of_two(9), 8);
        assert_eq!(last_power_of_two(1023), 512);
        assert_eq!(last_power_of_two(2_u64.pow(63) + 1000), 2_u64.pow(63));

        assert_eq!(next_power_of_two(1), 1);
        assert_eq!(next_power_of_two(2), 2);
        assert_eq!(next_power_of_two(9), 16);
        assert_eq!(next_power_of_two(1023), 1024);
        assert_eq!(next_power_of_two(2_u64.pow(62) + 1000), 2_u64.pow(63));
    }

    #[test]
    fn transform_subtree_index_to_general() {
        assert_eq!(subtree_index_to_general(1, 1), 1);
        assert_eq!(subtree_index_to_general(1, 2), 2);
        assert_eq!(subtree_index_to_general(1, 1000), 1000);
        assert_eq!(subtree_index_to_general(1, 99999), 99999);

        assert_eq!(subtree_index_to_general(2, 1), 2);
        assert_eq!(subtree_index_to_general(2, 2), 4);
        assert_eq!(subtree_index_to_general(2, 7), 11);
        assert_eq!(subtree_index_to_general(2, 11), 19);

        assert_eq!(subtree_index_to_general(6, 1), 6);
        assert_eq!(subtree_index_to_general(6, 2), 12);
        assert_eq!(subtree_index_to_general(6, 6), 26);

        assert_eq!(subtree_index_to_general(26, 1), 26);
        assert_eq!(subtree_index_to_general(26, 2), 52);
        assert_eq!(subtree_index_to_general(26, 3), 53);

        assert_eq!(subtree_index_to_general(26, 7), 107);
        assert_eq!(subtree_index_to_general(26, 12), 212);

        assert_eq!(subtree_index_to_general(11, 17), 177);
    }

    #[test]
    fn transform_general_index_to_subtree() {
        assert_eq!(general_index_to_subtree(1, 1), 1);
        assert_eq!(general_index_to_subtree(1, 2), 2);
        assert_eq!(general_index_to_subtree(1, 1000), 1000);
        assert_eq!(general_index_to_subtree(1, 99999), 99999);

        assert_eq!(general_index_to_subtree(2, 2), 1);
        assert_eq!(general_index_to_subtree(2, 4), 2);
        assert_eq!(general_index_to_subtree(2, 11), 7);
        assert_eq!(general_index_to_subtree(2, 19), 11);

        assert_eq!(general_index_to_subtree(6, 6), 1);
        assert_eq!(general_index_to_subtree(6, 12), 2);
        assert_eq!(general_index_to_subtree(6, 26), 6);

        assert_eq!(general_index_to_subtree(26, 26), 1);
        assert_eq!(general_index_to_subtree(26, 52), 2);
        assert_eq!(general_index_to_subtree(26, 53), 3);
        assert_eq!(general_index_to_subtree(26, 107), 7);
        assert_eq!(general_index_to_subtree(26, 212), 12);
    }

    #[test]
    fn compute_log_base_two() {
        assert_eq!(log_base_two(2_u64.pow(1)), 1);
        assert_eq!(log_base_two(2_u64.pow(10)), 10);
        assert_eq!(log_base_two(2_u64.pow(33)), 33);
        assert_eq!(log_base_two(2_u64.pow(45)), 45);
        assert_eq!(log_base_two(2_u64.pow(63)), 63);
    }

    #[test]
    fn compute_left_most_leaf() {
        assert_eq!(left_most_leaf(1, 1), 2);
        assert_eq!(left_most_leaf(1, 9), 2_u64.pow(9));
        assert_eq!(left_most_leaf(1, 50), 2_u64.pow(50));

        assert_eq!(left_most_leaf(2, 1), 2 * 2_u64.pow(1));
        assert_eq!(left_most_leaf(2, 4), 2 * 2_u64.pow(4));
        assert_eq!(left_most_leaf(2, 5), 2 * 2_u64.pow(5));

        assert_eq!(left_most_leaf(6, 1), 6 * 2_u64.pow(1));
        assert_eq!(left_most_leaf(6, 2), 6 * 2_u64.pow(2));
        assert_eq!(left_most_leaf(6, 11), 6 * 2_u64.pow(11));

        assert_eq!(left_most_leaf(25, 1), 25 * 2_u64.pow(1));
    }

    #[test]
    fn compute_right_most_leaf() {
        assert_eq!(right_most_leaf(1, 1), 3);
        assert_eq!(right_most_leaf(1, 9), 2_u64.pow(10) - 1);
        assert_eq!(right_most_leaf(1, 50), 2_u64.pow(51) - 1);

        assert_eq!(right_most_leaf(2, 1), 2 * 2_u64.pow(1) + 1);
        assert_eq!(right_most_leaf(2, 4), 2 * 2_u64.pow(4) + 15);
        assert_eq!(right_most_leaf(2, 5), 2 * 2_u64.pow(5) + 31);

        assert_eq!(right_most_leaf(6, 1), 6 * 2_u64.pow(1) + 1);
        assert_eq!(right_most_leaf(6, 2), 6 * 2_u64.pow(2) + 3);
        assert_eq!(right_most_leaf(6, 11), 6 * 2_u64.pow(11) + 2047);

        assert_eq!(right_most_leaf(25, 1), 25 * 2_u64.pow(1) + 1);
    }

    #[test]
    fn determine_if_index_is_in_subtree() {
        assert_eq!(is_in_subtree(1, 3), true);
        assert_eq!(is_in_subtree(1, 100), true);
        assert_eq!(is_in_subtree(2, 10), true);
        assert_eq!(is_in_subtree(2, 6), false);
        assert_eq!(is_in_subtree(2, 15), false);
    }
}

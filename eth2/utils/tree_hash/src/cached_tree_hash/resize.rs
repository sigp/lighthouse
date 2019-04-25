use super::*;

/// New vec is bigger than old vec.
pub fn grow_merkle_cache(
    old_bytes: &[u8],
    old_flags: &[bool],
    from_height: usize,
    to_height: usize,
) -> Option<(Vec<u8>, Vec<bool>)> {
    // Determine the size of our new tree. It is not just a simple `1 << to_height` as there can be
    // an arbitrary number of nodes in `old_bytes` leaves if those leaves are subtrees.
    let to_nodes = {
        let old_nodes = old_bytes.len() / HASHSIZE;
        let additional_nodes = old_nodes - nodes_in_tree_of_height(from_height);
        nodes_in_tree_of_height(to_height) + additional_nodes
    };

    let mut bytes = vec![0; to_nodes * HASHSIZE];
    let mut flags = vec![true; to_nodes];

    let leaf_level = from_height;

    for i in 0..=from_height as usize {
        // If we're on the leaf slice, grab the first byte and all the of the bytes after that.
        // This is required because we can have an arbitrary number of bytes at the leaf level
        // (e.g., the case where there are subtrees as leaves).
        //
        // If we're not on a leaf level, the number of nodes is fixed and known.
        let (old_byte_slice, old_flag_slice) = if i == leaf_level {
            (
                old_bytes.get(first_byte_at_height(i)..)?,
                old_flags.get(first_node_at_height(i)..)?,
            )
        } else {
            (
                old_bytes.get(byte_range_at_height(i))?,
                old_flags.get(node_range_at_height(i))?,
            )
        };

        let new_i = i + to_height - from_height;
        let (new_byte_slice, new_flag_slice) = if i == leaf_level {
            (
                bytes.get_mut(first_byte_at_height(new_i)..)?,
                flags.get_mut(first_node_at_height(new_i)..)?,
            )
        } else {
            (
                bytes.get_mut(byte_range_at_height(new_i))?,
                flags.get_mut(node_range_at_height(new_i))?,
            )
        };

        new_byte_slice
            .get_mut(0..old_byte_slice.len())?
            .copy_from_slice(old_byte_slice);
        new_flag_slice
            .get_mut(0..old_flag_slice.len())?
            .copy_from_slice(old_flag_slice);
    }

    Some((bytes, flags))
}

/// New vec is smaller than old vec.
pub fn shrink_merkle_cache(
    from_bytes: &[u8],
    from_flags: &[bool],
    from_height: usize,
    to_height: usize,
    to_nodes: usize,
) -> Option<(Vec<u8>, Vec<bool>)> {
    let mut bytes = vec![0; to_nodes * HASHSIZE];
    let mut flags = vec![true; to_nodes];

    for i in 0..=to_height as usize {
        let from_i = i + from_height - to_height;

        let (from_byte_slice, from_flag_slice) = if from_i == from_height {
            (
                from_bytes.get(first_byte_at_height(from_i)..)?,
                from_flags.get(first_node_at_height(from_i)..)?,
            )
        } else {
            (
                from_bytes.get(byte_range_at_height(from_i))?,
                from_flags.get(node_range_at_height(from_i))?,
            )
        };

        let (to_byte_slice, to_flag_slice) = if i == to_height {
            (
                bytes.get_mut(first_byte_at_height(i)..)?,
                flags.get_mut(first_node_at_height(i)..)?,
            )
        } else {
            (
                bytes.get_mut(byte_range_at_height(i))?,
                flags.get_mut(node_range_at_height(i))?,
            )
        };

        to_byte_slice.copy_from_slice(from_byte_slice.get(0..to_byte_slice.len())?);
        to_flag_slice.copy_from_slice(from_flag_slice.get(0..to_flag_slice.len())?);
    }

    Some((bytes, flags))
}

fn nodes_in_tree_of_height(h: usize) -> usize {
    2 * (1 << h) - 1
}

fn byte_range_at_height(h: usize) -> Range<usize> {
    let node_range = node_range_at_height(h);
    node_range.start * HASHSIZE..node_range.end * HASHSIZE
}

fn node_range_at_height(h: usize) -> Range<usize> {
    first_node_at_height(h)..last_node_at_height(h) + 1
}

fn first_byte_at_height(h: usize) -> usize {
    first_node_at_height(h) * HASHSIZE
}

fn first_node_at_height(h: usize) -> usize {
    (1 << h) - 1
}

fn last_node_at_height(h: usize) -> usize {
    (1 << (h + 1)) - 2
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_grow_and_shrink_three_levels() {
        let small: usize = 1;
        let big: usize = 15;

        let original_bytes = vec![42; small * HASHSIZE];
        let original_flags = vec![false; small];

        let (grown_bytes, grown_flags) = grow_merkle_cache(
            &original_bytes,
            &original_flags,
            (small + 1).trailing_zeros() as usize - 1,
            (big + 1).trailing_zeros() as usize - 1,
        )
        .unwrap();

        let mut expected_bytes = vec![];
        let mut expected_flags = vec![];
        // First level
        expected_bytes.append(&mut vec![0; 32]);
        expected_flags.push(true);
        // Second level
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_flags.push(true);
        expected_flags.push(true);
        // Third level
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_flags.push(true);
        expected_flags.push(true);
        expected_flags.push(true);
        expected_flags.push(true);
        // Fourth level
        expected_bytes.append(&mut vec![42; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_flags.push(false);
        expected_flags.push(true);
        expected_flags.push(true);
        expected_flags.push(true);
        expected_flags.push(true);
        expected_flags.push(true);
        expected_flags.push(true);
        expected_flags.push(true);

        assert_eq!(expected_bytes, grown_bytes);
        assert_eq!(expected_flags, grown_flags);

        let (shrunk_bytes, shrunk_flags) = shrink_merkle_cache(
            &grown_bytes,
            &grown_flags,
            (big + 1).trailing_zeros() as usize - 1,
            (small + 1).trailing_zeros() as usize - 1,
            small,
        )
        .unwrap();

        assert_eq!(original_bytes, shrunk_bytes);
        assert_eq!(original_flags, shrunk_flags);
    }

    #[test]
    fn can_grow_and_shrink_one_level() {
        let small: usize = 7;
        let big: usize = 15;

        let original_bytes = vec![42; small * HASHSIZE];
        let original_flags = vec![false; small];

        let (grown_bytes, grown_flags) = grow_merkle_cache(
            &original_bytes,
            &original_flags,
            (small + 1).trailing_zeros() as usize - 1,
            (big + 1).trailing_zeros() as usize - 1,
        )
        .unwrap();

        let mut expected_bytes = vec![];
        let mut expected_flags = vec![];
        // First level
        expected_bytes.append(&mut vec![0; 32]);
        expected_flags.push(true);
        // Second level
        expected_bytes.append(&mut vec![42; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_flags.push(false);
        expected_flags.push(true);
        // Third level
        expected_bytes.append(&mut vec![42; 32]);
        expected_bytes.append(&mut vec![42; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_flags.push(false);
        expected_flags.push(false);
        expected_flags.push(true);
        expected_flags.push(true);
        // Fourth level
        expected_bytes.append(&mut vec![42; 32]);
        expected_bytes.append(&mut vec![42; 32]);
        expected_bytes.append(&mut vec![42; 32]);
        expected_bytes.append(&mut vec![42; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_bytes.append(&mut vec![0; 32]);
        expected_flags.push(false);
        expected_flags.push(false);
        expected_flags.push(false);
        expected_flags.push(false);
        expected_flags.push(true);
        expected_flags.push(true);
        expected_flags.push(true);
        expected_flags.push(true);

        assert_eq!(expected_bytes, grown_bytes);
        assert_eq!(expected_flags, grown_flags);

        let (shrunk_bytes, shrunk_flags) = shrink_merkle_cache(
            &grown_bytes,
            &grown_flags,
            (big + 1).trailing_zeros() as usize - 1,
            (small + 1).trailing_zeros() as usize - 1,
            small,
        )
        .unwrap();

        assert_eq!(original_bytes, shrunk_bytes);
        assert_eq!(original_flags, shrunk_flags);
    }
}

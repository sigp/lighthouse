use super::*;

/// New vec is bigger than old vec.
pub fn grow_merkle_cache(
    old_bytes: &[u8],
    old_flags: &[bool],
    from_height: usize,
    to_height: usize,
) -> Option<(Vec<u8>, Vec<bool>)> {
    let to_nodes = (1 << to_height.next_power_of_two()) - 1;

    // Determine the size of our new tree. It is not just a simple `1 << to_height` as there can be
    // an arbitrary number of bytes in `old_bytes` leaves.
    let new_byte_count = {
        let additional_from_nodes = old_bytes.len() / HASHSIZE - ((1 << from_height) - 1);
        ((1 << to_height + additional_from_nodes) - 1) * HASHSIZE
    };

    let mut bytes = vec![0; new_byte_count];
    let mut flags = vec![true; to_nodes];

    let leaf_level = from_height - 1;

    // Loop through all internal levels of the tree (skipping the final, leaves level).
    for i in 0..from_height as usize {
        // If we're on the leaf slice, grab the first byte and all the of the bytes after that.
        // This is required because we can have an arbitrary number of bytes at the leaf level
        // (e.g., the case where there are subtrees as leaves).
        //
        // If we're not on a leaf level, the number of nodes is fixed and known.
        let (byte_slice, flag_slice) = if i == leaf_level {
            (
                old_bytes.get(first_byte_at_height(i)..)?,
                old_flags.get(first_node_at_height(i)..)?,
            )
        } else {
            (
                old_bytes.get(byte_range_at_height(i))?,
                old_flags.get(node_range_at_height(i))?
            )
        };

        bytes
            .get_mut(byte_range_at_height(i + to_height - from_height))?
            .get_mut(0..byte_slice.len())?
            .copy_from_slice(byte_slice);
        flags
            .get_mut(node_range_at_height(i + to_height - from_height))?
            .get_mut(0..flag_slice.len())?
            .copy_from_slice(flag_slice);
    }

    Some((bytes, flags))
}

fn byte_range_at_height(h: usize) -> Range<usize> {
    first_byte_at_height(h)..last_node_at_height(h) * HASHSIZE
}

fn node_range_at_height(h: usize) -> Range<usize> {
    first_node_at_height(h)..last_node_at_height(h)
}

fn first_byte_at_height(h: usize) -> usize {
    first_node_at_height(h) * HASHSIZE
}

fn first_node_at_height(h: usize) -> usize {
    (1 << h) - 1
}

fn last_node_at_height(h: usize) -> usize {
    (1 << (h + 1)) - 1
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_grow_three_levels() {
        let from: usize = 1;
        let to: usize = 15;

        let old_bytes = vec![42; from * HASHSIZE];
        let old_flags = vec![false; from];

        let (new_bytes, new_flags) = grow_merkle_cache(
            &old_bytes,
            &old_flags,
            (from + 1).trailing_zeros() as usize,
            (to + 1).trailing_zeros() as usize,
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

        assert_eq!(expected_bytes, new_bytes);
        assert_eq!(expected_flags, new_flags);
    }

    #[test]
    fn can_grow_one_level() {
        let from: usize = 7;
        let to: usize = 15;

        let old_bytes = vec![42; from * HASHSIZE];
        let old_flags = vec![false; from];

        let (new_bytes, new_flags) = grow_merkle_cache(
            &old_bytes,
            &old_flags,
            (from + 1).trailing_zeros() as usize,
            (to + 1).trailing_zeros() as usize,
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

        assert_eq!(expected_bytes, new_bytes);
        assert_eq!(expected_flags, new_flags);
    }
}

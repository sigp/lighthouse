use super::*;

/// New vec is bigger than old vec.
pub fn grow_merkle_tree(
    old_bytes: &[u8],
    old_flags: &[bool],
    from_height: usize,
    to_height: usize,
) -> Option<(Vec<u8>, Vec<bool>)> {
    let to_nodes = nodes_in_tree_of_height(to_height);

    let mut bytes = vec![0; to_nodes * HASHSIZE];
    let mut flags = vec![true; to_nodes];

    for i in 0..=from_height {
        let old_byte_slice = old_bytes.get(byte_range_at_height(i))?;
        let old_flag_slice = old_flags.get(node_range_at_height(i))?;

        let offset = i + to_height - from_height;
        let new_byte_slice = bytes.get_mut(byte_range_at_height(offset))?;
        let new_flag_slice = flags.get_mut(node_range_at_height(offset))?;

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
pub fn shrink_merkle_tree(
    from_bytes: &[u8],
    from_flags: &[bool],
    from_height: usize,
    to_height: usize,
) -> Option<(Vec<u8>, Vec<bool>)> {
    let to_nodes = nodes_in_tree_of_height(to_height);

    let mut bytes = vec![0; to_nodes * HASHSIZE];
    let mut flags = vec![true; to_nodes];

    for i in 0..=to_height as usize {
        let offset = i + from_height - to_height;
        let from_byte_slice = from_bytes.get(byte_range_at_height(offset))?;
        let from_flag_slice = from_flags.get(node_range_at_height(offset))?;

        let to_byte_slice = bytes.get_mut(byte_range_at_height(i))?;
        let to_flag_slice = flags.get_mut(node_range_at_height(i))?;

        to_byte_slice.copy_from_slice(from_byte_slice.get(0..to_byte_slice.len())?);
        to_flag_slice.copy_from_slice(from_flag_slice.get(0..to_flag_slice.len())?);
    }

    Some((bytes, flags))
}

pub fn nodes_in_tree_of_height(h: usize) -> usize {
    2 * (1 << h) - 1
}

fn byte_range_at_height(h: usize) -> Range<usize> {
    let node_range = node_range_at_height(h);
    node_range.start * HASHSIZE..node_range.end * HASHSIZE
}

fn node_range_at_height(h: usize) -> Range<usize> {
    first_node_at_height(h)..last_node_at_height(h) + 1
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

        let (grown_bytes, grown_flags) = grow_merkle_tree(
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

        let (shrunk_bytes, shrunk_flags) = shrink_merkle_tree(
            &grown_bytes,
            &grown_flags,
            (big + 1).trailing_zeros() as usize - 1,
            (small + 1).trailing_zeros() as usize - 1,
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

        let (grown_bytes, grown_flags) = grow_merkle_tree(
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

        let (shrunk_bytes, shrunk_flags) = shrink_merkle_tree(
            &grown_bytes,
            &grown_flags,
            (big + 1).trailing_zeros() as usize - 1,
            (small + 1).trailing_zeros() as usize - 1,
        )
        .unwrap();

        assert_eq!(original_bytes, shrunk_bytes);
        assert_eq!(original_flags, shrunk_flags);
    }
}

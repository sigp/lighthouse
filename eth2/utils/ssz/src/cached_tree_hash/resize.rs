use super::*;

/// New vec is bigger than old vec.
fn grow_merkle_cache(
    old_bytes: &[u8],
    old_flags: &[bool],
    from_height: usize,
    to_height: usize,
) -> Option<Vec<u8>> {
    let to_nodes = (1 << to_height.next_power_of_two()) - 1;

    // Determine the size of our new tree. It is not just a simple `1 << to_height` as there can be
    // an arbitrary number of bytes in `old_bytes` leaves.
    let new_byte_count = {
        let additional_from_nodes = old_bytes.len() / HASHSIZE - ((1 << from_height) - 1);
        ((1 << to_height + additional_from_nodes) - 1) * HASHSIZE
    };
    dbg!(new_byte_count / 32);

    let mut bytes = vec![0; new_byte_count];
    let mut flags = vec![true; to_nodes];

    let leaf_level = from_height - 1;

    // Loop through all internal levels of the tree (skipping the final, leaves level).
    for i in 0..from_height - 1 as usize {
        // If we're on the leaf slice, grab the first byte and all the of the bytes after that.
        // This is required because we can have an arbitrary number of bytes at the leaf level
        // (e.g., the case where there are subtrees as leaves).
        //
        // If we're not on a leaf level, the number of nodes is fixed and known.
        let old_slice = if i == leaf_level {
            old_bytes.get(first_byte_at_height(i)..)
        } else {
            old_bytes.get(byte_range_at_height(i))
        }?;

        let new_slice = bytes
            .get_mut(byte_range_at_height(i + to_height - from_height))?
            .get_mut(0..old_slice.len())?;

        new_slice.copy_from_slice(old_slice);
    }

    Some(bytes)
}

/*
fn copy_bytes(
    from_range: Range<usize>,
    to_range: Range<usize>,
    from: &[u8],
    to: &mut Vec<u8>,
) -> Option<()> {
    let from_slice = from.get(node_range_to_byte_range(from_range));

    let to_slice = to
        .get_mut(byte_range_at_height(i + to_height - from_height))?
        .get_mut(0..old_slice.len())?;

    Ok(())
}
*/

fn node_range_to_byte_range(node_range: Range<usize>) -> Range<usize> {
    node_range.start * HASHSIZE..node_range.end * HASHSIZE
}

fn byte_range_at_height(h: usize) -> Range<usize> {
    first_byte_at_height(h)..last_node_at_height(h) * HASHSIZE
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
    fn can_grow() {
        let from: usize = 7;
        let to: usize = 15;

        let old_bytes = vec![42; from * HASHSIZE];
        let old_flags = vec![false; from];

        let new = grow_merkle_cache(
            &old_bytes,
            &old_flags,
            (from + 1).trailing_zeros() as usize,
            (to + 1).trailing_zeros() as usize,
        )
        .unwrap();

        println!("{:?}", new);
        let mut expected = vec![];
        // First level
        expected.append(&mut vec![0; 32]);
        // Second level
        expected.append(&mut vec![42; 32]);
        expected.append(&mut vec![0; 32]);
        // Third level
        expected.append(&mut vec![42; 32]);
        expected.append(&mut vec![42; 32]);
        expected.append(&mut vec![0; 32]);
        expected.append(&mut vec![0; 32]);
        // Fourth level
        expected.append(&mut vec![0; 32]);
        expected.append(&mut vec![0; 32]);
        expected.append(&mut vec![0; 32]);
        expected.append(&mut vec![0; 32]);
        expected.append(&mut vec![0; 32]);
        expected.append(&mut vec![0; 32]);
        expected.append(&mut vec![0; 32]);
        expected.append(&mut vec![0; 32]);

        assert_eq!(expected, new);
    }
}

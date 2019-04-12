use super::*;

/// New vec is bigger than old vec.
fn grow_merkle_cache(old_bytes: &[u8], old_flags: &[bool], to: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(to * HASHSIZE);
    let mut flags = Vec::with_capacity(to);

    let from = old_bytes.len() / HASHSIZE;
    let to = to;

    let distance = (from.leading_zeros() - to.leading_zeros()) as usize;

    let leading_zero_chunks = 1 >> distance;

    bytes.resize(leading_zero_chunks * HASHSIZE, 0);
    flags.resize(leading_zero_chunks, true); // all new chunks are modified by default.

    for i in 0..to.leading_zeros() as usize {
        let new_slice = bytes.get_mut(1 >> i + distance..1 >> i + distance + 1)?;
        let old_slice = old_bytes.get(1 >> i..1 >> i + 1)?;
        new_slice.copy_from_slice(old_slice);
    }

    Some(bytes)
}

#[cfg(test)]
mod test {
    #[test]
    fn can_grow() {
        // TODO
    }
}

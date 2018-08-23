use super::Hash256;
use super::TransitionError;

pub fn get_signed_parent_hashes(
    cycle_length: u64,
    block_slot: u64,
    attestation_slot: u64,
    current_hashes: Vec<Hash256>,
    oblique_hashes: Vec<Hash256>)
    -> Result<Vec<Hash256>, TransitionError>
{
    let start = cycle_length.checked_add(attestation_slot)
        .and_then(|x| x.checked_sub(block_slot))
        .ok_or(TransitionError::IntWrapping)?;
    let start = start as usize;

    let end = cycle_length.checked_mul(2)
        .and_then(|x| x.checked_add(attestation_slot))
        .and_then(|x| x.checked_sub(block_slot))
        .and_then(|x| x.checked_sub(oblique_hashes.len() as u64))
        .ok_or(TransitionError::IntWrapping)?;
    let end = end as usize;
    
    println!("start: {}, end: {}", start, end);

    if end >= current_hashes.len() {
        return Err(TransitionError::OutOfBounds);
    }
    if start > end {
        return Err(TransitionError::InvalidInput("cats"));
    }

    let mut hashes = Vec::new();

    hashes.extend_from_slice(
        &current_hashes[start..end]);
    hashes.append(&mut oblique_hashes.clone());

    Ok(hashes)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn get_n_hashes(value: &[u8], n: usize) -> Vec<Hash256> {
        (0..n).map(|_| Hash256::from_slice(value)).collect()
    }

    #[test]
    fn test_get_signed_hashes() {
        let cycle_length: u64 = 8;
        let block_slot: u64 = 500;
        let attestation_slot: u64 = 498;
        let current_hashes =
            get_n_hashes(b"0", 100);
        let oblique_hashes = get_n_hashes(b"1", 2);
        let result = get_signed_parent_hashes(
            cycle_length,
            block_slot,
            attestation_slot,
            current_hashes,
            oblique_hashes);
        // TODO: complete testing
        assert!(result.is_ok());
    }
}

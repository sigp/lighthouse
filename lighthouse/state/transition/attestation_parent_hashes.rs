use super::Hash256;

#[derive(Debug)]
pub enum ParentHashesError {
    BadCurrentHashes,
    BadObliqueHashes,
    SlotTooHigh,
    SlotTooLow,
    IntWrapping,
}

/// This function is used to select the hashes used in
/// the signing of an AttestationRecord.
///
/// It either returns Result with a vector of length `cycle_length,` or
/// returns an Error.
///
/// This function corresponds to the `get_signed_parent_hashes` function
/// in the Python reference implentation.
///
/// See this slide for more information:
/// https://tinyurl.com/ybzn2spw
pub fn attestation_parent_hashes(
    cycle_length: u8,
    block_slot: u64,
    attestation_slot: u64,
    current_hashes: &[Hash256],
    oblique_hashes: &[Hash256])
    -> Result<Vec<Hash256>, ParentHashesError>
{
    // This cast places a limit on cycle_length. If you change it, check math
    // for overflow.
    let cycle_length: u64 = u64::from(cycle_length);

    if current_hashes.len() as u64 != (cycle_length * 2) {
        return Err(ParentHashesError::BadCurrentHashes);
    }
    if oblique_hashes.len() as u64 > cycle_length {
        return Err(ParentHashesError::BadObliqueHashes);
    }
    if attestation_slot >= block_slot {
        return Err(ParentHashesError::SlotTooHigh);
    }

    /*
     * Cannot underflow as block_slot cannot be less
     * than attestation_slot.
     */
    let attestation_distance = block_slot - attestation_slot;

    if attestation_distance > cycle_length {
        return Err(ParentHashesError::SlotTooLow);
    }

    /*
     * Cannot underflow because attestation_distance cannot
     * be larger than cycle_length.
     */
    let start = cycle_length - attestation_distance;

    /*
     * Overflow is potentially impossible, but proof is complicated
     * enough to just use checked math.
     *
     * Arithmetic is:
     * start + cycle_length - oblique_hashes.len()
     */
    let end = start.checked_add(cycle_length)
        .and_then(|x| x.checked_sub(oblique_hashes.len() as u64))
        .ok_or(ParentHashesError::IntWrapping)?;


    let mut hashes = Vec::new();
    hashes.extend_from_slice(
        &current_hashes[(start as usize)..(end as usize)]);
    hashes.extend_from_slice(oblique_hashes);

    Ok(hashes)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn get_range_of_hashes(from: usize, to: usize) -> Vec<Hash256> {
        (from..to).map(|i| get_hash(&vec![i as u8])).collect()
    }

    fn get_hash(value: &[u8]) -> Hash256 {
        Hash256::from_slice(value)
    }

    #[test]
    fn test_get_signed_hashes_oblique_scenario_1() {
        /*
         * Two oblique hashes.
         */
        let cycle_length: u8 = 8;
        let block_slot: u64 = 19;
        let attestation_slot: u64 = 15;
        let current_hashes = get_range_of_hashes(3, 19);
        let oblique_hashes = get_range_of_hashes(100, 102);
        let result = attestation_parent_hashes(
            cycle_length,
            block_slot,
            attestation_slot,
            &current_hashes,
            &oblique_hashes);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), cycle_length as usize);

        let mut expected_result = get_range_of_hashes(7, 13);
        expected_result.append(&mut get_range_of_hashes(100, 102));
        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_get_signed_hashes_oblique_scenario_2() {
        /*
         * All oblique hashes.
         */
        let cycle_length: u8 = 8;
        let block_slot: u64 = 19;
        let attestation_slot: u64 = 15;
        let current_hashes = get_range_of_hashes(3, 19);
        let oblique_hashes = get_range_of_hashes(100, 108);
        let result = attestation_parent_hashes(
            cycle_length,
            block_slot,
            attestation_slot,
            &current_hashes,
            &oblique_hashes);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), cycle_length as usize);

        let expected_result = get_range_of_hashes(100, 108);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_get_signed_hashes_scenario_1() {
        /*
         * Google Slides example.
         * https://tinyurl.com/ybzn2spw
         */
        let cycle_length: u8 = 8;
        let block_slot: u64 = 19;
        let attestation_slot: u64 = 15;
        let current_hashes = get_range_of_hashes(3, 19);
        let oblique_hashes = vec![];
        let result = attestation_parent_hashes(
            cycle_length,
            block_slot,
            attestation_slot,
            &current_hashes,
            &oblique_hashes);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), cycle_length as usize);
        let expected_result = get_range_of_hashes(7, 15);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_get_signed_hashes_scenario_2() {
        /*
         * Block 1, attestation 0.
         */
        let cycle_length: u8 = 8;
        let block_slot: u64 = 1;
        let attestation_slot: u64 = 0;
        let current_hashes = get_range_of_hashes(0, 16);
        let oblique_hashes = vec![];
        let result = attestation_parent_hashes(
            cycle_length,
            block_slot,
            attestation_slot,
            &current_hashes,
            &oblique_hashes);
        let result = result.unwrap();
        assert_eq!(result.len(), cycle_length as usize);
        let expected_result = get_range_of_hashes(7, 15);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_get_signed_hashes_scenario_3() {
        /*
         * attestation_slot too large
         */
        let cycle_length: u8 = 8;
        let block_slot: u64 = 100;
        let attestation_slot: u64 = 100;
        let current_hashes = get_range_of_hashes(0, 16);
        let oblique_hashes = vec![];
        let result = attestation_parent_hashes(
            cycle_length,
            block_slot,
            attestation_slot,
            &current_hashes,
            &oblique_hashes);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_signed_hashes_scenario_4() {
        /*
         * Current hashes too small
         */
        let cycle_length: u8 = 8;
        let block_slot: u64 = 100;
        let attestation_slot: u64 = 99;
        let current_hashes = get_range_of_hashes(0, 15);
        let oblique_hashes = vec![];
        let result = attestation_parent_hashes(
            cycle_length,
            block_slot,
            attestation_slot,
            &current_hashes,
            &oblique_hashes);
        assert!(result.is_err());
    }
}

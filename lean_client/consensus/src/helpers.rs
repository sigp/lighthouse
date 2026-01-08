/// Helper functions for consensus operations.

/// Determines if a slot can be a justification target based on the finalized slot.
///
/// Justifiable slots follow a specific pattern based on the delta from finalized:
/// - Slots within 5 of finalized are always justifiable (delta 0-5)
/// - Perfect squares (delta = 1, 4, 9, 16, 25...) are justifiable
/// - Numbers of form n² + n (delta = 6, 12, 20, 30, 42...) are justifiable
///
/// # Arguments
/// * `finalized_slot` - The slot of the latest finalized checkpoint
/// * `candidate_slot` - The slot being checked for justifiability
///
/// # Returns
/// * `Ok(true)` if the slot can be a justification target
/// * `Ok(false)` if the slot cannot be a justification target
/// * `Err` if candidate_slot < finalized_slot
pub fn is_justifiable_slot(finalized_slot: u64, candidate_slot: u64) -> Result<bool, String> {
    if candidate_slot < finalized_slot {
        return Err(format!(
            "candidate slot {} must be >= finalized slot {}",
            candidate_slot, finalized_slot
        ));
    }

    let delta = candidate_slot - finalized_slot;

    // Rule 1: First 6 slots (delta 0-5) are always justifiable
    if delta <= 5 {
        return Ok(true);
    }

    // Rule 2: Perfect squares are justifiable
    // Check if sqrt(delta) is an integer
    let sqrt = (delta as f64).sqrt();
    if sqrt.fract() == 0.0 {
        return Ok(true);
    }

    // Rule 3: Numbers of form n² + 2n are justifiable
    // This is equivalent to checking if sqrt(delta + 0.25) has fractional part 0.5
    // Because n² + 2n + 0.25 = (n + 0.5)²
    // So sqrt(n² + 2n + 0.25) = n + 0.5
    let sqrt_plus = ((delta as f64) + 0.25).sqrt();
    if (sqrt_plus.fract() - 0.5).abs() < f64::EPSILON {
        return Ok(true);
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_six_slots_always_justifiable() {
        // Slots 0-5 after finalized are always justifiable
        for delta in 0..=5 {
            assert!(
                is_justifiable_slot(0, delta).unwrap(),
                "slot {} should be justifiable",
                delta
            );
            // Also test with non-zero finalized slot
            assert!(
                is_justifiable_slot(10, 10 + delta).unwrap(),
                "slot {} (finalized=10) should be justifiable",
                10 + delta
            );
        }
    }

    #[test]
    fn test_perfect_squares_justifiable() {
        // Perfect squares: 1, 4, 9, 16, 25, 36, 49, 64, 81, 100...
        let perfect_squares = [1, 4, 9, 16, 25, 36, 49, 64, 81, 100];
        for &delta in &perfect_squares {
            assert!(
                is_justifiable_slot(0, delta).unwrap(),
                "slot {} (perfect square) should be justifiable",
                delta
            );
        }
    }

    #[test]
    fn test_n_squared_plus_n_justifiable() {
        // n² + n pattern (derived from sqrt(delta + 0.25) having fractional part 0.5):
        // n=2: 4 + 2 = 6
        // n=3: 9 + 3 = 12
        // n=4: 16 + 4 = 20
        // n=5: 25 + 5 = 30
        let n_squared_plus_n = [6, 12, 20, 30, 42, 56, 72, 90, 110];
        for &delta in &n_squared_plus_n {
            assert!(
                is_justifiable_slot(0, delta).unwrap(),
                "slot {} (n² + n pattern) should be justifiable",
                delta
            );
        }
    }

    #[test]
    fn test_non_justifiable_slots() {
        // Slots that should NOT be justifiable (not in any pattern)
        let non_justifiable = [7, 8, 10, 11, 13, 14, 15, 17, 18, 19, 21, 22, 23, 24, 26];
        for &delta in &non_justifiable {
            assert!(
                !is_justifiable_slot(0, delta).unwrap(),
                "slot {} should NOT be justifiable",
                delta
            );
        }
    }

    #[test]
    fn test_candidate_before_finalized_returns_error() {
        let result = is_justifiable_slot(10, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_with_nonzero_finalized() {
        // Test that the function works correctly with non-zero finalized slot
        let finalized = 100;

        // First 6 slots after finalized
        assert!(is_justifiable_slot(finalized, 100).unwrap()); // delta 0
        assert!(is_justifiable_slot(finalized, 105).unwrap()); // delta 5

        // Perfect square: delta 9
        assert!(is_justifiable_slot(finalized, 109).unwrap());

        // n² + n: delta 6
        assert!(is_justifiable_slot(finalized, 106).unwrap());

        // Non-justifiable: delta 7
        assert!(!is_justifiable_slot(finalized, 107).unwrap());
    }
}

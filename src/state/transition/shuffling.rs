use super::config::Config;
use super::blake2::{ Blake2s, Digest };
use super::utils::types::Sha256Digest;

// Interprets a 3-byte slice from a [u8] as an integer.
fn get_shift_from_source(source: &[u8], offset: usize) -> usize {
    (source[offset + 2] as usize) |
        ((source[offset + 1] as usize) << 8) |
        ((source[offset    ] as usize) << 16)
}

// Given entropy in the form of `seed`, return a shuffled list of validators
// indicies of size `validator_count` or `sample`.
pub fn get_shuffling(
    seed: &Sha256Digest,
    validator_count: &usize,
    config: &Config) 
    -> Vec<usize>
{
    assert!(*validator_count > 0, "cannot shuffle 0 validators");
    let mut output: Vec<usize> = (0..*validator_count).collect();
    assert!(*validator_count <= (config.max_validators as usize),
        "validator_count exceeds max_validators");

    // Do the first blake hash round
    let mut source = Blake2s::new();
    source.input(&seed);
    
    let mut v = 0;
    while v < *validator_count {
        let current_source = source.result();
        let mut source_offset = 0;
        while source_offset < 30 {
            let m = get_shift_from_source(&current_source, source_offset);
            let shuffled_position: usize = (m % (validator_count - v)) + v;
            output.swap(v as usize, shuffled_position as usize);
            v += 1;
            if v >= *validator_count { break; }
            source_offset += 3;
        }
        // Re-hash the source (TODO: this does one extra hash, can be optimised)
        source = Blake2s::new();
        source.input(&current_source);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shuffling_shift_fn() {
        let mut x = get_shift_from_source(
            &vec![0_u8, 0, 1],
            0);
        assert_eq!((x as u32), 1);

        x = get_shift_from_source(
            &vec![0_u8, 1, 1],
            0);
        assert_eq!(x, 257);
        
        x = get_shift_from_source(
            &vec![1_u8, 1, 1],
            0);
        assert_eq!(x, 65793);
        
        x = get_shift_from_source(
            &vec![255_u8, 1, 1],
            0);
        assert_eq!(x, 16711937);
    }


    #[test]
    fn test_shuffling() {
        let s = get_shuffling(
            &Sha256Digest::zero(),
            &10,
            &Config::standard());
        assert_eq!(s,
                   vec!(0, 9, 7, 6, 4, 1, 8, 5, 2, 3),
                   "10 validator shuffle was not as expected");
    }

    #[test]
    fn test_shuffling_with_gt_half_max_validators() {
        let mut config = Config::standard();
        config.max_validators = 19;
        let s = get_shuffling(
            &Sha256Digest::zero(),
            &10,
            &Config::standard());
        assert_eq!(s,
                   vec!(0, 9, 7, 6, 4, 1, 8, 5, 2, 3),
                   "10 validator shuffle was not as expected");
    }
}

/// A library for performing deterministic, pseudo-random shuffling on a vector.
///
/// This library is designed to confirm to the Ethereum 2.0 specification.

extern crate hashing;

mod rng;

use self::rng::ShuffleRng;

#[derive(Debug)]
pub enum ShuffleErr {
    ExceedsListLength,
}

/// Performs a deterministic, in-place shuffle of a vector.
///
/// The final order of the shuffle is determined by successive hashes
/// of the supplied `seed`.
///
/// This is a Fisher-Yates-Durtstenfeld shuffle.
pub fn shuffle<T>(
    seed: &[u8],
    mut list: Vec<T>)
    -> Result<Vec<T>, ShuffleErr>
{
    let mut rng = ShuffleRng::new(seed);
    if list.len() > rng.rand_max as usize {
        return Err(ShuffleErr::ExceedsListLength);
    }
    for i in 0..(list.len() - 1) {
        let n = list.len() - i;
        let j = rng.rand_range(n as u32) as usize + i;
        list.swap(i, j);
    }
    Ok(list)
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::hashing::canonical_hash;

    #[test]
    fn test_shuffling() {
        let seed = canonical_hash(b"4kn4driuctg8");
        let list: Vec<usize> = (0..12).collect();
        let s = shuffle(&seed, list).unwrap();
        assert_eq!(
            s,
            vec![7, 3, 2, 5, 11, 9, 1, 0, 4, 6, 10, 8],
        )
    }
}

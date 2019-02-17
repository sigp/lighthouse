use super::hashing::hash;

const SEED_SIZE_BYTES: usize = 32;
const RAND_BYTES: usize = 3; // 24 / 8
const RAND_MAX: u32 = 16_777_215; // 2 ** (rand_bytes * 8) - 1

/// A pseudo-random number generator which given a seed
/// uses successive blake2s hashing to generate "entropy".
pub struct ShuffleRng {
    seed: Vec<u8>,
    idx: usize,
    pub rand_max: u32,
}

impl ShuffleRng {
    /// Create a new instance given some "seed" bytes.
    pub fn new(initial_seed: &[u8]) -> Self {
        Self {
            seed: hash(initial_seed),
            idx: 0,
            rand_max: RAND_MAX,
        }
    }

    /// "Regenerates" the seed by hashing it.
    fn rehash_seed(&mut self) {
        self.seed = hash(&self.seed);
        self.idx = 0;
    }

    /// Extracts 3 bytes from the `seed`. Rehashes seed if required.
    fn rand(&mut self) -> u32 {
        self.idx += RAND_BYTES;
        if self.idx >= SEED_SIZE_BYTES {
            self.rehash_seed();
            self.rand()
        } else {
            int_from_byte_slice(&self.seed, self.idx - RAND_BYTES)
        }
    }

    /// Generate a random u32 below the specified maximum `n`.
    ///
    /// Provides a filtered result from a higher-level rng, by discarding
    /// results which may bias the output. Because of this, execution time is
    /// not linear and may potentially be infinite.
    pub fn rand_range(&mut self, n: u32) -> u32 {
        assert!(n < RAND_MAX, "RAND_MAX exceed");
        let mut x = self.rand();
        while x >= self.rand_max - (self.rand_max % n) {
            x = self.rand();
        }
        x % n
    }
}

/// Reads the next three bytes of `source`, starting from `offset` and
/// interprets those bytes as a 24 bit big-endian integer.
/// Returns that integer.
fn int_from_byte_slice(source: &[u8], offset: usize) -> u32 {
    (u32::from(source[offset + 2]))
        | (u32::from(source[offset + 1]) << 8)
        | (u32::from(source[offset]) << 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shuffling_int_from_slice() {
        let mut x = int_from_byte_slice(&[0, 0, 1], 0);
        assert_eq!((x as u32), 1);

        x = int_from_byte_slice(&[0, 1, 1], 0);
        assert_eq!(x, 257);

        x = int_from_byte_slice(&[1, 1, 1], 0);
        assert_eq!(x, 65793);

        x = int_from_byte_slice(&[255, 1, 1], 0);
        assert_eq!(x, 16711937);

        x = int_from_byte_slice(&[255, 255, 255], 0);
        assert_eq!(x, 16777215);

        x = int_from_byte_slice(&[0x8f, 0xbb, 0xc7], 0);
        assert_eq!(x, 9419719);
    }
}

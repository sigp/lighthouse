/*
 * Implemenation of a bitfield as a vec. Only
 * supports bytes (Vec<u8>) as the underlying
 * storage.
 *
 * A future implementation should be more efficient,
 * this is just to get the job done for now.
 */
use std::cmp::max;

#[derive(Eq,Clone)]
pub struct BooleanBitfield{
    len: usize,
    vec: Vec<u8>
}

impl BooleanBitfield {
    /// Create a new bitfield with a length of zero.
    pub fn new() -> Self {
        Self {
            len: 0,
            vec: vec![0]
        }
    }

    /// Create a new bitfield of a certain capacity
    pub fn with_capacity(capacity: usize) -> Self {
        let mut vec = Vec::with_capacity(capacity / 8 + 1);
        vec.push(0);
        Self {
            len: 0,
            vec
        }
    }

    /// Read the value of a bit.
    ///
    /// Will return `true` if the bit has been set to `true`
    /// without then being set to `False`.
    pub fn get_bit(&self, i: &usize) -> bool {
        let bit = |i: &usize| *i % 8;
        let byte = |i: &usize| *i / 8;

        if byte(i) >= self.vec.len() {
            false
        } else {
             self.vec[byte(i)] & (1 << (bit(i) as u8)) != 0
        }
    }

    /// Set the value of a bit.
    ///
    /// If this bit is larger than the length of the underlying byte
    /// array it will be extended.
    pub fn set_bit(&mut self, i: &usize, to: &bool) {
        let bit = |i: &usize| *i % 8;
        let byte = |i: &usize| *i / 8;

        self.len = max(self.len, i + 1);

        if byte(i) >= self.vec.len() {
            self.vec.resize(byte(i) + 1, 0);
        }
        match to {
            true =>  {
                self.vec[byte(i)] =
                    self.vec[byte(i)] |  (1 << (bit(i) as u8))
            }
            false => {
                self.vec[byte(i)] =
                    self.vec[byte(i)] & !(1 << (bit(i) as u8))
            }
        }
    }

    /// Return the "length" of this bitfield. Length is defined as
    /// the highest bit that has been set.
    ///
    /// Note: this is distinct from the length of the underlying
    /// vector.
    pub fn len(&self) -> usize { self.len }

    /// Iterate through the underlying vector and count the number of
    /// true bits.
    pub fn num_true_bits(&self) -> u64 {
        let mut count: u64 = 0;
        for byte in &self.vec {
            for bit in 0..8 {
                if byte & (1 << (bit as u8)) != 0 {
                    count += 1;
                }
            }
        }
        count
    }

    /// Clone and return the underlying byte array (`Vec<u8>`).
    pub fn to_be_vec(&self) -> Vec<u8> {
        let mut o = self.vec.clone();
        o.reverse();
        o
    }
}

impl PartialEq for BooleanBitfield {
    fn eq(&self, other: &BooleanBitfield) -> bool {
        (self.vec == other.vec) &
            (self.len == other.len)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_bitfield_len() {
        let b = BooleanBitfield::new();
        assert_eq!(b.len(), 0);
        assert_eq!(b.to_be_vec(), vec![0]);

        let b = BooleanBitfield::with_capacity(100);
        assert_eq!(b.len(), 0);
        assert_eq!(b.to_be_vec(), vec![0]);
    }

    #[test]
    fn test_bitfield_set() {
        let mut b = BooleanBitfield::new();
        b.set_bit(&0, &false);
        assert_eq!(b.to_be_vec(), [0]);

        b = BooleanBitfield::new();
        b.set_bit(&7, &true);
        assert_eq!(b.to_be_vec(), [128]);
        b.set_bit(&7, &false);
        assert_eq!(b.to_be_vec(), [0]);
        assert_eq!(b.len(), 8);

        b = BooleanBitfield::new();
        b.set_bit(&7, &true);
        b.set_bit(&0, &true);
        assert_eq!(b.to_be_vec(), [129]);
        b.set_bit(&7, &false);
        assert_eq!(b.to_be_vec(), [1]);
        assert_eq!(b.len(), 8);

        b = BooleanBitfield::new();
        b.set_bit(&8, &true);
        assert_eq!(b.to_be_vec(), [1, 0]);
        assert_eq!(b.len(), 9);
        b.set_bit(&8, &false);
        assert_eq!(b.to_be_vec(), [0, 0]);
        assert_eq!(b.len(), 9);

        b = BooleanBitfield::new();
        b.set_bit(&15, &true);
        assert_eq!(b.to_be_vec(), [128, 0]);
        b.set_bit(&15, &false);
        assert_eq!(b.to_be_vec(), [0, 0]);
        assert_eq!(b.len(), 16);

        b = BooleanBitfield::new();
        b.set_bit(&8, &true);
        b.set_bit(&15, &true);
        assert_eq!(b.to_be_vec(), [129, 0]);
        b.set_bit(&15, &false);
        assert_eq!(b.to_be_vec(), [1, 0]);
        assert_eq!(b.len(), 16);
    }

    #[test]
    fn test_bitfield_get() {
        let test_nums = vec![0, 8, 15, 42, 1337];
        for i in test_nums {
            let mut b = BooleanBitfield::new();
            assert_eq!(b.get_bit(&i), false);
            b.set_bit(&i, &true);
            assert_eq!(b.get_bit(&i), true);
            b.set_bit(&i, &true);
        }
    }

    #[test]
    fn test_bitfield_num_true_bits() {
        let mut b = BooleanBitfield::new();
        assert_eq!(b.num_true_bits(), 0);
        b.set_bit(&15, &true);
        assert_eq!(b.num_true_bits(), 1);
        b.set_bit(&15, &false);
        assert_eq!(b.num_true_bits(), 0);
        b.set_bit(&0, &true);
        b.set_bit(&7, &true);
        b.set_bit(&8, &true);
        b.set_bit(&1337, &true);
        assert_eq!(b.num_true_bits(), 4);
    }
}

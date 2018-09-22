/*
 * Implemenation of a bitfield as a vec. Only
 * supports bytes (Vec<u8>) as the underlying
 * storage.
 *
 * A future implementation should be more efficient,
 * this is just to get the job done for now.
 */
extern crate ssz;

use std::cmp::max;

#[derive(Eq, Clone, Default, Debug)]
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
    pub fn get_bit(&self, i: usize) -> bool {
        let bit = |i: usize| i % 8;
        let byte = |i: usize| i / 8;

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
    pub fn set_bit(&mut self, i: usize, to: bool) {
        let bit = |i: usize| i % 8;
        let byte = |i: usize| i / 8;

        self.len = max(self.len, i + 1);

        if byte(i) >= self.vec.len() {
            self.vec.resize(byte(i) + 1, 0);
        }
        if to {
            self.vec[byte(i)] =
                self.vec[byte(i)] |  (1 << (bit(i) as u8))
        } else {
            self.vec[byte(i)] =
                self.vec[byte(i)] & !(1 << (bit(i) as u8))
        }
    }

    /// Return the "length" of this bitfield. Length is defined as
    /// the highest bit that has been set.
    ///
    /// Note: this is distinct from the length of the underlying
    /// vector.
    pub fn len(&self) -> usize { self.len }

    /// True if no bits have ever been set. A bit that is set and then
    /// unset will still count to the length of the bitfield.
    ///
    /// Note: this is distinct from the length of the underlying
    /// vector.
    pub fn is_empty(&self) -> bool { self.len == 0 }

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

    /// Iterate through the underlying vector and find the highest
    /// set bit. Useful for instantiating a new instance from
    /// some set of bytes.
    pub fn compute_length(bytes: &[u8]) -> usize {
        for byte in (0..bytes.len()).rev() {
            for bit in (0..8).rev() {
                if byte & (1 << (bit as u8)) != 0 {
                    return (byte * 8) + bit
                }
            }
        }
        0
    }

    /// Clone and return the underlying byte array (`Vec<u8>`).
    pub fn to_be_vec(&self) -> Vec<u8> {
        let mut o = self.vec.clone();
        o.reverse();
        o
    }
}

impl<'a> From<&'a [u8]> for BooleanBitfield {
    fn from(input: &[u8]) -> Self {
        let mut vec = input.to_vec();
        vec.reverse();
        BooleanBitfield {
            vec,
            len: BooleanBitfield::compute_length(input)
        }
    }
}

impl PartialEq for BooleanBitfield {
    fn eq(&self, other: &BooleanBitfield) -> bool {
        (self.vec == other.vec) &
            (self.len == other.len)
    }
}

impl ssz::Encodable for BooleanBitfield {
    fn ssz_append(&self, s: &mut ssz::SszStream) {
        s.append_vec(&self.to_be_vec());
    }
}

impl ssz::Decodable for BooleanBitfield {
    fn ssz_decode(bytes: &[u8], index: usize)
        -> Result<(Self, usize), ssz::DecodeError>
    {
        let len = ssz::decode::decode_length(
            bytes,
            index,
            ssz::LENGTH_BYTES)?;
        if (ssz::LENGTH_BYTES + len) > bytes.len() {
            return Err(ssz::DecodeError::TooShort);
        }
        if len == 0 {
            Ok((BooleanBitfield::new(),
                index + ssz::LENGTH_BYTES))
        } else {
            let b = BooleanBitfield::
                from(&bytes[(index + 4)..(index + len + 4)]);
            let index = index + ssz::LENGTH_BYTES + len;
            Ok((b, index))
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ssz::Decodable;

    #[test]
    fn test_ssz_encoding() {
        let mut b = BooleanBitfield::new();
        b.set_bit(8, true);

        let mut stream = ssz::SszStream::new();
        stream.append(&b);

        assert_eq!(stream.drain(), vec![0, 0, 0, 2, 1, 0]);
    }

    #[test]
    fn test_ssz_decoding() {
        /*
         * Correct input
         */
        let input = vec![0, 0, 0, 2, 1, 0];
        let (b, i) = BooleanBitfield::ssz_decode(&input, 0).unwrap();
        assert_eq!(i, 6);
        assert_eq!(b.num_true_bits(), 1);
        assert_eq!(b.get_bit(8), true);

        /*
         * Input too long
         */
        let mut input = vec![0, 0, 0, 2, 1, 0];
        input.push(42);
        let (b, i) = BooleanBitfield::ssz_decode(&input, 0).unwrap();
        assert_eq!(i, 6);
        assert_eq!(b.num_true_bits(), 1);
        assert_eq!(b.get_bit(8), true);

        /*
         * Input too short
         */
        let input = vec![0, 0, 0, 2, 1];
        let res = BooleanBitfield::ssz_decode(&input, 0);
        assert_eq!(res, Err(ssz::DecodeError::TooShort));
    }

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
        b.set_bit(0, false);
        assert_eq!(b.to_be_vec(), [0]);

        b = BooleanBitfield::new();
        b.set_bit(7, true);
        assert_eq!(b.to_be_vec(), [128]);
        b.set_bit(7, false);
        assert_eq!(b.to_be_vec(), [0]);
        assert_eq!(b.len(), 8);

        b = BooleanBitfield::new();
        b.set_bit(7, true);
        b.set_bit(0, true);
        assert_eq!(b.to_be_vec(), [129]);
        b.set_bit(7, false);
        assert_eq!(b.to_be_vec(), [1]);
        assert_eq!(b.len(), 8);

        b = BooleanBitfield::new();
        b.set_bit(8, true);
        assert_eq!(b.to_be_vec(), [1, 0]);
        assert_eq!(b.len(), 9);
        b.set_bit(8, false);
        assert_eq!(b.to_be_vec(), [0, 0]);
        assert_eq!(b.len(), 9);

        b = BooleanBitfield::new();
        b.set_bit(15, true);
        assert_eq!(b.to_be_vec(), [128, 0]);
        b.set_bit(15, false);
        assert_eq!(b.to_be_vec(), [0, 0]);
        assert_eq!(b.len(), 16);

        b = BooleanBitfield::new();
        b.set_bit(8, true);
        b.set_bit(15, true);
        assert_eq!(b.to_be_vec(), [129, 0]);
        b.set_bit(15, false);
        assert_eq!(b.to_be_vec(), [1, 0]);
        assert_eq!(b.len(), 16);
    }

    #[test]
    fn test_bitfield_get() {
        let test_nums = vec![0, 8, 15, 42, 1337];
        for i in test_nums {
            let mut b = BooleanBitfield::new();
            assert_eq!(b.get_bit(i), false);
            b.set_bit(i, true);
            assert_eq!(b.get_bit(i), true);
            b.set_bit(i, true);
        }
    }

    #[test]
    fn test_bitfield_num_true_bits() {
        let mut b = BooleanBitfield::new();
        assert_eq!(b.num_true_bits(), 0);
        b.set_bit(15, true);
        assert_eq!(b.num_true_bits(), 1);
        b.set_bit(15, false);
        assert_eq!(b.num_true_bits(), 0);
        b.set_bit(0, true);
        b.set_bit(7, true);
        b.set_bit(8, true);
        b.set_bit(1337, true);
        assert_eq!(b.num_true_bits(), 4);
    }
}

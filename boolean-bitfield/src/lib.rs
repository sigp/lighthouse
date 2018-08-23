/*
 * Implemenation of a bitfield as a vec. Only
 * supports bytes (Vec<u8>) as the underlying
 * storage.
 *
 * A future implementation should be more efficient,
 * this is just to get the job done for now.
 */
use std::cmp::max;

#[derive(Eq)]
pub struct BooleanBitfield{
    len: usize,
    vec: Vec<u8>
}

impl BooleanBitfield {
    pub fn new() -> Self {
        Self {
            len: 0,
            vec: vec![]
        }
    }
    
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            len: 0,
            vec: Vec::with_capacity(capacity)
        }
    }

    // Output the bitfield as a big-endian vec of u8.
    pub fn to_be_vec(&self) -> Vec<u8> {
        let mut o = self.vec.clone();
        o.reverse();
        o
    }

    pub fn get_bit(&self, i: &usize) -> bool {
        self.get_bit_on_byte(*i % 8, *i / 8)
    }

    fn get_bit_on_byte(&self, bit: usize, byte: usize) -> bool {
        assert!(bit < 8);
        if byte >= self.vec.len() {
            false
        } else {
             self.vec[byte] & (1 << (bit as u8)) != 0
        }
    }

    pub fn set_bit(&mut self, bit: &usize, to: &bool) {
        self.len = max(self.len, *bit + 1);
        self.set_bit_on_byte(*bit % 8, *bit / 8, to);
    }

    fn set_bit_on_byte(&mut self, bit: usize, byte: usize, val: &bool) {
        assert!(bit < 8);
        if byte >= self.vec.len() {
            self.vec.resize(byte + 1, 0);
        }
        match val {
            true =>  self.vec[byte] = self.vec[byte] |  (1 << (bit as u8)),
            false => self.vec[byte] = self.vec[byte] & !(1 << (bit as u8))
        }
    }

    pub fn len(&self) -> usize { self.len }

    // Return the total number of bits set to true.
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
}

impl PartialEq for BooleanBitfield {
    fn eq(&self, other: &BooleanBitfield) -> bool {
        (self.vec == other.vec) &
            (self.len == other.len)
    }
}

impl Clone for BooleanBitfield {
    fn clone(&self) -> Self {
        Self {
            vec: self.vec.to_vec(),
            ..*self
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::rlp;

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

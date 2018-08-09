/*
 * This is a WIP of implementing an alternative 
 * serialization strategy. It attempts to follow Vitalik's
 * "ssz" format here: 
 * https://github.com/ethereum/research/tree/master/py_ssz
 *
 * This implementation is not final and would almost certainly
 * have issues.
 */
extern crate bytes;
extern crate ethereum_types;

use self::bytes::{ BytesMut, BufMut };
use self::ethereum_types::{ H256, U256 };

pub const LENGTH_BYTES: usize = 4;

pub trait Encodable {
    fn ssz_append(&self, s: &mut SszStream);
}

pub struct SszStream {
    buffer: Vec<u8>
}

impl SszStream {
    pub fn new() -> Self {
        SszStream {
            buffer: Vec::new()
        }
    }

    pub fn append<E>(&mut self, value: &E) -> &mut Self
        where E: Encodable
    {
        value.ssz_append(self);
        self
    }

    fn append_encoded_vec(&mut self, v: &mut Vec<u8>) {
        self.buffer.append(&mut encode_length(v.len(), LENGTH_BYTES));
        self.buffer.append(v) ;
    }
    
    fn append_encoded_array(&mut self, a: &mut [u8]) {
        let len = a.len();
        self.buffer.append(&mut encode_length(len, LENGTH_BYTES));
        self.buffer.extend_from_slice(&a[0..len]);
    }

    pub fn drain(self) -> Vec<u8> {
        self.buffer
    }
}

pub fn encode<E>(value: &E) -> Vec<u8>
    where E: Encodable
{
    let mut stream = SszStream::new();
    stream.append(value);
    stream.drain()
}

fn encode_length(len: usize, length_bytes: usize) -> Vec<u8> {
    assert!(length_bytes > 0);  // For sanity
    assert!((len as usize) < 2usize.pow(length_bytes as u32 * 8));
    let mut header: Vec<u8> = vec![0; length_bytes];
    for i in 0..length_bytes {
        let offset = (length_bytes - i - 1) * 8;
        header[i] = ((len >> offset) & 0xff) as u8;
    };
    header
}

/*
 * Implementations for various types
 */

impl Encodable for u32 {
    fn ssz_append(&self, s: &mut SszStream) {
        let mut buf = BytesMut::with_capacity(32/8);
        buf.put_u32_be(*self);
        s.append_encoded_vec(&mut buf.to_vec());
    }
}

impl Encodable for u64 {
    fn ssz_append(&self, s: &mut SszStream) {
        let mut buf = BytesMut::with_capacity(64/8);
        buf.put_u64_be(*self);
        s.append_encoded_vec(&mut buf.to_vec());
    }
}

impl Encodable for H256 {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_encoded_vec(&mut self.to_vec());
    }
}

impl Encodable for U256 {
    fn ssz_append(&self, s: &mut SszStream) {
        let mut a = [0; 32];
        self.to_big_endian(&mut a);
        s.append_encoded_array(&mut a);
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[should_panic]
    fn test_encode_length_0_bytes_panic() {
        encode_length(0, 0);
    }

    #[test]
    fn test_encode_length_4_bytes() {
        assert_eq!(
            encode_length(0, 4),
            vec![0; 4]
        );
        assert_eq!(
            encode_length(1, 4),
            vec![0, 0, 0, 1]
        );
        assert_eq!(
            encode_length(255, 4),
            vec![0, 0, 0, 255]
        );
        assert_eq!(
            encode_length(256, 4),
            vec![0, 0, 1, 0]
        );
        assert_eq!(
            encode_length(4294967295, 4),  // 2^(4*8) - 1
            vec![255, 255, 255, 255]
        );
    }
    
    #[test]
    #[should_panic]
    fn test_encode_length_4_bytes_panic() {
        encode_length(4294967296, 4);  // 2^(4*8)
    }

    #[test]
    fn test_serialization() {
        pub struct TestStruct {
            pub one: u32,
            pub two: H256,
            pub three: u64,        
        }

        impl Encodable for TestStruct {
            fn ssz_append(&self, s: &mut SszStream) {
                s.append(&self.one);
                s.append(&self.two);
                s.append(&self.three);
            }
        }

        let t = TestStruct {
            one: 1,
            two: H256::zero(),
            three: 100
        };

        let e = encode(&t);
        assert_eq!(e[0..4], [0, 0, 0, 4]);
        assert_eq!(e[4..8], [0, 0, 0, 1]);
        assert_eq!(e[8..12], [0, 0, 0, 32]);
        assert_eq!(e[12..44], [0; 32]);
        assert_eq!(e[44..48], [0, 0, 0, 8]);
        assert_eq!(e[48..56], [0, 0, 0, 0, 0, 0, 0, 100]);
        assert_eq!(e.len(), 56);
    }
}

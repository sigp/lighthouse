use super::LENGTH_BYTES;

pub trait Encodable {
    fn ssz_append(&self, s: &mut SszStream);
}

/// Provides a buffer for appending ssz-encodable values.
///
/// Use the `append()` fn to add a value to a list, then use
/// the `drain()` method to consume the struct and return the
/// ssz encoded bytes.
pub struct SszStream {
    buffer: Vec<u8>
}

impl SszStream {
    /// Create a new, empty steam for writing ssz values.
    pub fn new() -> Self {
        SszStream {
            buffer: Vec::new()
        }
    }

    /// Append some ssz encodable value to the stream.
    pub fn append<E>(&mut self, value: &E) -> &mut Self
        where E: Encodable
    {
        value.ssz_append(self);
        self
    }

    /// Append some ssz encoded bytes to the steam.
    ///
    /// The length of the supplied bytes will be concatenated
    /// to the stream before the supplied bytes.
    pub fn append_encoded_val(&mut self, vec: &Vec<u8>) {
        self.buffer.extend_from_slice(
            &encode_length(vec.len(),
            LENGTH_BYTES));
        self.buffer.extend_from_slice(&vec);
    }

    /// Append some vector (list) of encodable values to the stream.
    ///
    /// The length of the list will be concatenated to the stream, then
    /// each item in the vector will be encoded and concatenated.
    pub fn append_vec<E>(&mut self, vec: &Vec<E>)
        where E: Encodable
    {
        self.buffer.extend_from_slice(&encode_length(vec.len(), LENGTH_BYTES));
        for v in vec {
            v.ssz_append(self);
        }
    }

    /// Consume the stream and return the underlying bytes.
    pub fn drain(self) -> Vec<u8> {
        self.buffer
    }
}

/// Encode some length into a ssz size prefix.
///
/// The ssz size prefix is 4 bytes, which is treated as a continuious
/// 32bit big-endian integer.
pub fn encode_length(len: usize, length_bytes: usize) -> Vec<u8> {
    assert!(length_bytes > 0);  // For sanity
    assert!((len as usize) < 2usize.pow(length_bytes as u32 * 8));
    let mut header: Vec<u8> = vec![0; length_bytes];
    for i in 0..length_bytes {
        let offset = (length_bytes - i - 1) * 8;
        header[i] = ((len >> offset) & 0xff) as u8;
    };
    header
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ethereum_types::{ H256, U256 };

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
    fn test_encode_struct() {
        pub struct TestStruct {
            pub one: u32,
            pub two: H256,
            pub three: u64,
            pub four: U256,
        }

        impl Encodable for TestStruct {
            fn ssz_append(&self, s: &mut SszStream) {
                s.append(&self.one);
                s.append(&self.two);
                s.append(&self.three);
                s.append(&self.four);
            }
        }

        let t = TestStruct {
            one: 1,
            two: H256::zero(),
            three: 100,
            four: U256::zero(),
        };

        let mut s = SszStream::new();
        s.append(&t);
        let e = s.drain();

        let expected_len = {
            4 + 4 +
            4 + 32 +
            4 + 8 +
            4 + 32
        };

        assert_eq!(e[0..4], [0, 0, 0, 4]);
        assert_eq!(e[4..8], [0, 0, 0, 1]);
        assert_eq!(e[8..12], [0, 0, 0, 32]);
        assert_eq!(e[12..44], [0; 32]);
        assert_eq!(e[44..48], [0, 0, 0, 8]);
        assert_eq!(e[48..56], [0, 0, 0, 0, 0, 0, 0, 100]);
        assert_eq!(e[56..60], [0, 0, 0, 32]);
        assert_eq!(e[60..92], [0; 32]);
        assert_eq!(e.len(), expected_len);
    }
}

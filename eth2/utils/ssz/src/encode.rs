use super::*;

mod impls;

pub trait Encodable {
    fn is_ssz_fixed_len() -> bool;

    fn ssz_append(&self, buf: &mut Vec<u8>);

    /// The number of bytes this object occupies in the fixed-length portion of the SSZ bytes.
    ///
    /// By default, this is set to `BYTES_PER_LENGTH_OFFSET` which is suitable for variable length
    /// objects, but not fixed-length objects. Fixed-length objects _must_ return a value which
    /// represents their length.
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }

    fn as_ssz_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];

        self.ssz_append(&mut buf);

        buf
    }
}

/// Allow for encoding an ordered series of distinct or indistinct objects as SSZ bytes.
///
/// **You must call `finalize(..)` after the final `append(..)` call** to ensure the bytes are
/// written to `buf`.
pub struct SszEncoder<'a> {
    offset: usize,
    buf: &'a mut Vec<u8>,
    variable_bytes: Vec<u8>,
}

impl<'a> SszEncoder<'a> {
    pub fn list(buf: &'a mut Vec<u8>, num_fixed_bytes: usize) -> Self {
        Self::container(buf, num_fixed_bytes)
    }

    pub fn container(buf: &'a mut Vec<u8>, num_fixed_bytes: usize) -> Self {
        buf.reserve(num_fixed_bytes);

        Self {
            offset: num_fixed_bytes,
            buf,
            variable_bytes: vec![],
        }
    }

    pub fn append<T: Encodable>(&mut self, item: &T) {
        if T::is_ssz_fixed_len() {
            item.ssz_append(&mut self.buf);
        } else {
            self.buf
                .append(&mut encode_length(self.offset + self.variable_bytes.len()));

            item.ssz_append(&mut self.variable_bytes);
        }
    }

    pub fn finalize(&mut self) -> &mut Vec<u8> {
        self.buf.append(&mut self.variable_bytes);

        &mut self.buf
    }
}

/// Encode `len` as a little-endian byte vec of `BYTES_PER_LENGTH_OFFSET` length.
///
/// If `len` is larger than `2 ^ BYTES_PER_LENGTH_OFFSET`, a `debug_assert` is raised.
pub fn encode_length(len: usize) -> Vec<u8> {
    // Note: it is possible for `len` to be larger than what can be encoded in
    // `BYTES_PER_LENGTH_OFFSET` bytes, triggering this debug assertion.
    //
    // These are the alternatives to using a `debug_assert` here:
    //
    // 1. Use `assert`.
    // 2. Push an error to the caller (e.g., `Option` or `Result`).
    // 3. Ignore it completely.
    //
    // I have avoided (1) because it's basically a choice between "produce invalid SSZ" or "kill
    // the entire program". I figure it may be possible for an attacker to trigger this assert and
    // take the program down -- I think producing invalid SSZ is a better option than this.
    //
    // I have avoided (2) because this error will need to be propagated upstream, making encoding a
    // function which may fail. I don't think this is ergonomic and the upsides don't outweigh the
    // downsides.
    //
    // I figure a `debug_assertion` is better than (3) as it will give us a change to detect the
    // error during testing.
    //
    // If you have a different opinion, feel free to start an issue and tag @paulhauner.
    debug_assert!(len <= MAX_LENGTH_VALUE);

    len.to_le_bytes()[0..BYTES_PER_LENGTH_OFFSET].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_length() {
        assert_eq!(encode_length(0), vec![0; 4]);

        assert_eq!(encode_length(1), vec![1, 0, 0, 0]);

        assert_eq!(
            encode_length(MAX_LENGTH_VALUE),
            vec![255; BYTES_PER_LENGTH_OFFSET]
        );
    }

    #[test]
    #[should_panic]
    #[cfg(debug_assertions)]
    fn test_encode_length_above_max_debug_panics() {
        encode_length(MAX_LENGTH_VALUE + 1);
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_encode_length_above_max_not_debug_does_not_panic() {
        assert_eq!(encode_length(MAX_LENGTH_VALUE + 1), vec![0; 4]);
    }
}

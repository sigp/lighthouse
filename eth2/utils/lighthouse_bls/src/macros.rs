macro_rules! impl_tree_hash {
    ($byte_size: expr) => {
        fn tree_hash_type() -> tree_hash::TreeHashType {
            tree_hash::TreeHashType::Vector
        }

        fn tree_hash_packed_encoding(&self) -> Vec<u8> {
            unreachable!("Vector should never be packed.")
        }

        fn tree_hash_packing_factor() -> usize {
            unreachable!("Vector should never be packed.")
        }

        fn tree_hash_root(&self) -> Vec<u8> {
            // We could use the tree hash implementation for `FixedVec<u8, $byte_size>`,
            // but benchmarks have show that to be at least 15% slower because of the
            // unnecessary copying and allocation (one Vec per byte)
            let values_per_chunk = tree_hash::BYTES_PER_CHUNK;
            let minimum_chunk_count = ($byte_size + values_per_chunk - 1) / values_per_chunk;
            tree_hash::merkle_root(&self.serialize(), minimum_chunk_count)
        }
    };
}

macro_rules! impl_ssz_encode {
    ($byte_size: expr) => {
        fn is_ssz_fixed_len() -> bool {
            true
        }

        fn ssz_fixed_len() -> usize {
            $byte_size
        }

        fn ssz_bytes_len(&self) -> usize {
            $byte_size
        }

        fn ssz_append(&self, buf: &mut Vec<u8>) {
            buf.extend_from_slice(&self.serialize())
        }
    };
}

macro_rules! impl_ssz_decode {
    ($byte_size: expr) => {
        fn is_ssz_fixed_len() -> bool {
            true
        }

        fn ssz_fixed_len() -> usize {
            $byte_size
        }

        fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
            let len = bytes.len();
            let expected = <Self as ssz::Decode>::ssz_fixed_len();

            if len != expected {
                Err(ssz::DecodeError::InvalidByteLength { len, expected })
            } else {
                Self::deserialize(bytes)
                    .map_err(|e| ssz::DecodeError::BytesInvalid(format!("{:?}", e)))
            }
        }
    };
}

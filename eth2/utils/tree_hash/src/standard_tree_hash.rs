use super::*;
use hashing::hash;
use int_to_bytes::int_to_bytes32;
use ssz::ssz_encode;

mod impls;

pub trait TreeHash {
    fn tree_hash_type() -> TreeHashType;

    fn tree_hash_packed_encoding(&self) -> Vec<u8>;

    fn tree_hash_packing_factor() -> usize;

    fn tree_hash_root(&self) -> Vec<u8>;
}

pub fn merkle_root(bytes: &[u8]) -> Vec<u8> {
    // TODO: replace this with a _more_ efficient fn which is more memory efficient.
    efficient_merkleize(&bytes)[0..32].to_vec()
}

pub fn efficient_merkleize(bytes: &[u8]) -> Vec<u8> {
    let leaves = num_sanitized_leaves(bytes.len());
    let nodes = num_nodes(leaves);
    let internal_nodes = nodes - leaves;

    let num_bytes = internal_nodes * HASHSIZE + bytes.len();

    let mut o: Vec<u8> = vec![0; internal_nodes * HASHSIZE];
    o.append(&mut bytes.to_vec());

    assert_eq!(o.len(), num_bytes);

    let empty_chunk_hash = hash(&[0; MERKLE_HASH_CHUNCK]);

    let mut i = nodes * HASHSIZE;
    let mut j = internal_nodes * HASHSIZE;

    while i >= MERKLE_HASH_CHUNCK {
        i -= MERKLE_HASH_CHUNCK;

        j -= HASHSIZE;
        let hash = match o.get(i..i + MERKLE_HASH_CHUNCK) {
            // All bytes are available, hash as ususal.
            Some(slice) => hash(slice),
            // Unable to get all the bytes.
            None => {
                match o.get(i..) {
                    // Able to get some of the bytes, pad them out.
                    Some(slice) => {
                        let mut bytes = slice.to_vec();
                        bytes.resize(MERKLE_HASH_CHUNCK, 0);
                        hash(&bytes)
                    }
                    // Unable to get any bytes, use the empty-chunk hash.
                    None => empty_chunk_hash.clone(),
                }
            }
        };

        o[j..j + HASHSIZE].copy_from_slice(&hash);
    }

    o
}

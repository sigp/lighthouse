use super::*;
use hashing::hash;

pub fn merkle_root(bytes: &[u8]) -> Vec<u8> {
    standard_merkleize(&bytes)[0..32].to_vec()
}

pub fn standard_merkleize(bytes: &[u8]) -> Vec<u8> {
    // If the bytes are just one chunk (or less than one chunk) just return them.
    if bytes.len() <= HASHSIZE {
        let mut o = bytes.to_vec();
        o.resize(HASHSIZE, 0);
        return o;
    }

    let leaves = num_sanitized_leaves(bytes.len());
    let nodes = num_nodes(leaves);
    let internal_nodes = nodes - leaves;

    let num_bytes = std::cmp::max(internal_nodes, 1) * HASHSIZE + bytes.len();

    let mut o: Vec<u8> = vec![0; internal_nodes * HASHSIZE];

    o.append(&mut bytes.to_vec());

    assert_eq!(o.len(), num_bytes);

    let empty_chunk_hash = hash(&[0; MERKLE_HASH_CHUNK]);

    let mut i = nodes * HASHSIZE;
    let mut j = internal_nodes * HASHSIZE;

    while i >= MERKLE_HASH_CHUNK {
        i -= MERKLE_HASH_CHUNK;

        j -= HASHSIZE;
        let hash = match o.get(i..i + MERKLE_HASH_CHUNK) {
            // All bytes are available, hash as ususal.
            Some(slice) => hash(slice),
            // Unable to get all the bytes.
            None => {
                match o.get(i..) {
                    // Able to get some of the bytes, pad them out.
                    Some(slice) => {
                        let mut bytes = slice.to_vec();
                        bytes.resize(MERKLE_HASH_CHUNK, 0);
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

fn num_sanitized_leaves(num_bytes: usize) -> usize {
    let leaves = (num_bytes + HASHSIZE - 1) / HASHSIZE;
    leaves.next_power_of_two()
}

fn num_nodes(num_leaves: usize) -> usize {
    2 * num_leaves - 1
}

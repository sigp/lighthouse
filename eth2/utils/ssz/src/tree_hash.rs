use hashing::hash;

const SSZ_CHUNK_SIZE: usize = 128;
const HASHSIZE: usize = 32;

pub trait TreeHash {
    fn hash_tree_root_internal(&self) -> Vec<u8>;
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result = self.hash_tree_root_internal();
        if result.len() < HASHSIZE {
            zpad(&mut result, HASHSIZE);
        }
        result
    }
}

/// Returns a 32 byte hash of 'list' - a vector of byte vectors.
/// Note that this will consume 'list'.
pub fn merkle_hash(list: &mut Vec<Vec<u8>>) -> Vec<u8> {
    // flatten list
    let (mut chunk_size, mut chunkz) = list_to_blob(list);

    // get data_len as bytes. It will hashed will the merkle root
    let mut datalen = list.len().to_le_bytes().to_vec();
    zpad(&mut datalen, 32);

    // Tree-hash
    while chunkz.len() > HASHSIZE {
        let mut new_chunkz: Vec<u8> = Vec::new();

        for two_chunks in chunkz.chunks(chunk_size * 2) {
            if two_chunks.len() == chunk_size {
                // Odd number of chunks
                let mut c = two_chunks.to_vec();
                c.append(&mut vec![0; SSZ_CHUNK_SIZE]);
                new_chunkz.append(&mut hash(&c));
            } else {
                // Hash two chuncks together
                new_chunkz.append(&mut hash(two_chunks));
            }
        }

        chunk_size = HASHSIZE;
        chunkz = new_chunkz;
    }

    chunkz.append(&mut datalen);
    hash(&chunkz)
}

fn list_to_blob(list: &mut Vec<Vec<u8>>) -> (usize, Vec<u8>) {
    let chunk_size = if list.is_empty() || list[0].len() < SSZ_CHUNK_SIZE {
        SSZ_CHUNK_SIZE
    } else {
        list[0].len()
    };

    let items_per_chunk = SSZ_CHUNK_SIZE / list[0].len();
    let chunk_count = list.len() / items_per_chunk;

    let mut chunkz = Vec::new();
    if list.is_empty() {
        // handle and empty list
        chunkz.append(&mut vec![0; SSZ_CHUNK_SIZE]);
    } else if list[0].len() <= SSZ_CHUNK_SIZE {
        // just create a blob here; we'll divide into
        // chunked slices when we merklize
        let mut chunk = Vec::with_capacity(chunk_size);
        let mut item_count_in_chunk = 0;
        chunkz.reserve(chunk_count * chunk_size);
        for item in list.iter_mut() {
            item_count_in_chunk += 1;
            chunk.append(item);

            // completed chunk?
            if item_count_in_chunk == items_per_chunk {
                zpad(&mut chunk, chunk_size);
                chunkz.append(&mut chunk);
                item_count_in_chunk = 0;
            }
        }

        // left-over uncompleted chunk?
        if item_count_in_chunk != 0 {
            zpad(&mut chunk, chunk_size);
            chunkz.append(&mut chunk);
        }
    } else {
        // chunks larger than SSZ_CHUNK_SIZE
        chunkz.reserve(chunk_count * chunk_size);
        for item in list.iter_mut() {
            chunkz.append(item);
        }
    }

    (chunk_size, chunkz)
}

/// right pads with zeros making 'bytes' 'size' in length
fn zpad(bytes: &mut Vec<u8>, size: usize) {
    if bytes.len() < size {
        bytes.resize(size, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_hash() {
        let data1 = vec![1; 100];
        let data2 = vec![2; 100];
        let data3 = vec![3; 100];
        let mut list = vec![data1, data2, data3];
        let result = merkle_hash(&mut list);

        //note: should test againt a known test hash value
        assert_eq!(HASHSIZE, result.len());
    }
}

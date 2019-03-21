use hashing::hash;

const BYTES_PER_CHUNK: usize = 32;
const HASHSIZE: usize = 32;

pub trait TreeHash {
    fn hash_tree_root(&self) -> Vec<u8>;
}

/// Returns a 32 byte hash of 'list' - a vector of byte vectors.
/// Note that this will consume 'list'.
pub fn merkle_hash(list: &mut Vec<Vec<u8>>) -> Vec<u8> {
    // flatten list
    let mut chunkz = list_to_blob(list);

    // get data_len as bytes. It will hashed will the merkle root
    let mut datalen = list.len().to_le_bytes().to_vec();
    zpad(&mut datalen, 32);

    // merklelize
    while chunkz.len() > HASHSIZE {
        let mut new_chunkz: Vec<u8> = Vec::new();

        for two_chunks in chunkz.chunks(BYTES_PER_CHUNK * 2) {
            // Hash two chuncks together
            new_chunkz.append(&mut hash(two_chunks));
        }

        chunkz = new_chunkz;
    }

    chunkz.append(&mut datalen);
    hash(&chunkz)
}

fn list_to_blob(list: &mut Vec<Vec<u8>>) -> Vec<u8> {
    // pack - fit as many many items per chunk as we can and then
    // right pad to BYTES_PER_CHUNCK
    let (items_per_chunk, chunk_count) = if list.is_empty() {
        (1, 1)
    } else {
        let items_per_chunk = BYTES_PER_CHUNK / list[0].len();
        let chunk_count = list.len() / items_per_chunk;
        (items_per_chunk, chunk_count)
    };

    let mut chunkz = Vec::new();
    if list.is_empty() {
        // handle and empty list
        chunkz.append(&mut vec![0; BYTES_PER_CHUNK * 2]);
    } else if list[0].len() <= BYTES_PER_CHUNK {
        // just create a blob here; we'll divide into
        // chunked slices when we merklize
        let mut chunk = Vec::with_capacity(BYTES_PER_CHUNK);
        let mut item_count_in_chunk = 0;
        chunkz.reserve(chunk_count * BYTES_PER_CHUNK);
        for item in list.iter_mut() {
            item_count_in_chunk += 1;
            chunk.append(item);

            // completed chunk?
            if item_count_in_chunk == items_per_chunk {
                zpad(&mut chunk, BYTES_PER_CHUNK);
                chunkz.append(&mut chunk);
                item_count_in_chunk = 0;
            }
        }

        // left-over uncompleted chunk?
        if item_count_in_chunk != 0 {
            zpad(&mut chunk, BYTES_PER_CHUNK);
            chunkz.append(&mut chunk);
        }
    }

    // extend the number of chunks to a power of two if necessary
    if !chunk_count.is_power_of_two() {
        let zero_chunks_count = chunk_count.next_power_of_two() - chunk_count;
        chunkz.append(&mut vec![0; zero_chunks_count * BYTES_PER_CHUNK]);
    }

    chunkz
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
        let data1 = vec![1; 32];
        let data2 = vec![2; 32];
        let data3 = vec![3; 32];
        let mut list = vec![data1, data2, data3];
        let result = merkle_hash(&mut list);

        //note: should test againt a known test hash value
        assert_eq!(HASHSIZE, result.len());
    }
}

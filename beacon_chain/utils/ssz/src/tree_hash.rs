const CHUNKSIZE: usize = 128;
const HASHSIZE: usize = 32;

pub trait TreeHash {
    // Note: it would be nice to have a default trait implementation here
    // i.e. szz_encode(self) - but rust complains it does not know
    // the size of 'self'.  Not sure if there's a way around this.

    fn tree_hash(&self) -> Vec<u8>;
}

// python example:  Note - I'm seeing some inconsistencies
// between this and the 'Tree Hash' section in the SSZ spec.
// So, I imagine it will change.
/* def merkle_hash(lst):
    # Concatenate list into data
    if len(lst[0]) != next_power_of_2(len(lst[0])):
        lst = [extend_to_power_of_2(x) for x in lst]
    data = b''.join(lst)
    # Add padding
    data += b'\x00' * (CHUNKSIZE - (len(data) % CHUNKSIZE or CHUNKSIZE))
    assert len(data) % CHUNKSIZE == 0
    # Store length (to compensate for non-bijectiveness of padding)
    datalen = len(lst).to_bytes(32, 'big')
    # Convert to chunks
    chunkz = [data[i:i+CHUNKSIZE] for i in range(0, len(data), CHUNKSIZE)]
    chunkz = [None] * next_power_of_2(len(chunkz)) + chunkz + [b'\x00' * CHUNKSIZE]
    for i in range(len(chunkz)//2 - 1, 0, -1):
        chunkz[i] = hash(chunkz[i*2] + chunkz[i*2+1])
    return hash(chunkz[1] + datalen) */

/**
 * Returns a 32 byte hash of 'list', a vector of byte vectors.
 * Note that this will consume 'list'.
 * */
pub fn merkle_hash(list: &mut Vec<Vec<u8>>) -> Vec<u8> {
    // flatten list
    let data = &mut list_to_blob(list);

    // data should be divisible by CHUNKSIZE
    assert_eq!(data.len() % CHUNKSIZE, 0);

    // get data_len as bytes. It will hashed will the merkle root
    let dlen = data.len() as u64;
    let data_len_bytes = &mut dlen.tree_hash();
    data_len_bytes.resize(32, 0);

    // merklize
    //
    // From the Spec:
    // while len(chunkz) > 1:
    //    if len(chunkz) % 2 == 1:
    //        chunkz.append(b'\x00' * SSZ_CHUNK_SIZE)
    //    chunkz = [hash(chunkz[i] + chunkz[i+1]) for i in range(0, len(chunkz), 2)]
    let mut mhash = hash_level(data, CHUNKSIZE);
    while mhash.len() > HASHSIZE {
        mhash = hash_level(&mut mhash, HASHSIZE);
    }

    assert_eq!(mhash.len(), HASHSIZE);

    mhash.append(data_len_bytes);
    mhash.tree_hash()
}

/**
 * Takes a flat vector of bytes. It then hashes (chunk_size * 2) into
 * a byte vector of hashes, divisible by the 32 byte hashsize
 */
fn hash_level(data: &mut Vec<u8>, chunk_size: usize) -> Vec<u8> {
    assert!(data.len() % chunk_size == 0);

    let mut result: Vec<u8> = Vec::new();
    for two_chunks in data.chunks(chunk_size * 2) {
        if two_chunks.len() == chunk_size && data.len() > chunk_size {
            // if there is only one chunk here, hash it with a zero-byte
            // CHUNKSIZE vector
            let mut c = two_chunks.to_vec();
            c.append(&mut vec![0; CHUNKSIZE]);
            result.append(&mut c.tree_hash());
        } else {
            result.append(&mut two_chunks.tree_hash());
        }
    }

    result
}

fn list_to_blob(list: &mut Vec<Vec<u8>>) -> Vec<u8> {
    let mut data_len = 0;
    if list[0].len().is_power_of_two() == false {
        for x in list.iter_mut() {
            extend_to_power_of_2(x);
            data_len += x.len();
        }
    }

    // do we need padding?
    let extend_by = if data_len % CHUNKSIZE > 0 {
        CHUNKSIZE - (data_len % CHUNKSIZE)
    } else {
        0
    };

    // allocate buffer and append each list element (flatten the vec of vecs)
    data_len += extend_by;
    let mut data: Vec<u8> = Vec::with_capacity(data_len);
    for x in list.iter_mut() {
        data.append(x);
    }

    // add padding
    let mut i = 0;
    while i < extend_by {
        data.push(0);
        i += 1;
    }

    data
}

/**
 * Extends data length to a power of 2 by minimally right-zero-padding
 */
fn extend_to_power_of_2(data: &mut Vec<u8>) {
    let len = data.len();
    let new_len = len.next_power_of_two();
    if new_len > len {
        data.resize(new_len, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extend_to_power_of_2() {
        let mut data = vec![1, 2, 3, 4, 5];
        extend_to_power_of_2(&mut data);
        assert_eq!(data, [1, 2, 3, 4, 5, 0, 0, 0]);
    }

    #[test]
    fn test_merkle_hash() {
        let data1 = vec![1; 100];
        let data2 = vec![2; 100];
        let data3 = vec![3; 100];
        let mut list = vec![data1, data2, data3];
        let result = merkle_hash(&mut list);

        //note: should test againt a known test hash value
        assert_eq!(HASHSIZE, result.len());
        println!("merkle_hash: {:?}", result);
    }

}

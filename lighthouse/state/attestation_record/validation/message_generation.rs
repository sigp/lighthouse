use super::ssz::SszStream;
use super::utils::hash::canonical_hash;
use super::utils::types::Hash256;

/// Generates the message used to validate the signature provided with an AttestationRecord.
///
/// Ensures that the signer of the message has a view of the chain that is compatible with ours.
pub fn generate_signed_message(
    slot: u64,
    parent_hashes: &[Hash256],
    shard_id: u16,
    shard_block_hash: &Hash256,
    justified_slot: u64)
    -> Vec<u8>
{
    /*
     * Note: it's a little risky here to use SSZ, because the encoding is not necessarily SSZ
     * (for example, SSZ might change whilst this doesn't).
     *
     * I have suggested switching this to ssz here:
     * https://github.com/ethereum/eth2.0-specs/issues/5
     *
     * If this doesn't happen, it would be safer to not use SSZ at all.
     */
    let mut ssz_stream = SszStream::new();
    ssz_stream.append(&slot);
    ssz_stream.append_vec(&parent_hashes.to_vec());
    ssz_stream.append(&shard_id);
    ssz_stream.append(shard_block_hash);
    ssz_stream.append(&justified_slot);
    let bytes = ssz_stream.drain();
    canonical_hash(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_signed_message() {
        let slot = 93;
        let parent_hashes: Vec<Hash256> = (0..12)
            .map(|i| Hash256::from(i as u64))
            .collect();
        let shard_id = 15;
        let shard_block_hash = Hash256::from("shard_block_hash".as_bytes());
        let justified_slot = 18;

        let output = generate_signed_message(
            slot,
            &parent_hashes,
            shard_id,
            &shard_block_hash,
            justified_slot);

        /*
         * Note: this is not some well-known test vector, it's simply the result of running
         * this and printing the output.
         *
         * Once well-known test vectors are established, they should be placed here.
         */
        let expected = vec![
            149, 99, 94, 229, 72, 144, 233, 14, 164, 16, 143, 53, 94, 48,
            118, 179, 33, 181, 172, 215, 2, 191, 176, 18, 188, 172, 137,
            178, 236, 66, 74, 120
        ];

        assert_eq!(output, expected);
    }
}

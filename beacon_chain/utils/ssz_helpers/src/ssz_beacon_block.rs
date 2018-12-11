use super::hashing::canonical_hash;
use super::ssz::decode::{decode_length, Decodable};
use super::types::beacon_block::{MAX_SSZ_BLOCK_LENGTH, MIN_SSZ_BLOCK_LENGTH};

#[derive(Debug, PartialEq)]
pub enum SszBeaconBlockError {
    TooShort,
    TooLong,
}

/*
 * Constants used for navigating the SSZ bytes.
 */
const LENGTH_PREFIX_BYTES: usize = 4;
const SLOT_BYTES: usize = 8;
const HASH_SIZE: usize = 32;
const RANDAO_REVEAL_BYTES: usize = HASH_SIZE;
const POW_CHAIN_REF_BYTES: usize = HASH_SIZE;
const ACTIVE_STATE_BYTES: usize = HASH_SIZE;
const CRYSTALLIZED_STATE_BYTES: usize = HASH_SIZE;

/// Allows for reading of block values directly from serialized ssz bytes.
///
/// The purpose of this struct is to provide the functionality to read block fields directly from
/// some serialized SSZ slice allowing us to read the block without fully
/// de-serializing it.
///
/// This struct should be as "zero-copy" as possible. The `ssz` field is a reference to some slice
/// and each function reads from that slice.
///
/// Use this to perform intial checks before we fully de-serialize a block. It should only really
/// be used to verify blocks that come in from the network, for internal operations we should use a
/// full `BeaconBlock`.
#[derive(Debug, PartialEq)]
pub struct SszBeaconBlock<'a> {
    ssz: &'a [u8],
    block_ssz_len: usize,
    // Ancestors
    ancestors_position: usize,
    ancestors_len: usize,
    // Attestations
    attestations_position: usize,
    attestations_len: usize,
    // Specials
    specials_position: usize,
    specials_len: usize,
}

impl<'a> SszBeaconBlock<'a> {
    /// Create a new instance from a slice reference.
    ///
    /// This function will validate the length of the ssz string, however it will not validate the
    /// contents.
    ///
    /// The returned `SszBeaconBlock` instance will contain a `len` field which can be used to determine
    /// how many bytes were read from the slice. In the case of multiple, sequentually serialized
    /// blocks `len` can be used to assume the location of the next serialized block.
    pub fn from_slice(vec: &'a [u8]) -> Result<Self, SszBeaconBlockError> {
        let untrimmed_ssz = &vec[..];

        /*
         * Ensure the SSZ is long enough to be a block
         */
        if vec.len() < MIN_SSZ_BLOCK_LENGTH {
            return Err(SszBeaconBlockError::TooShort);
        }

        /*
         * Ensure the SSZ slice isn't longer than is possible for a block.
         */
        if vec.len() > MAX_SSZ_BLOCK_LENGTH {
            return Err(SszBeaconBlockError::TooLong);
        }

        /*
         * Determine how many bytes are used to store ancestor hashes.
         */
        let ancestors_position = SLOT_BYTES + RANDAO_REVEAL_BYTES + POW_CHAIN_REF_BYTES;
        let ancestors_len = decode_length(untrimmed_ssz, ancestors_position, LENGTH_PREFIX_BYTES)
            .map_err(|_| SszBeaconBlockError::TooShort)?;

        /*
         * Determine how many bytes are used to store attestation records.
         */
        let attestations_position = ancestors_position + LENGTH_PREFIX_BYTES + ancestors_len +     // end of ancestor bytes
            ACTIVE_STATE_BYTES +
            CRYSTALLIZED_STATE_BYTES;
        let attestations_len =
            decode_length(untrimmed_ssz, attestations_position, LENGTH_PREFIX_BYTES)
                .map_err(|_| SszBeaconBlockError::TooShort)?;

        /*
         * Determine how many bytes are used to store specials.
         */
        let specials_position = attestations_position + LENGTH_PREFIX_BYTES + attestations_len;
        let specials_len = decode_length(untrimmed_ssz, specials_position, LENGTH_PREFIX_BYTES)
            .map_err(|_| SszBeaconBlockError::TooShort)?;

        /*
         * Now that all variable field lengths are known (ancestors, attestations, specials) we can
         * know the exact length of the block and reject it if the slice is too short.
         */
        let block_ssz_len = MIN_SSZ_BLOCK_LENGTH + ancestors_len + attestations_len + specials_len;
        if vec.len() < block_ssz_len {
            return Err(SszBeaconBlockError::TooShort);
        }

        Ok(Self {
            ssz: &untrimmed_ssz[0..block_ssz_len],
            block_ssz_len,
            ancestors_position,
            ancestors_len,
            attestations_position,
            attestations_len,
            specials_position,
            specials_len,
        })
    }

    pub fn len(&self) -> usize {
        self.ssz.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ssz.is_empty()
    }

    /// Returns this block as ssz.
    ///
    /// Does not include any excess ssz bytes that were supplied to this struct.
    pub fn block_ssz(&self) -> &'a [u8] {
        &self.ssz[0..self.block_ssz_len]
    }

    /// Return the canonical hash for this block.
    pub fn block_hash(&self) -> Vec<u8> {
        canonical_hash(&self.ssz)
    }

    /// Return the bytes representing `ancestor_hashes[0]`.
    ///
    /// The first hash in `ancestor_hashes` is the parent of the block.
    pub fn parent_hash(&self) -> Option<&[u8]> {
        let ancestor_ssz = self.ancestor_hashes();
        let start = LENGTH_PREFIX_BYTES;
        ancestor_ssz.get(start..start + HASH_SIZE)
    }

    /// Return the `slot` field.
    pub fn slot(&self) -> u64 {
        /*
         * An error should be unreachable from this decode
         * because we checked the length of the array at
         * the initalization of this struct.
         *
         * If you can make this function panic, please report
         * it to paul@sigmaprime.io
         */
        if let Ok((n, _)) = u64::ssz_decode(&self.ssz, 0) {
            n
        } else {
            unreachable!();
        }
    }

    /// Return the `randao_reveal` field.
    pub fn randao_reveal(&self) -> &[u8] {
        let start = SLOT_BYTES;
        &self.ssz[start..start + RANDAO_REVEAL_BYTES]
    }

    /// Return the `pow_chain_reference` field.
    pub fn pow_chain_reference(&self) -> &[u8] {
        let start = SLOT_BYTES + RANDAO_REVEAL_BYTES;
        &self.ssz[start..start + POW_CHAIN_REF_BYTES]
    }

    /// Return the serialized `ancestor_hashes` bytes, including length prefix.
    pub fn ancestor_hashes(&self) -> &[u8] {
        let start = self.ancestors_position;
        &self.ssz[start..(start + self.ancestors_len + LENGTH_PREFIX_BYTES)]
    }

    /// Return the `active_state_root` field.
    pub fn act_state_root(&self) -> &[u8] {
        let start = self.ancestors_position + LENGTH_PREFIX_BYTES + self.ancestors_len;
        &self.ssz[start..(start + 32)]
    }

    /// Return the `active_state_root` field.
    pub fn cry_state_root(&self) -> &[u8] {
        let start =
            self.ancestors_position + LENGTH_PREFIX_BYTES + self.ancestors_len + ACTIVE_STATE_BYTES;
        &self.ssz[start..(start + 32)]
    }

    /// Return the serialized `attestations` bytes, including length prefix.
    pub fn attestations(&self) -> &[u8] {
        let start = self.attestations_position;
        &self.ssz[start..(start + self.attestations_len + LENGTH_PREFIX_BYTES)]
    }

    /// Return the serialized `attestations` bytes _without_ the length prefix.
    pub fn attestations_without_length(&self) -> &[u8] {
        let start = self.attestations_position + LENGTH_PREFIX_BYTES;
        &self.ssz[start..start + self.attestations_len]
    }

    /// Return the serialized `specials` bytes, including length prefix.
    pub fn specials(&self) -> &[u8] {
        let start = self.specials_position;
        &self.ssz[start..(start + self.specials_len + LENGTH_PREFIX_BYTES)]
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::encode::encode_length;
    use super::super::ssz::SszStream;
    use super::super::types::Hash256;
    use super::super::types::{AttestationRecord, BeaconBlock, SpecialRecord};
    use super::*;

    fn get_block_ssz(b: &BeaconBlock) -> Vec<u8> {
        let mut ssz_stream = SszStream::new();
        ssz_stream.append(b);
        ssz_stream.drain()
    }

    fn get_special_record_ssz(sr: &SpecialRecord) -> Vec<u8> {
        let mut ssz_stream = SszStream::new();
        ssz_stream.append(sr);
        ssz_stream.drain()
    }

    fn get_attestation_record_ssz(ar: &AttestationRecord) -> Vec<u8> {
        let mut ssz_stream = SszStream::new();
        ssz_stream.append(ar);
        ssz_stream.drain()
    }

    #[test]
    fn test_ssz_block_zero_attestation_records() {
        let mut b = BeaconBlock::zero();
        b.attestations = vec![];
        let ssz = get_block_ssz(&b);

        assert!(SszBeaconBlock::from_slice(&ssz[..]).is_ok());
    }

    #[test]
    fn test_ssz_block_single_attestation_record_one_byte_short() {
        let mut b = BeaconBlock::zero();
        b.attestations = vec![AttestationRecord::zero()];
        let ssz = get_block_ssz(&b);

        assert_eq!(
            SszBeaconBlock::from_slice(&ssz[0..(ssz.len() - 1)]),
            Err(SszBeaconBlockError::TooShort)
        );
    }

    #[test]
    fn test_ssz_block_single_attestation_record_one_byte_long() {
        let mut b = BeaconBlock::zero();
        b.attestations = vec![AttestationRecord::zero()];
        let mut ssz = get_block_ssz(&b);
        let original_len = ssz.len();
        ssz.push(42);

        let ssz_block = SszBeaconBlock::from_slice(&ssz[..]).unwrap();

        assert_eq!(ssz_block.len(), original_len);
    }

    #[test]
    fn test_ssz_block_single_attestation_record() {
        let mut b = BeaconBlock::zero();
        b.attestations = vec![AttestationRecord::zero()];
        let ssz = get_block_ssz(&b);

        assert!(SszBeaconBlock::from_slice(&ssz[..]).is_ok());
    }

    #[test]
    fn test_ssz_block_block_hash() {
        let mut block = BeaconBlock::zero();
        block.attestations.push(AttestationRecord::zero());
        let serialized = get_block_ssz(&block);
        let ssz_block = SszBeaconBlock::from_slice(&serialized).unwrap();
        let hash = ssz_block.block_hash();
        // Note: this hash was not generated by some external program,
        // it was simply printed then copied into the code. This test
        // will tell us if the hash changes, not that it matches some
        // canonical reference.
        let expected_hash = [
            254, 192, 124, 164, 240, 137, 162, 126, 50, 255, 118, 88, 189, 151, 221, 4, 40, 121,
            198, 33, 248, 221, 104, 255, 46, 234, 146, 161, 202, 140, 109, 175,
        ];
        assert_eq!(hash, expected_hash);

        /*
         * Test if you give the SszBeaconBlock too many ssz bytes
         */
        let mut too_long = serialized.clone();
        too_long.push(42);
        let ssz_block = SszBeaconBlock::from_slice(&too_long).unwrap();
        let hash = ssz_block.block_hash();
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_ssz_block_slot() {
        let mut block = BeaconBlock::zero();
        block.attestations.push(AttestationRecord::zero());
        block.slot = 42;

        let serialized = get_block_ssz(&block);
        let ssz_block = SszBeaconBlock::from_slice(&serialized).unwrap();

        assert_eq!(ssz_block.slot(), 42);
    }

    #[test]
    fn test_ssz_block_randao_reveal() {
        let mut block = BeaconBlock::zero();
        block.attestations.push(AttestationRecord::zero());
        let reference_hash = Hash256::from([42_u8; 32]);
        block.randao_reveal = reference_hash.clone();

        let serialized = get_block_ssz(&block);
        let ssz_block = SszBeaconBlock::from_slice(&serialized).unwrap();

        assert_eq!(ssz_block.randao_reveal(), &reference_hash.to_vec()[..]);
    }

    #[test]
    fn test_ssz_block_ancestor_hashes() {
        let mut block = BeaconBlock::zero();
        let h = Hash256::from(&vec![42_u8; 32][..]);
        block.ancestor_hashes.push(h);

        let serialized = get_block_ssz(&block);
        let ssz_block = SszBeaconBlock::from_slice(&serialized).unwrap();

        let mut expected = encode_length(32, LENGTH_PREFIX_BYTES);
        expected.append(&mut h.to_vec());

        assert_eq!(ssz_block.ancestor_hashes(), &expected[..]);
    }

    #[test]
    fn test_ssz_block_parent_hash() {
        let mut block = BeaconBlock::zero();
        block.ancestor_hashes = vec![
            Hash256::from("cats".as_bytes()),
            Hash256::from("dogs".as_bytes()),
            Hash256::from("birds".as_bytes()),
        ];

        let serialized = get_block_ssz(&block);
        let ssz_block = SszBeaconBlock::from_slice(&serialized).unwrap();

        assert_eq!(
            ssz_block.parent_hash().unwrap(),
            &Hash256::from("cats".as_bytes()).to_vec()[..]
        );
    }

    #[test]
    fn test_ssz_block_specials() {
        /*
         * Without data
         */
        let mut block = BeaconBlock::zero();
        let s = SpecialRecord::logout(&[]);
        block.specials.push(s.clone());

        let serialized = get_block_ssz(&block);
        let ssz_block = SszBeaconBlock::from_slice(&serialized).unwrap();
        let sr_ssz = get_special_record_ssz(&s);

        let mut expected = encode_length(sr_ssz.len(), LENGTH_PREFIX_BYTES);
        expected.append(&mut sr_ssz.to_vec());

        assert_eq!(ssz_block.specials(), &expected[..]);

        /*
         * With data
         */
        let mut block = BeaconBlock::zero();
        let s = SpecialRecord::randao_change(&[16, 17, 18]);
        block.specials.push(s.clone());

        let serialized = get_block_ssz(&block);
        let ssz_block = SszBeaconBlock::from_slice(&serialized).unwrap();
        let sr_ssz = get_special_record_ssz(&s);

        let mut expected = encode_length(sr_ssz.len(), LENGTH_PREFIX_BYTES);
        expected.append(&mut sr_ssz.to_vec());

        assert_eq!(ssz_block.specials(), &expected[..]);
    }

    #[test]
    fn test_ssz_block_attestations() {
        /*
         * Single AttestationRecord
         */
        let mut block = BeaconBlock::zero();
        block.attestations.push(AttestationRecord::zero());

        let serialized = get_block_ssz(&block);
        let ssz_block = SszBeaconBlock::from_slice(&serialized).unwrap();
        let ssz_ar = get_attestation_record_ssz(&AttestationRecord::zero());

        let mut expected = encode_length(ssz_ar.len(), LENGTH_PREFIX_BYTES);
        expected.append(&mut ssz_ar.to_vec());

        assert_eq!(ssz_block.attestations(), &expected[..]);

        /*
         * Multiple AttestationRecords
         */
        let mut block = BeaconBlock::zero();
        block.attestations.push(AttestationRecord::zero());
        block.attestations.push(AttestationRecord::zero());

        let serialized = get_block_ssz(&block);
        let ssz_block = SszBeaconBlock::from_slice(&serialized).unwrap();
        let mut ssz_ar = get_attestation_record_ssz(&AttestationRecord::zero());
        ssz_ar.append(&mut get_attestation_record_ssz(&AttestationRecord::zero()));

        let mut expected = encode_length(ssz_ar.len(), LENGTH_PREFIX_BYTES);
        expected.append(&mut ssz_ar.to_vec());

        assert_eq!(ssz_block.attestations(), &expected[..]);
    }

    #[test]
    fn test_ssz_block_pow_chain_reference() {
        let mut block = BeaconBlock::zero();
        block.attestations.push(AttestationRecord::zero());
        let reference_hash = Hash256::from([42_u8; 32]);
        block.pow_chain_reference = reference_hash.clone();

        let serialized = get_block_ssz(&block);
        let ssz_block = SszBeaconBlock::from_slice(&serialized).unwrap();

        assert_eq!(
            ssz_block.pow_chain_reference(),
            &reference_hash.to_vec()[..]
        );
    }

    #[test]
    fn test_ssz_block_act_state_root() {
        let mut block = BeaconBlock::zero();
        block.attestations.push(AttestationRecord::zero());
        let reference_hash = Hash256::from([42_u8; 32]);
        block.active_state_root = reference_hash.clone();

        let serialized = get_block_ssz(&block);
        let ssz_block = SszBeaconBlock::from_slice(&serialized).unwrap();

        assert_eq!(ssz_block.act_state_root(), &reference_hash.to_vec()[..]);
    }

    #[test]
    fn test_ssz_block_cry_state_root() {
        let mut block = BeaconBlock::zero();
        block.attestations.push(AttestationRecord::zero());
        let reference_hash = Hash256::from([42_u8; 32]);
        block.crystallized_state_root = reference_hash.clone();

        let serialized = get_block_ssz(&block);
        let ssz_block = SszBeaconBlock::from_slice(&serialized).unwrap();

        assert_eq!(ssz_block.cry_state_root(), &reference_hash.to_vec()[..]);
    }
}

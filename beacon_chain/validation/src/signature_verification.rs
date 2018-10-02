use std::collections::HashSet;
use super::bls::{
    AggregateSignature,
    AggregatePublicKey,
};
use super::db::ClientDB;
use super::db::stores::{
    ValidatorStore,
    ValidatorStoreError,
};
use super::types::Bitfield;

#[derive(Debug, PartialEq)]
pub enum SignatureVerificationError {
    BadValidatorIndex,
    PublicKeyCorrupt,
    NoPublicKeyForValidator,
    DBError(String),
}

/// Verify an aggregate signature across the supplied message.
///
/// The public keys used for verification are collected by mapping
/// each true bitfield bit to canonical ValidatorRecord index through
/// the attestation_indicies map.
///
/// Each public key is loaded from the store on-demand.
pub fn verify_aggregate_signature_for_indices<T>(
    message: &[u8],
    agg_sig: &AggregateSignature,
    attestation_indices: &[usize],
    bitfield: &Bitfield,
    validator_store: &ValidatorStore<T>)
    -> Result<Option<HashSet<usize>>, SignatureVerificationError>
    where T: ClientDB + Sized
{
    let mut voters = HashSet::new();
    let mut agg_pub_key = AggregatePublicKey::new();

    for i in 0..attestation_indices.len() {
        let voted = bitfield.get_bit(i);
        if voted {
            /*
             * De-reference the attestation index into a canonical ValidatorRecord index.
             */
            let validator = *attestation_indices.get(i)
                .ok_or(SignatureVerificationError::BadValidatorIndex)?;
            /*
             * Load the validators public key from our store.
             */
            let pub_key = validator_store
                .get_public_key_by_index(validator)?
                .ok_or(SignatureVerificationError::NoPublicKeyForValidator)?;
            /*
             * Add the validators public key to the aggregate public key.
             */
            agg_pub_key.add(&pub_key);
            /*
             * Add to the validator to the set of voters for this attestation record.
             */
            voters.insert(validator);
        }
    }
    /*
     * Verify the aggregate public key against the aggregate signature.
     *
     * This verification will only succeed if the exact set of public keys
     * were added to the aggregate public key as those that signed the aggregate signature.
     */
    if agg_sig.verify(&message, &agg_pub_key) {
        Ok(Some(voters))
    } else {
        Ok(None)
    }
}

impl From<ValidatorStoreError> for SignatureVerificationError {
    fn from(error: ValidatorStoreError) -> Self {
        match error {
            ValidatorStoreError::DBError(s) =>
                SignatureVerificationError::DBError(s),
            ValidatorStoreError::DecodeError =>
                SignatureVerificationError::PublicKeyCorrupt,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::bls::{
        Keypair,
        Signature,
    };
    use super::super::db::MemoryDB;
    use std::sync::Arc;

    /*
     * Cases that still need testing:
     *
     * - No signatures.
     * - Database failure.
     * - Unknown validator index.
     * - Extra validator on signature.
     */

    #[test]
    fn test_signature_verification() {
        let message = "cats".as_bytes();
        let signing_keypairs = vec![
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
        ];
        let non_signing_keypairs = vec![
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
        ];
        /*
         * Signing keypairs first, then non-signing
         */
        let mut all_keypairs = signing_keypairs.clone();
        all_keypairs.append(&mut non_signing_keypairs.clone());

        let attestation_indices: Vec<usize> = (0..all_keypairs.len())
            .collect();
        let mut bitfield = Bitfield::new();
        for i in 0..signing_keypairs.len() {
            bitfield.set_bit(i, true);
        }

        let db = Arc::new(MemoryDB::open());
        let store = ValidatorStore::new(db);

        for (i, keypair) in all_keypairs.iter().enumerate() {
            store.put_public_key_by_index(i, &keypair.pk).unwrap();
        }

        let mut agg_sig = AggregateSignature::new();
        for keypair in &signing_keypairs {
            let sig = Signature::new(&message, &keypair.sk);
            agg_sig.add(&sig);
        }

        /*
         * Test using all valid parameters.
         */
        let voters = verify_aggregate_signature_for_indices(
            &message,
            &agg_sig,
            &attestation_indices,
            &bitfield,
            &store).unwrap();

        let voters = voters.unwrap();
        (0..signing_keypairs.len())
            .for_each(|i| assert!(voters.contains(&i)));
        (signing_keypairs.len()..non_signing_keypairs.len())
            .for_each(|i| assert!(!voters.contains(&i)));

        /*
         * Add another validator to the bitfield, run validation will all other
         * parameters the same and assert that it fails.
         */
        bitfield.set_bit(signing_keypairs.len() + 1, true);
        let voters = verify_aggregate_signature_for_indices(
            &message,
            &agg_sig,
            &attestation_indices,
            &bitfield,
            &store).unwrap();

        assert_eq!(voters, None);
    }
}

use super::bls::{AggregatePublicKey, AggregateSignature};
use super::db::stores::{ValidatorStore, ValidatorStoreError};
use super::db::ClientDB;
use super::types::{AttestationData, Bitfield, BitfieldError};
use super::{Error, Invalid, Outcome};

/// Validate that some signature is correct for some attestation data and known validator set.
pub fn validate_attestation_signature<T>(
    attestation_data: &AttestationData,
    participation_bitfield: &Bitfield,
    aggregate_signature: &AggregateSignature,
    attestation_indices: &[usize],
    validator_store: &ValidatorStore<T>,
) -> Result<Outcome, Error>
where
    T: ClientDB + Sized,
{
    let mut agg_pub_key = AggregatePublicKey::new();

    for i in 0..attestation_indices.len() {
        let voted = participation_bitfield.get(i)?;
        if voted {
            // De-reference the attestation index into a canonical ValidatorRecord index.
            let validator = *attestation_indices.get(i).ok_or(Error::BadValidatorIndex)?;
            // Load the public key.
            let pub_key = validator_store
                .get_public_key_by_index(validator)?
                .ok_or(Error::NoPublicKeyForValidator)?;
            // Aggregate the public key.
            agg_pub_key.add(&pub_key);
        }
    }

    let signed_message = attestation_data_signing_message(attestation_data);
    verify_or!(
        // TODO: ensure "domain" for aggregate signatures is included.
        // https://github.com/sigp/lighthouse/issues/91
        aggregate_signature.verify(&signed_message, &agg_pub_key),
        reject!(Invalid::SignatureInvalid)
    );

    accept!()
}

fn attestation_data_signing_message(attestation_data: &AttestationData) -> Vec<u8> {
    let mut signed_message = attestation_data.canonical_root().to_vec();
    signed_message.append(&mut vec![0]);
    signed_message
}

impl From<ValidatorStoreError> for Error {
    fn from(error: ValidatorStoreError) -> Self {
        match error {
            ValidatorStoreError::DBError(s) => Error::DBError(s),
            ValidatorStoreError::DecodeError => Error::PublicKeyCorrupt,
        }
    }
}

impl From<BitfieldError> for Error {
    fn from(_error: BitfieldError) -> Self {
        Error::OutOfBoundsBitfieldIndex
    }
}

#[cfg(test)]
mod tests {
    use super::super::bls::{Keypair, Signature};
    use super::super::db::MemoryDB;
    use super::*;
    use std::sync::Arc;

    /*
     * TODO: Test cases are not comprehensive.
     * https://github.com/sigp/lighthouse/issues/94
     */

    #[test]
    fn test_signature_verification() {
        let attestation_data = AttestationData::zero();
        let message = attestation_data_signing_message(&attestation_data);
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

        let attestation_indices: Vec<usize> = (0..all_keypairs.len()).collect();
        let mut bitfield = Bitfield::from_elem(all_keypairs.len(), false);
        for i in 0..signing_keypairs.len() {
            bitfield.set(i, true).unwrap();
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
        let outcome = validate_attestation_signature(
            &attestation_data,
            &bitfield,
            &agg_sig,
            &attestation_indices,
            &store,
        ).unwrap();
        assert_eq!(outcome, Outcome::Valid);

        /*
         * Add another validator to the bitfield, run validation will all other
         * parameters the same and assert that it fails.
         */
        bitfield.set(signing_keypairs.len() + 1, true).unwrap();
        let outcome = validate_attestation_signature(
            &attestation_data,
            &bitfield,
            &agg_sig,
            &attestation_indices,
            &store,
        ).unwrap();
        assert_eq!(outcome, Outcome::Invalid(Invalid::SignatureInvalid));
    }
}

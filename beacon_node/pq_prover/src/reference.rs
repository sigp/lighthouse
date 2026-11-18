//! The spec's reference "prover": a proof is the signatures, concatenated.

use crate::{Error, Proof, ProverBackend, Statement, check_shape};
use xmss::{LeafIndex, XMSS_SIGNATURE_BYTES_LEN, XmssSignature};

/// The consensus-specs stand-in for a recursive STARK: `prove` and `merge` concatenate their
/// inputs, `verify` checks each signature in turn at its statement's leaf.
///
/// Proofs are `2404` bytes per signature and are not interchangeable with any other
/// backend's. Unlike a real proof, a merged proof only verifies against the children's
/// statements concatenated in the order the children were merged.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReferenceBackend;

impl ProverBackend for ReferenceBackend {
    fn name(&self) -> &'static str {
        "reference"
    }

    /// Concatenates the signatures, after checking each one, so that a bad signature is
    /// reported where a real prover would report it.
    fn prove(
        &self,
        statements: &[Statement],
        signatures: &[Vec<XmssSignature>],
    ) -> Result<Proof, Error> {
        check_shape(statements, signatures)?;
        let count: usize = signatures.iter().map(Vec::len).sum();
        let mut proof = Vec::with_capacity(count.saturating_mul(XMSS_SIGNATURE_BYTES_LEN));
        for (statement_index, (statement, group)) in statements.iter().zip(signatures).enumerate() {
            let leaf_index = leaf_index(statement);
            for (signature_index, (pubkey, signature)) in
                statement.pubkeys.iter().zip(group).enumerate()
            {
                let valid = leaf_index
                    .is_some_and(|leaf| xmss::verify(pubkey, leaf, &statement.message, signature));
                if !valid {
                    return Err(Error::InvalidSignature {
                        statement: statement_index,
                        signature: signature_index,
                    });
                }
                proof.extend_from_slice(signature.as_bytes());
            }
        }
        Ok(Proof::from_bytes(proof))
    }

    fn merge(&self, children: &[(Vec<Statement>, Proof)]) -> Result<Proof, Error> {
        let mut merged = Vec::with_capacity(children.iter().map(|(_, proof)| proof.len()).sum());
        for (_, proof) in children {
            merged.extend_from_slice(proof.as_bytes());
        }
        Ok(Proof::from_bytes(merged))
    }

    fn verify(&self, statements: &[Statement], proof: &Proof) -> Result<bool, Error> {
        let count: usize = statements
            .iter()
            .map(|statement| statement.pubkeys.len())
            .sum();
        if count.checked_mul(XMSS_SIGNATURE_BYTES_LEN) != Some(proof.len()) {
            return Ok(false);
        }
        let mut signatures = proof.as_bytes().chunks_exact(XMSS_SIGNATURE_BYTES_LEN);
        for statement in statements {
            let Some(leaf_index) = leaf_index(statement) else {
                return Ok(false);
            };
            for pubkey in &statement.pubkeys {
                let Some(Ok(signature)) = signatures.next().map(XmssSignature::from_bytes) else {
                    return Ok(false);
                };
                if !xmss::verify(pubkey, leaf_index, &statement.message, &signature) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

/// The statement's leaf, if a signature can carry it at all.
fn leaf_index(statement: &Statement) -> Option<LeafIndex> {
    LeafIndex::try_from(statement.leaf_index).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmss::{XmssPublicKey, XmssSecretKey};

    const LEAF: u32 = (1 << 15) + 3;

    fn keys(count: u8) -> Vec<XmssSecretKey> {
        (1..=count)
            .map(|i| XmssSecretKey::from_seed(&[i; 32]))
            .collect()
    }

    /// One statement signed by every key, with its signatures.
    fn signed(
        keys: &[XmssSecretKey],
        leaf_index: u32,
        message: [u8; 32],
    ) -> (Statement, Vec<XmssSignature>) {
        let statement = Statement {
            pubkeys: keys.iter().map(XmssSecretKey::public_key).collect(),
            leaf_index: u64::from(leaf_index),
            message,
        };
        let signatures = keys
            .iter()
            .map(|key| key.sign(&message, leaf_index).unwrap())
            .collect();
        (statement, signatures)
    }

    #[test]
    fn prove_merge_verify() {
        let backend = ReferenceBackend;
        let keys = keys(3);
        let (first, first_signatures) = signed(&keys[..2], LEAF, [1; 32]);
        let (second, second_signatures) = signed(&keys[1..], LEAF, [2; 32]);
        let (third, third_signatures) = signed(&keys, LEAF + 1, [3; 32]);

        // Two statements in one proof, a third in another.
        let left_statements = vec![first, second];
        let left = backend
            .prove(&left_statements, &[first_signatures, second_signatures])
            .unwrap();
        assert_eq!(left.len(), 4 * XMSS_SIGNATURE_BYTES_LEN);
        assert!(backend.verify(&left_statements, &left).unwrap());

        let right_statements = vec![third];
        let right = backend
            .prove(&right_statements, &[third_signatures])
            .unwrap();
        assert!(backend.verify(&right_statements, &right).unwrap());

        // Merged, it proves the concatenation of the statements, in order.
        let merged = backend
            .merge(&[
                (left_statements.clone(), left.clone()),
                (right_statements.clone(), right.clone()),
            ])
            .unwrap();
        let all_statements = [left_statements.clone(), right_statements.clone()].concat();
        assert_eq!(merged.len(), 7 * XMSS_SIGNATURE_BYTES_LEN);
        assert!(backend.verify(&all_statements, &merged).unwrap());

        // And nothing else.
        assert!(!backend.verify(&left_statements, &merged).unwrap());
        assert!(!backend.verify(&all_statements, &left).unwrap());
        let reordered = [right_statements, left_statements].concat();
        assert!(!backend.verify(&reordered, &merged).unwrap());
    }

    #[test]
    fn tampering_is_rejected() {
        let backend = ReferenceBackend;
        let keys = keys(2);
        let (statement, signatures) = signed(&keys, LEAF, [1; 32]);
        let statements = vec![statement];
        let proof = backend.prove(&statements, &[signatures]).unwrap();
        assert!(backend.verify(&statements, &proof).unwrap());

        // A flipped bit in the proof.
        let mut bytes = proof.as_bytes().to_vec();
        bytes[XMSS_SIGNATURE_BYTES_LEN + 100] ^= 1;
        assert!(
            !backend
                .verify(&statements, &Proof::from_bytes(bytes))
                .unwrap()
        );

        // A truncated or extended proof.
        let bytes = proof.as_bytes();
        let truncated = Proof::from_bytes(bytes[..bytes.len() - 1].to_vec());
        assert!(!backend.verify(&statements, &truncated).unwrap());
        let extended = Proof::from_bytes([bytes, &[0]].concat());
        assert!(!backend.verify(&statements, &extended).unwrap());

        // Another message.
        let mut other_message = statements.clone();
        other_message[0].message = [9; 32];
        assert!(!backend.verify(&other_message, &proof).unwrap());

        // Another key in the statement, and the keys swapped.
        let mut other_key = statements.clone();
        other_key[0].pubkeys[1] = XmssPublicKey::from([0x55; 32]);
        assert!(!backend.verify(&other_key, &proof).unwrap());
        let mut swapped = statements.clone();
        swapped[0].pubkeys.swap(0, 1);
        assert!(!backend.verify(&swapped, &proof).unwrap());
    }

    #[test]
    fn wrong_leaf_is_rejected() {
        let backend = ReferenceBackend;
        let keys = keys(2);
        let (statement, signatures) = signed(&keys, LEAF, [1; 32]);
        let proof = backend
            .prove(std::slice::from_ref(&statement), &[signatures.clone()])
            .unwrap();

        // Valid signatures, but the statement schedules another leaf.
        let mut other_leaf = statement.clone();
        other_leaf.leaf_index += 1;
        assert!(
            !backend
                .verify(std::slice::from_ref(&other_leaf), &proof)
                .unwrap()
        );
        // A leaf no signature can carry.
        let mut huge_leaf = statement.clone();
        huge_leaf.leaf_index = u64::from(u32::MAX) + 1 + u64::from(LEAF);
        assert!(!backend.verify(&[huge_leaf], &proof).unwrap());

        // Proving refuses them up front.
        assert!(matches!(
            backend.prove(&[other_leaf], &[signatures]),
            Err(Error::LeafIndexMismatch {
                statement: 0,
                signature: 0,
                ..
            })
        ));
    }

    #[test]
    fn prove_rejects_bad_input() {
        let backend = ReferenceBackend;
        let keys = keys(2);
        let (statement, signatures) = signed(&keys, LEAF, [1; 32]);
        let statements = vec![statement];

        // No signature groups, and a group that is one signature short.
        assert!(matches!(
            backend.prove(&statements, &[]),
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            backend.prove(&statements, &[signatures[..1].to_vec()]),
            Err(Error::InvalidInput(_))
        ));

        // Signatures in the wrong order do not verify against their keys.
        let swapped = vec![signatures[1].clone(), signatures[0].clone()];
        assert!(matches!(
            backend.prove(&statements, &[swapped]),
            Err(Error::InvalidSignature {
                statement: 0,
                signature: 0
            })
        ));
    }

    #[test]
    fn empty_proof_proves_only_nothing() {
        let backend = ReferenceBackend;
        let empty = backend.prove(&[], &[]).unwrap();
        assert!(empty.is_empty());
        assert!(backend.verify(&[], &empty).unwrap());
        assert!(backend.merge(&[]).unwrap().is_empty());

        let keys = keys(1);
        let (statement, signatures) = signed(&keys, LEAF, [1; 32]);
        let statements = vec![statement];
        assert!(!backend.verify(&statements, &empty).unwrap());
        let proof = backend.prove(&statements, &[signatures]).unwrap();
        assert!(!backend.verify(&[], &proof).unwrap());
    }
}

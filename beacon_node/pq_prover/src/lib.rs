//! Aggregation of XMSS signatures into proofs, behind a synchronous backend trait.
//!
//! Production uses [`InProcessBackend`] and the leanVM revision in `leanvm-revision`.
//! [`ReferenceBackend`] is the signature-concatenating stand-in for consensus tests.
//! Call from a blocking worker, never directly on an async executor. Proving is admitted
//! by the beacon node's shared scheduler; leanVM owns its own bounded worker pool.
//!
//! leanVM claims bind `(pubkey, message)`, not the XMSS leaf index. `prove` checks the
//! supplied signature's leaf; a recursive proof cannot establish that index on verification.

mod claims;
mod in_process;
mod reference;

pub use claims::{statements_to_claims, statements_to_claims_bytes};
pub use in_process::{InProcessBackend, MAX_CHILDREN_PER_AGGREGATE, merge_plan};
pub use leanvm_claims::AggregateClaims;
pub use reference::ReferenceBackend;
pub use xmss::{XMSS_MESSAGE_BYTES_LEN, XMSS_SIGNATURE_BYTES_LEN, XmssPublicKey, XmssSignature};

/// The common leanVM revision for signing, proving and verification.
pub const LEANVM_REV: &str = env!("LIGHTHOUSE_LEANVM_REVISION");

/// The spec's `XMSSAggregateStatement`: every one of `pubkeys` signed `message` at
/// `leaf_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub pubkeys: Vec<XmssPublicKey>,
    pub leaf_index: u64,
    pub message: [u8; XMSS_MESSAGE_BYTES_LEN],
}

/// An aggregation proof (the content of the spec's `AttestationProof`). Opaque: its bytes
/// only mean something to the backend that made it.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Proof(Vec<u8>);

impl Proof {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Proof({} bytes)", self.0.len())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The caller's statements and signatures do not line up.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// A signature handed to `prove` was made at another leaf than its statement's.
    #[error(
        "signature {signature} of statement {statement} is at leaf {found}, expected {expected}"
    )]
    LeafIndexMismatch {
        statement: usize,
        signature: usize,
        expected: u64,
        found: u64,
    },
    /// A signature handed to `prove` does not verify (reference backend).
    #[error("signature {signature} of statement {statement} is invalid")]
    InvalidSignature { statement: usize, signature: usize },
    #[error("leanVM initialization: {0}")]
    Initialization(String),
    #[error("leanVM rejected the aggregate: {0}")]
    ProvingFailed(String),
    #[error("leanVM proof does not decode")]
    InvalidChild,
    #[error("leanVM panicked; restart the node before reusing the prover")]
    BackendPanicked,
    #[error("leanVM returned {found} claims, expected {expected} other claims")]
    ClaimsMismatch { expected: usize, found: usize },
}

/// Proves, merges and verifies aggregates of XMSS signatures (the spec's `stark` module).
///
/// All methods are synchronous and may take seconds: call them from `spawn_blocking` or a
/// beacon processor worker, never directly from an async task.
pub trait ProverBackend: Send + Sync {
    /// A short name for logs and metrics.
    fn name(&self) -> &'static str;

    /// The spec's `ProveAggregates`: a proof that, for each statement and each of its public
    /// keys, a signature of the statement's message at the statement's leaf exists.
    ///
    /// `signatures` holds one group per statement, in order, and within a group one
    /// signature per public key, in the order of `Statement::pubkeys`.
    fn prove(
        &self,
        statements: &[Statement],
        signatures: &[Vec<XmssSignature>],
    ) -> Result<Proof, Error>;

    /// The spec's `MergeProofs`: one proof of the concatenation, in order, of the children's
    /// statement lists. Each child is the statements it proves and its proof.
    ///
    /// Children are assumed valid: verify untrusted ones first.
    fn merge(&self, children: &[(Vec<Statement>, Proof)]) -> Result<Proof, Error>;

    /// Merge one scheduled batch into the exact claims in the final packed statements.
    fn merge_for_statements(
        &self,
        children: &[(Vec<Statement>, Proof)],
        output: &[Statement],
        max_proof_bytes: usize,
    ) -> Result<Proof, Error> {
        check_packed_claims(children, output)?;
        let proof = self.merge(children)?;
        if proof.len() > max_proof_bytes {
            return Err(Error::InvalidInput(
                "packed proof exceeds its byte bound".into(),
            ));
        }
        Ok(proof)
    }

    /// The spec's `VerifyAggregates`. `Ok(false)` is an invalid proof; `Err` means the
    /// backend could not decide (e.g. an internal backend failure).
    fn verify(&self, statements: &[Statement], proof: &Proof) -> Result<bool, Error>;
}

fn statement_witnesses(
    statements: &[Statement],
) -> impl Iterator<Item = (XmssPublicKey, [u8; 32], u64)> + '_ {
    statements.iter().flat_map(|statement| {
        statement
            .pubkeys
            .iter()
            .map(|key| (*key, statement.message, statement.leaf_index))
    })
}

fn check_packed_claims(
    children: &[(Vec<Statement>, Proof)],
    output: &[Statement],
) -> Result<(), Error> {
    use std::collections::BTreeSet;
    if children.is_empty()
        || children.len() > 16
        || children.iter().any(|(statements, proof)| {
            proof.is_empty() || statement_witnesses(statements).next().is_none()
        })
    {
        return Err(Error::InvalidInput("invalid packed proof batch".into()));
    }
    let provided: BTreeSet<_> = children
        .iter()
        .flat_map(|(statements, _)| statement_witnesses(statements))
        .collect();
    if provided != statement_witnesses(output).collect() {
        return Err(Error::InvalidInput(
            "packed statements differ from the child claims".into(),
        ));
    }
    Ok(())
}

/// Checks that `signatures` has one group per statement and one signature per public key,
/// each made at its statement's leaf.
fn check_shape(statements: &[Statement], signatures: &[Vec<XmssSignature>]) -> Result<(), Error> {
    if statements.len() != signatures.len() {
        return Err(Error::InvalidInput(format!(
            "{} statements but {} signature groups",
            statements.len(),
            signatures.len()
        )));
    }
    for (statement_index, (statement, group)) in statements.iter().zip(signatures).enumerate() {
        if statement.pubkeys.len() != group.len() {
            return Err(Error::InvalidInput(format!(
                "statement {statement_index} has {} public keys but {} signatures",
                statement.pubkeys.len(),
                group.len()
            )));
        }
        for (signature_index, signature) in group.iter().enumerate() {
            let found = u64::from(signature.leaf_index());
            if found != statement.leaf_index {
                return Err(Error::LeafIndexMismatch {
                    statement: statement_index,
                    signature: signature_index,
                    expected: statement.leaf_index,
                    found,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backends_are_object_safe() {
        let backend: Box<dyn ProverBackend> = Box::new(ReferenceBackend);
        assert_eq!(backend.name(), "reference");
    }
}

//! Aggregation of XMSS signatures into one proof, behind a backend trait.
//!
//! The PQ consensus-specs feature (`specs/_features/pq`) replaces BLS aggregation with a proof
//! that many XMSS signatures exist: `stark.ProveAggregates`, `stark.MergeProofs` and
//! `stark.VerifyAggregates`. [`ProverBackend`] is those three functions. Two backends exist:
//!
//! - [`ReferenceBackend`]: the spec's stand-in, where a proof is the signatures themselves.
//!   No external process, usable in debug builds and CI.
//! - [`SidecarBackend`] (Unix only): proofs from leanVM's `leanvm-sidecar` process over its
//!   Unix socket.
//!
//! # The leanVM revision
//!
//! Everything from leanVM is pinned to ONE commit, [`LEANVM_REV`]: the `lean_xmss` scheme
//! behind the `xmss` crate, the claims encoding, the sidecar client, and the `leanvm-sidecar`
//! binary every node runs. Build the sidecar from exactly that commit:
//!
//! ```text
//! git clone https://github.com/leanEthereum/leanVM && cd leanVM
//! git checkout --detach "$(cat /path/to/lighthouse/leanvm-revision)"
//! cargo build --release -p leanvm-sidecar --features experimental_prover
//! target/release/leanvm-sidecar --socket <dir only the node's user can write>/sidecar.sock
//! ```
//!
//! (On x86_64 add `RUSTFLAGS="-C target-feature=+avx2,+pclmulqdq"` or `-C target-cpu=native`
//! for the fast kernels.) A proof only verifies with a verifier built from a compatible
//! revision, and nothing on the wire detects a mismatch: the hello's verifier tag
//! (`leanvm-v1`) is not bumped when the guest program changes. A mismatched sidecar shows up
//! only as proofs that fail to verify, so all nodes of a network must agree on the commit.
//!
//! # Blocking
//!
//! Every method blocks the calling thread: a proof takes seconds, a verification
//! milliseconds plus a socket round trip. Never call them from an async task; use
//! `spawn_blocking` or a beacon processor worker.
//!
//! # Leaf indices
//!
//! A leanVM claim is `(pubkey, message)`. The leaf a signature was made at is not part of what
//! a proof attests (leanEthereum/leanVM#787), so [`SidecarBackend::verify`] cannot enforce
//! [`Statement::leaf_index`]: it shows each key signed the message at *some* leaf.
//! [`SidecarBackend::prove`] does refuse signatures made at another leaf, since it sees them.
//! [`ReferenceBackend`] checks the leaf on every verification, as the spec does.

mod claims;
mod reference;
#[cfg(unix)]
mod sidecar;

pub use claims::{statements_to_claims, statements_to_claims_bytes};
pub use leanvm_claims::AggregateClaims;
pub use reference::ReferenceBackend;
#[cfg(unix)]
pub use sidecar::{MAX_CHILDREN_PER_AGGREGATE, SidecarBackend, SidecarConfig, merge_plan};
pub use xmss::{XMSS_MESSAGE_BYTES_LEN, XmssPublicKey, XmssSignature};

/// The leanVM commit every leanVM dependency of the workspace is pinned to, and that the
/// `leanvm-sidecar` binary must be built from.
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
    /// The socket failed or timed out, or the sidecar closed it. The next call reconnects.
    #[error("sidecar connection: {0}")]
    SidecarIo(#[source] std::io::Error),
    /// The peer is not a leanVM sidecar, speaks another protocol version, or proves for
    /// another verifier.
    #[error("incompatible sidecar: {0}")]
    SidecarIncompatible(String),
    /// The sidecar's bytes are not the protocol. The next call reconnects.
    #[error("sidecar protocol violation: {0}")]
    SidecarProtocol(String),
    /// Status 1: a rate out of range, too many children, nothing to prove.
    #[error("sidecar rejected the request as invalid input: {0}")]
    SidecarInvalidInput(String),
    /// Status 2: a signature does not verify.
    #[error("sidecar found an invalid signature: {0}")]
    SidecarInvalidSignature(String),
    /// Status 3: a child proof is invalid or does not decode.
    #[error("sidecar found an invalid child proof: {0}")]
    SidecarInvalidChild(String),
    /// Status 4: proving failed, e.g. the request is too large for one proof.
    #[error("sidecar failed to prove: {0}")]
    SidecarProvingFailed(String),
    /// Status 5: the request did not decode, or exceeds the sidecar's maximum request size.
    #[error("sidecar could not read the request: {0}")]
    SidecarMalformed(String),
    /// The sidecar proved something other than what was asked.
    #[error("sidecar returned a proof of {found} claims, expected {expected} other claims")]
    SidecarClaimsMismatch { expected: usize, found: usize },
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

    /// The spec's `VerifyAggregates`. `Ok(false)` is an invalid proof; `Err` means the
    /// backend could not decide (e.g. the sidecar is unreachable).
    fn verify(&self, statements: &[Statement], proof: &Proof) -> Result<bool, Error>;
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

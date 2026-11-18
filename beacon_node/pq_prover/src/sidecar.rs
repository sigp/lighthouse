//! Proofs from a `leanvm-sidecar` process, over its Unix socket (protocol version 1, specified
//! in `bins/leanvm-sidecar/README.md` of the leanVM repository).
//!
//! The wire protocol is not reimplemented here: this uses leanVM's own client crate
//! (`crates/sidecar` without its `server` feature) at the pinned revision. That crate builds
//! no prover and depends only on other leanVM crates with no third-party dependencies, and
//! taking it from the same commit as the sidecar binary keeps the encoding and the hello's
//! verifier tag check in step with the pin.

use crate::claims::statements_to_claims;
use crate::{Error, Proof, ProverBackend, Statement, check_shape};
use lean_xmss::{LeanXmssPublicKey, LeanXmssSignature};
use leanvm_claims::{AggregateClaims, OutputClaims};
use leanvm_sidecar::{Client, Rejection, SidecarError};
use parking_lot::Mutex;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::Duration;
use xmss::XmssSignature;

/// The most children one aggregate request takes.
pub const MAX_CHILDREN_PER_AGGREGATE: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarConfig {
    /// The Unix socket `leanvm-sidecar --socket` listens on.
    pub socket: PathBuf,
    /// `log_inv_rate` of the proofs requested, 1 to 4: a higher rate gives smaller proofs
    /// that take longer to make. A proof verifies whatever rate it was made at.
    pub log_inv_rate: u8,
    /// How long one prove or merge request may wait on the sidecar (it proves requests one
    /// at a time, so this includes queueing behind others). `None` waits indefinitely.
    pub prove_timeout: Option<Duration>,
    /// How long one verify request may wait on the sidecar. `None` waits indefinitely.
    pub verify_timeout: Option<Duration>,
}

impl SidecarConfig {
    pub const DEFAULT_LOG_INV_RATE: u8 = 2;
    pub const DEFAULT_PROVE_TIMEOUT: Duration = Duration::from_secs(300);
    pub const DEFAULT_VERIFY_TIMEOUT: Duration = Duration::from_secs(30);

    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            log_inv_rate: Self::DEFAULT_LOG_INV_RATE,
            prove_timeout: Some(Self::DEFAULT_PROVE_TIMEOUT),
            verify_timeout: Some(Self::DEFAULT_VERIFY_TIMEOUT),
        }
    }
}

/// Proves and verifies through a `leanvm-sidecar`, which must be built from
/// [`crate::LEANVM_REV`].
///
/// Proof bytes are the sidecar's proof alone. The claims it proves are not stored with it:
/// the verifier rebuilds them from the statements ([`statements_to_claims`]). The empty
/// proof stands for "nothing to prove" (the sidecar refuses to prove zero claims) and
/// verifies only against statements with no public keys.
///
/// Two connections are kept, opened on first use and reopened after a failure: one for
/// proving, where requests queue in the sidecar, and one for verifying, which the sidecar
/// answers without waiting for proofs in progress. Each is used by one call at a time.
///
/// Lock ordering: the two connection locks are independent, and no call holds both.
///
/// Leaf indices: `verify` cannot check [`Statement::leaf_index`] (see the crate docs).
pub struct SidecarBackend {
    config: SidecarConfig,
    prove_connection: Mutex<Option<Client>>,
    verify_connection: Mutex<Option<Client>>,
}

impl SidecarBackend {
    /// Does not connect: connections open on first use.
    pub fn new(config: SidecarConfig) -> Self {
        Self {
            config,
            prove_connection: Mutex::new(None),
            verify_connection: Mutex::new(None),
        }
    }

    /// Opens both connections now, checking each hello (magic, protocol version, verifier
    /// tag), so that a missing or incompatible sidecar is reported at startup.
    pub fn connect(config: SidecarConfig) -> Result<Self, Error> {
        let prove_connection = open(&config, config.prove_timeout)?;
        let verify_connection = open(&config, config.verify_timeout)?;
        Ok(Self {
            config,
            prove_connection: Mutex::new(Some(prove_connection)),
            verify_connection: Mutex::new(Some(verify_connection)),
        })
    }

    pub fn config(&self) -> &SidecarConfig {
        &self.config
    }

    /// The prover the sidecar runs, from its hello: `stable` or `experimental`.
    pub fn prover_kind(&self) -> Result<String, Error> {
        with_connection(
            &self.config,
            &self.verify_connection,
            self.config.verify_timeout,
            |client| Ok(client.prover().to_string()),
        )
    }

    /// One aggregate request on the proving connection. Checks the sidecar proved exactly
    /// `expected`.
    fn aggregate(
        &self,
        children: &[(AggregateClaims, Vec<u8>)],
        raw_signatures: &[(LeanXmssPublicKey, lean_xmss::Message, LeanXmssSignature)],
        expected: &AggregateClaims,
    ) -> Result<Vec<u8>, Error> {
        let (claims, proof) = with_connection(
            &self.config,
            &self.prove_connection,
            self.config.prove_timeout,
            |client| {
                client.aggregate(
                    children,
                    raw_signatures,
                    &[],
                    &[],
                    OutputClaims::All,
                    usize::from(self.config.log_inv_rate),
                )
            },
        )?;
        if claims != *expected {
            return Err(Error::SidecarClaimsMismatch {
                expected: expected.num_signature_claims(),
                found: claims.num_signature_claims(),
            });
        }
        Ok(proof)
    }
}

impl ProverBackend for SidecarBackend {
    fn name(&self) -> &'static str {
        "sidecar"
    }

    /// One aggregate request with every signature. Signatures made at another leaf than
    /// their statement's are refused here, since a proof would hide them.
    fn prove(
        &self,
        statements: &[Statement],
        signatures: &[Vec<XmssSignature>],
    ) -> Result<Proof, Error> {
        check_shape(statements, signatures)?;
        let expected = statements_to_claims(statements);
        if expected.lean_xmss.is_empty() {
            return Ok(Proof::default());
        }
        let raw_signatures: Vec<_> = statements
            .iter()
            .zip(signatures)
            .flat_map(|(statement, group)| {
                statement
                    .pubkeys
                    .iter()
                    .zip(group)
                    .map(|(pubkey, signature)| {
                        (
                            LeanXmssPublicKey::from_bytes(pubkey.as_bytes()),
                            statement.message,
                            LeanXmssSignature::from_bytes(signature.as_bytes()),
                        )
                    })
            })
            .collect();
        self.aggregate(&[], &raw_signatures, &expected)
            .map(Proof::from_bytes)
    }

    /// Folds the children [`MAX_CHILDREN_PER_AGGREGATE`] at a time, round after round, until
    /// one proof remains ([`merge_plan`] gives the cost). Children that prove nothing are
    /// skipped, and a single child is returned as it is, without proving.
    ///
    /// The sidecar does not verify children: an invalid one fails the request
    /// ([`Error::SidecarInvalidChild`] or [`Error::SidecarProvingFailed`]).
    fn merge(&self, children: &[(Vec<Statement>, Proof)]) -> Result<Proof, Error> {
        let mut level: Vec<(AggregateClaims, Vec<u8>)> = Vec::with_capacity(children.len());
        for (index, (statements, proof)) in children.iter().enumerate() {
            let claims = statements_to_claims(statements);
            match (claims.lean_xmss.is_empty(), proof.is_empty()) {
                (true, true) => {}
                (false, false) => level.push((claims, proof.as_bytes().to_vec())),
                (true, false) => {
                    return Err(Error::InvalidInput(format!(
                        "child {index} has a proof but no claims"
                    )));
                }
                (false, true) => {
                    return Err(Error::InvalidInput(format!(
                        "child {index} has claims but an empty proof"
                    )));
                }
            }
        }

        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(MAX_CHILDREN_PER_AGGREGATE));
            for chunk in level.chunks(MAX_CHILDREN_PER_AGGREGATE) {
                if let [only] = chunk {
                    next.push(only.clone());
                    continue;
                }
                let expected = union(chunk);
                let proof = self.aggregate(chunk, &[], &expected)?;
                next.push((expected, proof));
            }
            level = next;
        }
        Ok(level
            .pop()
            .map(|(_, proof)| Proof::from_bytes(proof))
            .unwrap_or_default())
    }

    /// One verify request on the verifying connection. Does not check the statements' leaf
    /// indices.
    fn verify(&self, statements: &[Statement], proof: &Proof) -> Result<bool, Error> {
        let claims = statements_to_claims(statements);
        if claims.lean_xmss.is_empty() || proof.is_empty() {
            return Ok(claims.lean_xmss.is_empty() && proof.is_empty());
        }
        with_connection(
            &self.config,
            &self.verify_connection,
            self.config.verify_timeout,
            |client| client.verify(&claims, proof.as_bytes()),
        )
    }
}

/// What merging `children` non-empty proofs costs: `(rounds, proofs made)`. Proofs within a
/// round are still made one after another, since the sidecar proves one request at a time.
pub fn merge_plan(children: usize) -> (usize, usize) {
    let (mut remaining, mut rounds, mut proofs) = (children, 0usize, 0usize);
    while remaining > 1 {
        let full_chunks = remaining / MAX_CHILDREN_PER_AGGREGATE;
        let leftover = remaining % MAX_CHILDREN_PER_AGGREGATE;
        // A leftover of one is carried to the next round as it is.
        proofs = proofs
            .saturating_add(full_chunks)
            .saturating_add(usize::from(leftover > 1));
        remaining = full_chunks.saturating_add(usize::from(leftover > 0));
        rounds = rounds.saturating_add(1);
    }
    (rounds, proofs)
}

/// The claims a proof of all of `children` attests: their union, strictly sorted.
fn union(children: &[(AggregateClaims, Vec<u8>)]) -> AggregateClaims {
    let mut lean_xmss: Vec<_> = children
        .iter()
        .flat_map(|(claims, _)| claims.lean_xmss.iter().copied())
        .collect();
    lean_xmss.sort_unstable();
    lean_xmss.dedup();
    AggregateClaims {
        lean_xmss,
        lean_sphincs: Vec::new(),
        da_commitment: None,
    }
}

/// Connects and checks the hello. The timeout applies to requests on the connection, not to
/// reading the hello, which upstream's client reads without one.
fn open(config: &SidecarConfig, timeout: Option<Duration>) -> Result<Client, Error> {
    let client = Client::connect(&config.socket)?;
    client.set_timeout(timeout).map_err(Error::SidecarIo)?;
    Ok(client)
}

/// Runs `call` on the connection in `slot`, opening it first if needed.
///
/// A connection that fails is dropped, as the protocol requires after anything but a
/// rejection. If it was an existing connection that failed, other than by timing out, the
/// sidecar may simply have restarted: reconnect and try once more.
fn with_connection<T>(
    config: &SidecarConfig,
    slot: &Mutex<Option<Client>>,
    timeout: Option<Duration>,
    mut call: impl FnMut(&mut Client) -> Result<T, SidecarError>,
) -> Result<T, Error> {
    let mut slot = slot.lock();
    let mut reused = slot.is_some();
    loop {
        let client = match slot.as_mut() {
            Some(client) => client,
            None => slot.insert(open(config, timeout)?),
        };
        match call(client) {
            Ok(value) => return Ok(value),
            Err(SidecarError::Rejected(rejection, message)) => {
                return Err(SidecarError::Rejected(rejection, message).into());
            }
            Err(SidecarError::Io(error)) if reused && !is_timeout(&error) => {
                *slot = None;
                reused = false;
            }
            Err(error) => {
                *slot = None;
                return Err(error.into());
            }
        }
    }
}

fn is_timeout(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

impl From<SidecarError> for Error {
    fn from(error: SidecarError) -> Self {
        match error {
            SidecarError::Io(error) => Error::SidecarIo(error),
            SidecarError::Incompatible(why) => Error::SidecarIncompatible(why),
            SidecarError::Protocol(why) => Error::SidecarProtocol(why),
            SidecarError::Rejected(rejection, message) => match rejection {
                Rejection::InvalidInput => Error::SidecarInvalidInput(message),
                Rejection::InvalidSignature => Error::SidecarInvalidSignature(message),
                Rejection::InvalidChild => Error::SidecarInvalidChild(message),
                Rejection::ProvingFailed => Error::SidecarProvingFailed(message),
                Rejection::Malformed => Error::SidecarMalformed(message),
            },
        }
    }
}

#[cfg(test)]
mod tests;

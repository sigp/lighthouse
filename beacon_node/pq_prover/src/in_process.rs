//! leanVM's pinned in-process API. No child process or socket is involved.
use crate::{
    Error, Proof, ProverBackend, Statement, check_packed_claims, check_shape, statements_to_claims,
};
use lean_vm::{AggregateClaims, AggregateProof, OutputClaims};
use lean_xmss::{LeanXmssPublicKey, LeanXmssSignature};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};
use xmss::XmssSignature;

pub const MAX_CHILDREN_PER_AGGREGATE: usize = lean_vm::MAX_RECURSIONS;
static SETUP: OnceLock<(usize, Result<(), String>)> = OnceLock::new();
// A panic may poison leanVM's process-wide internals. Never submit another request afterwards.
static FAILED: AtomicBool = AtomicBool::new(false);

pub struct InProcessBackend {
    log_inv_rate: usize,
}

impl InProcessBackend {
    pub fn new(threads: usize, log_inv_rate: u8) -> Result<Self, Error> {
        let log_inv_rate = usize::from(log_inv_rate);
        if !(lean_vm::MIN_LOG_INV_RATE..=lean_vm::MAX_LOG_INV_RATE).contains(&log_inv_rate) {
            return Err(Error::InvalidInput(
                "leanVM inverse rate is out of range".into(),
            ));
        }
        let (configured, result) = SETUP.get_or_init(|| {
            let result = catch_unwind(|| lean_vm::setup(threads))
                .map_err(|_| "thread pool or CPU tier initialization failed".to_owned());
            (threads, result)
        });
        if *configured != threads {
            return Err(Error::Initialization(format!(
                "process already configured with {configured} prover threads, requested {threads}"
            )));
        }
        result
            .as_ref()
            .map_err(|error| Error::Initialization(error.clone()))?;
        Ok(Self { log_inv_rate })
    }

    pub fn protocol_version(&self) -> u32 {
        lean_vm::PROTOCOL_VERSION
    }

    fn aggregate(
        &self,
        children: &[(AggregateClaims, Vec<u8>)],
        signatures: Vec<(LeanXmssPublicKey, lean_xmss::Message, LeanXmssSignature)>,
        expected: &AggregateClaims,
    ) -> Result<Vec<u8>, Error> {
        guarded(|| {
            let children = children
                .iter()
                .map(|(claims, bytes)| {
                    AggregateProof::from_bytes(bytes)
                        .map(|proof| (claims.clone(), proof))
                        .ok_or(Error::InvalidChild)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let (claims, proof) = lean_vm::aggregate(
                &children,
                signatures,
                vec![],
                None,
                OutputClaims::All,
                self.log_inv_rate,
            )
            .map_err(|error| match error {
                lean_vm::AggregateError::ProvingFailed => Error::ProvingFailed(error.to_string()),
                lean_vm::AggregateError::InvalidChild => Error::InvalidChild,
                lean_vm::AggregateError::InvalidInput(_)
                | lean_vm::AggregateError::InvalidSignature => {
                    Error::InvalidInput(error.to_string())
                }
            })?;
            if claims != *expected {
                return Err(Error::ClaimsMismatch {
                    expected: expected.num_signature_claims(),
                    found: claims.num_signature_claims(),
                });
            }
            Ok(proof.to_bytes())
        })
    }
}

fn guarded<T>(operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    if FAILED.load(Ordering::Acquire) {
        return Err(Error::BackendPanicked);
    }
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or_else(|_| {
        FAILED.store(true, Ordering::Release);
        Err(Error::BackendPanicked)
    })
}

impl ProverBackend for InProcessBackend {
    fn name(&self) -> &'static str {
        "leanvm-in-process"
    }

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
        let signatures = statements
            .iter()
            .zip(signatures)
            .flat_map(|(statement, group)| {
                statement.pubkeys.iter().zip(group).map(|(key, signature)| {
                    (
                        LeanXmssPublicKey::from_bytes(key.as_bytes()),
                        statement.message,
                        LeanXmssSignature::from_bytes(signature.as_bytes()),
                    )
                })
            })
            .collect();
        self.aggregate(&[], signatures, &expected)
            .map(Proof::from_bytes)
    }

    fn merge(&self, children: &[(Vec<Statement>, Proof)]) -> Result<Proof, Error> {
        let mut level = Vec::with_capacity(children.len());
        for (statements, proof) in children {
            let claims = statements_to_claims(statements);
            match (claims.lean_xmss.is_empty(), proof.is_empty()) {
                (true, true) => {}
                (false, false) => level.push((claims, proof.as_bytes().to_vec())),
                _ => {
                    return Err(Error::InvalidInput(
                        "child claims and proof emptiness differ".into(),
                    ));
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
                let proof = self.aggregate(chunk, vec![], &expected)?;
                next.push((expected, proof));
            }
            level = next;
        }
        Ok(level
            .pop()
            .map(|(_, bytes)| Proof::from_bytes(bytes))
            .unwrap_or_default())
    }

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

    fn verify(&self, statements: &[Statement], proof: &Proof) -> Result<bool, Error> {
        let claims = statements_to_claims(statements);
        if claims.lean_xmss.is_empty() || proof.is_empty() {
            return Ok(claims.lean_xmss.is_empty() && proof.is_empty());
        }
        guarded(|| {
            Ok(AggregateProof::from_bytes(proof.as_bytes())
                .is_some_and(|proof| proof.verify(&claims)))
        })
    }
}

fn union(children: &[(AggregateClaims, Vec<u8>)]) -> AggregateClaims {
    let mut lean_xmss: Vec<_> = children
        .iter()
        .flat_map(|(claims, _)| claims.lean_xmss.iter().copied())
        .collect();
    lean_xmss.sort_unstable();
    lean_xmss.dedup();
    AggregateClaims {
        lean_xmss,
        lean_sphincs: vec![],
        da_commitment: None,
    }
}

pub fn merge_plan(children: usize) -> (usize, usize) {
    let (mut remaining, mut rounds, mut proofs) = (children, 0usize, 0usize);
    while remaining > 1 {
        let full = remaining / MAX_CHILDREN_PER_AGGREGATE;
        let leftover = remaining % MAX_CHILDREN_PER_AGGREGATE;
        proofs = proofs
            .saturating_add(full)
            .saturating_add(usize::from(leftover > 1));
        remaining = full.saturating_add(usize::from(leftover > 0));
        rounds = rounds.saturating_add(1);
    }
    (rounds, proofs)
}

#[cfg(all(test, not(feature = "fake_crypto")))]
mod tests {
    use super::*;
    use xmss::XmssSecretKey;

    #[test]
    fn real_prove_merge_verify_and_reject_wrong_claims() {
        let backend = InProcessBackend::new(0, 2).unwrap();
        let key = XmssSecretKey::from_seed(&[43; 32]);
        let mut children = vec![];
        for (leaf, message) in [(32_769, [1; 32]), (32_770, [2; 32])] {
            let statement = Statement {
                pubkeys: vec![key.public_key()],
                leaf_index: leaf,
                message,
            };
            let signature = key.sign(&message, leaf as u32).unwrap();
            let proof = backend
                .prove(std::slice::from_ref(&statement), &[vec![signature]])
                .unwrap();
            assert!(
                backend
                    .verify(std::slice::from_ref(&statement), &proof)
                    .unwrap()
            );
            children.push((vec![statement], proof));
        }
        let statements: Vec<_> = children
            .iter()
            .flat_map(|(statements, _)| statements.clone())
            .collect();
        let merged = backend
            .merge_for_statements(&children, &statements, 1_000_000)
            .unwrap();
        assert!(backend.verify(&statements, &merged).unwrap());
        assert!(!backend.verify(&statements[..1], &merged).unwrap());
        assert!(
            !backend
                .verify(&statements, &Proof::from_bytes(vec![0xff; 64]))
                .unwrap()
        );
        assert_eq!(backend.merge(&children[..1]).unwrap(), children[0].1);
        assert!(
            backend
                .merge_for_statements(&children, &statements[..1], 1_000_000)
                .is_err()
        );
        assert!(backend.prove(&statements[..1], &[]).is_err());
        assert!(backend.verify(&[], &Proof::default()).unwrap());
    }

    #[test]
    fn merge_plan_counts_recursive_requests() {
        assert_eq!(merge_plan(1), (0, 0));
        assert_eq!(merge_plan(16), (1, 1));
        assert_eq!(merge_plan(17), (2, 2));
        assert_eq!(merge_plan(32), (2, 3));
    }
}

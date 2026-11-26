//! Benchmarks XMSS signing and proof aggregation for the PQ fork prototype.
//!
//! Generates `--sigs` keys, has each sign an attestation-style 32-byte message at a common
//! leaf, proves the signatures with the chosen backend, optionally builds `--merge` such
//! proofs and merges them, verifies everything, and prints the timings and sizes as JSON.

use clap::ArgMatches;
use clap_utils::parse_required;
use ethereum_hashing::hash_fixed;
use pq_prover::{LEANVM_REV, Proof, ProverBackend, ReferenceBackend, Statement};
use rayon::prelude::*;
use serde::Serialize;
use std::time::{Duration, Instant};
use xmss::{LeafIndex, XMSS_SIGNATURE_BYTES_LEN, XmssPublicKey, XmssSecretKey, XmssSignature};

#[derive(Serialize)]
struct Report {
    backend: &'static str,
    leanvm_rev: &'static str,
    /// The in-process leanVM prover implementation.
    leanvm_prover: Option<String>,
    log_inv_rate: Option<u8>,
    fake_crypto: bool,
    host: Host,
    /// Threads configured for key generation, signing and leanVM proving.
    threads: usize,
    signers_per_proof: usize,
    messages_per_proof: usize,
    first_leaf_index: LeafIndex,
    keygen: Keygen,
    sign: Sign,
    /// One entry per proof made from raw signatures.
    prove: Vec<ProofRun>,
    /// Further prove and verify runs of the first proof (`--reps`).
    repeat_prove_ms: Vec<f64>,
    repeat_verify_ms: Vec<f64>,
    merge: Option<Merge>,
    /// A proof must not verify for a statement with another message.
    wrong_message_rejected: bool,
    /// Whether a proof still verifies when the statement names another leaf than the one
    /// signed at. `true` is the known gap of leanVM claims (leanEthereum/leanVM#787).
    wrong_leaf_accepted: bool,
}

#[derive(Serialize)]
struct Host {
    os: &'static str,
    arch: &'static str,
    logical_cpus: usize,
}

#[derive(Serialize)]
struct Keygen {
    keys: usize,
    /// Wall-clock time to generate all keys on `threads` threads.
    wall_ms: f64,
    /// Mean single-threaded time to expand one seed into a key (the top tree).
    mean_ms_per_key: f64,
    /// Mean single-threaded time to prepare one key for a range of 2^16 leaves (the bottom
    /// tree), which the first signature in that range otherwise pays.
    mean_prepare_ms_per_key: f64,
}

#[derive(Serialize)]
struct Sign {
    signatures: usize,
    signature_bytes: usize,
    /// Mean single-threaded time per signature, on a prepared key.
    mean_sign_us: f64,
    /// Mean single-threaded time to verify one signature.
    mean_verify_us: f64,
}

#[derive(Serialize)]
struct ProofRun {
    signers: usize,
    statements: usize,
    leaf_index: u64,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
}

#[derive(Serialize)]
struct Merge {
    children: usize,
    /// Signers summed over the children. Children reuse the same keys with other messages
    /// (at other leaves), so every (key, message) claim is distinct.
    total_signers: usize,
    total_statements: usize,
    rounds: usize,
    proofs_made: usize,
    merge_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
    child_proof_bytes_total: usize,
}

/// What one key contributes: its signatures, one per proof, and what they cost.
struct Signer {
    public_key: XmssPublicKey,
    signatures: Vec<XmssSignature>,
    keygen: Duration,
    prepare: Duration,
    sign: Duration,
    verify: Duration,
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}

fn mean(total: Duration, count: usize) -> Duration {
    total.div_f64(count.max(1) as f64)
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let value = f();
    (value, start.elapsed())
}

/// A stand-in for an attestation's signing root: statement `statement` of proof `proof`.
fn message(seed: u64, proof: usize, statement: usize) -> [u8; 32] {
    let mut preimage = b"lcli pq-bench message".to_vec();
    preimage.extend_from_slice(&seed.to_le_bytes());
    preimage.extend_from_slice(&(proof as u64).to_le_bytes());
    preimage.extend_from_slice(&(statement as u64).to_le_bytes());
    hash_fixed(&preimage)
}

fn key_seed(seed: u64, signer: usize) -> [u8; 32] {
    let mut preimage = b"lcli pq-bench key".to_vec();
    preimage.extend_from_slice(&seed.to_le_bytes());
    preimage.extend_from_slice(&(signer as u64).to_le_bytes());
    hash_fixed(&preimage)
}

fn make_backend(
    matches: &ArgMatches,
    rate: u8,
) -> Result<(Box<dyn ProverBackend>, Option<String>), String> {
    let backend: String = parse_required(matches, "backend")?;
    match backend.as_str() {
        "reference" => Ok((Box::new(ReferenceBackend), None)),
        "in-process" => make_in_process_backend(matches, rate),
        other => Err(format!("Unknown backend {other}")),
    }
}

fn make_in_process_backend(
    matches: &ArgMatches,
    rate: u8,
) -> Result<(Box<dyn ProverBackend>, Option<String>), String> {
    let threads: usize = parse_required(matches, "threads")?;
    let backend = pq_prover::InProcessBackend::new(threads, rate)
        .map_err(|error| format!("Unable to initialize leanVM: {error}"))?;
    Ok((Box::new(backend), Some("experimental-in-process".into())))
}

pub fn run(matches: &ArgMatches) -> Result<(), String> {
    let signers: usize = parse_required(matches, "sigs")?;
    let merge: usize = parse_required(matches, "merge")?;
    let rate: u8 = parse_required(matches, "rate")?;
    let messages: usize = parse_required(matches, "messages")?;
    let first_leaf: LeafIndex = parse_required(matches, "leaf-index")?;
    let reps: usize = parse_required(matches, "reps")?;
    let threads: usize = parse_required(matches, "threads")?;
    let seed: u64 = parse_required(matches, "seed")?;

    if signers == 0 {
        return Err("--sigs must be at least 1".to_string());
    }
    if messages == 0 || messages > signers {
        return Err("--messages must be between 1 and --sigs".to_string());
    }
    let proofs = merge.max(1);
    // Proof `p` is signed at leaf `first_leaf + p`: a key never signs twice at one leaf.
    let last_leaf = u32::try_from(proofs.saturating_sub(1))
        .ok()
        .and_then(|offset| first_leaf.checked_add(offset))
        .ok_or("--leaf-index plus --merge exceeds the 2^32 leaves of a key")?;

    let (backend, leanvm_prover) = make_backend(matches, rate)?;
    let is_leanvm = leanvm_prover.is_some();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| format!("Unable to start threads: {e}"))?;
    let threads = pool.current_num_threads();

    // Each key is generated, signs once per proof, and is dropped again: an expanded key
    // holds its trees (a few MiB), which adds up over thousands of keys.
    eprintln!("Generating {signers} keys and {proofs} signature(s) each on {threads} threads");
    let (signed, keygen_wall) = timed(|| {
        pool.install(|| {
            (0..signers)
                .into_par_iter()
                .map(|signer| {
                    let (secret_key, keygen) =
                        timed(|| XmssSecretKey::from_seed(&key_seed(seed, signer)));
                    let public_key = secret_key.public_key();
                    let (prepared, prepare) = timed(|| {
                        secret_key
                            .prepare(first_leaf)
                            .and_then(|()| secret_key.prepare(last_leaf))
                    });
                    prepared.map_err(|e| format!("Unable to prepare key {signer}: {e}"))?;

                    let (mut sign, mut verify) = (Duration::ZERO, Duration::ZERO);
                    let mut signatures = Vec::with_capacity(proofs);
                    for (proof, leaf) in (first_leaf..=last_leaf).enumerate() {
                        let message = message(seed, proof, signer % messages);
                        let (signature, elapsed) = timed(|| secret_key.sign(&message, leaf));
                        let signature =
                            signature.map_err(|e| format!("Key {signer} failed to sign: {e}"))?;
                        sign = sign.saturating_add(elapsed);
                        let (valid, elapsed) =
                            timed(|| xmss::verify(&public_key, leaf, &message, &signature));
                        verify = verify.saturating_add(elapsed);
                        if !valid {
                            return Err(format!("Key {signer} made an invalid signature"));
                        }
                        signatures.push(signature);
                    }
                    Ok(Signer {
                        public_key,
                        signatures,
                        keygen,
                        prepare,
                        sign,
                        verify,
                    })
                })
                .collect::<Result<Vec<Signer>, String>>()
        })
    });
    let signed = signed?;

    let signature_count = signers.saturating_mul(proofs);
    let total = |cost: fn(&Signer) -> Duration| signed.iter().map(cost).sum::<Duration>();
    let keygen = Keygen {
        keys: signers,
        wall_ms: millis(keygen_wall),
        mean_ms_per_key: millis(mean(total(|s| s.keygen), signers)),
        mean_prepare_ms_per_key: millis(mean(total(|s| s.prepare), signers)),
    };
    let sign = Sign {
        signatures: signature_count,
        signature_bytes: XMSS_SIGNATURE_BYTES_LEN,
        mean_sign_us: millis(mean(total(|s| s.sign), signature_count)) * 1e3,
        mean_verify_us: millis(mean(total(|s| s.verify), signature_count)) * 1e3,
    };

    // Proof `p` has `messages` statements; signer `i` is in statement `i % messages`.
    let statements_of =
        |proof: usize, leaf: LeafIndex| -> (Vec<Statement>, Vec<Vec<XmssSignature>>) {
            let mut statements: Vec<Statement> = (0..messages)
                .map(|statement| Statement {
                    pubkeys: Vec::new(),
                    leaf_index: u64::from(leaf),
                    message: message(seed, proof, statement),
                })
                .collect();
            let mut signatures: Vec<Vec<XmssSignature>> = vec![Vec::new(); messages];
            for (index, signer) in signed.iter().enumerate() {
                let slot = index % messages;
                if let (Some(statement), Some(group), Some(signature)) = (
                    statements.get_mut(slot),
                    signatures.get_mut(slot),
                    signer.signatures.get(proof),
                ) {
                    statement.pubkeys.push(signer.public_key);
                    group.push(signature.clone());
                }
            }
            (statements, signatures)
        };

    let mut prove_runs = Vec::with_capacity(proofs);
    let mut children: Vec<(Vec<Statement>, Proof)> = Vec::with_capacity(proofs);
    let (mut repeat_prove_ms, mut repeat_verify_ms) = (Vec::new(), Vec::new());
    for (proof_index, leaf) in (first_leaf..=last_leaf).enumerate() {
        let (statements, signatures) = statements_of(proof_index, leaf);
        eprintln!(
            "Proving {signers} signatures ({} of {proofs})",
            proof_index.saturating_add(1)
        );
        let (proof, prove_time) = timed(|| backend.prove(&statements, &signatures));
        let proof = proof.map_err(|e| format!("Proving failed: {e}"))?;
        let (valid, verify_time) = timed(|| backend.verify(&statements, &proof));
        if !valid.map_err(|e| format!("Verification failed: {e}"))? {
            return Err(format!("Proof {proof_index} does not verify"));
        }
        if proof_index == 0 {
            for _ in 1..reps {
                let (again, elapsed) = timed(|| backend.prove(&statements, &signatures));
                let again = again.map_err(|e| format!("Proving failed: {e}"))?;
                repeat_prove_ms.push(millis(elapsed));
                let (valid, elapsed) = timed(|| backend.verify(&statements, &again));
                if !valid.map_err(|e| format!("Verification failed: {e}"))? {
                    return Err("A repeated proof does not verify".to_string());
                }
                repeat_verify_ms.push(millis(elapsed));
            }
        }
        prove_runs.push(ProofRun {
            signers,
            statements: statements.len(),
            leaf_index: u64::from(leaf),
            prove_ms: millis(prove_time),
            verify_ms: millis(verify_time),
            proof_bytes: proof.len(),
        });
        children.push((statements, proof));
    }

    // Sanity checks on the first proof.
    let (wrong_message_rejected, wrong_leaf_accepted) = {
        let (statements, proof) = children.first().ok_or("No proof was made")?;
        let mut wrong_message = statements.clone();
        if let Some(statement) = wrong_message.first_mut() {
            statement.message = message(seed, usize::MAX, 0);
        }
        let mut wrong_leaf = statements.clone();
        if let Some(statement) = wrong_leaf.first_mut() {
            statement.leaf_index = statement.leaf_index.saturating_add(1 << 20);
        }
        let check = |statements: &[Statement]| {
            backend
                .verify(statements, proof)
                .map_err(|e| format!("Verification failed: {e}"))
        };
        (!check(&wrong_message)?, check(&wrong_leaf)?)
    };
    if !wrong_message_rejected {
        return Err("A proof verified for a message that was not signed".to_string());
    }

    let merge_report = if merge >= 2 {
        eprintln!("Merging {merge} proofs");
        let (merged, merge_time) = timed(|| backend.merge(&children));
        let merged = merged.map_err(|e| format!("Merging failed: {e}"))?;
        let all_statements: Vec<Statement> = children
            .iter()
            .flat_map(|(statements, _)| statements.iter().cloned())
            .collect();
        let (valid, verify_time) = timed(|| backend.verify(&all_statements, &merged));
        if !valid.map_err(|e| format!("Verification failed: {e}"))? {
            return Err("The merged proof does not verify".to_string());
        }
        let (rounds, proofs_made) = merge_cost(is_leanvm, children.len());
        Some(Merge {
            children: children.len(),
            total_signers: signers.saturating_mul(children.len()),
            total_statements: all_statements.len(),
            rounds,
            proofs_made,
            merge_ms: millis(merge_time),
            verify_ms: millis(verify_time),
            proof_bytes: merged.len(),
            child_proof_bytes_total: children.iter().map(|(_, proof)| proof.len()).sum(),
        })
    } else {
        None
    };

    let report = Report {
        backend: backend.name(),
        leanvm_rev: LEANVM_REV,
        leanvm_prover,
        log_inv_rate: is_leanvm.then_some(rate),
        fake_crypto: xmss::FAKE_CRYPTO,
        host: Host {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            logical_cpus: std::thread::available_parallelism().map_or(0, usize::from),
        },
        threads,
        signers_per_proof: signers,
        messages_per_proof: messages,
        first_leaf_index: first_leaf,
        keygen,
        sign,
        prove: prove_runs,
        repeat_prove_ms,
        repeat_verify_ms,
        merge: merge_report,
        wrong_message_rejected,
        wrong_leaf_accepted,
    };
    let json = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Unable to serialize the report: {e}"))?;
    println!("{json}");
    Ok(())
}

/// `(rounds, proofs made)` to merge `children` proofs.
fn merge_cost(is_leanvm: bool, children: usize) -> (usize, usize) {
    if is_leanvm {
        pq_prover::merge_plan(children)
    } else {
        (1, 1)
    }
}

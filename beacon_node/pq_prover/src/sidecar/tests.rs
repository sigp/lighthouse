//! The sidecar backend against a scripted stand-in speaking the README's protocol, and,
//! when `LEANVM_SIDECAR_SOCKET` names a running `leanvm-sidecar`, against the real thing.

use super::*;
use crate::claims::statements_to_claims_bytes;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;
use xmss::{XMSS_SIGNATURE_BYTES_LEN, XmssPublicKey};

const MAX_REQUEST: u64 = 64 << 20;

/// What the stand-in does with the next request it reads.
enum Step {
    Respond(Vec<u8>),
    /// Close the connection without answering.
    HangUp,
    /// Answer, but only after a pause.
    Stall(Duration, Vec<u8>),
}

#[derive(Default)]
struct Shared {
    script: Mutex<VecDeque<Step>>,
    requests: Mutex<Vec<Vec<u8>>>,
    connections: Mutex<usize>,
}

/// A scripted sidecar: greets every connection with `hello`, records each request body and
/// plays the next step of the script.
struct MockSidecar {
    _dir: TempDir,
    socket: PathBuf,
    shared: Arc<Shared>,
}

impl MockSidecar {
    fn start(hello: Vec<u8>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("s.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let shared = Arc::new(Shared::default());
        let accept_shared = shared.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                *accept_shared.connections.lock() += 1;
                let shared = accept_shared.clone();
                let hello = hello.clone();
                thread::spawn(move || serve(stream, &hello, &shared));
            }
        });
        Self {
            _dir: dir,
            socket,
            shared,
        }
    }

    fn good() -> Self {
        Self::start(hello(b"leanvmsc", 1, b"leanvm-v1"))
    }

    fn backend(&self) -> SidecarBackend {
        SidecarBackend::new(self.config())
    }

    fn config(&self) -> SidecarConfig {
        SidecarConfig::new(&self.socket)
    }

    fn script(&self, steps: impl IntoIterator<Item = Step>) {
        self.shared.script.lock().extend(steps);
    }

    fn respond(&self, bodies: impl IntoIterator<Item = Vec<u8>>) {
        self.script(bodies.into_iter().map(Step::Respond));
    }

    fn requests(&self) -> Vec<Vec<u8>> {
        self.shared.requests.lock().clone()
    }

    fn connections(&self) -> usize {
        *self.shared.connections.lock()
    }
}

fn serve(mut stream: UnixStream, hello: &[u8], shared: &Shared) {
    if stream.write_all(&frame(hello)).is_err() {
        return;
    }
    loop {
        let mut len = [0; 8];
        if stream.read_exact(&mut len).is_err() {
            return;
        }
        let mut body = vec![0; u64::from_le_bytes(len) as usize];
        if stream.read_exact(&mut body).is_err() {
            return;
        }
        shared.requests.lock().push(body);
        let step = shared.script.lock().pop_front();
        let response = match step {
            Some(Step::Respond(response)) => response,
            Some(Step::Stall(pause, response)) => {
                thread::sleep(pause);
                response
            }
            Some(Step::HangUp) | None => return,
        };
        if stream.write_all(&frame(&response)).is_err() {
            return;
        }
    }
}

fn frame(body: &[u8]) -> Vec<u8> {
    [&(body.len() as u64).to_le_bytes()[..], body].concat()
}

/// A length-prefixed field.
fn field(bytes: &[u8]) -> Vec<u8> {
    frame(bytes)
}

fn hello(magic: &[u8; 8], version: u32, tag: &[u8]) -> Vec<u8> {
    [
        &magic[..],
        &version.to_le_bytes(),
        &MAX_REQUEST.to_le_bytes(),
        &field(tag),
        &field(b"experimental"),
    ]
    .concat()
}

fn verdict(valid: bool) -> Vec<u8> {
    vec![0, u8::from(valid)]
}

fn rejection(status: u8, message: &str) -> Vec<u8> {
    [&[status][..], &field(message.as_bytes())].concat()
}

fn proven(statements: &[Statement], proof: &[u8]) -> Vec<u8> {
    [
        &[0][..],
        &field(&statements_to_claims_bytes(statements)),
        &field(proof),
    ]
    .concat()
}

fn pubkey(index: usize) -> XmssPublicKey {
    let mut bytes = [0x40; 32];
    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
    XmssPublicKey::from(bytes)
}

/// Not a valid signature, but bytes carrying `leaf_index`, which is all the client reads.
fn signature_at(leaf_index: u32, fill: u8) -> XmssSignature {
    let mut bytes = [fill; XMSS_SIGNATURE_BYTES_LEN];
    bytes[..4].copy_from_slice(&leaf_index.to_le_bytes());
    XmssSignature::from(bytes)
}

fn statement(keys: std::ops::Range<usize>, message: u8) -> Statement {
    Statement {
        pubkeys: keys.map(pubkey).collect(),
        leaf_index: 40_000,
        message: [message; 32],
    }
}

/// One child per index, each claiming one key, with a recognisable proof.
fn children(count: usize) -> Vec<(Vec<Statement>, Proof)> {
    (0..count)
        .map(|i| {
            (
                vec![statement(i..i + 1, 1)],
                Proof::from_bytes(vec![i as u8; 3]),
            )
        })
        .collect()
}

/// The number of children an aggregate request carries.
fn child_count(request: &[u8]) -> u64 {
    assert_eq!(request[0], 1, "an aggregate request");
    u64::from_le_bytes(request[2..10].try_into().unwrap())
}

#[test]
fn hello_is_checked() {
    let good = MockSidecar::good();
    let backend = SidecarBackend::connect(good.config()).unwrap();
    assert_eq!(backend.prover_kind().unwrap(), "experimental");
    assert_eq!(backend.name(), "sidecar");
    assert_eq!(good.connections(), 2);

    for bad_hello in [
        hello(b"notleanv", 1, b"leanvm-v1"),
        hello(b"leanvmsc", 2, b"leanvm-v1"),
        hello(b"leanvmsc", 1, b"leanvm-v2"),
    ] {
        let mock = MockSidecar::start(bad_hello);
        assert!(matches!(
            SidecarBackend::connect(mock.config()),
            Err(Error::SidecarIncompatible(_))
        ));
        // The lazily connecting constructor reports it on first use.
        let backend = mock.backend();
        assert!(matches!(
            backend.verify(&[statement(0..1, 1)], &Proof::from_bytes(vec![1])),
            Err(Error::SidecarIncompatible(_))
        ));
        assert!(mock.requests().is_empty());
    }

    // A hello cut short.
    let mock = MockSidecar::start(b"leanvmsc\x01\0\0\0".to_vec());
    assert!(matches!(
        SidecarBackend::connect(mock.config()),
        Err(Error::SidecarProtocol(_))
    ));

    // Nothing listening.
    let dir = tempfile::tempdir().unwrap();
    let missing = SidecarConfig::new(dir.path().join("none.sock"));
    assert!(matches!(
        SidecarBackend::connect(missing),
        Err(Error::SidecarIo(_))
    ));
}

#[test]
fn verify_request_and_verdict() {
    let mock = MockSidecar::good();
    let backend = mock.backend();
    let statements = [statement(0..2, 1), statement(1..3, 2)];
    let proof = Proof::from_bytes(vec![7, 8, 9]);

    mock.respond([verdict(true), verdict(false)]);
    assert!(backend.verify(&statements, &proof).unwrap());
    assert!(!backend.verify(&statements, &proof).unwrap());

    // Operation 2, then the claims and the proof, each length-prefixed.
    let expected = [
        &[2][..],
        &field(&statements_to_claims_bytes(&statements)),
        &field(&[7, 8, 9]),
    ]
    .concat();
    assert_eq!(mock.requests(), vec![expected.clone(), expected]);
    // Verification has its own connection, and only that one was opened.
    assert_eq!(mock.connections(), 1);
}

#[test]
fn empty_proof_proves_only_nothing() {
    let mock = MockSidecar::good();
    let backend = mock.backend();
    let no_keys = Statement {
        pubkeys: vec![],
        leaf_index: 1,
        message: [1; 32],
    };

    let empty = backend.prove(&[], &[]).unwrap();
    assert!(empty.is_empty());
    assert!(
        backend
            .prove(std::slice::from_ref(&no_keys), &[vec![]])
            .unwrap()
            .is_empty()
    );
    assert!(backend.merge(&[]).unwrap().is_empty());
    assert!(
        backend
            .merge(&[(vec![], Proof::default())])
            .unwrap()
            .is_empty()
    );

    assert!(backend.verify(&[], &empty).unwrap());
    assert!(backend.verify(&[no_keys], &empty).unwrap());
    assert!(!backend.verify(&[statement(0..1, 1)], &empty).unwrap());
    assert!(!backend.verify(&[], &Proof::from_bytes(vec![1])).unwrap());

    // None of this reached the sidecar.
    assert_eq!(mock.connections(), 0);
}

#[test]
fn every_status_code_is_an_error() {
    let mock = MockSidecar::good();
    let backend = mock.backend();
    let statements = [statement(0..1, 1)];
    let proof = Proof::from_bytes(vec![1]);

    mock.respond((1..=5).map(|status| rejection(status, "why")));
    let mut errors = Vec::new();
    for _ in 1..=5 {
        errors.push(backend.verify(&statements, &proof).unwrap_err());
    }
    assert!(matches!(&errors[0], Error::SidecarInvalidInput(why) if why == "why"));
    assert!(matches!(&errors[1], Error::SidecarInvalidSignature(why) if why == "why"));
    assert!(matches!(&errors[2], Error::SidecarInvalidChild(why) if why == "why"));
    assert!(matches!(&errors[3], Error::SidecarProvingFailed(why) if why == "why"));
    assert!(matches!(&errors[4], Error::SidecarMalformed(why) if why == "why"));
    // A rejection leaves the connection usable.
    assert_eq!(mock.connections(), 1);

    // A status outside the protocol, and a verdict that is not one: the connection is
    // dropped and the next call opens another.
    mock.respond([rejection(9, "?"), vec![0, 2], verdict(true)]);
    assert!(matches!(
        backend.verify(&statements, &proof),
        Err(Error::SidecarProtocol(_))
    ));
    assert!(matches!(
        backend.verify(&statements, &proof),
        Err(Error::SidecarProtocol(_))
    ));
    assert!(backend.verify(&statements, &proof).unwrap());
    assert_eq!(mock.connections(), 3);
}

#[test]
fn prove_request_and_response() {
    let mock = MockSidecar::good();
    let mut config = mock.config();
    config.log_inv_rate = 3;
    let backend = SidecarBackend::new(config);

    // Key 1 signs both messages; the statements are not in claim order.
    let statements = [statement(1..3, 9), statement(0..2, 4)];
    let signatures = [
        vec![signature_at(40_000, 0xa1), signature_at(40_000, 0xa2)],
        vec![signature_at(40_000, 0xb0), signature_at(40_000, 0xb1)],
    ];

    mock.respond([proven(&statements, b"a proof")]);
    let proof = backend.prove(&statements, &signatures).unwrap();
    // The proof is the sidecar's proof alone, without the claims.
    assert_eq!(proof.as_bytes(), b"a proof");

    let mut expected = vec![1, 3];
    expected.extend_from_slice(&0u64.to_le_bytes());
    expected.extend_from_slice(&4u64.to_le_bytes());
    for (statement, group) in statements.iter().zip(&signatures) {
        for (pubkey, signature) in statement.pubkeys.iter().zip(group) {
            expected.extend_from_slice(pubkey.as_bytes());
            expected.extend_from_slice(&statement.message);
            expected.extend_from_slice(signature.as_bytes());
        }
    }
    // No leanSPHINCS signatures, no blobs, output: every covered claim.
    expected.extend_from_slice(&0u64.to_le_bytes());
    expected.extend_from_slice(&0u64.to_le_bytes());
    expected.push(0);
    assert_eq!(mock.requests(), vec![expected]);

    // A proof of other claims than those asked for is refused.
    mock.respond([proven(&statements[..1], b"a proof")]);
    assert!(matches!(
        backend.prove(&statements, &signatures),
        Err(Error::SidecarClaimsMismatch {
            expected: 4,
            found: 2
        })
    ));

    // The sidecar's verdict on a bad signature.
    mock.respond([rejection(2, "signature 1")]);
    assert!(matches!(
        backend.prove(&statements, &signatures),
        Err(Error::SidecarInvalidSignature(_))
    ));
    assert_eq!(mock.requests().len(), 3);

    // A signature at another leaf never reaches the sidecar, nor do mismatched shapes.
    let mut wrong_leaf = signatures.clone();
    wrong_leaf[1][0] = signature_at(40_001, 0xb0);
    assert!(matches!(
        backend.prove(&statements, &wrong_leaf),
        Err(Error::LeafIndexMismatch {
            statement: 1,
            signature: 0,
            expected: 40_000,
            found: 40_001
        })
    ));
    assert!(matches!(
        backend.prove(&statements, &signatures[..1]),
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(mock.requests().len(), 3);
}

#[test]
fn merge_folds_sixteen_at_a_time() {
    let all = |children: &[(Vec<Statement>, Proof)]| -> Vec<Statement> {
        children
            .iter()
            .flat_map(|(statements, _)| statements.clone())
            .collect()
    };

    // 18 children: 16 and 2 in the first round, their 2 proofs in the second.
    let mock = MockSidecar::good();
    let backend = mock.backend();
    let eighteen = children(18);
    mock.respond([
        proven(&all(&eighteen[..16]), b"first sixteen"),
        proven(&all(&eighteen[16..]), b"last two"),
        proven(&all(&eighteen), b"root"),
    ]);
    assert_eq!(backend.merge(&eighteen).unwrap().as_bytes(), b"root");
    let requests = mock.requests();
    assert_eq!(
        requests.iter().map(|r| child_count(r)).collect::<Vec<_>>(),
        vec![16, 2, 2]
    );
    assert_eq!(merge_plan(18), (2, 3));
    // A child goes as its claims then its proof, and the request has no signatures.
    let first_child = [
        &field(&statements_to_claims_bytes(&eighteen[0].0))[..],
        &field(eighteen[0].1.as_bytes()),
    ]
    .concat();
    assert_eq!(requests[0][10..10 + first_child.len()], first_child);
    assert!(requests[0].ends_with(&[0; 8 + 8 + 8 + 1]));
    // The second round's children are the first round's proofs.
    let second_round = [
        &field(&statements_to_claims_bytes(&all(&eighteen[..16])))[..],
        &field(b"first sixteen"),
        &field(&statements_to_claims_bytes(&all(&eighteen[16..]))),
        &field(b"last two"),
    ]
    .concat();
    assert_eq!(requests[2][10..10 + second_round.len()], second_round);

    // 17 children: the odd one out is carried into the second round as it is.
    let mock = MockSidecar::good();
    let backend = mock.backend();
    let seventeen = children(17);
    mock.respond([
        proven(&all(&seventeen[..16]), b"first sixteen"),
        proven(&all(&seventeen), b"root"),
    ]);
    assert_eq!(backend.merge(&seventeen).unwrap().as_bytes(), b"root");
    assert_eq!(
        mock.requests()
            .iter()
            .map(|r| child_count(r))
            .collect::<Vec<_>>(),
        vec![16, 2]
    );

    // One child, alone or among children that prove nothing: returned without proving.
    let mock = MockSidecar::good();
    let backend = mock.backend();
    let mut one = children(1);
    assert_eq!(backend.merge(&one).unwrap(), one[0].1);
    one.push((vec![], Proof::default()));
    assert_eq!(backend.merge(&one).unwrap(), one[0].1);
    assert_eq!(mock.connections(), 0);

    // A child whose proof and claims disagree about being empty.
    one.push((vec![], Proof::from_bytes(vec![1])));
    assert!(matches!(backend.merge(&one), Err(Error::InvalidInput(_))));
    let no_proof = [(vec![statement(0..1, 1)], Proof::default())];
    assert!(matches!(
        backend.merge(&no_proof),
        Err(Error::InvalidInput(_))
    ));

    // An invalid child fails the merge.
    mock.respond([rejection(3, "child 1")]);
    assert!(matches!(
        backend.merge(&children(2)),
        Err(Error::SidecarInvalidChild(_))
    ));
}

#[test]
fn merge_plan_counts_rounds_and_proofs() {
    assert_eq!(merge_plan(0), (0, 0));
    assert_eq!(merge_plan(1), (0, 0));
    assert_eq!(merge_plan(2), (1, 1));
    assert_eq!(merge_plan(16), (1, 1));
    assert_eq!(merge_plan(17), (2, 2));
    assert_eq!(merge_plan(32), (2, 3));
    assert_eq!(merge_plan(64), (2, 5));
    assert_eq!(merge_plan(256), (2, 17));
    assert_eq!(merge_plan(257), (3, 18));
}

#[test]
fn reconnects_when_the_sidecar_went_away() {
    let mock = MockSidecar::good();
    let backend = mock.backend();
    let statements = [statement(0..1, 1)];
    let proof = Proof::from_bytes(vec![1]);

    // The established connection dies on the second request: it is retried on a new one.
    mock.script([
        Step::Respond(verdict(true)),
        Step::HangUp,
        Step::Respond(verdict(true)),
    ]);
    assert!(backend.verify(&statements, &proof).unwrap());
    assert!(backend.verify(&statements, &proof).unwrap());
    assert_eq!(mock.connections(), 2);
    assert_eq!(mock.requests().len(), 3);

    // If the retry dies too, that is an error, not a loop: one retry, on one new connection.
    mock.script([Step::HangUp, Step::HangUp, Step::HangUp]);
    assert!(matches!(
        backend.verify(&statements, &proof),
        Err(Error::SidecarIo(_))
    ));
    assert_eq!(mock.connections(), 3);
    assert_eq!(mock.requests().len(), 5);
    // And a request that fails on a connection opened for it is not retried at all.
    assert!(matches!(
        backend.verify(&statements, &proof),
        Err(Error::SidecarIo(_))
    ));
    assert_eq!(mock.connections(), 4);
    assert_eq!(mock.requests().len(), 6);
}

#[test]
fn timeouts_are_errors_and_are_not_retried() {
    let mock = MockSidecar::good();
    let mut config = mock.config();
    config.verify_timeout = Some(Duration::from_millis(100));
    let backend = SidecarBackend::new(config);
    let statements = [statement(0..1, 1)];
    let proof = Proof::from_bytes(vec![1]);

    mock.script([
        Step::Respond(verdict(true)),
        Step::Stall(Duration::from_millis(600), verdict(true)),
        Step::Respond(verdict(true)),
    ]);
    assert!(backend.verify(&statements, &proof).unwrap());
    let error = backend.verify(&statements, &proof).unwrap_err();
    assert!(matches!(&error, Error::SidecarIo(e) if is_timeout(e)));
    assert_eq!(mock.requests().len(), 2);
    // The next call uses a new connection.
    assert!(backend.verify(&statements, &proof).unwrap());
    assert_eq!(mock.connections(), 2);
}

/// Against a real `leanvm-sidecar` built from `LEANVM_REV`:
/// `LEANVM_SIDECAR_SOCKET=/path/to/sidecar.sock cargo nextest run --release -p pq_prover live`
#[cfg(not(feature = "fake_crypto"))]
#[test]
fn live_sidecar_round_trip() {
    use xmss::XmssSecretKey;

    let Some(socket) = std::env::var_os("LEANVM_SIDECAR_SOCKET") else {
        eprintln!("skipped: LEANVM_SIDECAR_SOCKET is not set");
        return;
    };
    let backend = SidecarBackend::connect(SidecarConfig::new(socket)).unwrap();
    let leaf = (1u32 << 15) + 5;
    let keys: Vec<XmssSecretKey> = (1..=3u8)
        .map(|i| XmssSecretKey::from_seed(&[i; 32]))
        .collect();
    let signed = |keys: &[XmssSecretKey], message: [u8; 32]| {
        let statement = Statement {
            pubkeys: keys.iter().map(XmssSecretKey::public_key).collect(),
            leaf_index: u64::from(leaf),
            message,
        };
        let signatures: Vec<XmssSignature> = keys
            .iter()
            .map(|key| key.sign(&message, leaf).unwrap())
            .collect();
        (statement, signatures)
    };

    let (first, first_signatures) = signed(&keys[..2], [1; 32]);
    let (second, second_signatures) = signed(&keys[1..], [2; 32]);
    let left_statements = vec![first];
    let right_statements = vec![second];
    let left = backend
        .prove(&left_statements, std::slice::from_ref(&first_signatures))
        .unwrap();
    let right = backend
        .prove(&right_statements, &[second_signatures])
        .unwrap();
    assert!(backend.verify(&left_statements, &left).unwrap());
    assert!(backend.verify(&right_statements, &right).unwrap());

    // Tampered proof, other statements.
    let mut tampered = left.as_bytes().to_vec();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 1;
    assert!(
        !backend
            .verify(&left_statements, &Proof::from_bytes(tampered))
            .unwrap()
    );
    assert!(!backend.verify(&right_statements, &left).unwrap());
    let mut other_message = left_statements.clone();
    other_message[0].message = [3; 32];
    assert!(!backend.verify(&other_message, &left).unwrap());

    // Merged, in either statement order.
    let merged = backend
        .merge(&[
            (left_statements.clone(), left.clone()),
            (right_statements.clone(), right),
        ])
        .unwrap();
    let all_statements = [left_statements.clone(), right_statements.clone()].concat();
    let reordered = [right_statements, left_statements.clone()].concat();
    assert!(backend.verify(&all_statements, &merged).unwrap());
    assert!(backend.verify(&reordered, &merged).unwrap());
    assert!(!backend.verify(&left_statements, &merged).unwrap());

    // An invalid signature is the sidecar's to find.
    let swapped = vec![first_signatures[1].clone(), first_signatures[0].clone()];
    assert!(matches!(
        backend.prove(&left_statements, &[swapped]),
        Err(Error::SidecarInvalidSignature(_))
    ));
}

use std::borrow::Cow;

use bls::{verify_signature_sets, Hash256, PublicKey, SecretKey, SignatureSet};
use criterion::{criterion_group, criterion_main, Criterion};

pub fn bench_verify_signature_set(c: &mut Criterion) {
    let private_keys: Vec<_> = (0..16384).map(|_| SecretKey::random()).collect();
    let public_keys: Vec<Cow<PublicKey>> = private_keys
        .iter()
        .map(|sk| Cow::Owned(sk.public_key()))
        .collect();
    let num_signature_sets = 1;
    let msgs = (0..num_signature_sets)
        .map(|_| Hash256::random())
        .collect::<Vec<_>>();

    // For each message, we want the private key to sign over them
    let set_of_signatures: Vec<Vec<_>> = msgs
        .iter()
        .map(|msg| {
            private_keys
                .iter()
                .map(|sk| sk.sign(*msg))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let num_signatures = [32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768];

    for num_sig in num_signatures.iter() {
        let mut signature_sets = Vec::new();
        for i in 0..num_signature_sets {
            let msg = msgs[i];
            let public_keys: Vec<_> = public_keys.iter().cloned().take(*num_sig).collect();
            signature_sets.push(SignatureSet::multiple_pubkeys(
                &set_of_signatures[i][0],
                public_keys,
                msg,
            ));
        }

        c.bench_function(
            &format!(
                "num signatures {}, sig_sets {}",
                num_sig, num_signature_sets
            ),
            |b| b.iter(|| verify_signature_sets(signature_sets.iter())),
        );
    }
}

criterion_group!(benches, bench_verify_signature_set,);
criterion_main!(benches);

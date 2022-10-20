use bls::{PublicKey, SecretKey};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

pub fn compress(c: &mut Criterion) {
    let private_key = SecretKey::random();
    let public_key = private_key.public_key();
    c.bench_with_input(
        BenchmarkId::new("compress", 1),
        &public_key,
        |b, public_key| {
            b.iter(|| public_key.compress());
        },
    );
}

pub fn decompress(c: &mut Criterion) {
    let private_key = SecretKey::random();
    let public_key_bytes = private_key.public_key().compress();
    c.bench_with_input(
        BenchmarkId::new("decompress", 1),
        &public_key_bytes,
        |b, public_key_bytes| {
            b.iter(|| public_key_bytes.decompress().unwrap());
        },
    );
}

pub fn deserialize_uncompressed(c: &mut Criterion) {
    let private_key = SecretKey::random();
    let public_key_bytes = private_key.public_key().serialize_uncompressed();
    c.bench_with_input(
        BenchmarkId::new("deserialize_uncompressed", 1),
        &public_key_bytes,
        |b, public_key_bytes| {
            b.iter(|| PublicKey::deserialize_uncompressed(public_key_bytes).unwrap());
        },
    );
}

pub fn compress_all(c: &mut Criterion) {
    let n = 500_000;
    let keys = (0..n)
        .map(|_| {
            let private_key = SecretKey::random();
            private_key.public_key()
        })
        .collect::<Vec<_>>();
    c.bench_with_input(BenchmarkId::new("compress", n), &keys, |b, keys| {
        b.iter(|| {
            for key in keys {
                key.compress();
            }
        });
    });
}

criterion_group!(
    benches,
    compress,
    decompress,
    deserialize_uncompressed,
    compress_all
);
criterion_main!(benches);

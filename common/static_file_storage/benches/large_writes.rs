//! Benchmarks for the write path under ERA-load-shaped record sizes.
//!
//! The targeted profile is mainnet ERA import: ~10–30 MB state-snapshot and
//! state-diff records into columns where `compression: false` (the production
//! setting for those columns, since HDiff is already compressed internally).
//!
//! Each iteration fixtures a fresh temp directory so the bench measures
//! steady-state put cost, not first-open or healing overhead.
//!
//! Run with: `cargo bench -p static_file_storage --bench large_writes`.

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use static_file_storage::{Config, StaticFile};
use std::hint::black_box;
use std::path::PathBuf;

const RECORD_30MB: usize = 30 * 1024 * 1024;
const RECORD_4MB: usize = 4 * 1024 * 1024;

const NO_COMPRESSION: Config = Config {
    record_type: [0x04, 0x00],
    compression: false,
    max_value_bytes: 1024 * 1024 * 1024,
};

const SNAPPY: Config = Config {
    record_type: [0x04, 0x00],
    compression: true,
    max_value_bytes: 1024 * 1024 * 1024,
};

fn payload(seed: u64, len: usize) -> Vec<u8> {
    // xorshift fill — fast, deterministic, incompressible enough that snappy
    // can't shortcut (we care about the path it actually takes in production
    // where HDiff outputs are already entropy-dense).
    let mut buf = vec![0u8; len];
    let mut s = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    for chunk in buf.chunks_mut(8) {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        chunk.copy_from_slice(&s.to_le_bytes()[..chunk.len()]);
    }
    buf
}

fn fresh_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();
    (dir, path)
}

fn bench_put_single_30mb(c: &mut Criterion) {
    let value = payload(1, RECORD_30MB);
    let mut group = c.benchmark_group("put_single_30mb_no_compression");
    group.sample_size(20);
    group.throughput(Throughput::Bytes(RECORD_30MB as u64));
    group.bench_function("put", |b| {
        b.iter_batched(
            || {
                let (dir, path) = fresh_dir();
                let sf = StaticFile::open(path, NO_COMPRESSION).expect("open");
                (dir, sf)
            },
            |(_dir, sf)| {
                sf.put(0, black_box(&value)).expect("put");
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn bench_put_batch_eight_30mb_one_file(c: &mut Criterion) {
    let values: Vec<(u64, Vec<u8>)> = (0..8).map(|i| (i, payload(i, RECORD_30MB))).collect();
    let total_bytes = (RECORD_30MB * 8) as u64;
    let mut group = c.benchmark_group("put_batch_eight_30mb_in_one_file_no_compression");
    group.sample_size(20);
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("put_batch", |b| {
        b.iter_batched(
            || {
                let (dir, path) = fresh_dir();
                let sf = StaticFile::open(path, NO_COMPRESSION).expect("open");
                (dir, sf, values.clone())
            },
            |(_dir, sf, items)| {
                sf.put_batch(items).expect("put_batch");
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn bench_put_batch_eight_30mb_snappy(c: &mut Criterion) {
    // Same shape as the no-compression bench but with snappy on, to quantify
    // the cost we explicitly avoid by setting `compression: false` for the
    // state-snapshot / state-diff columns.
    let values: Vec<(u64, Vec<u8>)> = (0..8).map(|i| (i, payload(i, RECORD_30MB))).collect();
    let total_bytes = (RECORD_30MB * 8) as u64;
    let mut group = c.benchmark_group("put_batch_eight_30mb_in_one_file_snappy");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("put_batch", |b| {
        b.iter_batched(
            || {
                let (dir, path) = fresh_dir();
                let sf = StaticFile::open(path, SNAPPY).expect("open");
                (dir, sf, values.clone())
            },
            |(_dir, sf, items)| {
                sf.put_batch(items).expect("put_batch");
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn bench_put_batch_32_records_4mb_cross_file(c: &mut Criterion) {
    // 32 × 4 MB records spanning a file boundary at slot 8192. Catches
    // anything quadratic in the per-group rewrite path.
    let values: Vec<(u64, Vec<u8>)> = (8176u64..8208)
        .map(|i| (i, payload(i, RECORD_4MB)))
        .collect();
    let total_bytes = (RECORD_4MB * values.len()) as u64;
    let mut group = c.benchmark_group("put_batch_32_records_4mb_cross_file_no_compression");
    group.sample_size(20);
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("put_batch", |b| {
        b.iter_batched(
            || {
                let (dir, path) = fresh_dir();
                let sf = StaticFile::open(path, NO_COMPRESSION).expect("open");
                (dir, sf, values.clone())
            },
            |(_dir, sf, items)| {
                sf.put_batch(items).expect("put_batch");
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_put_single_30mb,
    bench_put_batch_eight_30mb_one_file,
    bench_put_batch_eight_30mb_snappy,
    bench_put_batch_32_records_4mb_cross_file,
);
criterion_main!(benches);

//! Benchmarks for the write path under ERA-load-shaped record sizes.
//!
//! The targeted profile is mainnet ERA import: ~10–30 MB state-snapshot and
//! state-diff records. Callers are expected to pre-compress payloads if they
//! want compression; this benchmark measures only static storage write cost.
//!
//! Each iteration fixtures a fresh temp directory so the bench measures
//! steady-state put cost, not first-open or healing overhead.
//!
//! Run with: `cargo bench -p static_file_storage --bench large_writes`.

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use rand::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use static_file_storage::{SLOTS_PER_FILE, StaticFile};
use std::hint::black_box;
use std::path::PathBuf;

const RECORD_30MB: usize = 30 * 1024 * 1024;
const RECORD_4MB: usize = 4 * 1024 * 1024;
const RECORD_1KB: usize = 1024;

const MAX_VALUE_BYTES: u64 = 1024 * 1024 * 1024;

fn payload(seed: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    XorShiftRng::seed_from_u64(seed).fill_bytes(&mut buf);
    buf
}

fn fresh_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();
    (dir, path)
}

fn borrowed_items(values: &[(u64, Vec<u8>)]) -> Vec<(u64, &[u8])> {
    values
        .iter()
        .map(|(slot, value)| (*slot, value.as_slice()))
        .collect()
}

fn batch_values(start_slot: u64, count: u64, record_size: usize) -> Vec<(u64, Vec<u8>)> {
    (0..count)
        .map(|i| {
            let slot = start_slot + i;
            (slot, payload(slot, record_size))
        })
        .collect()
}

fn bench_put_single_30mb(c: &mut Criterion) {
    let value = payload(1, RECORD_30MB);
    let mut group = c.benchmark_group("put_single_30mb");
    group.sample_size(20);
    group.throughput(Throughput::Bytes(RECORD_30MB as u64));
    group.bench_function("put", |b| {
        b.iter_batched(
            || {
                let (dir, path) = fresh_dir();
                let sf = StaticFile::open(path, MAX_VALUE_BYTES).expect("open");
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

fn bench_put_batch(c: &mut Criterion) {
    for (name, start_slot, count, record_size, sample_size) in [
        ("eight_30mb_one_file", 0, 8, RECORD_30MB, 20),
        (
            "32_records_4mb_cross_file",
            SLOTS_PER_FILE - 16,
            32,
            RECORD_4MB,
            20,
        ),
        ("two_full_files_1kb", 0, SLOTS_PER_FILE * 2, RECORD_1KB, 10),
    ] {
        let values = batch_values(start_slot, count, record_size);
        let total_bytes = count * record_size as u64;
        let mut group = c.benchmark_group(format!("put_batch_{name}"));
        group.sample_size(sample_size);
        group.throughput(Throughput::Bytes(total_bytes));
        group.bench_function("put_batch", |b| {
            b.iter_batched(
                || {
                    let (dir, path) = fresh_dir();
                    let sf = StaticFile::open(path, MAX_VALUE_BYTES).expect("open");
                    (dir, sf, values.clone())
                },
                |(_dir, sf, items)| {
                    sf.put_batch(&borrowed_items(&items)).expect("put_batch");
                },
                BatchSize::PerIteration,
            );
        });
        group.finish();
    }
}

criterion_group!(benches, bench_put_single_30mb, bench_put_batch,);
criterion_main!(benches);

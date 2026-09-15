use criterion::measurement::Measurement;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_main};
use perf_benchmarking::InstructionCount;
use std::hint::black_box;
use swap_or_not_shuffle::{compute_shuffled_index, shuffle_list};

const SHUFFLE_ROUND_COUNT: u8 = 90;

fn shuffle_indices_individually(seed: &[u8], list_size: usize) -> Vec<usize> {
    let mut output = Vec::with_capacity(list_size);
    for i in 0..list_size {
        output.push(compute_shuffled_index(i, list_size, seed, SHUFFLE_ROUND_COUNT).unwrap());
    }
    output
}

/// Prefix benchmark names so that time-based and hardware performance data results are stored and
/// compared separately by criterion.
fn name(prefix: &str, base: &str) -> String {
    if prefix.is_empty() {
        base.to_string()
    } else {
        format!("{prefix}/{base}")
    }
}

fn shuffles<M: Measurement + 'static>(c: &mut Criterion<M>, prefix: &str) {
    c.bench_function(&name(prefix, "single swap"), move |b| {
        let seed = vec![42; 32];
        b.iter(|| black_box(compute_shuffled_index(0, 10, &seed, SHUFFLE_ROUND_COUNT)))
    });

    c.bench_function(&name(prefix, "whole list of size 8"), move |b| {
        let seed = vec![42; 32];
        b.iter(|| black_box(shuffle_indices_individually(&seed, 8)))
    });

    for size in [8, 16, 512, 16_384] {
        c.bench_with_input(
            BenchmarkId::new(
                name(prefix, "whole list shuffle"),
                format!("{size} elements"),
            ),
            &size,
            move |b, &n| {
                let seed = vec![42; 32];
                b.iter(|| black_box(shuffle_indices_individually(&seed, n)))
            },
        );
    }

    let mut group = c.benchmark_group(name(prefix, "whole_list_shuffle"));
    group.sample_size(10);
    for size in [512, 16_384, 1_000_000, 4_000_000] {
        group.throughput(Throughput::Elements(size as u64));

        for (direction, forwards) in [("forward", true), ("reverse", false)] {
            let seed = [42; 32];
            let template: Vec<usize> = (0..size).collect();
            let batch_size = if size <= 16_384 {
                BatchSize::LargeInput
            } else {
                BatchSize::PerIteration
            };

            group.bench_with_input(BenchmarkId::new(direction, size), &size, move |b, _| {
                b.iter_batched(
                    || template.clone(),
                    |input| black_box(shuffle_list(input, SHUFFLE_ROUND_COUNT, &seed, forwards)),
                    batch_size,
                )
            });
        }
    }
    group.finish();
}

/// Wall-clock benchmarks, measure real time spent
fn time_benches() {
    let mut criterion = Criterion::default().configure_from_args();
    shuffles(&mut criterion, "time");
}

/// The same benchmarks measured in CPU instructions, which are far more reproducible
/// than wall-clock time. Skipped when the hardware counter cannot be opened (non-Linux, or
/// `kernel.perf_event_paranoid` too restrictive).
fn cpu_instructions_benches() {
    match InstructionCount::new() {
        Ok(measurement) => {
            let mut criterion = Criterion::default()
                .with_measurement(measurement)
                .configure_from_args();
            shuffles(&mut criterion, "CPU instructions");
        }
        Err(e) => eprintln!("Skipping CPU instructions benchmarks: {e}"),
    }
}

criterion_main!(time_benches, cpu_instructions_benches);

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use swap_or_not_shuffle::{compute_shuffled_index, shuffle_list as fast_shuffle};

const SHUFFLE_ROUND_COUNT: u8 = 90;

fn shuffle_list(seed: &[u8], list_size: usize) -> Vec<usize> {
    let mut output = Vec::with_capacity(list_size);
    for i in 0..list_size {
        output.push(compute_shuffled_index(i, list_size, seed, SHUFFLE_ROUND_COUNT).unwrap());
    }
    output
}

fn shuffles(c: &mut Criterion) {
    c.bench_function("single swap", move |b| {
        let seed = vec![42; 32];
        b.iter(|| black_box(compute_shuffled_index(0, 10, &seed, SHUFFLE_ROUND_COUNT)))
    });

    c.bench_function("whole list of size 8", move |b| {
        let seed = vec![42; 32];
        b.iter(|| black_box(shuffle_list(&seed, 8)))
    });

    for size in [8, 16, 512, 16_384] {
        c.bench_with_input(
            BenchmarkId::new("whole list shuffle", format!("{size} elements")),
            &size,
            move |b, &n| {
                let seed = vec![42; 32];
                b.iter(|| black_box(shuffle_list(&seed, n)))
            },
        );
    }

    let mut group = c.benchmark_group("fast");
    group.sample_size(10);
    for size in [512, 16_384, 4_000_000] {
        group.bench_with_input(
            BenchmarkId::new("whole list shuffle", format!("{size} elements")),
            &size,
            move |b, &n| {
                let seed = vec![42; 32];
                let list: Vec<usize> = (0..n).collect();
                b.iter(|| black_box(fast_shuffle(list.clone(), SHUFFLE_ROUND_COUNT, &seed, true)))
            },
        );
    }
    group.finish();
}

criterion_group!(benches, shuffles);
criterion_main!(benches);

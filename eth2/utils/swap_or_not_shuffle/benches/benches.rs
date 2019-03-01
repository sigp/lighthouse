use criterion::Criterion;
use criterion::{black_box, criterion_group, criterion_main, Benchmark};
use swap_or_not_shuffle::{get_permutated_index, shuffle_list as fast_shuffle};

const SHUFFLE_ROUND_COUNT: u8 = 90;

fn shuffle_list(seed: &[u8], list_size: usize) -> Vec<usize> {
    let mut output = Vec::with_capacity(list_size);
    for i in 0..list_size {
        output.push(get_permutated_index(i, list_size, seed, SHUFFLE_ROUND_COUNT).unwrap());
    }
    output
}

fn shuffles(c: &mut Criterion) {
    c.bench_function("single swap", move |b| {
        let seed = vec![42; 32];
        b.iter(|| black_box(get_permutated_index(0, 10, &seed, SHUFFLE_ROUND_COUNT)))
    });

    c.bench_function("whole list of size 8", move |b| {
        let seed = vec![42; 32];
        b.iter(|| black_box(shuffle_list(&seed, 8)))
    });

    c.bench(
        "whole list shuffle",
        Benchmark::new("8 elements", move |b| {
            let seed = vec![42; 32];
            b.iter(|| black_box(shuffle_list(&seed, 8)))
        }),
    );

    c.bench(
        "whole list shuffle",
        Benchmark::new("16 elements", move |b| {
            let seed = vec![42; 32];
            b.iter(|| black_box(shuffle_list(&seed, 16)))
        }),
    );

    c.bench(
        "whole list shuffle",
        Benchmark::new("512 elements", move |b| {
            let seed = vec![42; 32];
            b.iter(|| black_box(shuffle_list(&seed, 512)))
        })
        .sample_size(10),
    );

    c.bench(
        "_fast_ whole list shuffle",
        Benchmark::new("512 elements", move |b| {
            let seed = vec![42; 32];
            let list: Vec<usize> = (0..512).collect();
            b.iter(|| black_box(fast_shuffle(list.clone(), SHUFFLE_ROUND_COUNT, &seed, true)))
        })
        .sample_size(10),
    );

    c.bench(
        "whole list shuffle",
        Benchmark::new("16384 elements", move |b| {
            let seed = vec![42; 32];
            b.iter(|| black_box(shuffle_list(&seed, 16_384)))
        })
        .sample_size(10),
    );

    c.bench(
        "_fast_ whole list shuffle",
        Benchmark::new("16384 elements", move |b| {
            let seed = vec![42; 32];
            let list: Vec<usize> = (0..16384).collect();
            b.iter(|| black_box(fast_shuffle(list.clone(), SHUFFLE_ROUND_COUNT, &seed, true)))
        })
        .sample_size(10),
    );

    c.bench(
        "_fast_ whole list shuffle",
        Benchmark::new("4m elements", move |b| {
            let seed = vec![42; 32];
            let list: Vec<usize> = (0..4_000_000).collect();
            b.iter(|| black_box(fast_shuffle(list.clone(), SHUFFLE_ROUND_COUNT, &seed, true)))
        })
        .sample_size(10),
    );
}

criterion_group!(benches, shuffles,);
criterion_main!(benches);

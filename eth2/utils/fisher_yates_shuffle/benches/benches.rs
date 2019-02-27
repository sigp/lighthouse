use criterion::Criterion;
use criterion::{black_box, criterion_group, criterion_main, Benchmark};
use fisher_yates_shuffle::shuffle;

fn get_list(n: usize) -> Vec<usize> {
    let mut list = Vec::with_capacity(n);
    for i in 0..n {
        list.push(i)
    }
    assert_eq!(list.len(), n);
    list
}

fn shuffles(c: &mut Criterion) {
    c.bench(
        "whole list shuffle",
        Benchmark::new("8 elements", move |b| {
            let seed = vec![42; 32];
            let list = get_list(8);
            b.iter_with_setup(|| list.clone(), |list| black_box(shuffle(&seed, list)))
        }),
    );

    c.bench(
        "whole list shuffle",
        Benchmark::new("16 elements", move |b| {
            let seed = vec![42; 32];
            let list = get_list(16);
            b.iter_with_setup(|| list.clone(), |list| black_box(shuffle(&seed, list)))
        }),
    );

    c.bench(
        "whole list shuffle",
        Benchmark::new("512 elements", move |b| {
            let seed = vec![42; 32];
            let list = get_list(512);
            b.iter_with_setup(|| list.clone(), |list| black_box(shuffle(&seed, list)))
        })
        .sample_size(10),
    );

    c.bench(
        "whole list shuffle",
        Benchmark::new("16384 elements", move |b| {
            let seed = vec![42; 32];
            let list = get_list(16_384);
            b.iter_with_setup(|| list.clone(), |list| black_box(shuffle(&seed, list)))
        })
        .sample_size(10),
    );
}

criterion_group!(benches, shuffles);
criterion_main!(benches);

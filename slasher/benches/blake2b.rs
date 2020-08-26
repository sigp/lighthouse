use blake2b_simd::{Hash, Params};
use byte_slice_cast::AsByteSlice;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};

const CHUNK_SIZE: usize = 2048;
type Chunk = [u16; CHUNK_SIZE];

fn blake2b(data: &Chunk) -> Hash {
    let mut params = Params::new();
    params.hash_length(16);
    params.hash(data.as_byte_slice())
}

fn make_random_chunk() -> Chunk {
    let mut chunk = [0; CHUNK_SIZE];
    thread_rng().fill(&mut chunk[..]);
    chunk
}

pub fn uniform_chunk(c: &mut Criterion) {
    let chunk = [33; CHUNK_SIZE];
    c.bench_function("uniform_chunk", |b| b.iter(|| blake2b(&black_box(chunk))));
}

pub fn random_chunk(c: &mut Criterion) {
    let chunk = make_random_chunk();
    c.bench_function("random_chunk", |b| b.iter(|| blake2b(&black_box(chunk))));
}

criterion_group!(benches, uniform_chunk, random_chunk);
criterion_main!(benches);

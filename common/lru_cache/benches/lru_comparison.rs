//! Benchmarks comparing `lru` (old) vs `hashlink` (new) LruCache implementations.
//!
//! These benchmarks simulate the hot-path access patterns found in Lighthouse:
//!
//! 1. **Pre-finalization cache** (attestation verification): `contains_key` + `insert`
//!    - Hottest path: called on every attestation to an unknown block (~hundreds/sec)
//!    - Pattern: mostly `contains_key` hits with occasional `insert`
//!
//! 2. **Data availability checker overflow LRU**: `entry().or_insert_with()` + `get_mut` + `peek`
//!    - Called on every blob/data column received during block processing (Deneb+)
//!    - Pattern: `entry` API for upserts, `peek` for reads without promotion, `get_mut` for
//!      mutation
//!
//! 3. **State cache**: `get` + `peek` + `insert` with LRU eviction
//!    - Called on every block import and state access
//!    - Pattern: frequent `get` (promotes to front), occasional `insert` with eviction
//!
//! 4. **Block cache**: `get` + `insert` + `remove`
//!    - Called on block import and retrieval
//!    - Pattern: insert on import, get on retrieval, remove on finalization
//!
//! 5. **Payload ID cache**: `get` + `insert`
//!    - Called on every forkchoice update to EL (once per slot, latency-sensitive)
//!
//! 6. **Discovery ENR cache**: `insert` + `remove` + iteration
//!    - Called on peer discovery events

#![allow(dead_code)]

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::prelude::*;

// ── Wrappers to unify the API differences between `lru` and `hashlink` ──────

/// Wrapper around `lru::LruCache` (the old implementation).
struct OldLru<K: Eq + std::hash::Hash, V> {
    inner: lru::LruCache<K, V>,
}

impl<K: Eq + std::hash::Hash, V> OldLru<K, V> {
    fn new(cap: usize) -> Self {
        Self {
            inner: lru::LruCache::new(
                std::num::NonZeroUsize::new(cap).expect("capacity must be > 0"),
            ),
        }
    }

    #[inline]
    fn get(&mut self, k: &K) -> Option<&V> {
        self.inner.get(k)
    }

    #[inline]
    fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        self.inner.get_mut(k)
    }

    #[inline]
    fn peek(&self, k: &K) -> Option<&V> {
        self.inner.peek(k)
    }

    #[inline]
    fn insert(&mut self, k: K, v: V) -> Option<V> {
        self.inner.put(k, v)
    }

    #[inline]
    fn remove(&mut self, k: &K) -> Option<V> {
        self.inner.pop(k)
    }

    #[inline]
    fn contains_key(&self, k: &K) -> bool {
        self.inner.contains(k)
    }

    #[inline]
    fn get_or_insert_mut(&mut self, k: K, default: impl FnOnce() -> V) -> &mut V {
        self.inner.get_or_insert_mut(k, default)
    }

    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.inner.iter()
    }
}

/// Wrapper around `hashlink::lru_cache::LruCache` (the new implementation).
struct NewLru<K: Eq + std::hash::Hash, V> {
    inner: hashlink::lru_cache::LruCache<K, V>,
}

impl<K: Eq + std::hash::Hash, V> NewLru<K, V> {
    fn new(cap: usize) -> Self {
        Self {
            inner: hashlink::lru_cache::LruCache::new(cap),
        }
    }

    #[inline]
    fn get(&mut self, k: &K) -> Option<&V> {
        self.inner.get(k)
    }

    #[inline]
    fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        self.inner.get_mut(k)
    }

    #[inline]
    fn peek(&self, k: &K) -> Option<&V> {
        self.inner.peek(k)
    }

    #[inline]
    fn insert(&mut self, k: K, v: V) -> Option<V> {
        self.inner.insert(k, v)
    }

    #[inline]
    fn remove(&mut self, k: &K) -> Option<V> {
        self.inner.remove(k)
    }

    #[inline]
    fn contains_key(&self, k: &K) -> bool {
        self.inner.contains_key(k)
    }

    #[inline]
    fn get_or_insert_mut(&mut self, k: K, default: impl FnOnce() -> V) -> &mut V {
        self.inner.entry(k).or_insert_with(default)
    }

    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.inner.iter()
    }
}

// ── Key types to simulate real Lighthouse usage ─────────────────────────────

/// Simulates `Hash256` (32-byte block/state roots) used as keys in most caches.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FakeHash256([u8; 32]);

impl FakeHash256 {
    fn random(rng: &mut impl Rng) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// Simulates `(Epoch, Hash256)` tuples used as keys in the proposer cache.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct EpochBlockKey(u64, FakeHash256);

/// Simulates a medium-sized cached value (~256 bytes, like LightClientCachedData proofs).
#[derive(Clone)]
struct MediumValue {
    _data: [u8; 256],
}

impl MediumValue {
    fn new() -> Self {
        Self { _data: [0u8; 256] }
    }
}

/// Simulates a small cached value (like `()` used in pre-finalization cache).
type UnitValue = ();

// ── Helpers ─────────────────────────────────────────────────────────────────

fn generate_keys(n: usize, rng: &mut impl Rng) -> Vec<FakeHash256> {
    (0..n).map(|_| FakeHash256::random(rng)).collect()
}

fn prefill_old(cache: &mut OldLru<FakeHash256, UnitValue>, keys: &[FakeHash256]) {
    for k in keys {
        cache.insert(*k, ());
    }
}

fn prefill_new(cache: &mut NewLru<FakeHash256, UnitValue>, keys: &[FakeHash256]) {
    for k in keys {
        cache.insert(*k, ());
    }
}

// ── Benchmark 1: Pre-finalization cache pattern ─────────────────────────────
// Hottest path: attestation verification. Mostly `contains_key` with rare `insert`.
// Cache size: 512 block roots + 8 lookups.
// Pattern: 90% contains_key (hit), 5% contains_key (miss), 5% insert.

fn bench_pre_finalization_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("pre_finalization_cache");
    let cache_size: usize = 512;
    let ops_per_iter: usize = 1000;
    group.throughput(Throughput::Elements(ops_per_iter as u64));

    let mut rng = rand::rng();
    let known_keys = generate_keys(cache_size, &mut rng);
    let unknown_keys = generate_keys(ops_per_iter, &mut rng);

    // Pre-generate the operation sequence: 90% hit, 5% miss, 5% insert
    let ops: Vec<u8> = (0..ops_per_iter)
        .map(|_| {
            let r: f64 = rng.random();
            if r < 0.90 {
                0 // contains_key hit
            } else if r < 0.95 {
                1 // contains_key miss
            } else {
                2 // insert
            }
        })
        .collect();
    let hit_indices: Vec<usize> = (0..ops_per_iter)
        .map(|_| rng.random_range(0..cache_size))
        .collect();
    let miss_indices: Vec<usize> = (0..ops_per_iter)
        .map(|_| rng.random_range(0..ops_per_iter))
        .collect();

    group.bench_function(BenchmarkId::new("lru", cache_size), |b| {
        b.iter_batched(
            || {
                let mut cache = OldLru::new(cache_size);
                prefill_old(&mut cache, &known_keys);
                cache
            },
            |mut cache| {
                for i in 0..ops_per_iter {
                    match ops[i] {
                        0 => {
                            let _ = cache.contains_key(&known_keys[hit_indices[i]]);
                        }
                        1 => {
                            let _ = cache.contains_key(&unknown_keys[miss_indices[i]]);
                        }
                        _ => {
                            cache.insert(unknown_keys[i], ());
                        }
                    }
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function(BenchmarkId::new("hashlink", cache_size), |b| {
        b.iter_batched(
            || {
                let mut cache = NewLru::new(cache_size);
                prefill_new(&mut cache, &known_keys);
                cache
            },
            |mut cache| {
                for i in 0..ops_per_iter {
                    match ops[i] {
                        0 => {
                            let _ = cache.contains_key(&known_keys[hit_indices[i]]);
                        }
                        1 => {
                            let _ = cache.contains_key(&unknown_keys[miss_indices[i]]);
                        }
                        _ => {
                            cache.insert(unknown_keys[i], ());
                        }
                    }
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ── Benchmark 2: Data availability checker pattern ──────────────────────────
// entry().or_insert_with() + peek + get_mut — blob/column processing.
// Cache size: 32, values are medium-sized (pending components).
// Pattern: 40% entry-or-insert, 30% peek, 20% get_mut, 10% remove.

fn bench_data_availability_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_availability_cache");
    let cache_size: usize = 32;
    let ops_per_iter: usize = 500;
    group.throughput(Throughput::Elements(ops_per_iter as u64));

    let mut rng = rand::rng();
    let keys = generate_keys(cache_size * 2, &mut rng);

    let ops: Vec<u8> = (0..ops_per_iter)
        .map(|_| {
            let r: f64 = rng.random();
            if r < 0.40 {
                0 // entry or_insert
            } else if r < 0.70 {
                1 // peek
            } else if r < 0.90 {
                2 // get_mut
            } else {
                3 // remove
            }
        })
        .collect();
    let key_indices: Vec<usize> = (0..ops_per_iter)
        .map(|_| rng.random_range(0..cache_size * 2))
        .collect();

    group.bench_function(BenchmarkId::new("lru", cache_size), |b| {
        b.iter_batched(
            || {
                let mut cache = OldLru::<FakeHash256, MediumValue>::new(cache_size);
                for k in &keys[..cache_size] {
                    cache.insert(*k, MediumValue::new());
                }
                cache
            },
            |mut cache| {
                for i in 0..ops_per_iter {
                    let key = &keys[key_indices[i]];
                    match ops[i] {
                        0 => {
                            let _ = cache.get_or_insert_mut(*key, MediumValue::new);
                        }
                        1 => {
                            let _ = cache.peek(key);
                        }
                        2 => {
                            let _ = cache.get_mut(key);
                        }
                        _ => {
                            let _ = cache.remove(key);
                        }
                    }
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function(BenchmarkId::new("hashlink", cache_size), |b| {
        b.iter_batched(
            || {
                let mut cache = NewLru::<FakeHash256, MediumValue>::new(cache_size);
                for k in &keys[..cache_size] {
                    cache.insert(*k, MediumValue::new());
                }
                cache
            },
            |mut cache| {
                for i in 0..ops_per_iter {
                    let key = &keys[key_indices[i]];
                    match ops[i] {
                        0 => {
                            let _ = cache.get_or_insert_mut(*key, MediumValue::new);
                        }
                        1 => {
                            let _ = cache.peek(key);
                        }
                        2 => {
                            let _ = cache.get_mut(key);
                        }
                        _ => {
                            let _ = cache.remove(key);
                        }
                    }
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ── Benchmark 3: State cache pattern ────────────────────────────────────────
// get + peek + insert with eviction. Block import and state access.
// Cache size: 128, values are a stand-in for large BeaconState (~1KB placeholder).
// Pattern: 50% get (promotes), 20% peek (no promote), 20% insert (with eviction), 10% remove.

fn bench_state_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_cache");

    for cache_size in [64, 128, 256] {
        let ops_per_iter: usize = 1000;
        group.throughput(Throughput::Elements(ops_per_iter as u64));

        let mut rng = rand::rng();
        // Generate more keys than the cache can hold to trigger evictions.
        let total_keys = cache_size * 3;
        let keys = generate_keys(total_keys, &mut rng);

        let ops: Vec<u8> = (0..ops_per_iter)
            .map(|_| {
                let r: f64 = rng.random();
                if r < 0.50 {
                    0 // get (hit)
                } else if r < 0.70 {
                    1 // peek
                } else if r < 0.90 {
                    2 // insert (may evict)
                } else {
                    3 // remove
                }
            })
            .collect();

        // Indices for hits target the first `cache_size` keys (which are pre-filled).
        let hit_indices: Vec<usize> = (0..ops_per_iter)
            .map(|_| rng.random_range(0..cache_size))
            .collect();
        // Indices for inserts target all keys (some new, some existing).
        let insert_indices: Vec<usize> = (0..ops_per_iter)
            .map(|_| rng.random_range(0..total_keys))
            .collect();

        // Use a Box<[u8; 1024]> as a stand-in for a large value like BeaconState.
        type LargeValue = Box<[u8; 1024]>;
        fn make_large_value() -> LargeValue {
            Box::new([0u8; 1024])
        }

        group.bench_function(BenchmarkId::new("lru", cache_size), |b| {
            b.iter_batched(
                || {
                    let mut cache = OldLru::<FakeHash256, LargeValue>::new(cache_size);
                    for k in &keys[..cache_size] {
                        cache.insert(*k, make_large_value());
                    }
                    cache
                },
                |mut cache| {
                    for i in 0..ops_per_iter {
                        match ops[i] {
                            0 => {
                                let _ = cache.get(&keys[hit_indices[i]]);
                            }
                            1 => {
                                let _ = cache.peek(&keys[hit_indices[i]]);
                            }
                            2 => {
                                cache.insert(keys[insert_indices[i]], make_large_value());
                            }
                            _ => {
                                let _ = cache.remove(&keys[hit_indices[i]]);
                            }
                        }
                    }
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(BenchmarkId::new("hashlink", cache_size), |b| {
            b.iter_batched(
                || {
                    let mut cache = NewLru::<FakeHash256, LargeValue>::new(cache_size);
                    for k in &keys[..cache_size] {
                        cache.insert(*k, make_large_value());
                    }
                    cache
                },
                |mut cache| {
                    for i in 0..ops_per_iter {
                        match ops[i] {
                            0 => {
                                let _ = cache.get(&keys[hit_indices[i]]);
                            }
                            1 => {
                                let _ = cache.peek(&keys[hit_indices[i]]);
                            }
                            2 => {
                                cache.insert(keys[insert_indices[i]], make_large_value());
                            }
                            _ => {
                                let _ = cache.remove(&keys[hit_indices[i]]);
                            }
                        }
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// ── Benchmark 4: Block cache pattern ────────────────────────────────────────
// get + insert + remove — block import and retrieval.
// Cache size: 64 (typical), with steady-state insert/get/remove.
// Pattern: 40% get, 40% insert, 20% remove.

fn bench_block_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_cache");
    let cache_size: usize = 64;
    let ops_per_iter: usize = 1000;
    group.throughput(Throughput::Elements(ops_per_iter as u64));

    let mut rng = rand::rng();
    let total_keys = cache_size * 2;
    let keys = generate_keys(total_keys, &mut rng);

    let ops: Vec<u8> = (0..ops_per_iter)
        .map(|_| {
            let r: f64 = rng.random();
            if r < 0.40 {
                0 // get
            } else if r < 0.80 {
                1 // insert
            } else {
                2 // remove
            }
        })
        .collect();
    let key_indices: Vec<usize> = (0..ops_per_iter)
        .map(|_| rng.random_range(0..total_keys))
        .collect();

    group.bench_function(BenchmarkId::new("lru", cache_size), |b| {
        b.iter_batched(
            || {
                let mut cache = OldLru::<FakeHash256, MediumValue>::new(cache_size);
                for k in &keys[..cache_size] {
                    cache.insert(*k, MediumValue::new());
                }
                cache
            },
            |mut cache| {
                for i in 0..ops_per_iter {
                    let key = &keys[key_indices[i]];
                    match ops[i] {
                        0 => {
                            let _ = cache.get(key);
                        }
                        1 => {
                            cache.insert(*key, MediumValue::new());
                        }
                        _ => {
                            let _ = cache.remove(key);
                        }
                    }
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function(BenchmarkId::new("hashlink", cache_size), |b| {
        b.iter_batched(
            || {
                let mut cache = NewLru::<FakeHash256, MediumValue>::new(cache_size);
                for k in &keys[..cache_size] {
                    cache.insert(*k, MediumValue::new());
                }
                cache
            },
            |mut cache| {
                for i in 0..ops_per_iter {
                    let key = &keys[key_indices[i]];
                    match ops[i] {
                        0 => {
                            let _ = cache.get(key);
                        }
                        1 => {
                            cache.insert(*key, MediumValue::new());
                        }
                        _ => {
                            let _ = cache.remove(key);
                        }
                    }
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ── Benchmark 5: Payload ID cache pattern ───────────────────────────────────
// get + insert — forkchoice updates. Latency-sensitive, once per slot.
// Cache size: 512, small values (~64 bytes payload ID).
// Pattern: 60% get, 40% insert. Mostly hits (recent payload IDs reused).

fn bench_payload_id_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("payload_id_cache");
    let cache_size: usize = 512;
    let ops_per_iter: usize = 1000;
    group.throughput(Throughput::Elements(ops_per_iter as u64));

    let mut rng = rand::rng();
    let keys: Vec<EpochBlockKey> = (0..cache_size)
        .map(|_| EpochBlockKey(rng.random_range(0..100), FakeHash256::random(&mut rng)))
        .collect();
    let extra_keys: Vec<EpochBlockKey> = (0..256)
        .map(|_| EpochBlockKey(rng.random_range(0..100), FakeHash256::random(&mut rng)))
        .collect();

    #[derive(Clone, Copy)]
    struct PayloadId([u8; 8]);
    impl PayloadId {
        fn new() -> Self {
            Self([0xAB; 8])
        }
    }

    let ops: Vec<u8> = (0..ops_per_iter)
        .map(|_| if rng.random::<f64>() < 0.60 { 0 } else { 1 })
        .collect();
    let hit_indices: Vec<usize> = (0..ops_per_iter)
        .map(|_| rng.random_range(0..cache_size))
        .collect();
    let insert_indices: Vec<usize> = (0..ops_per_iter)
        .map(|_| rng.random_range(0..extra_keys.len()))
        .collect();

    group.bench_function(BenchmarkId::new("lru", cache_size), |b| {
        b.iter_batched(
            || {
                let mut cache = OldLru::<EpochBlockKey, PayloadId>::new(cache_size);
                for k in &keys {
                    cache.insert(*k, PayloadId::new());
                }
                cache
            },
            |mut cache| {
                for i in 0..ops_per_iter {
                    match ops[i] {
                        0 => {
                            let _ = cache.get(&keys[hit_indices[i]]);
                        }
                        _ => {
                            cache.insert(extra_keys[insert_indices[i]], PayloadId::new());
                        }
                    }
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function(BenchmarkId::new("hashlink", cache_size), |b| {
        b.iter_batched(
            || {
                let mut cache = NewLru::<EpochBlockKey, PayloadId>::new(cache_size);
                for k in &keys {
                    cache.insert(*k, PayloadId::new());
                }
                cache
            },
            |mut cache| {
                for i in 0..ops_per_iter {
                    match ops[i] {
                        0 => {
                            let _ = cache.get(&keys[hit_indices[i]]);
                        }
                        _ => {
                            cache.insert(extra_keys[insert_indices[i]], PayloadId::new());
                        }
                    }
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ── Benchmark 6: Discovery ENR cache pattern ────────────────────────────────
// insert + remove + iteration — peer discovery.
// Cache size: 50, with churn (peers discovered and disconnected).
// Pattern: 40% insert, 20% remove, 20% get, 20% iteration.

fn bench_discovery_enr_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("discovery_enr_cache");
    let cache_size: usize = 50;
    let ops_per_iter: usize = 500;
    group.throughput(Throughput::Elements(ops_per_iter as u64));

    let mut rng = rand::rng();
    let total_keys = cache_size * 3;
    let keys = generate_keys(total_keys, &mut rng);

    let ops: Vec<u8> = (0..ops_per_iter)
        .map(|_| {
            let r: f64 = rng.random();
            if r < 0.40 {
                0 // insert
            } else if r < 0.60 {
                1 // remove
            } else if r < 0.80 {
                2 // get
            } else {
                3 // iterate
            }
        })
        .collect();
    let key_indices: Vec<usize> = (0..ops_per_iter)
        .map(|_| rng.random_range(0..total_keys))
        .collect();

    group.bench_function(BenchmarkId::new("lru", cache_size), |b| {
        b.iter_batched(
            || {
                let mut cache = OldLru::<FakeHash256, MediumValue>::new(cache_size);
                for k in &keys[..cache_size] {
                    cache.insert(*k, MediumValue::new());
                }
                cache
            },
            |mut cache| {
                for i in 0..ops_per_iter {
                    let key = &keys[key_indices[i]];
                    match ops[i] {
                        0 => {
                            cache.insert(*key, MediumValue::new());
                        }
                        1 => {
                            let _ = cache.remove(key);
                        }
                        2 => {
                            let _ = cache.get(key);
                        }
                        _ => {
                            // Iteration pattern: count matching entries (simulates ENR filtering)
                            let _ = cache.iter().count();
                        }
                    }
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function(BenchmarkId::new("hashlink", cache_size), |b| {
        b.iter_batched(
            || {
                let mut cache = NewLru::<FakeHash256, MediumValue>::new(cache_size);
                for k in &keys[..cache_size] {
                    cache.insert(*k, MediumValue::new());
                }
                cache
            },
            |mut cache| {
                for i in 0..ops_per_iter {
                    let key = &keys[key_indices[i]];
                    match ops[i] {
                        0 => {
                            cache.insert(*key, MediumValue::new());
                        }
                        1 => {
                            let _ = cache.remove(key);
                        }
                        2 => {
                            let _ = cache.get(key);
                        }
                        _ => {
                            let _ = cache.iter().count();
                        }
                    }
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ── Benchmark 7: Isolated operation microbenchmarks ─────────────────────────
// Pure get, insert, contains_key, and remove to measure per-op overhead.

fn bench_isolated_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("isolated_ops");

    for cache_size in [32, 128, 512] {
        let mut rng = rand::rng();
        let keys = generate_keys(cache_size, &mut rng);
        let extra_key = FakeHash256::random(&mut rng);

        // -- get (hit) --
        group.bench_function(BenchmarkId::new("lru/get_hit", cache_size), |b| {
            b.iter_batched(
                || {
                    let mut cache = OldLru::<FakeHash256, UnitValue>::new(cache_size);
                    prefill_old(&mut cache, &keys);
                    cache
                },
                |mut cache| {
                    for k in &keys {
                        let _ = cache.get(k);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(BenchmarkId::new("hashlink/get_hit", cache_size), |b| {
            b.iter_batched(
                || {
                    let mut cache = NewLru::<FakeHash256, UnitValue>::new(cache_size);
                    prefill_new(&mut cache, &keys);
                    cache
                },
                |mut cache| {
                    for k in &keys {
                        let _ = cache.get(k);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        // -- get (miss) --
        group.bench_function(BenchmarkId::new("lru/get_miss", cache_size), |b| {
            b.iter_batched(
                || {
                    let mut cache = OldLru::<FakeHash256, UnitValue>::new(cache_size);
                    prefill_old(&mut cache, &keys);
                    cache
                },
                |mut cache| {
                    for _ in 0..cache_size {
                        let _ = cache.get(&extra_key);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(BenchmarkId::new("hashlink/get_miss", cache_size), |b| {
            b.iter_batched(
                || {
                    let mut cache = NewLru::<FakeHash256, UnitValue>::new(cache_size);
                    prefill_new(&mut cache, &keys);
                    cache
                },
                |mut cache| {
                    for _ in 0..cache_size {
                        let _ = cache.get(&extra_key);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        // -- contains_key --
        group.bench_function(BenchmarkId::new("lru/contains_key", cache_size), |b| {
            b.iter_batched(
                || {
                    let mut cache = OldLru::<FakeHash256, UnitValue>::new(cache_size);
                    prefill_old(&mut cache, &keys);
                    cache
                },
                |cache| {
                    for k in &keys {
                        let _ = cache.contains_key(k);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(BenchmarkId::new("hashlink/contains_key", cache_size), |b| {
            b.iter_batched(
                || {
                    let mut cache = NewLru::<FakeHash256, UnitValue>::new(cache_size);
                    prefill_new(&mut cache, &keys);
                    cache
                },
                |cache| {
                    for k in &keys {
                        let _ = cache.contains_key(k);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        // -- insert (evicting) --
        group.bench_function(BenchmarkId::new("lru/insert_evict", cache_size), |b| {
            let evict_keys = generate_keys(cache_size, &mut rng);
            b.iter_batched(
                || {
                    let mut cache = OldLru::<FakeHash256, UnitValue>::new(cache_size);
                    prefill_old(&mut cache, &keys);
                    cache
                },
                |mut cache| {
                    for k in &evict_keys {
                        cache.insert(*k, ());
                    }
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(BenchmarkId::new("hashlink/insert_evict", cache_size), |b| {
            let evict_keys = generate_keys(cache_size, &mut rng);
            b.iter_batched(
                || {
                    let mut cache = NewLru::<FakeHash256, UnitValue>::new(cache_size);
                    prefill_new(&mut cache, &keys);
                    cache
                },
                |mut cache| {
                    for k in &evict_keys {
                        cache.insert(*k, ());
                    }
                },
                BatchSize::SmallInput,
            );
        });

        // -- peek (no promotion) --
        group.bench_function(BenchmarkId::new("lru/peek", cache_size), |b| {
            b.iter_batched(
                || {
                    let mut cache = OldLru::<FakeHash256, UnitValue>::new(cache_size);
                    prefill_old(&mut cache, &keys);
                    cache
                },
                |cache| {
                    for k in &keys {
                        let _ = cache.peek(k);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(BenchmarkId::new("hashlink/peek", cache_size), |b| {
            b.iter_batched(
                || {
                    let mut cache = NewLru::<FakeHash256, UnitValue>::new(cache_size);
                    prefill_new(&mut cache, &keys);
                    cache
                },
                |cache| {
                    for k in &keys {
                        let _ = cache.peek(k);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        // -- remove --
        group.bench_function(BenchmarkId::new("lru/remove", cache_size), |b| {
            b.iter_batched(
                || {
                    let mut cache = OldLru::<FakeHash256, UnitValue>::new(cache_size);
                    prefill_old(&mut cache, &keys);
                    cache
                },
                |mut cache| {
                    for k in &keys {
                        let _ = cache.remove(k);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(BenchmarkId::new("hashlink/remove", cache_size), |b| {
            b.iter_batched(
                || {
                    let mut cache = NewLru::<FakeHash256, UnitValue>::new(cache_size);
                    prefill_new(&mut cache, &keys);
                    cache
                },
                |mut cache| {
                    for k in &keys {
                        let _ = cache.remove(k);
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_pre_finalization_cache,
    bench_data_availability_cache,
    bench_state_cache,
    bench_block_cache,
    bench_payload_id_cache,
    bench_discovery_enr_cache,
    bench_isolated_ops,
);
criterion_main!(benches);

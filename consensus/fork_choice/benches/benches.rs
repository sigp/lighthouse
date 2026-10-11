use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fork_choice::{QueuedAttestation, dequeue_attestations};
use std::collections::BTreeMap;
use types::{Epoch, Hash256, Slot};

fn att(slot: Slot) -> QueuedAttestation {
    QueuedAttestation {
        slot,
        attesting_indices: vec![],
        block_root: Hash256::ZERO,
        target_epoch: Epoch::new(0),
        payload_present: false,
    }
}

// Anticipated steady-state workload on mainnet: ~94k attestations spread over a small number of slots, then
// many iterations of dequeue (one slot's worth) + enqueue (one slot's worth for a future slot).
// The queue stays at a constant size, exercising the per-slot dequeue cost.
const NUM_ATTESTATIONS: usize = 1_500_000 / 16;
const UNIQUE_SLOTS: usize = 2;
const NUM_ITERATIONS: usize = 64;
const PER_SLOT: usize = NUM_ATTESTATIONS / UNIQUE_SLOTS;

fn build_queue() -> BTreeMap<Slot, Vec<QueuedAttestation>> {
    let mut queue: BTreeMap<Slot, Vec<QueuedAttestation>> = BTreeMap::new();
    for i in 0..NUM_ATTESTATIONS {
        let slot = Slot::from(i / PER_SLOT);
        queue.entry(slot).or_default().push(att(slot));
    }
    queue
}

fn all_benches(c: &mut Criterion) {
    let initial = build_queue();

    c.bench_with_input(
        BenchmarkId::new("dequeue_attestations", NUM_ATTESTATIONS),
        &initial,
        |b, initial| {
            b.iter(|| {
                let mut queue = initial.clone();
                for i in 1..=NUM_ITERATIONS {
                    let dequeued = dequeue_attestations(Slot::from(i), &mut queue);
                    let dequeued_count: usize = dequeued.values().map(Vec::len).sum();
                    assert_eq!(dequeued_count, PER_SLOT);

                    let next_slot = Slot::from(UNIQUE_SLOTS + i - 1);
                    queue
                        .entry(next_slot)
                        .or_default()
                        .extend(std::iter::repeat_with(|| att(next_slot)).take(PER_SLOT));

                    let total: usize = queue.values().map(Vec::len).sum();
                    assert_eq!(total, NUM_ATTESTATIONS);
                }
            })
        },
    );
}

criterion_group!(benches, all_benches);
criterion_main!(benches);

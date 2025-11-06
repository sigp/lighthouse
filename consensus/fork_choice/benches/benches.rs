use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use fork_choice::{QueuedAttestation, dequeue_attestations};
use std::collections::VecDeque;
use types::{Epoch, Hash256, Slot};

fn all_benches(c: &mut Criterion) {
    let num_attestations = 1_500_000_usize / 16;
    let unique_slots = 2_usize;
    let attestations_per_slot = num_attestations / unique_slots;
    let queued_attestations = (0..num_attestations)
        .map(|i| QueuedAttestation {
            slot: Slot::from(i / attestations_per_slot),
            attesting_indices: vec![],
            block_root: Hash256::ZERO,
            target_epoch: Epoch::new(0),
        })
        .collect::<VecDeque<_>>();

    let current_slot = Slot::from(unique_slots) - 1;

    c.bench_with_input(
        BenchmarkId::new("dequeue_attestations", num_attestations),
        &queued_attestations,
        |b, attestations| {
            b.iter(|| {
                let mut attestations = attestations.clone();
                let dequeued = dequeue_attestations(current_slot, &mut attestations);
                assert_eq!(dequeued.len(), num_attestations - attestations_per_slot);
                black_box(dequeued);
            })
        },
    );
}

criterion_group!(benches, all_benches);
criterion_main!(benches);

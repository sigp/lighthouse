use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fork_choice::{QueuedAttestation, dequeue_attestations};
use std::collections::VecDeque;
use types::{Epoch, Hash256, Slot};

fn all_benches(c: &mut Criterion) {
    let num_attestations = 1_500_000_usize / 16;
    let unique_slots = 2_usize;
    let num_iterations = 64;
    let attestations_per_slot = num_attestations / unique_slots;
    let queued_attestations = (0..num_attestations)
        .map(|i| QueuedAttestation {
            slot: Slot::from(i / attestations_per_slot),
            attesting_indices: vec![],
            block_root: Hash256::ZERO,
            target_epoch: Epoch::new(0),
        })
        .collect::<VecDeque<_>>();

    c.bench_with_input(
        BenchmarkId::new("dequeue_attestations", num_attestations),
        &queued_attestations,
        |b, attestations| {
            b.iter(|| {
                // Simulate dequeueing and queuing of attestations over multiple slots.
                let mut attestations = attestations.clone();
                let end_slot = unique_slots;
                for i in 1..=num_iterations {
                    let dequeued = dequeue_attestations(Slot::from(i), &mut attestations);
                    assert_eq!(dequeued.len(), attestations_per_slot);

                    // Capacity should be unchanged.
                    assert_eq!(attestations.capacity(), num_attestations);

                    let next_slot = end_slot + i - 1;
                    let new_attestations = std::iter::repeat(QueuedAttestation {
                        slot: Slot::from(next_slot),
                        attesting_indices: vec![],
                        block_root: Hash256::ZERO,
                        target_epoch: Epoch::new(0),
                    })
                    .take(attestations_per_slot);

                    for attestation in new_attestations {
                        attestations.push_back(attestation);
                    }

                    assert_eq!(attestations.len(), num_attestations);
                }
            })
        },
    );
}

criterion_group!(benches, all_benches);
criterion_main!(benches);

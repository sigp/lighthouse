use slog::Logger;
use sloggers::Build;
use types::{
    AggregateSignature, AttestationData, AttesterSlashing, Checkpoint, Epoch, Hash256,
    IndexedAttestation, MainnetEthSpec, Slot,
};

pub type E = MainnetEthSpec;

pub fn logger() -> Logger {
    if cfg!(feature = "test_logger") {
        sloggers::terminal::TerminalLoggerBuilder::new()
            .level(sloggers::types::Severity::Trace)
            .build()
            .unwrap()
    } else {
        sloggers::null::NullLoggerBuilder.build().unwrap()
    }
}

pub fn indexed_att(
    attesting_indices: impl AsRef<[u64]>,
    source_epoch: u64,
    target_epoch: u64,
    target_root: u64,
) -> IndexedAttestation<E> {
    IndexedAttestation {
        attesting_indices: attesting_indices.as_ref().to_vec().into(),
        data: AttestationData {
            slot: Slot::new(0),
            index: 0,
            beacon_block_root: Hash256::zero(),
            source: Checkpoint {
                epoch: Epoch::new(source_epoch),
                root: Hash256::from_low_u64_be(0),
            },
            target: Checkpoint {
                epoch: Epoch::new(target_epoch),
                root: Hash256::from_low_u64_be(target_root),
            },
        },
        signature: AggregateSignature::empty(),
    }
}

pub fn att_slashing(
    attestation_1: &IndexedAttestation<E>,
    attestation_2: &IndexedAttestation<E>,
) -> AttesterSlashing<E> {
    AttesterSlashing {
        attestation_1: attestation_1.clone(),
        attestation_2: attestation_2.clone(),
    }
}

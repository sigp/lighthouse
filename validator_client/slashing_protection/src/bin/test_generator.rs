use slashing_protection::interchange::{
    Interchange, InterchangeData, InterchangeMetadata, SignedAttestation, SignedBlock,
};
use slashing_protection::interchange_test::TestCase;
use slashing_protection::test_utils::{pubkey, DEFAULT_GENESIS_VALIDATORS_ROOT};
use slashing_protection::SUPPORTED_INTERCHANGE_FORMAT_VERSION;
use std::fs::{self, File};
use std::path::Path;
use types::{Epoch, Hash256, Slot};

fn metadata(genesis_validators_root: Hash256) -> InterchangeMetadata {
    InterchangeMetadata {
        interchange_format_version: SUPPORTED_INTERCHANGE_FORMAT_VERSION,
        genesis_validators_root,
    }
}

type TestPubkey = usize;
type TestBlocks = Vec<u64>;
type TestBlocksWithRoots = Vec<(u64, Option<u64>)>;
type TestAttestations = Vec<(u64, u64)>;
type TestAttestationsWithRoots = Vec<(u64, u64, Option<u64>)>;

fn interchange(data: Vec<(TestPubkey, TestBlocks, TestAttestations)>) -> Interchange {
    let data = data
        .into_iter()
        .map(|(pk, blocks, attestations)| {
            (
                pk,
                blocks.into_iter().map(|slot| (slot, None)).collect(),
                attestations
                    .into_iter()
                    .map(|(source, target)| (source, target, None))
                    .collect(),
            )
        })
        .collect();
    interchange_with_signing_roots(data)
}

fn interchange_with_signing_roots(
    data: Vec<(TestPubkey, TestBlocksWithRoots, TestAttestationsWithRoots)>,
) -> Interchange {
    let data = data
        .into_iter()
        .map(|(pk, blocks, attestations)| InterchangeData {
            pubkey: pubkey(pk),
            signed_blocks: blocks
                .into_iter()
                .map(|(slot, signing_root)| SignedBlock {
                    slot: Slot::new(slot),
                    signing_root: signing_root.map(Hash256::from_low_u64_be),
                })
                .collect(),
            signed_attestations: attestations
                .into_iter()
                .map(|(source, target, signing_root)| SignedAttestation {
                    source_epoch: Epoch::new(source),
                    target_epoch: Epoch::new(target),
                    signing_root: signing_root.map(Hash256::from_low_u64_be),
                })
                .collect(),
        })
        .collect();
    Interchange {
        metadata: metadata(DEFAULT_GENESIS_VALIDATORS_ROOT),
        data,
    }
}

fn main() {
    let single_validator_blocks =
        vec![(0, 32, false), (0, 33, true), (0, 31, false), (0, 1, false)];
    let single_validator_attestations = vec![
        (0, 3, 4, false),
        (0, 14, 19, false),
        (0, 15, 20, false),
        (0, 16, 20, false),
        (0, 15, 21, true),
    ];

    let tests = vec![
        TestCase::new(
            "single_validator_import_only",
            interchange(vec![(0, vec![22], vec![(0, 2)])]),
        ),
        TestCase::new(
            "single_validator_single_block",
            interchange(vec![(0, vec![32], vec![])]),
        )
        .with_blocks(single_validator_blocks.clone()),
        TestCase::new(
            "single_validator_single_attestation",
            interchange(vec![(0, vec![], vec![(15, 20)])]),
        )
        .with_attestations(single_validator_attestations.clone()),
        TestCase::new(
            "single_validator_single_block_and_attestation",
            interchange(vec![(0, vec![32], vec![(15, 20)])]),
        )
        .with_blocks(single_validator_blocks)
        .with_attestations(single_validator_attestations),
        TestCase::new(
            "single_validator_genesis_attestation",
            interchange(vec![(0, vec![], vec![(0, 0)])]),
        )
        .with_attestations(vec![(0, 0, 0, false)]),
        TestCase::new(
            "single_validator_multiple_blocks_and_attestations",
            interchange(vec![(
                0,
                vec![2, 3, 10, 1200],
                vec![(10, 11), (12, 13), (20, 24)],
            )]),
        )
        .with_blocks(vec![
            (0, 1, false),
            (0, 2, false),
            (0, 3, false),
            (0, 10, false),
            (0, 1200, false),
            (0, 4, true),
            (0, 256, true),
            (0, 1201, true),
        ])
        .with_attestations(vec![
            (0, 9, 10, false),
            (0, 12, 13, false),
            (0, 11, 14, false),
            (0, 21, 22, false),
            (0, 10, 24, false),
            (0, 11, 12, true),
            (0, 20, 25, true),
        ]),
        TestCase::new(
            "single_validator_single_block_and_attestation_signing_root",
            interchange_with_signing_roots(vec![(0, vec![(19, Some(1))], vec![(0, 1, Some(2))])]),
        ),
        TestCase::new(
            "multiple_validators_multiple_blocks_and_attestations",
            interchange(vec![
                (
                    0,
                    vec![10, 15, 20],
                    vec![(0, 1), (0, 2), (1, 3), (2, 4), (4, 5)],
                ),
                (
                    1,
                    vec![3, 4, 100],
                    vec![(0, 0), (0, 1), (1, 2), (2, 5), (5, 6)],
                ),
                (2, vec![10, 15, 20], vec![(1, 2), (1, 3), (2, 4)]),
            ]),
        )
        .with_blocks(vec![
            (0, 9, false),
            (0, 10, false),
            (0, 21, true),
            (0, 11, true),
            (1, 2, false),
            (1, 3, false),
            (1, 0, false),
            (1, 101, true),
            (2, 9, false),
            (2, 10, false),
            (2, 22, true),
        ])
        .with_attestations(vec![
            (0, 0, 5, false),
            (0, 3, 6, false),
            (0, 4, 6, true),
            (0, 5, 7, true),
            (0, 6, 8, true),
            (1, 1, 7, false),
            (1, 1, 4, true),
            (1, 5, 7, true),
            (2, 0, 0, false),
            (2, 0, 1, false),
            (2, 2, 5, true),
        ]),
        TestCase::new("wrong_genesis_validators_root", interchange(vec![]))
            .gvr(Hash256::from_low_u64_be(1))
            .should_fail(),
    ];

    let args = std::env::args().collect::<Vec<_>>();
    let output_dir = Path::new(&args[1]);
    fs::create_dir_all(output_dir).unwrap();

    for test in tests {
        test.run();
        let f = File::create(output_dir.join(format!("{}.json", test.name))).unwrap();
        serde_json::to_writer(f, &test).unwrap();
    }
}

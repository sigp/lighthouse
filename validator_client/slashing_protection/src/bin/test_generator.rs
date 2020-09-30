use slashing_protection::interchange::{
    CompleteInterchangeData, Interchange, InterchangeFormat, InterchangeMetadata,
    SignedAttestation, SignedBlock,
};
use slashing_protection::interchange_test::TestCase;
use slashing_protection::test_utils::{pubkey, DEFAULT_GENESIS_VALIDATORS_ROOT};
use slashing_protection::SUPPORTED_INTERCHANGE_FORMAT_VERSION;
use std::fs::{self, File};
use std::path::Path;
use types::{Epoch, Hash256, Slot};

fn metadata(genesis_validators_root: Hash256) -> InterchangeMetadata {
    InterchangeMetadata {
        interchange_format: InterchangeFormat::Complete,
        interchange_format_version: SUPPORTED_INTERCHANGE_FORMAT_VERSION,
        genesis_validators_root,
    }
}

fn interchange(data: Vec<(usize, Vec<u64>, Vec<(u64, u64)>)>) -> Interchange {
    let data = data
        .into_iter()
        .map(|(pk, blocks, attestations)| CompleteInterchangeData {
            pubkey: pubkey(pk),
            signed_blocks: blocks
                .into_iter()
                .map(|slot| SignedBlock {
                    slot: Slot::new(slot),
                    signing_root: None,
                })
                .collect(),
            signed_attestations: attestations
                .into_iter()
                .map(|(source, target)| SignedAttestation {
                    source_epoch: Epoch::new(source),
                    target_epoch: Epoch::new(target),
                    signing_root: None,
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
        .with_blocks(single_validator_blocks.clone())
        .with_attestations(single_validator_attestations.clone()),
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
        TestCase::new("wrong_genesis_validators_root", interchange(vec![]))
            .gvr(Hash256::from_low_u64_be(1))
            .should_fail(),
    ];
    // TODO: multi-validator test

    let args = std::env::args().collect::<Vec<_>>();
    let output_dir = Path::new(&args[1]);
    fs::create_dir_all(output_dir).unwrap();

    for test in tests {
        test.run();
        let f = File::create(output_dir.join(format!("{}.json", test.name))).unwrap();
        serde_json::to_writer(f, &test).unwrap();
    }
}

use slashing_protection::interchange::{
    Interchange, InterchangeData, InterchangeMetadata, SignedAttestation, SignedBlock,
};
use slashing_protection::interchange_test::{MultiTestCase, TestCase};
use slashing_protection::test_utils::{pubkey, DEFAULT_GENESIS_VALIDATORS_ROOT};
use slashing_protection::SUPPORTED_INTERCHANGE_FORMAT_VERSION;
use std::fs::{self, File};
use std::io::Write;
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
        MultiTestCase::single(
            "single_validator_import_only",
            TestCase::new(interchange(vec![(0, vec![22], vec![(0, 2)])])),
        ),
        MultiTestCase::single(
            "single_validator_single_block",
            TestCase::new(interchange(vec![(0, vec![32], vec![])]))
                .with_blocks(single_validator_blocks.clone()),
        ),
        MultiTestCase::single(
            "single_validator_single_attestation",
            TestCase::new(interchange(vec![(0, vec![], vec![(15, 20)])]))
                .with_attestations(single_validator_attestations.clone()),
        ),
        MultiTestCase::single(
            "single_validator_single_block_and_attestation",
            TestCase::new(interchange(vec![(0, vec![32], vec![(15, 20)])]))
                .with_blocks(single_validator_blocks)
                .with_attestations(single_validator_attestations),
        ),
        MultiTestCase::single(
            "single_validator_genesis_attestation",
            TestCase::new(interchange(vec![(0, vec![], vec![(0, 0)])]))
                .with_attestations(vec![(0, 0, 0, false)]),
        ),
        MultiTestCase::single(
            "single_validator_multiple_blocks_and_attestations",
            TestCase::new(interchange(vec![(
                0,
                vec![2, 3, 10, 1200],
                vec![(10, 11), (12, 13), (20, 24)],
            )]))
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
        ),
        MultiTestCase::single(
            "single_validator_single_block_and_attestation_signing_root",
            TestCase::new(interchange_with_signing_roots(vec![(
                0,
                vec![(19, Some(1))],
                vec![(0, 1, Some(2))],
            )])),
        ),
        MultiTestCase::single(
            "multiple_validators_multiple_blocks_and_attestations",
            TestCase::new(interchange(vec![
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
            ]))
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
        ),
        MultiTestCase::single(
            "multiple_validators_same_slot_blocks",
            TestCase::new(interchange_with_signing_roots(vec![
                (0, vec![(1, Some(0)), (2, Some(0)), (3, Some(0))], vec![]),
                (1, vec![(1, Some(1)), (3, Some(1))], vec![]),
                (2, vec![(1, Some(2)), (2, Some(2))], vec![]),
            ])),
        ),
        MultiTestCase::single(
            "wrong_genesis_validators_root",
            TestCase::new(interchange(vec![])).should_fail(),
        )
        .gvr(Hash256::from_low_u64_be(1)),
        MultiTestCase::new(
            "multiple_interchanges_single_validator_single_message_gap",
            vec![
                TestCase::new(interchange(vec![(0, vec![40], vec![(2, 30)])])),
                TestCase::new(interchange(vec![(0, vec![50], vec![(10, 50)])]))
                    .with_blocks(vec![
                        (0, 41, false),
                        (0, 45, false),
                        (0, 49, false),
                        (0, 50, false),
                        (0, 51, true),
                    ])
                    .with_attestations(vec![
                        (0, 3, 31, false),
                        (0, 9, 49, false),
                        (0, 10, 51, true),
                    ]),
            ],
        ),
        MultiTestCase::new(
            "multiple_interchanges_single_validator_single_block_out_of_order",
            vec![
                TestCase::new(interchange(vec![(0, vec![40], vec![])])),
                TestCase::new(interchange(vec![(0, vec![20], vec![])]))
                    .contains_slashable_data()
                    .with_blocks(vec![(0, 20, false)]),
            ],
        ),
        MultiTestCase::new(
            "multiple_interchanges_single_validator_fail_iff_imported",
            vec![
                TestCase::new(interchange(vec![(0, vec![40], vec![])])),
                TestCase::new(interchange(vec![(0, vec![20, 50], vec![])]))
                    .contains_slashable_data()
                    .with_blocks(vec![(0, 20, false), (0, 50, false)]),
            ],
        ),
        MultiTestCase::new(
            "multiple_interchanges_single_validator_single_att_out_of_order",
            vec![
                TestCase::new(interchange(vec![(0, vec![], vec![(12, 13)])])),
                TestCase::new(interchange(vec![(0, vec![], vec![(10, 11)])]))
                    .contains_slashable_data()
                    .with_attestations(vec![
                        (0, 10, 14, false),
                        (0, 12, 13, false),
                        (0, 12, 14, true),
                        (0, 13, 15, true),
                    ]),
            ],
        ),
        MultiTestCase::new(
            "multiple_interchanges_single_validator_second_surrounds_first",
            vec![
                TestCase::new(interchange(vec![(0, vec![], vec![(10, 20)])])),
                TestCase::new(interchange(vec![(0, vec![], vec![(9, 21)])]))
                    .contains_slashable_data()
                    .with_attestations(vec![
                        (0, 10, 20, false),
                        (0, 10, 21, false),
                        (0, 9, 21, false),
                        (0, 9, 22, false),
                        (0, 10, 22, true),
                    ]),
            ],
        ),
        MultiTestCase::new(
            "multiple_interchanges_single_validator_first_surrounds_second",
            vec![
                TestCase::new(interchange(vec![(0, vec![], vec![(9, 21)])])),
                TestCase::new(interchange(vec![(0, vec![], vec![(10, 20)])]))
                    .contains_slashable_data()
                    .with_attestations(vec![
                        (0, 10, 20, false),
                        (0, 10, 21, false),
                        (0, 9, 21, false),
                        (0, 9, 22, false),
                        (0, 10, 22, true),
                    ]),
            ],
        ),
        MultiTestCase::new(
            "multiple_interchanges_multiple_validators_repeat_idem",
            vec![
                TestCase::new(interchange(vec![
                    (0, vec![2, 4, 6], vec![(0, 1), (1, 2)]),
                    (1, vec![8, 10, 12], vec![(0, 1), (0, 3)]),
                ])),
                TestCase::new(interchange(vec![
                    (0, vec![2, 4, 6], vec![(0, 1), (1, 2)]),
                    (1, vec![8, 10, 12], vec![(0, 1), (0, 3)]),
                ]))
                .contains_slashable_data()
                .with_blocks(vec![
                    (0, 0, false),
                    (0, 3, true),
                    (0, 7, true),
                    (0, 3, true),
                    (1, 0, false),
                ])
                .with_attestations(vec![(0, 0, 4, false), (1, 0, 4, true)]),
            ],
        ),
        MultiTestCase::new(
            "multiple_interchanges_overlapping_validators_repeat_idem",
            vec![
                TestCase::new(interchange(vec![
                    (0, vec![2, 4, 6], vec![(0, 1), (1, 2)]),
                    (1, vec![8, 10, 12], vec![(0, 1), (0, 3)]),
                ])),
                TestCase::new(interchange(vec![
                    (0, vec![2, 4, 6], vec![(0, 1), (1, 2)]),
                    (2, vec![8, 10, 12], vec![(0, 1), (0, 3)]),
                ]))
                .contains_slashable_data(),
                TestCase::new(interchange(vec![
                    (1, vec![8, 10, 12], vec![(0, 1), (0, 3)]),
                    (2, vec![8, 10, 12], vec![(0, 1), (0, 3)]),
                ]))
                .contains_slashable_data()
                .with_attestations(vec![
                    (0, 0, 4, false),
                    (1, 1, 2, false),
                    (2, 1, 2, false),
                ]),
            ],
        ),
        MultiTestCase::new(
            "multiple_interchanges_overlapping_validators_merge_stale",
            vec![
                TestCase::new(interchange(vec![
                    (0, vec![100], vec![(12, 13)]),
                    (1, vec![101], vec![(12, 13)]),
                    (2, vec![4], vec![(4, 5)]),
                ])),
                TestCase::new(interchange(vec![
                    (0, vec![2], vec![(4, 5)]),
                    (1, vec![3], vec![(3, 4)]),
                    (2, vec![102], vec![(12, 13)]),
                ]))
                .contains_slashable_data()
                .with_blocks(vec![
                    (0, 100, false),
                    (1, 101, false),
                    (2, 102, false),
                    (0, 103, true),
                    (1, 104, true),
                    (2, 105, true),
                ])
                .with_attestations(vec![
                    (0, 12, 13, false),
                    (0, 11, 14, false),
                    (1, 12, 13, false),
                    (1, 11, 14, false),
                    (2, 12, 13, false),
                    (2, 11, 14, false),
                    (0, 12, 14, true),
                    (1, 13, 14, true),
                    (2, 13, 14, true),
                ]),
            ],
        ),
        MultiTestCase::single(
            "single_validator_source_greater_than_target",
            TestCase::new(interchange(vec![(0, vec![], vec![(8, 7)])])).contains_slashable_data(),
        ),
        MultiTestCase::single(
            "single_validator_source_greater_than_target_surrounding",
            TestCase::new(interchange(vec![(0, vec![], vec![(5, 2)])]))
                .contains_slashable_data()
                .with_attestations(vec![(0, 3, 4, false)]),
        ),
        MultiTestCase::single(
            "single_validator_source_greater_than_target_surrounded",
            TestCase::new(interchange(vec![(0, vec![], vec![(5, 2)])]))
                .contains_slashable_data()
                .with_attestations(vec![(0, 6, 1, false)]),
        ),
        MultiTestCase::single(
            "single_validator_source_greater_than_target_sensible_iff_minified",
            TestCase::new(interchange(vec![(0, vec![], vec![(5, 2), (6, 7)])]))
                .contains_slashable_data()
                .with_attestations(vec![(0, 5, 8, false), (0, 6, 8, true)]),
        ),
        MultiTestCase::single(
            "single_validator_out_of_order_blocks",
            TestCase::new(interchange(vec![(0, vec![6, 5], vec![])])).with_blocks(vec![
                (0, 5, false),
                (0, 6, false),
                (0, 7, true),
            ]),
        ),
        MultiTestCase::single(
            "single_validator_out_of_order_attestations",
            TestCase::new(interchange(vec![(0, vec![], vec![(4, 5), (3, 4)])])).with_attestations(
                vec![
                    (0, 3, 4, false),
                    (0, 4, 5, false),
                    (0, 1, 10, false),
                    (0, 3, 3, false),
                ],
            ),
        ),
        // Ensure that it's not just the minimum bound check preventing blocks at the same slot
        // from being signed.
        MultiTestCase::single(
            "single_validator_two_blocks_no_signing_root",
            TestCase::new(interchange(vec![(0, vec![10, 20], vec![])]))
                .with_blocks(vec![(0, 20, false)]),
        ),
        MultiTestCase::single(
            "single_validator_multiple_block_attempts",
            TestCase::new(interchange(vec![(0, vec![15, 16, 17], vec![])]))
                .with_signing_root_blocks(vec![
                    (0, 16, 0, false),
                    (0, 16, 1, false),
                    (0, 16, u64::MAX, false),
                ]),
        ),
        MultiTestCase::single(
            "single_validator_resign_block",
            TestCase::new(interchange_with_signing_roots(vec![(
                0,
                vec![(15, Some(151)), (16, Some(161)), (17, Some(171))],
                vec![],
            )]))
            .with_signing_root_blocks(vec![
                (0, 15, 151, true),
                (0, 16, 161, true),
                (0, 17, 171, true),
                (0, 15, 152, false),
                (0, 15, 0, false),
                (0, 16, 151, false),
                (0, 17, 151, false),
                (0, 18, 151, true),
                (0, 14, 171, false),
            ]),
        ),
        MultiTestCase::single(
            "single_validator_resign_attestation",
            TestCase::new(interchange_with_signing_roots(vec![(
                0,
                vec![],
                vec![(5, 15, Some(515))],
            )]))
            .with_signing_root_attestations(vec![
                (0, 5, 15, 0, false),
                (0, 5, 15, 1, false),
                (0, 5, 15, 515, true),
                (0, 6, 15, 615, false),
                (0, 5, 14, 515, false),
            ]),
        ),
        MultiTestCase::single(
            "single_validator_slashable_blocks",
            TestCase::new(interchange_with_signing_roots(vec![(
                0,
                vec![(10, Some(0)), (10, Some(11))],
                vec![],
            )]))
            .contains_slashable_data(),
        ),
        MultiTestCase::single(
            "single_validator_slashable_blocks_no_root",
            TestCase::new(interchange(vec![(0, vec![10, 10], vec![])])).contains_slashable_data(),
        ),
        MultiTestCase::single(
            "single_validator_slashable_attestations_double_vote",
            TestCase::new(interchange_with_signing_roots(vec![(
                0,
                vec![],
                vec![(2, 3, Some(0)), (2, 3, Some(1))],
            )]))
            .contains_slashable_data(),
        ),
        MultiTestCase::single(
            "single_validator_slashable_attestations_surrounds_existing",
            TestCase::new(interchange(vec![(0, vec![], vec![(2, 3), (0, 4)])]))
                .contains_slashable_data(),
        ),
        MultiTestCase::single(
            "single_validator_slashable_attestations_surrounded_by_existing",
            TestCase::new(interchange(vec![(0, vec![], vec![(0, 4), (2, 3)])]))
                .contains_slashable_data(),
        ),
        MultiTestCase::single(
            "duplicate_pubkey_not_slashable",
            TestCase::new(interchange(vec![
                (0, vec![10, 11], vec![(0, 2)]),
                (0, vec![12, 13], vec![(1, 3)]),
            ]))
            .with_blocks(vec![(0, 10, false), (0, 13, false), (0, 14, true)])
            .with_attestations(vec![(0, 0, 2, false), (0, 1, 3, false)]),
        ),
        MultiTestCase::single(
            "duplicate_pubkey_slashable_block",
            TestCase::new(interchange(vec![
                (0, vec![10], vec![(0, 2)]),
                (0, vec![10], vec![(1, 3)]),
            ]))
            .contains_slashable_data()
            .with_blocks(vec![(0, 10, false), (0, 11, true)]),
        ),
        MultiTestCase::single(
            "duplicate_pubkey_slashable_attestation",
            TestCase::new(interchange_with_signing_roots(vec![
                (0, vec![], vec![(0, 3, Some(3))]),
                (0, vec![], vec![(1, 2, None)]),
            ]))
            .contains_slashable_data()
            .with_attestations(vec![
                (0, 0, 1, false),
                (0, 0, 2, false),
                (0, 0, 4, false),
                (0, 1, 4, true),
            ]),
        ),
    ];

    let args = std::env::args().collect::<Vec<_>>();
    let output_dir = Path::new(&args[1]);
    fs::create_dir_all(output_dir).unwrap();

    for test in tests {
        // Check that test case passes without minification
        test.run(false);

        // Check that test case passes with minification
        test.run(true);

        let f = File::create(output_dir.join(format!("{}.json", test.name))).unwrap();
        serde_json::to_writer_pretty(&f, &test).unwrap();
        writeln!(&f).unwrap();
    }
}

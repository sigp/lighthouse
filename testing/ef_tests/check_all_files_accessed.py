#!/usr/bin/env python3

# The purpose of this script is to compare a list of file names that were accessed during testing
# against all the file names in the consensus-spec-tests repository. It then checks to see which files
# were not accessed and returns an error if any non-intentionally-ignored files are detected.
#
# The ultimate goal is to detect any accidentally-missed spec tests.

import os
import re
import sys

# First argument should the path to a file which contains a list of accessed file names.
accessed_files_filename = sys.argv[1]

# Second argument should be the path to the consensus-spec-tests directory.
tests_dir_filename = sys.argv[2]

# If any of the file names found in the consensus-spec-tests directory *starts with* one of the
# following regular expressions, we will assume they are to be ignored (i.e., we are purposefully
# *not* running the spec tests).
excluded_paths = [
    # Eth1Block and PowBlock
    #
    # Intentionally omitted, as per https://github.com/sigp/lighthouse/issues/1835
    "tests/.*/.*/ssz_static/Eth1Block/",
    "tests/.*/.*/ssz_static/PowBlock/",
    # Lighthouse's Engine API NewPayloadRequest is not an SSZ container.
    "tests/[^/]+/[^/]+/ssz_static/NewPayloadRequest/",
    # We no longer implement merge logic.
    "tests/.*/bellatrix/fork_choice/on_merge_block",
    # Light client sync is not implemented
    "tests/.*/.*/light_client/sync",
    # LightClientStore
    "tests/.*/.*/ssz_static/LightClientStore",
    # LightClientSnapshot
    "tests/.*/.*/ssz_static/LightClientSnapshot",
    # LightClientDataCollection
    "tests/minimal/.*/light_client/data_collection",
    # One of the EF researchers likes to pack the tarballs on a Mac
    ".*\\.DS_Store.*",
    # More Mac weirdness.
    "tests/mainnet/bellatrix/operations/deposit/pyspec_tests/deposit_with_previous_fork_version__valid_ineffective/._meta.yaml",
    # bls tests are moved to bls12-381-tests directory
    "tests/general/phase0/bls",
    # some bls tests are not included now
    "bls12-381-tests/deserialization_G1",
    "bls12-381-tests/deserialization_G2",
    "bls12-381-tests/hash_to_G2",
    "tests/.*/eip7732",
    "tests/.*/eip7805",
    # Heze fork is not implemented
    "tests/.*/heze/.*",
    # Ignore MatrixEntry SSZ tests for now.
    "tests/.*/.*/ssz_static/MatrixEntry/.*",
    # TODO: partial data column not implemented yet
    "tests/.*/.*/ssz_static/PartialDataColumn.*/.*",
    # Execution payload header is irrelevant after Gloas, this type will probably be deleted.
    "tests/.*/gloas/ssz_static/ExecutionPayloadHeader/.*",
    # ForkChoiceNode is internal to fork choice and probably doesn't need SSZ tests.
    "tests/.*/gloas/ssz_static/ForkChoiceNode/.*",
    # Ignore KZG tests that target internal kzg library functions
    "tests/.*/compute_verify_cell_kzg_proof_batch_challenge/.*",
    "tests/.*/compute_challenge/.*",
    # We don't need these manifest files at the moment.
    "tests/.*/manifest.yaml",
    # These cases return SkippedKnownFailure before their fixture files are loaded. Keep these
    # synchronized with IGNORED_BEACON_BLOCK_CASES in gossip_validation.rs, where the per-case
    # rationale is documented.
    "tests/.*/.*/networking/gossip_beacon_block/.*/gossip_beacon_block__ignore_parent_consensus_failed_execution_known/.*",
    "tests/.*/.*/networking/gossip_beacon_block/.*/gossip_beacon_block__reject_parent_consensus_failed_execution_not_verified/.*",
    "tests/.*/.*/networking/gossip_beacon_block/.*/gossip_beacon_block__reject_parent_failed_validation/.*",
    # Gossip validation tests target the latest stable fork and Gloas.
    "tests/.*/(phase0|altair|bellatrix|capella|deneb|electra)/networking/gossip_beacon_attestation/.*",
    "tests/.*/(phase0|altair|bellatrix|capella|deneb|electra)/networking/gossip_beacon_aggregate_and_proof/.*",
    "tests/.*/(phase0|altair|bellatrix|capella|deneb|electra)/networking/gossip_voluntary_exit/.*",
    "tests/.*/(phase0|altair|bellatrix|capella|deneb|electra)/networking/gossip_bls_to_execution_change/.*",
    "tests/.*/(phase0|altair|bellatrix|capella|deneb|electra)/networking/gossip_sync_committee_message/.*",
    "tests/.*/(phase0|altair|bellatrix|capella|deneb|electra)/networking/gossip_sync_committee_contribution_and_proof/.*",
    # Lighthouse does not retain consensus-invalid blocks, and its attestation past-tolerance is
    # exclusive at the epoch window disparity edge. Keep these patterns synchronized with
    # GossipValidation::has_known_harness_limitation.
    "tests/.*/(fulu|gloas)/networking/gossip_(beacon_attestation|beacon_aggregate_and_proof)/.*/gossip_.*__accepts_(first|last)_slot_when_epoch_window_closes/.*",
    "tests/.*/(fulu|gloas)/networking/gossip_(beacon_attestation|beacon_aggregate_and_proof)/.*/gossip_.*__reject_block_failed_validation/.*",
    # Advancing the parent state across an epoch for every gossip bid would put epoch processing
    # on the gossip hot path. Keep synchronized with IGNORED_EXECUTION_PAYLOAD_BID_CASES.
    "tests/.*/gloas/networking/gossip_execution_payload_bid/.*/gossip_execution_payload_bid__valid_requires_state_advanced_across_epoch/.*",
    # Gloas execution payload envelope cases with production-harness limitations. Keep these
    # synchronized with IGNORED_EXECUTION_PAYLOAD_ENVELOPE_CASES.
    "tests/.*/gloas/networking/gossip_execution_payload_envelope/.*/gossip_execution_payload_envelope__reject_block_failed_validation/.*",
    # Lighthouse cannot distinguish a consensus-invalid block from an unseen block when
    # validating payload attestations. Keep this synchronized with
    # IGNORED_PAYLOAD_ATTESTATION_CASES.
    "tests/.*/gloas/networking/gossip_payload_attestation_message/.*/gossip_payload_attestation_message__reject_block_failed_validation/.*",
    # Fulu partial data column cases with production-harness limitations. Keep synchronized with
    # IGNORED_PARTIAL_DATA_COLUMN_CASES.
    "tests/.*/fulu/networking/gossip_partial_data_column_sidecar/.*/gossip_partial_data_column_sidecar__(reject_parent_failed_validation|ignore_cells_with_cached_header_future_slot|ignore_cells_with_cached_header_not_later_than_finalized_slot|reject_empty|reject_non_ancestor_finalized_checkpoint)/.*",
    "tests/.*/.*/networking/gossip_blob_sidecar/.*",
    # Data column gossip tests only run for Gloas. Lighthouse cannot distinguish a
    # consensus-invalid block from an unseen block. Keep synchronized with IGNORED_DATA_COLUMN_CASES.
    "tests/.*/fulu/networking/gossip_data_column_sidecar/.*",
    "tests/.*/gloas/networking/gossip_data_column_sidecar/.*/gossip_data_column_sidecar__reject_block_failed_validation/.*",
]

# Extra arguments are ignored paths. Useful for skipping another preset's vectors.
excluded_paths += sys.argv[3:]


def normalize_path(path):
    return path.split("consensus-spec-tests/")[1]


# Determine the list of filenames which were accessed during tests.
passed = set()
for line in open(accessed_files_filename, 'r').readlines():
    file = normalize_path(line.strip().strip('"'))
    passed.add(file)

missed = set()
accessed_files = 0
excluded_files = 0

# Iterate all files in the tests directory, ensure that all files were either accessed
# or intentionally missed.
for root, dirs, files in os.walk(tests_dir_filename):
    for name in files:
        name = normalize_path(os.path.join(root, name))
        if name not in passed:
            excluded = False
            for excluded_path_regex in excluded_paths:
                if re.match(excluded_path_regex, name):
                    excluded = True
                    break
            if excluded:
                excluded_files += 1
            else:
                print(name)
                missed.add(name)
        else:
            accessed_files += 1

# Exit with an error if there were any files missed.
assert len(missed) == 0, "{} missed files".format(len(missed))

print("Accessed {} files ({} intentionally excluded)".format(
    accessed_files, excluded_files))

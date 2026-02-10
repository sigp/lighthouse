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
    # TODO(gloas): remove these ignores as more Gloas operations are implemented
    "tests/.*/gloas/operations/block_header/.*",
    "tests/.*/gloas/operations/execution_payload_bid/.*",
    "tests/.*/gloas/operations/payload_attestation/.*",
    # TODO(EIP-7732): remove these ignores as Gloas consensus is implemented
    "tests/.*/gloas/epoch_processing/.*",
    "tests/.*/gloas/finality/.*",
    "tests/.*/gloas/fork/.*",
    "tests/.*/gloas/fork_choice/.*",
    "tests/.*/gloas/networking/.*",
    "tests/.*/gloas/rewards/.*",
    "tests/.*/gloas/sanity/.*",
    "tests/.*/gloas/transition/.*",
    # Ignore MatrixEntry SSZ tests for now.
    "tests/.*/.*/ssz_static/MatrixEntry/.*",
    # TODO(gloas): Ignore Gloas light client stuff for now
    "tests/.*/gloas/ssz_static/LightClient.*/.*",
    # Execution payload header is irrelevant after Gloas, this type will probably be deleted.
    "tests/.*/gloas/ssz_static/ExecutionPayloadHeader/.*",
    # ForkChoiceNode is internal to fork choice and probably doesn't need SSZ tests.
    "tests/.*/gloas/ssz_static/ForkChoiceNode/.*",
    # EIP-7916 is still in draft and hasn't been implemented yet https://eips.ethereum.org/EIPS/eip-7916
    "tests/general/phase0/ssz_generic/progressive_bitlist",
    "tests/general/phase0/ssz_generic/basic_progressive_list",
    "tests/general/phase0/ssz_generic/containers/.*/ProgressiveBitsStruct.*",
    "tests/general/phase0/ssz_generic/containers/.*/ProgressiveTestStruct.*",
    "tests/general/phase0/ssz_generic/progressive_containers/.*",
    "tests/general/phase0/ssz_generic/compatible_unions/.*",
    # Ignore full epoch tests for now (just test the sub-transitions).
    "tests/.*/.*/epoch_processing/.*/pre_epoch.ssz_snappy",
    "tests/.*/.*/epoch_processing/.*/post_epoch.ssz_snappy",
    # Ignore inactivity_scores tests for now (should implement soon).
    "tests/.*/.*/rewards/inactivity_scores/.*",
    # Ignore KZG tests that target internal kzg library functions
    "tests/.*/compute_verify_cell_kzg_proof_batch_challenge/.*",
    "tests/.*/compute_challenge/.*",
    # We don't need these manifest files at the moment.
    "tests/.*/manifest.yaml"
]


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
